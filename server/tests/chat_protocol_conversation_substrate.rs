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

use chat_protocol::public_state::encode_public_tree_summary;
use chat_protocol::repository::core::{
    hydrate_locked_conversation_head, hydrate_locked_creation_head,
    hydrate_locked_direct_conversation_lookup, hydrate_locked_public_state,
    ConversationHeadHydrationError, CreationHeadHydrationError, DirectConversationLookupError,
    LockedDirectLookupOutcome, PublicStateHydrationError,
};
use chat_protocol::snapshot::{
    PublicGroupSnapshotLeaf, PublicGroupSnapshotLifecycle, PublicGroupSnapshotTreeSummary,
};

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
    let (snapshot, snapshot_sha256) = canonical_snapshot();
    let (tree_summary_bytes, tree_summary_sha256) = canonical_tree_summary();
    seed_base_with_public_state(
        pool,
        &snapshot,
        &snapshot_sha256,
        &tree_summary_bytes,
        &tree_summary_sha256,
    )
    .await
}

/// Seed the base GROUP conversation with caller-supplied public-state columns so
/// the fail-closed coherence case can inject a non-canonical tree summary.
/// (A mismatched snapshot digest is unpersistable: the DDL constraint
/// `generation_states_snapshot_hash_check` rejects it at insert.) `seed_base`
/// supplies the canonical, self-consistent values.
async fn seed_base_with_public_state(
    pool: &PgPool,
    snapshot: &[u8],
    snapshot_sha256: &[u8],
    tree_summary_bytes: &[u8],
    tree_summary_sha256: &[u8],
) -> BaseConversation {
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
        snapshot,
        snapshot_sha256,
        tree_summary_bytes,
        tree_summary_sha256,
    )
    .await;
    BaseConversation {
        conversation_id,
        actor_did,
        actor_device_id,
        actor_key_id,
    }
}

/// A non-empty public-snapshot blob and its exact SHA-256. The G1 snapshot-leg
/// guard only checks this digest and never decodes the blob (that is
/// `load_persisted_active_snapshot`'s job), so opaque bytes suffice here.
fn canonical_snapshot() -> (Vec<u8>, [u8; 32]) {
    let snapshot = vec![0x5A_u8; 64];
    let sha: [u8; 32] = Sha256::digest(&snapshot).into();
    (snapshot, sha)
}

/// A CANONICAL one-leaf public tree summary (the exact encoding
/// `decode_public_tree_summary` accepts) and its SHA-256. Lengths follow the
/// production caps: 49-byte basic credential, 32-byte Ed25519 signature key,
/// 1216-byte X-Wing encryption key.
fn canonical_tree_summary() -> (Vec<u8>, [u8; 32]) {
    let summary = PublicGroupSnapshotTreeSummary::new(
        [0x33_u8; 32],
        vec![PublicGroupSnapshotLeaf::new(
            0,
            vec![0x44_u8; 49],
            vec![0x45_u8; 32],
            vec![0x46_u8; 1216],
        )],
    );
    let (bytes, sha) = encode_public_tree_summary(&summary)
        .expect("canonical tree summary encodes")
        .into_parts();
    (bytes, sha)
}

#[allow(clippy::too_many_arguments)]
async fn commit_coherent_group_creation(
    pool: &PgPool,
    principal: &str,
    actor_device_id: Uuid,
    actor_key_id: &str,
    actor_public_key: &[u8],
    snapshot: &[u8],
    snapshot_sha256: &[u8],
    tree_summary_bytes: &[u8],
    tree_summary_sha256: &[u8],
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
    .bind(snapshot)
    .bind(snapshot_sha256)
    .bind(tree_summary_bytes)
    .bind(tree_summary_sha256)
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

// ===========================================================================
// G3 — direct-pair absence-CAS lookup + creation/absence head variant.
// ===========================================================================

async fn seed_principal(pool: &PgPool, did: &str) {
    let at = clock_now(pool).await;
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(did)
    .bind(at)
    .execute(pool)
    .await
    .expect("insert principal");
}

fn canonical_pair(a: &str, b: &str) -> (String, String) {
    if a < b {
        (a.to_owned(), b.to_owned())
    } else {
        (b.to_owned(), a.to_owned())
    }
}

/// No active direct conversation for the pair → `Absent`, under the principals lock.
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn direct_lookup_absent_when_no_active_direct_conversation() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let (low, high) = canonical_pair(&random_plc_did(), &random_plc_did());
    seed_principal(&pool, &low).await;
    seed_principal(&pool, &high).await;
    let locked_at = clock_now_millis(&pool).await;

    let mut tx = pool.begin().await.expect("begin");
    let guard = hydrate_locked_direct_conversation_lookup(&mut tx, &low, &high, locked_at)
        .await
        .expect("direct lookup");
    tx.commit().await.expect("commit");

    assert_eq!(guard.did_low(), low);
    assert_eq!(guard.did_high(), high);
    assert!(matches!(guard.outcome(), LockedDirectLookupOutcome::Absent));
}

/// A non-canonical pair (low !< high) is rejected before any DB access.
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn direct_lookup_rejects_non_canonical_pair() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let did = random_plc_did();
    let locked_at = clock_now_millis(&pool).await;

    let mut tx = pool.begin().await.expect("begin");
    let result = hydrate_locked_direct_conversation_lookup(&mut tx, &did, &did, locked_at).await;
    tx.rollback().await.expect("rollback");

    assert!(matches!(
        result,
        Err(DirectConversationLookupError::NonCanonicalPair)
    ));
}

/// MUTUAL EXCLUSION (absence-CAS): the lookup's `chat.principals FOR UPDATE` on
/// the canonical pair is a real serialization point — a second lookup on the same
/// pair BLOCKS until the first transaction releases the principal-row locks.
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn direct_lookup_blocks_on_principals_pair_for_update() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let (low, high) = canonical_pair(&random_plc_did(), &random_plc_did());
    seed_principal(&pool, &low).await;
    seed_principal(&pool, &high).await;

    // A locks the principals pair and holds its transaction open.
    let mut tx_a = pool.begin().await.expect("begin A");
    let locked_at_a = clock_now_millis(&pool).await;
    let _guard_a = hydrate_locked_direct_conversation_lookup(&mut tx_a, &low, &high, locked_at_a)
        .await
        .expect("A locks the pair");

    // B contends for the same pair; it must block until A releases.
    let pool_b = pool.clone();
    let (low_b, high_b) = (low.clone(), high.clone());
    let mut b = tokio::spawn(async move {
        let mut tx_b = pool_b.begin().await.expect("begin B");
        let locked_at_b = clock_now_millis(&pool_b).await;
        let guard =
            hydrate_locked_direct_conversation_lookup(&mut tx_b, &low_b, &high_b, locked_at_b)
                .await
                .expect("B locks the pair after A releases");
        tx_b.commit().await.expect("B commits");
        matches!(guard.outcome(), LockedDirectLookupOutcome::Absent)
    });

    match tokio::time::timeout(Duration::from_millis(1000), &mut b).await {
        Err(_elapsed) => { /* blocked on the principals pair — the property under test */ }
        Ok(_) => panic!("B must block on the principals pair FOR UPDATE while A holds it"),
    }

    tx_a.commit().await.expect("A commits");
    assert!(b.await.expect("B joins"), "B sees the pair still absent");
}

/// The creation/absence head witnesses an absent conversation id and mints the
/// `prior=None`, `next_entry_seq=1` creation head.
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn creation_head_hydrates_absent_conversation() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let conversation_id = Uuid::new_v4();
    let locked_at = clock_now_millis(&pool).await;

    let mut tx = pool.begin().await.expect("begin");
    let head = hydrate_locked_creation_head(&mut tx, conversation_id, locked_at)
        .await
        .expect("creation head");
    tx.commit().await.expect("commit");

    assert_eq!(head.conversation_id(), conversation_id);
    assert_eq!(head.next_entry_seq(), 1);
    assert!(
        head.prior_coordinate().is_none(),
        "a creation head carries no prior coordinate"
    );
}

/// CONFLICT-based exclusion (fork ruling): once a conversation id is taken, the
/// creation head fails closed with `ConversationExists` — a second creator for an
/// existing id can never mint a creation witness. (The concurrent arbiter for two
/// racing fresh creates is the executor's INSERT: the `chat.conversations` PK and
/// the `conversations_active_direct_pair_uq` partial unique index.)
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn creation_head_rejects_existing_conversation_id() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let base = seed_base(&pool).await;
    let locked_at = clock_now_millis(&pool).await;

    let mut tx = pool.begin().await.expect("begin");
    let result = hydrate_locked_creation_head(&mut tx, base.conversation_id, locked_at).await;
    tx.rollback().await.expect("rollback");

    assert!(matches!(
        result,
        Err(CreationHeadHydrationError::ConversationExists)
    ));
}

/// Seed a coherent committed ACTIVE DIRECT conversation for `(creator, recipient)`:
/// the creator is an active admin with a genesis leaf, the recipient is a pending
/// admin with NO leaf (satisfying the direct roster invariant: exactly two current
/// admin participants, one active, per `chat.enforce_roster_invariants`). Returns
/// (conversation_id, did_low, did_high).
async fn commit_coherent_direct_creation(
    pool: &PgPool,
    creator: &str,
    creator_device_id: Uuid,
    creator_key_id: &str,
    creator_public_key: &[u8],
    recipient: &str,
) -> (Uuid, String, String) {
    let (did_low, did_high) = canonical_pair(creator, recipient);
    let conversation_id = Uuid::new_v4();
    let creation_transition_id = Uuid::new_v4();
    let creation_entry_id = Uuid::new_v4();
    let creator_period_id = Uuid::new_v4();
    let recipient_period_id = Uuid::new_v4();
    let leaf_period_id = Uuid::new_v4();
    let metadata_snapshot_id = Uuid::new_v4();
    let group_id = vec![0x21_u8; 32];
    let group_context_hash = vec![0x22_u8; 32];
    let confirmation_tag = vec![0x23_u8; 32];
    let group_info = vec![0x24_u8; 8];
    let snapshot = vec![0x25_u8; 8];
    let tree_summary = vec![0x26_u8; 8];
    let signed_request = vec![0x27_u8; 8];
    let unsigned_projection = vec![0x28_u8; 8];
    let signing_transcript = vec![0x29_u8; 8];
    let request_digest = Sha256::digest(&signing_transcript).to_vec();
    let signature = vec![0x2a_u8; 64];
    let accepted_payload = vec![0x2b_u8; 8];
    let creation_fingerprint = vec![0x2c_u8; 32];
    let metadata_ciphertext = vec![0x2d_u8; 16];
    let basic_credential = format!("{creator}#{creator_device_id}").into_bytes();
    let at = clock_now(pool).await;

    let mut tx = pool.begin().await.expect("begin direct creation");
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(recipient)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("insert recipient principal");
    sqlx::query(
        "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,direct_did_low,direct_did_high,created_at) VALUES($1,'direct','active',0,0,2,$2,$3,$4)",
    )
    .bind(conversation_id)
    .bind(&did_low)
    .bind(&did_high)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("insert direct conversation");
    sqlx::query(
        "INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) VALUES($1,0,$2,'active',$3,$4,0,1,$5)",
    )
    .bind(conversation_id)
    .bind(&group_id)
    .bind(&group_info)
    .bind(Sha256::digest(&group_info).to_vec())
    .bind(at)
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
    .bind(creator)
    .bind(creator_device_id)
    .bind(creator_key_id)
    .bind(&signed_request)
    .bind(&unsigned_projection)
    .bind(&signing_transcript)
    .bind(&request_digest)
    .bind(&signature)
    .bind(metadata_snapshot_id)
    .bind(at)
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
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("insert creation state");
    // Creator: active admin (genesis provenance, no invitation).
    sqlx::query(
        r#"INSERT INTO chat.participants(
            participant_period_id,conversation_id,user_did,status,role,role_transition_id,
            role_changed_at,created_by_did,created_by_device_id,current_membership,created_at
        ) VALUES($1,$2,$3,'active','admin',$4,$5,$3,$6,true,$5)"#,
    )
    .bind(creator_period_id)
    .bind(conversation_id)
    .bind(creator)
    .bind(creation_transition_id)
    .bind(at)
    .bind(creator_device_id)
    .execute(&mut *tx)
    .await
    .expect("insert creator participant");
    sqlx::query(
        r#"INSERT INTO chat.member_devices(
            leaf_period_id,participant_period_id,conversation_id,generation,user_did,
            device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,
            leaf_auth_generation,origin,joined_state_version,joined_transition_id,
            joined_seq,active,created_at
        ) VALUES($1,$2,$3,0,$4,$5,0,$6,$7,$8,1,'genesis',0,$9,1,true,$10)"#,
    )
    .bind(leaf_period_id)
    .bind(creator_period_id)
    .bind(conversation_id)
    .bind(creator)
    .bind(creator_device_id)
    .bind(&basic_credential)
    .bind(creator_public_key)
    .bind(creator_key_id)
    .bind(creation_transition_id)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("insert creator leaf");
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
    .bind(vec![0x2e_u8; 12])
    .bind(&metadata_ciphertext)
    .bind(Sha256::digest(&metadata_ciphertext).to_vec())
    .bind(creator)
    .bind(creator_device_id)
    .bind(creator_key_id)
    .bind(creator_public_key)
    .bind(at)
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
    .bind(creator)
    .bind(creator_device_id)
    .bind(creator_key_id)
    .bind(creation_transition_id)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("insert creation entry");
    // Recipient: pending admin, invited by the creator (invitation bound to the
    // genesis creation entry), NO leaf. Inserted after the entry so the immediate
    // invitation_entry_id -> chat.entries FK is satisfied.
    sqlx::query(
        r#"INSERT INTO chat.participants(
            participant_period_id,conversation_id,user_did,status,role,role_transition_id,
            role_changed_at,created_by_did,created_by_device_id,invitation_transition_id,
            invitation_entry_id,invited_at,current_membership,created_at
        ) VALUES($1,$2,$3,'pending','admin',$4,$5,$6,$7,$4,$8,$5,true,$5)"#,
    )
    .bind(recipient_period_id)
    .bind(conversation_id)
    .bind(recipient)
    .bind(creation_transition_id)
    .bind(at)
    .bind(creator)
    .bind(creator_device_id)
    .bind(creation_entry_id)
    .execute(&mut *tx)
    .await
    .expect("insert recipient participant");
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
    .bind(creator)
    .bind(creator_device_id)
    .bind(&creation_fingerprint)
    .bind(&group_id)
    .bind(&group_context_hash)
    .bind(&confirmation_tag)
    .bind(leaf_period_id)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("insert creation interval");
    tx.commit().await.expect("commit direct creation");
    (conversation_id, did_low, did_high)
}

/// An ACTIVE direct conversation for the pair → `Existing` carrying that
/// conversation's current coordinate (lifecycle Active) and a non-zero head digest.
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn direct_lookup_existing_returns_active_direct_coordinate() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let (creator, creator_device_id, creator_key_id) = seed_actor(&pool).await;
    let creator_public_key: Vec<u8> =
        sqlx::query_scalar("SELECT signing_public_key FROM chat.device_keys WHERE key_id=$1")
            .bind(&creator_key_id)
            .fetch_one(&pool)
            .await
            .expect("read creator public key");
    let recipient = random_plc_did();
    let (conversation_id, did_low, did_high) = commit_coherent_direct_creation(
        &pool,
        &creator,
        creator_device_id,
        &creator_key_id,
        &creator_public_key,
        &recipient,
    )
    .await;
    let locked_at = clock_now_millis(&pool).await;

    let mut tx = pool.begin().await.expect("begin");
    let guard = hydrate_locked_direct_conversation_lookup(&mut tx, &did_low, &did_high, locked_at)
        .await
        .expect("direct lookup");
    tx.commit().await.expect("commit");

    match guard.outcome() {
        LockedDirectLookupOutcome::Existing {
            conversation_id: found,
            coordinate,
            locked_head_digest,
        } => {
            assert_eq!(*found, conversation_id);
            assert_eq!(coordinate.conversation_id(), conversation_id.as_bytes());
            assert_eq!(coordinate.generation(), 0);
            assert_eq!(coordinate.state_version(), 0);
            assert_eq!(coordinate.group_id(), &[0x21_u8; 32]);
            assert_eq!(coordinate.lifecycle(), PublicGroupSnapshotLifecycle::Active);
            assert_ne!(locked_head_digest, &[0_u8; 32]);
        }
        LockedDirectLookupOutcome::Absent => {
            panic!("an active direct conversation must be Existing")
        }
    }
}

// ===========================================================================
// G1 (snapshot leg) — locked public-state witness of the current generation.
// ===========================================================================

/// The hydrator assembles the current coordinate from the `chat.conversations`
/// head + `chat.generation_states` crypto columns, carries the persisted snapshot
/// blob verbatim, re-decodes the canonical tree summary, and mints a non-zero
/// transaction-local generation-row digest.
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn public_state_hydrates_the_current_generation_witness() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let base = seed_base(&pool).await;
    let (expected_snapshot, expected_snapshot_sha) = canonical_snapshot();
    let (expected_tree_bytes, expected_tree_sha) = canonical_tree_summary();
    let locked_at = clock_now_millis(&pool).await;

    let mut tx = pool.begin().await.expect("begin");
    let guard = hydrate_locked_public_state(&mut tx, base.conversation_id, locked_at)
        .await
        .expect("public state hydrates");
    tx.commit().await.expect("commit");

    let (
        txid,
        conversation_id,
        coordinate,
        snapshot,
        binding,
        encoded_tree,
        tree_sha,
        at,
        gen_digest,
    ) = guard.into_parts();
    assert!(
        !txid.is_empty(),
        "the guard carries its locking transaction id"
    );
    assert_eq!(conversation_id, base.conversation_id);
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
    assert_eq!(
        snapshot, expected_snapshot,
        "snapshot blob carried verbatim"
    );
    assert_eq!(binding.coordinate(), &coordinate);
    assert_eq!(binding.snapshot_sha256(), &expected_snapshot_sha);
    assert_eq!(encoded_tree, expected_tree_bytes);
    assert_eq!(tree_sha, expected_tree_sha);
    assert_eq!(at.timestamp_millis(), locked_at.timestamp_millis());
    assert_ne!(
        gen_digest, [0_u8; 32],
        "transaction-local generation-row digest"
    );
}

/// Absence is fail-closed: no `chat.conversations` row yields `ConversationMissing`,
/// never a fabricated public-state witness.
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn absent_conversation_public_state_is_conversation_missing() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let locked_at = clock_now_millis(&pool).await;

    let mut tx = pool.begin().await.expect("begin");
    let result = hydrate_locked_public_state(&mut tx, Uuid::new_v4(), locked_at).await;
    tx.rollback().await.expect("rollback");

    assert!(matches!(
        result,
        Err(PublicStateHydrationError::ConversationMissing)
    ));
}

/// MUTUAL EXCLUSION: the public-state hydrator's `FOR UPDATE OF c` on
/// `chat.conversations` is the same real serialization point as the head lock — a
/// second transaction hydrating the SAME conversation's public state BLOCKS until
/// the first releases the row lock, then completes. There is no lock-free
/// hydration path.
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn concurrent_public_state_hydration_blocks_on_for_update() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let base = seed_base(&pool).await;
    let conversation_id = base.conversation_id;

    // A acquires the public-state lock first (in this task) and holds its
    // transaction open, so B necessarily contends against a held `c` row lock.
    let mut tx_a = pool.begin().await.expect("begin A");
    let locked_at_a = clock_now_millis(&pool).await;
    let _guard_a = hydrate_locked_public_state(&mut tx_a, conversation_id, locked_at_a)
        .await
        .expect("A acquires the public-state lock");

    let pool_b = pool.clone();
    let mut b = tokio::spawn(async move {
        let mut tx_b = pool_b.begin().await.expect("begin B");
        let locked_at_b = clock_now_millis(&pool_b).await;
        let guard_b = hydrate_locked_public_state(&mut tx_b, conversation_id, locked_at_b)
            .await
            .expect("B acquires the public-state lock after A releases");
        tx_b.commit().await.expect("B commits");
        let (_txid, _cid, coordinate, _snap, _binding, _tsb, _tss, _at, digest) =
            guard_b.into_parts();
        (coordinate.state_version(), digest != [0_u8; 32])
    });

    // While A holds the lock, B cannot finish — it is blocked on `FOR UPDATE OF c`.
    match tokio::time::timeout(Duration::from_millis(1000), &mut b).await {
        Err(_elapsed) => { /* still blocked — the property under test */ }
        Ok(_) => panic!("B must block on FOR UPDATE while A holds the conversation head"),
    }

    tx_a.commit().await.expect("A commits");
    let (state_version, non_zero_digest) = b.await.expect("B task joins");
    assert_eq!(state_version, 0, "B observes the same committed generation");
    assert!(non_zero_digest, "B seals a non-zero generation-row digest");
}

/// Fail-closed: a stored tree summary that is not the exact canonical encoding is
/// rejected even when its own digest column is self-consistent.
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn public_state_non_canonical_tree_summary_fails_closed() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let (snapshot, snapshot_sha) = canonical_snapshot();
    let non_canonical_tree = vec![0x6_u8; 8];
    let self_consistent_sha: [u8; 32] = Sha256::digest(&non_canonical_tree).into();
    let base = seed_base_with_public_state(
        &pool,
        &snapshot,
        &snapshot_sha,
        &non_canonical_tree,
        &self_consistent_sha,
    )
    .await;
    let locked_at = clock_now_millis(&pool).await;

    let mut tx = pool.begin().await.expect("begin");
    let result = hydrate_locked_public_state(&mut tx, base.conversation_id, locked_at).await;
    tx.rollback().await.expect("rollback");

    assert!(matches!(
        result,
        Err(PublicStateHydrationError::InvalidTreeSummary)
    ));
}

// ---------------------------------------------------------------------------
// G1b-1b — HistoricalRehydrationAuthority, signed-request path (OQ-G1-3(a)).
//
// Pure-crypto (no DB): the signed-request re-verification is over the raw
// ed25519 wrapper + the frozen row digest, corpus-independent. Drift fence for
// the duplicated `historical_signed_request_evidence` (state_machine.rs) vs the
// certified `HydrationAuthority::signed_request` / `hydrate_persisted_signed_request`:
// per-kind byte-equivalence (coordinator condition 2) + the fail-closed family
// (condition 3, minus the seq<head control-only case).
// ---------------------------------------------------------------------------
mod historical_signed_path {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};
    use uuid::Uuid;

    use crate::chat_protocol::snapshot::{
        PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle,
    };
    use crate::chat_protocol::state_machine::{
        DeviceIdentity, DurableSignedRequestEnvelope, HistoricalRehydrationAuthority,
        HydrationAuthority, PersistedSignedRequestRow, PrincipalId, StateMachineError,
    };
    use crate::chat_protocol::transcript::{
        decode_and_verify_signed_mutation, decode_canonical_signed_mutation, SignedMutationKind,
    };
    use crate::chat_protocol::validation::{
        ed25519_key_id, CanonicalTimestamp, TrustedRequestInstant,
    };

    pub(super) const RECEIVED_AT: &str = "2030-01-01T00:00:00.000Z";

    fn uuid_v4_bytes(byte: u8) -> [u8; 16] {
        let mut value = [byte; 16];
        value[6] = 0x40 | (byte & 0x0f);
        value[8] = 0x80 | (byte & 0x3f);
        value
    }

    pub(super) fn sample_coordinate(conversation_id: [u8; 16]) -> PublicGroupSnapshotCoordinate {
        PublicGroupSnapshotCoordinate::new(
            conversation_id,
            5,
            0,
            [0x07; 32],
            3,
            [0x09; 32],
            [0x11; 32],
            PublicGroupSnapshotLifecycle::Active,
        )
    }

    pub(super) fn sample_actor() -> DeviceIdentity {
        let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
        DeviceIdentity::new(
            PrincipalId::new(did.as_bytes().to_vec()).unwrap(),
            uuid_v4_bytes(0x41),
        )
        .unwrap()
    }

    fn coordinate_json(coordinate: &PublicGroupSnapshotCoordinate) -> Value {
        json!({
            "conversationId":
                Uuid::from_bytes(*coordinate.conversation_id()).hyphenated().to_string(),
            "generation": coordinate.generation(),
            "stateVersion": coordinate.state_version(),
            "groupId": STANDARD.encode(coordinate.group_id()),
            "epoch": coordinate.epoch(),
            "groupContextHash": STANDARD.encode(coordinate.group_context_hash()),
            "confirmationTag": STANDARD.encode(coordinate.confirmation_tag()),
            "lifecycle": match coordinate.lifecycle() {
                PublicGroupSnapshotLifecycle::Active => "active",
                PublicGroupSnapshotLifecycle::Superseded => "superseded",
            },
        })
    }

    fn resign_signed_wrapper(mut wrapper: Value, signing_key: &SigningKey) -> Vec<u8> {
        wrapper["signature"] = Value::String(STANDARD.encode([0u8; 64]));
        let unsigned = serde_json::to_vec(&wrapper).unwrap();
        let canonical = decode_canonical_signed_mutation(&unsigned).unwrap();
        wrapper["signature"] = Value::String(
            STANDARD.encode(signing_key.sign(canonical.transcript_bytes()).to_bytes()),
        );
        serde_json::to_vec(&wrapper).unwrap()
    }

    fn envelope_fields(
        kind: SignedMutationKind,
        actor: &DeviceIdentity,
        signing_key: &SigningKey,
    ) -> Value {
        json!({
            "$type": kind.type_id(),
            "signatureDomain": String::from_utf8(kind.domain().to_vec()).unwrap(),
            "actorDid": std::str::from_utf8(actor.principal().as_bytes()).unwrap(),
            "actorDeviceId": Uuid::from_bytes(*actor.device_id()).hyphenated().to_string(),
            "keyId": ed25519_key_id(&signing_key.verifying_key().to_bytes()).unwrap().as_str(),
            "authGeneration": 1,
            "idempotencyKey": Uuid::from_bytes(uuid_v4_bytes(0x6d)).hyphenated().to_string(),
            "signedAt": "2029-12-31T23:59:59.000Z",
        })
    }

    fn merge(mut base: Value, extra: Value) -> Value {
        if let (Some(base), Some(extra)) = (base.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                base.insert(key.clone(), value.clone());
            }
        }
        base
    }

    fn leaf_recovery_request_raw(
        coordinate: &PublicGroupSnapshotCoordinate,
        actor: &DeviceIdentity,
        request_id: [u8; 16],
        signing_key: &SigningKey,
    ) -> Vec<u8> {
        let kind = SignedMutationKind::LeafRecoveryRequest;
        let body = merge(
            envelope_fields(kind, actor, signing_key),
            json!({
                "recoveryRequestId": Uuid::from_bytes(request_id).hyphenated().to_string(),
                "prior": coordinate_json(coordinate),
                "recoveryKind": "replace",
            }),
        );
        resign_signed_wrapper(json!({ "body": body, "signature": "" }), signing_key)
    }

    fn leaf_recovery_cancellation_raw(
        actor: &DeviceIdentity,
        request_id: [u8; 16],
        signing_key: &SigningKey,
    ) -> Vec<u8> {
        let kind = SignedMutationKind::LeafRecoveryCancellation;
        let body = merge(
            envelope_fields(kind, actor, signing_key),
            json!({
                "recoveryRequestId": Uuid::from_bytes(request_id).hyphenated().to_string(),
            }),
        );
        resign_signed_wrapper(json!({ "body": body, "signature": "" }), signing_key)
    }

    fn welcome_response_raw(
        kind: SignedMutationKind,
        coordinate: &PublicGroupSnapshotCoordinate,
        actor: &DeviceIdentity,
        welcome_id: [u8; 16],
        signing_key: &SigningKey,
    ) -> Vec<u8> {
        let mut fields = json!({
            "welcomeId": Uuid::from_bytes(welcome_id).hyphenated().to_string(),
            "coordinates": coordinate_json(coordinate),
            "transitionSeq": 3,
        });
        // `welcomeRejectionBody` requires a `reason` enum field that the
        // acknowledgement body does not carry (lexicon `#welcomeRejectionReason`).
        if kind == SignedMutationKind::WelcomeRejection {
            fields["reason"] = Value::String("invalidWelcome".to_string());
        }
        let body = merge(envelope_fields(kind, actor, signing_key), fields);
        resign_signed_wrapper(json!({ "body": body, "signature": "" }), signing_key)
    }

    pub(super) fn all_kinds(
        coordinate: &PublicGroupSnapshotCoordinate,
        actor: &DeviceIdentity,
        signing_key: &SigningKey,
    ) -> Vec<Vec<u8>> {
        vec![
            leaf_recovery_request_raw(coordinate, actor, uuid_v4_bytes(0x31), signing_key),
            leaf_recovery_cancellation_raw(actor, uuid_v4_bytes(0x32), signing_key),
            welcome_response_raw(
                SignedMutationKind::WelcomeAcknowledgement,
                coordinate,
                actor,
                uuid_v4_bytes(0x33),
                signing_key,
            ),
            welcome_response_raw(
                SignedMutationKind::WelcomeRejection,
                coordinate,
                actor,
                uuid_v4_bytes(0x34),
                signing_key,
            ),
        ]
    }

    pub(super) fn trusted_received_at() -> TrustedRequestInstant {
        TrustedRequestInstant::from_canonical_for_test(
            CanonicalTimestamp::parse(RECEIVED_AT).unwrap(),
        )
    }

    #[test]
    fn historical_signed_request_matches_append_time_per_kind() {
        let conversation_id = uuid_v4_bytes(0x21);
        let coordinate = sample_coordinate(conversation_id);
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifying = signing_key.verifying_key().to_bytes();
        let actor = sample_actor();

        let append = HydrationAuthority::new(conversation_id).unwrap();
        let historical = HistoricalRehydrationAuthority::new(conversation_id, 9).unwrap();

        for raw in all_kinds(&coordinate, &actor, &signing_key) {
            let mutation = decode_and_verify_signed_mutation(&raw, &verifying).unwrap();
            let envelope =
                DurableSignedRequestEnvelope::new(conversation_id, &trusted_received_at()).unwrap();
            let admitted = append.signed_request(envelope, mutation).unwrap();
            let digest = *admitted.durable_row_digest();
            let row =
                || PersistedSignedRequestRow::new(conversation_id, RECEIVED_AT, digest).unwrap();

            // Certified original: append-time re-hydration (head binding cfg'd out under test).
            let certified = append
                .hydrate_persisted_signed_request(row(), &raw, &verifying)
                .unwrap();
            // Read-time historical authority: MUST be byte-equal per kind.
            let historical_evidence = historical
                .hydrate_historical_signed_request(row(), &raw, &verifying)
                .unwrap();
            assert_eq!(historical_evidence, certified);
            assert_eq!(historical_evidence, admitted);
        }
    }

    #[test]
    fn historical_signed_request_fails_closed() {
        let conversation_id = uuid_v4_bytes(0x21);
        let coordinate = sample_coordinate(conversation_id);
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifying = signing_key.verifying_key().to_bytes();
        let actor = sample_actor();

        let raw = leaf_recovery_request_raw(&coordinate, &actor, uuid_v4_bytes(0x31), &signing_key);
        let mutation = decode_and_verify_signed_mutation(&raw, &verifying).unwrap();
        let append = HydrationAuthority::new(conversation_id).unwrap();
        let envelope =
            DurableSignedRequestEnvelope::new(conversation_id, &trusted_received_at()).unwrap();
        let admitted = append.signed_request(envelope, mutation).unwrap();
        let digest = *admitted.durable_row_digest();
        let row = || PersistedSignedRequestRow::new(conversation_id, RECEIVED_AT, digest).unwrap();

        let historical = HistoricalRehydrationAuthority::new(conversation_id, 9).unwrap();

        // Wrong historical key.
        let wrong = SigningKey::from_bytes(&[0x43; 32]);
        assert_eq!(
            historical.hydrate_historical_signed_request(
                row(),
                &raw,
                &wrong.verifying_key().to_bytes()
            ),
            Err(StateMachineError::InvalidHydrationAuthority)
        );

        // Signature tamper.
        let mut signature_tamper: Value = serde_json::from_slice(&raw).unwrap();
        signature_tamper["signature"] = Value::String(STANDARD.encode([0x99; 64]));
        let signature_tamper = serde_json::to_vec(&signature_tamper).unwrap();
        assert_eq!(
            historical.hydrate_historical_signed_request(row(), &signature_tamper, &verifying),
            Err(StateMachineError::InvalidHydrationAuthority)
        );

        // Tampered frozen-row digest.
        let mut tampered = digest;
        tampered[0] ^= 0x01;
        assert_eq!(
            historical.hydrate_historical_signed_request(
                PersistedSignedRequestRow::new(conversation_id, RECEIVED_AT, tampered).unwrap(),
                &raw,
                &verifying
            ),
            Err(StateMachineError::InvalidHydrationAuthority)
        );

        // Wrong conversation_id (authority bound to a different conversation).
        let other = HistoricalRehydrationAuthority::new(uuid_v4_bytes(0x55), 9).unwrap();
        assert_eq!(
            other.hydrate_historical_signed_request(row(), &raw, &verifying),
            Err(StateMachineError::InvalidHydrationAuthority)
        );
    }

    /// Drift fence for the production loader seam
    /// `hydrate_historical_signed_request_from_durable_bytes`: for every signed
    /// kind, deriving the durable-row digest from the bytes (loader path) is
    /// byte-equal to the row path that is handed the digest from its durable row,
    /// which is in turn byte-equal to append-time admission. It also fails closed
    /// under a wrong key and a foreign-conversation authority, exactly like the
    /// row path (the seam re-verifies through `hydrate_historical_signed_request`).
    #[test]
    fn historical_signed_request_from_durable_bytes_matches_row_path() {
        let conversation_id = uuid_v4_bytes(0x21);
        let coordinate = sample_coordinate(conversation_id);
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifying = signing_key.verifying_key().to_bytes();
        let actor = sample_actor();

        let append = HydrationAuthority::new(conversation_id).unwrap();
        let historical = HistoricalRehydrationAuthority::new(conversation_id, 9).unwrap();

        for raw in all_kinds(&coordinate, &actor, &signing_key) {
            let mutation = decode_and_verify_signed_mutation(&raw, &verifying).unwrap();
            let envelope =
                DurableSignedRequestEnvelope::new(conversation_id, &trusted_received_at()).unwrap();
            let admitted = append.signed_request(envelope, mutation).unwrap();
            let digest = *admitted.durable_row_digest();
            let row = PersistedSignedRequestRow::new(conversation_id, RECEIVED_AT, digest).unwrap();

            // Row path: the digest is supplied from the durable row.
            let row_path = historical
                .hydrate_historical_signed_request(row, &raw, &verifying)
                .unwrap();
            // Loader path: the digest is DERIVED from the bytes, not supplied.
            let from_bytes = historical
                .hydrate_historical_signed_request_from_durable_bytes(
                    conversation_id,
                    RECEIVED_AT,
                    &raw,
                    &verifying,
                )
                .unwrap();
            assert_eq!(from_bytes, row_path);
            assert_eq!(from_bytes, admitted);
        }

        // Wrong key fails closed.
        let raw = leaf_recovery_request_raw(&coordinate, &actor, uuid_v4_bytes(0x31), &signing_key);
        let wrong = SigningKey::from_bytes(&[0x43; 32]);
        assert_eq!(
            historical.hydrate_historical_signed_request_from_durable_bytes(
                conversation_id,
                RECEIVED_AT,
                &raw,
                &wrong.verifying_key().to_bytes()
            ),
            Err(StateMachineError::InvalidHydrationAuthority)
        );
        // Foreign-conversation authority fails closed.
        let other = HistoricalRehydrationAuthority::new(uuid_v4_bytes(0x55), 9).unwrap();
        assert_eq!(
            other.hydrate_historical_signed_request_from_durable_bytes(
                conversation_id,
                RECEIVED_AT,
                &raw,
                &verifying
            ),
            Err(StateMachineError::InvalidHydrationAuthority)
        );
    }
}

// ---------------------------------------------------------------------------
// G1b-1b — HistoricalRehydrationAuthority, CONTROL-entry path (OQ-G1-3(a)).
//
// Drift fence for the two duplicated head-binding-free minters
// (`historical_transition_evidence` / `historical_control_request_evidence`,
// state_machine.rs) vs the certified `HydrationAuthority::transition_from_control`
// / `control_request` (exercised end-to-end through `hydrate_persisted_control`):
// per-mutation-kind byte-equivalence (coordinator condition 2) over ALL 13
// control-entry kinds (10 transition arms + 3 control-request arms) + the
// fail-closed family (condition 3, incl. the control-only `seq >= head`).
//
// Fixtures are the STATIC `mls_chat_contract_vectors.json` control-entry vectors
// (the same authoritative, frozen contract vectors `chat_protocol_auth.rs`
// drives) — NOT the crypto-wire corpus. The re-hydration path here runs only
// `decode_and_verify_control_entry` (ed25519 + DAG-CBOR structure) + byte
// digests; it NEVER reprocesses through OpenMLS leaf-lifetime validation
// (`verify_genesis_group_info`, one call site: the creation planner), so this
// suite stays green regardless of crypto-wire corpus age — it is
// corpus-reprocessing-independent, same posture the interim gate requires.
// The DAG-CBOR->schema-JSON reconstruction (`FixtureDagValue`) is ported
// verbatim from `chat_protocol_auth.rs`.
// ---------------------------------------------------------------------------
mod historical_control_path {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
    use serde::Deserialize;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::fmt;
    use uuid::Uuid;

    use crate::chat_protocol::state_machine::{
        classify_acceptance, classify_role_producer, HistoricalRehydrationAuthority,
        HydrationAuthority, ParticipantRole, PersistedControlAuthority, PersistedControlRow,
        PrincipalId, StateMachineError,
    };
    use crate::chat_protocol::transcript::{
        decode_and_verify_control_entry, decode_canonical_signed_mutation,
        rebind_persisted_control_entry, VerifiedMutationProjection,
    };
    use crate::chat_protocol::validation::ed25519_key_id;

    const CONTRACT_VECTORS: &str = include_str!("fixtures/mls_chat_contract_vectors.json");
    const LEXICON: &str =
        include_str!("../../lexicon/blue/catbird/chat/blue.catbird.chat.defs.json");

    fn uuid_v4_bytes(byte: u8) -> [u8; 16] {
        let mut value = [byte; 16];
        value[6] = 0x40 | (byte & 0x0f);
        value[8] = 0x80 | (byte & 0x3f);
        value
    }

    // Ported verbatim from chat_protocol_auth.rs: schema-aware DAG-CBOR -> JSON
    // so the frozen unsigned signing projection re-canonicalizes to the exact
    // bytes the fixture signature covers (bytes -> STANDARD base64, uuid bytes ->
    // hyphenated string, unions/objects walked by their lexicon schema).
    enum FixtureDagValue {
        String(String),
        Integer(u64),
        Bool(bool),
        Bytes(Vec<u8>),
        Array(Vec<Self>),
        Map(BTreeMap<String, Self>),
    }

    impl<'de> Deserialize<'de> for FixtureDagValue {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(FixtureDagVisitor)
        }
    }

    struct FixtureDagVisitor;

    impl<'de> Visitor<'de> for FixtureDagVisitor {
        type Value = FixtureDagValue;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("the frozen clean-chat DAG-CBOR value profile")
        }

        fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
            Ok(FixtureDagValue::Bool(value))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
            Ok(FixtureDagValue::Integer(value))
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u64::try_from(value)
                .map(FixtureDagValue::Integer)
                .map_err(|_| E::custom("negative fixture integer"))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
            Ok(FixtureDagValue::String(value.to_owned()))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
            Ok(FixtureDagValue::String(value))
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E> {
            Ok(FixtureDagValue::Bytes(value.to_vec()))
        }

        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E> {
            Ok(FixtureDagValue::Bytes(value))
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element()? {
                values.push(value);
            }
            Ok(FixtureDagValue::Array(values))
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = map.next_entry()? {
                values.insert(key, value);
            }
            Ok(FixtureDagValue::Map(values))
        }
    }

    impl FixtureDagValue {
        fn into_json_for_schema(
            self,
            schema: &Value,
            definitions: &serde_json::Map<String, Value>,
        ) -> Value {
            match schema["type"].as_str().unwrap() {
                "ref" => {
                    let definition_name =
                        schema["ref"].as_str().unwrap().strip_prefix('#').unwrap();
                    if matches!(definition_name, "operationId" | "deviceId") {
                        let Self::Bytes(value) = self else {
                            panic!("frozen UUID projection was not DAG-CBOR bytes");
                        };
                        Value::String(Uuid::from_slice(&value).unwrap().hyphenated().to_string())
                    } else {
                        self.into_json_for_schema(&definitions[definition_name], definitions)
                    }
                }
                "union" => {
                    let definition_name = {
                        let Self::Map(values) = &self else {
                            panic!("frozen union projection was not a DAG-CBOR map");
                        };
                        let Some(Self::String(type_id)) = values.get("$type") else {
                            panic!("frozen union projection omitted its type tag");
                        };
                        type_id
                            .strip_prefix("blue.catbird.chat.defs#")
                            .unwrap()
                            .to_owned()
                    };
                    let allowed = schema["refs"].as_array().unwrap().iter().any(|reference| {
                        reference.as_str() == Some(&format!("#{definition_name}"))
                    });
                    assert!(allowed, "frozen union selected a disallowed type");
                    self.into_json_for_schema(&definitions[definition_name.as_str()], definitions)
                }
                "object" => {
                    let Self::Map(values) = self else {
                        panic!("frozen object projection was not a DAG-CBOR map");
                    };
                    let properties = schema["properties"].as_object().unwrap();
                    Value::Object(
                        values
                            .into_iter()
                            .map(|(name, value)| {
                                let value = if name == "$type" {
                                    let Self::String(type_id) = value else {
                                        panic!("frozen object type tag was not text");
                                    };
                                    Value::String(type_id)
                                } else {
                                    value.into_json_for_schema(&properties[&name], definitions)
                                };
                                (name, value)
                            })
                            .collect(),
                    )
                }
                "string" => {
                    let Self::String(value) = self else {
                        panic!("frozen string projection was not DAG-CBOR text");
                    };
                    Value::String(value)
                }
                "bytes" => {
                    let Self::Bytes(value) = self else {
                        panic!("frozen byte projection was not DAG-CBOR bytes");
                    };
                    Value::String(STANDARD.encode(value))
                }
                "integer" => {
                    let Self::Integer(value) = self else {
                        panic!("frozen integer projection was not a DAG-CBOR integer");
                    };
                    json!(value)
                }
                "boolean" => {
                    let Self::Bool(value) = self else {
                        panic!("frozen boolean projection was not a DAG-CBOR boolean");
                    };
                    json!(value)
                }
                "array" => {
                    let Self::Array(values) = self else {
                        panic!("frozen array projection was not a DAG-CBOR array");
                    };
                    Value::Array(
                        values
                            .into_iter()
                            .map(|value| value.into_json_for_schema(&schema["items"], definitions))
                            .collect(),
                    )
                }
                other => panic!("unsupported frozen fixture schema type {other}"),
            }
        }
    }

    struct ControlCase {
        entry_kind: String,
        cid: [u8; 16],
        seq: u64,
        public_row_json: Vec<u8>,
        raw_wrapper: Vec<u8>,
        public_key: Vec<u8>,
        outer_projection: Vec<u8>,
        server_fields_dag_cbor: Vec<u8>,
        outer_fingerprint: [u8; 32],
        durable_row_digest: [u8; 32],
    }

    impl ControlCase {
        fn row(&self) -> PersistedControlRow {
            PersistedControlRow::new(
                self.public_row_json.clone(),
                self.raw_wrapper.clone(),
                self.outer_projection.clone(),
                self.server_fields_dag_cbor.clone(),
                self.outer_fingerprint,
                self.durable_row_digest,
            )
            .unwrap()
        }
    }

    /// Re-signs a `{body, signature}` wrapper with the test key over the exact
    /// canonical transcript the strict decoder derives (mirrors the signed-path
    /// `resign_signed_wrapper`).
    fn resign(mut wrapper: Value, signing_key: &SigningKey) -> Vec<u8> {
        wrapper["signature"] = Value::String(STANDARD.encode([0u8; 64]));
        let unsigned = serde_json::to_vec(&wrapper).unwrap();
        let canonical = decode_canonical_signed_mutation(&unsigned).unwrap();
        wrapper["signature"] = Value::String(
            STANDARD.encode(signing_key.sign(canonical.transcript_bytes()).to_bytes()),
        );
        serde_json::to_vec(&wrapper).unwrap()
    }

    /// Repairs the internal digests the semantic transition parse recomputes, so
    /// a placeholder-hash contract vector becomes a byte-consistent body:
    /// - every artifact `{bytes, sha256}` (commit / genesisGroupInfo) gets
    ///   `sha256 = sha256(bytes)` (`checked_artifact_sha256`);
    /// - a metadata snapshot's `ciphertextSha256`/`ciphertextSize` are rebound to
    ///   its `ciphertext` (`parse_metadata_snapshot`);
    /// - a metadata `authorProof`'s `authorKeyId` is rebound to
    ///   `ed25519_key_id(signaturePublicKey)` (the derivation the parser checks).
    /// Everything else — coordinates, manifests, actor identity, server fields —
    /// is left verbatim.
    fn repair_body_digests(value: &mut Value) {
        match value {
            Value::Object(map) => {
                if let (Some(Value::String(bytes_b64)), true) =
                    (map.get("bytes").cloned(), map.contains_key("sha256"))
                {
                    if let Ok(bytes) = STANDARD.decode(&bytes_b64) {
                        map.insert(
                            "sha256".to_string(),
                            json!(STANDARD.encode(Sha256::digest(&bytes))),
                        );
                    }
                }
                if let (Some(Value::String(cipher_b64)), true) = (
                    map.get("ciphertext").cloned(),
                    map.contains_key("ciphertextSha256"),
                ) {
                    if let Ok(bytes) = STANDARD.decode(&cipher_b64) {
                        map.insert(
                            "ciphertextSha256".to_string(),
                            json!(STANDARD.encode(Sha256::digest(&bytes))),
                        );
                        map.insert("ciphertextSize".to_string(), json!(bytes.len()));
                    }
                }
                if let (Some(Value::String(pk_b64)), true) = (
                    map.get("signaturePublicKey").cloned(),
                    map.contains_key("authorKeyId"),
                ) {
                    if let Ok(pk) = STANDARD.decode(&pk_b64) {
                        if let Ok(pk) = <[u8; 32]>::try_from(pk.as_slice()) {
                            map.insert(
                                "authorKeyId".to_string(),
                                json!(ed25519_key_id(&pk).unwrap().as_str()),
                            );
                        }
                    }
                }
                // A metadata snapshot's authorProof.originTransitionId must equal
                // the snapshot's own originTransitionId (`parse_metadata_snapshot`).
                if let (Some(origin), true) = (
                    map.get("originTransitionId").cloned(),
                    map.get("authorProof")
                        .map(Value::is_object)
                        .unwrap_or(false),
                ) {
                    if let Some(Value::Object(proof)) = map.get_mut("authorProof") {
                        proof.insert("originTransitionId".to_string(), origin);
                    }
                }
                for child in map.values_mut() {
                    repair_body_digests(child);
                }
            }
            Value::Array(items) => {
                for child in items.iter_mut() {
                    repair_body_digests(child);
                }
            }
            _ => {}
        }
    }

    // Rebuild every frozen control-entry vector into a durable row + the
    // append-time-minted digest that the row must carry.
    fn build_cases() -> Vec<ControlCase> {
        let fixture: Value = serde_json::from_str(CONTRACT_VECTORS).unwrap();
        let contract: Value = serde_json::from_str(LEXICON).unwrap();
        let definitions = contract["defs"].as_object().unwrap();
        let cef = &fixture["controlEntryFingerprints"];

        // One test signer re-signs every rebuilt body; the historical public key
        // handed to the re-hydration authorities is therefore this test key.
        let signing_key = SigningKey::from_bytes(&[0x24; 32]);
        let verifying = signing_key.verifying_key().to_bytes();

        let mut cases = Vec::new();
        for case in cef["cases"].as_array().unwrap() {
            let body_cbor = hex::decode(
                case["unsignedSigningProjectionCanonicalDagCborHex"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            let body: FixtureDagValue = serde_ipld_dagcbor::from_slice(&body_cbor).unwrap();
            let signed_name = case["signedRequestRef"]
                .as_str()
                .unwrap()
                .strip_prefix("blue.catbird.chat.defs#")
                .unwrap();
            let body_name = definitions[signed_name]["properties"]["body"]["refs"][0]
                .as_str()
                .unwrap()
                .strip_prefix('#')
                .unwrap();
            let mut signing_body = body.into_json_for_schema(&definitions[body_name], definitions);
            // The contract vectors carry PLACEHOLDER artifact/metadata digests and
            // are signed by keys whose privates we do not hold — they validate at
            // the wire/fingerprint layer only (all `chat_protocol_auth.rs` checks),
            // never through the semantic transition parse. Reuse them as STRUCTURAL
            // templates: repair every internal digest so `transition_from_control`
            // accepts them, rebind the signer key id to our test key, and re-sign.
            // The frozen server fields (close tombstone / acceptance recovery) stay
            // internally consistent because the actor DID/device, seq, receivedAt,
            // conversation id, and retired coordinate are all kept verbatim.
            repair_body_digests(&mut signing_body);
            signing_body["keyId"] = json!(ed25519_key_id(&verifying).unwrap().as_str());
            let raw_wrapper = resign(
                json!({ "body": signing_body, "signature": "" }),
                &signing_key,
            );
            let signed_request: Value = serde_json::from_slice(&raw_wrapper).unwrap();

            let mut row = json!({
                "$type": case["entryKind"],
                "entryId": case["entryId"],
                "conversationId": case["conversationId"],
                "seq": case["seq"],
                "signedRequest": signed_request,
                "receivedAt": case["receivedAt"],
            });
            row.as_object_mut().unwrap().extend(
                case["serverFields"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone())),
            );
            let public_row_json = serde_json::to_vec(&row).unwrap();
            let public_key = verifying.to_vec();

            let decoded = decode_and_verify_control_entry(&public_row_json, &public_key).unwrap();
            let outer_projection = decoded.outer_control_projection().to_vec();
            let outer_fingerprint = *decoded.outer_control_fingerprint();
            let server_fields_dag_cbor = decoded.server_fields_dag_cbor().unwrap();
            let cid = *Uuid::parse_str(case["conversationId"].as_str().unwrap())
                .unwrap()
                .as_bytes();
            let seq = case["seq"].as_u64().unwrap();

            // The row's durable digest is whatever the certified APPEND-TIME
            // minter produces (head guards cfg'd out under test). Historical
            // re-hydration MUST reproduce the identical evidence + digest.
            let entry_for_digest = rebind_persisted_control_entry(
                decode_and_verify_control_entry(&public_row_json, &public_key).unwrap(),
                &raw_wrapper,
                &public_key,
            )
            .unwrap();
            let append = HydrationAuthority::new(cid).unwrap();
            // The certified append-time minter fixes the digest the row must
            // carry. Every one of the 13 control-entry kinds — including the 6
            // metadata-bearing arms healed by the parse_metadata_snapshot fix
            // (metadataCryptoContext.conversationId read as exact-16 bytes) —
            // mints successfully here.
            let durable_row_digest = match entry_for_digest.mutation().projection() {
                VerifiedMutationProjection::ResetRequest(_)
                | VerifiedMutationProjection::LeaveRequest(_)
                | VerifiedMutationProjection::LeaveCancellation(_) => *append
                    .control_request(entry_for_digest)
                    .unwrap()
                    .durable_row_digest(),
                _ => *append
                    .control_transition(entry_for_digest)
                    .unwrap()
                    .durable_row_digest(),
            };

            cases.push(ControlCase {
                entry_kind: case["entryKind"].as_str().unwrap().to_owned(),
                cid,
                seq,
                public_row_json,
                raw_wrapper,
                public_key,
                outer_projection,
                server_fields_dag_cbor,
                outer_fingerprint,
                durable_row_digest,
            });
        }
        cases
    }

    fn is_control_request(entry_kind: &str) -> bool {
        [
            "resetRequestEntry",
            "leaveRequestEntry",
            "leaveCancellationEntry",
        ]
        .iter()
        .any(|k| entry_kind.ends_with(k))
    }

    // -----------------------------------------------------------------------
    // Real seq-1 creation-entry fixture for the DB loader atom.
    //
    // The frozen creation contract vector is signed at seq 45 / conversationId
    // 11111111-1111-4111-9111-111111111111. The chat.entries contiguity trigger
    // forces a single seeded entry to seq 1, and entries are immutable (not
    // deletable) so each gate-DB run needs a FRESH conversationId. So the vector
    // is reused as a STRUCTURAL creation template: digests repaired + signer key
    // rebound to the test key (as `build_cases` does), then the top-level seq is
    // set to 1 and every conversationId occurrence — top-level + the signed-body
    // coordinates — is rewritten to a fresh v4, and the body re-signed. The
    // result is a genuinely ed25519-signed, decodable creation entry the loader
    // can re-verify.
    // -----------------------------------------------------------------------

    pub(super) struct RealCreationEntry {
        pub(super) cid: [u8; 16],
        pub(super) entry_id: uuid::Uuid,
        pub(super) public_row_json: Vec<u8>,
        pub(super) raw_wrapper: Vec<u8>,
        pub(super) public_key: Vec<u8>,
        pub(super) outer_entry_fingerprint: [u8; 32],
        pub(super) actor_did: String,
        pub(super) actor_device_id: uuid::Uuid,
        pub(super) actor_key_id: String,
        pub(super) signing_seed: [u8; 32],
        pub(super) head_next_entry_seq: u64,
    }

    impl RealCreationEntry {
        pub(super) fn signing_key(&self) -> SigningKey {
            SigningKey::from_bytes(&self.signing_seed)
        }
    }

    fn rewrite_conversation_id(
        value: &mut Value,
        from_uuid: &str,
        to_uuid: &str,
        from_b64: &str,
        to_b64: &str,
    ) {
        match value {
            Value::String(text) => {
                if text == from_uuid {
                    *text = to_uuid.to_owned();
                } else if text == from_b64 {
                    *text = to_b64.to_owned();
                }
            }
            Value::Array(items) => {
                for child in items.iter_mut() {
                    rewrite_conversation_id(child, from_uuid, to_uuid, from_b64, to_b64);
                }
            }
            Value::Object(map) => {
                for child in map.values_mut() {
                    rewrite_conversation_id(child, from_uuid, to_uuid, from_b64, to_b64);
                }
            }
            _ => {}
        }
    }

    fn rewrite_exact_text(value: &mut Value, from: &str, to: &str) {
        match value {
            Value::String(text) if text == from => *text = to.to_owned(),
            Value::Array(items) => {
                for child in items {
                    rewrite_exact_text(child, from, to);
                }
            }
            Value::Object(map) => {
                for child in map.values_mut() {
                    rewrite_exact_text(child, from, to);
                }
            }
            _ => {}
        }
    }

    pub(super) fn build_real_creation_entry(fresh_cid: [u8; 16]) -> RealCreationEntry {
        let fixture: Value = serde_json::from_str(CONTRACT_VECTORS).unwrap();
        let contract: Value = serde_json::from_str(LEXICON).unwrap();
        let definitions = contract["defs"].as_object().unwrap();
        let cef = &fixture["controlEntryFingerprints"];

        let mut signing_seed_digest = Sha256::new();
        signing_seed_digest.update(b"CATBIRD-CHAT-REAL-CREATION-FIXTURE\0");
        signing_seed_digest.update(fresh_cid);
        let signing_seed: [u8; 32] = signing_seed_digest.finalize().into();
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let verifying = signing_key.verifying_key().to_bytes();

        let case = cef["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["entryKind"].as_str().unwrap().ends_with("creationEntry"))
            .expect("creation control vector present");

        let body_cbor = hex::decode(
            case["unsignedSigningProjectionCanonicalDagCborHex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let body: FixtureDagValue = serde_ipld_dagcbor::from_slice(&body_cbor).unwrap();
        let signed_name = case["signedRequestRef"]
            .as_str()
            .unwrap()
            .strip_prefix("blue.catbird.chat.defs#")
            .unwrap();
        let body_name = definitions[signed_name]["properties"]["body"]["refs"][0]
            .as_str()
            .unwrap()
            .strip_prefix('#')
            .unwrap();
        let mut signing_body = body.into_json_for_schema(&definitions[body_name], definitions);
        repair_body_digests(&mut signing_body);
        signing_body["keyId"] = json!(ed25519_key_id(&verifying).unwrap().as_str());

        // Rewrite the frozen conversationId (UUID-text and, defensively, its
        // 16-byte base64 form) to the fresh v4 throughout the signed body.
        const FROZEN_CID: [u8; 16] = [
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x91, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11,
        ];
        let from_uuid = Uuid::from_bytes(FROZEN_CID).hyphenated().to_string();
        let to_uuid = Uuid::from_bytes(fresh_cid).hyphenated().to_string();
        let from_b64 = STANDARD.encode(FROZEN_CID);
        let to_b64 = STANDARD.encode(fresh_cid);
        rewrite_conversation_id(&mut signing_body, &from_uuid, &to_uuid, &from_b64, &to_b64);

        // `chat.transitions.transition_id` is globally unique. Rebind the
        // frozen creation vector's signed transition id (UUID text and its AAD
        // byte encoding) so every independently committed fixture remains both
        // unique and direct-cause exact.
        let frozen_transition_id =
            Uuid::parse_str(signing_body["transitionId"].as_str().unwrap()).unwrap();
        let fresh_transition_id = Uuid::new_v4();
        rewrite_conversation_id(
            &mut signing_body,
            &frozen_transition_id.hyphenated().to_string(),
            &fresh_transition_id.hyphenated().to_string(),
            &STANDARD.encode(frozen_transition_id.as_bytes()),
            &STANDARD.encode(fresh_transition_id.as_bytes()),
        );

        let frozen_actor_device_id = signing_body["actorDeviceId"].as_str().unwrap().to_owned();
        let fresh_actor_device_id = Uuid::new_v4().hyphenated().to_string();
        rewrite_exact_text(
            &mut signing_body,
            &frozen_actor_device_id,
            &fresh_actor_device_id,
        );
        const PLC_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let fresh_actor_suffix: String = signing_seed
            .iter()
            .take(24)
            .map(|byte| PLC_ALPHABET[usize::from(*byte % 32)] as char)
            .collect();
        let fresh_actor_did = format!("did:plc:{fresh_actor_suffix}");
        let frozen_actor_did = signing_body["actorDid"].as_str().unwrap().to_owned();
        rewrite_exact_text(&mut signing_body, &frozen_actor_did, &fresh_actor_did);
        let actor_did = signing_body["actorDid"].as_str().unwrap().to_owned();
        let actor_device_id =
            Uuid::parse_str(signing_body["actorDeviceId"].as_str().unwrap()).unwrap();
        let actor_key_id = ed25519_key_id(&verifying).unwrap().as_str().to_owned();
        // The frozen vector intentionally carries placeholder roster/coordinate
        // values. This helper seeds a live durable genesis, so bind the signed
        // Creation body to the exact graph the repository rows retain; otherwise
        // aggregate interval validation correctly rejects the spliced opening.
        signing_body["conversationKind"] = json!("group");
        signing_body["next"]["groupId"] = json!(STANDARD.encode([1_u8; 32]));
        signing_body["next"]["groupContextHash"] = json!(STANDARD.encode([2_u8; 32]));
        signing_body["next"]["confirmationTag"] = json!(STANDARD.encode([3_u8; 32]));
        signing_body["metadataSnapshot"]["coordinate"]["conversationId"] =
            json!(STANDARD.encode(fresh_cid));
        signing_body["metadataSnapshot"]["coordinate"]["generation"] = json!(0);
        signing_body["metadataSnapshot"]["coordinate"]["groupId"] =
            json!(STANDARD.encode([1_u8; 32]));
        signing_body["metadataSnapshot"]["coordinate"]["epoch"] = json!(0);
        signing_body["metadataSnapshot"]["coordinate"]["groupContextHash"] =
            json!(STANDARD.encode([2_u8; 32]));
        signing_body["metadataSnapshot"]["coordinate"]["confirmationTag"] =
            json!(STANDARD.encode([3_u8; 32]));
        signing_body["manifest"]["actorLeaf"]["userDid"] = json!(&actor_did);
        signing_body["manifest"]["actorLeaf"]["deviceId"] =
            json!(actor_device_id.hyphenated().to_string());
        signing_body["manifest"]["participants"] = json!([{
            "userDid": &actor_did,
            "status": "active",
            "role": "admin",
        }]);

        let raw_wrapper = resign(
            json!({ "body": signing_body, "signature": "" }),
            &signing_key,
        );
        let signed_request: Value = serde_json::from_slice(&raw_wrapper).unwrap();

        let entry_id = Uuid::new_v4();
        let row = json!({
            "$type": case["entryKind"],
            "entryId": entry_id.hyphenated().to_string(),
            "conversationId": to_uuid,
            "seq": 1,
            "signedRequest": signed_request,
            "receivedAt": case["receivedAt"],
        });
        let public_row_json = serde_json::to_vec(&row).unwrap();

        // Fail fast on fixture drift: it must decode + verify under the test key,
        // and its derived outer fingerprint is the durable column value.
        let decoded = decode_and_verify_control_entry(&public_row_json, &verifying)
            .expect("rewritten creation entry decodes under the test key");
        assert_eq!(decoded.conversation_id().as_bytes(), &fresh_cid);
        let outer_entry_fingerprint = *decoded.outer_control_fingerprint();

        RealCreationEntry {
            cid: fresh_cid,
            entry_id,
            public_row_json,
            raw_wrapper,
            public_key: verifying.to_vec(),
            outer_entry_fingerprint,
            actor_did,
            actor_device_id,
            actor_key_id,
            signing_seed,
            head_next_entry_seq: 2,
        }
    }

    #[test]
    fn historical_control_matches_append_time_per_kind() {
        let cases = build_cases();
        // All 13 control-entry kinds: 10 transition arms + 3 control-request arms.
        assert_eq!(cases.len(), 13);
        for case in &cases {
            let append = HydrationAuthority::new(case.cid).unwrap();
            // Certified append-time re-hydration (head binding cfg'd out under
            // test). Every kind mints full evidence — the 6 metadata-bearing arms
            // are healed by the parse_metadata_snapshot fix.
            let certified = append
                .hydrate_persisted_control(case.row(), &case.public_key)
                .unwrap_or_else(|e| {
                    panic!("append-time hydrate failed for {}: {e:?}", case.entry_kind)
                });
            // Read-time historical authority: MUST be byte-equal per kind, with
            // the head bound far above the entry seq so the strict `seq < head`
            // holds. This is the drift fence — any divergence between the
            // duplicated head-binding-free minters and the certified originals in
            // ANY arm makes the evidence differ.
            let historical = HistoricalRehydrationAuthority::new(case.cid, case.seq + 1_000_000)
                .unwrap()
                .hydrate_historical_control(case.row(), &case.public_key)
                .unwrap_or_else(|e| {
                    panic!("historical hydrate failed for {}: {e:?}", case.entry_kind)
                });
            assert_eq!(historical, certified, "kind {}", case.entry_kind);

            // The variant is the one the aggregate consumes for this kind.
            let is_request = matches!(historical, PersistedControlAuthority::Request(_));
            assert_eq!(
                is_request,
                is_control_request(&case.entry_kind),
                "authority variant mismatch for {}",
                case.entry_kind
            );
        }
    }

    #[test]
    fn historical_control_fails_closed() {
        let cases = build_cases();
        // A transition-kind case (commitEntry, seq 42) drives the fail-closed
        // family; the seq >= head arm is the control-only global constraint.
        let case = cases
            .iter()
            .find(|c| c.entry_kind.ends_with("commitEntry"))
            .expect("commit control vector present");

        // Tampered frozen-row digest.
        let mut tampered = case.durable_row_digest;
        tampered[0] ^= 0x01;
        let good_head = HistoricalRehydrationAuthority::new(case.cid, case.seq + 10).unwrap();
        assert_eq!(
            good_head.hydrate_historical_control(
                PersistedControlRow::new(
                    case.public_row_json.clone(),
                    case.raw_wrapper.clone(),
                    case.outer_projection.clone(),
                    case.server_fields_dag_cbor.clone(),
                    case.outer_fingerprint,
                    tampered,
                )
                .unwrap(),
                &case.public_key,
            ),
            Err(StateMachineError::InvalidHydrationAuthority)
        );

        // Wrong conversation_id: authority bound to a different conversation.
        let other =
            HistoricalRehydrationAuthority::new(uuid_v4_bytes(0x55), case.seq + 10).unwrap();
        assert_eq!(
            other.hydrate_historical_control(case.row(), &case.public_key),
            Err(StateMachineError::InvalidHydrationAuthority)
        );

        // Control-only global constraint: entry seq NOT strictly below the head.
        let at_head = HistoricalRehydrationAuthority::new(case.cid, case.seq).unwrap();
        assert_eq!(
            at_head.hydrate_historical_control(case.row(), &case.public_key),
            Err(StateMachineError::InvalidHydrationAuthority)
        );

        // Signature failure: verified under the wrong historical key.
        let wrong_key = [0x11_u8; 32];
        assert_eq!(
            good_head.hydrate_historical_control(case.row(), &wrong_key),
            Err(StateMachineError::InvalidHydrationAuthority)
        );
    }

    // -----------------------------------------------------------------------
    // Durable-row loader seam (`hydrate_historical_control_from_durable_bytes`):
    // the state_machine.rs half of the G1b-2 evidence loader. The core.rs DB
    // loader reads `accepted_payload_bytes` + `signed_request_bytes` from
    // `chat.entries` (+ the `chat.device_keys` signing key), then calls this seam
    // — which DERIVES the un-stored outer-row projection/fingerprint/server-fields
    // and the durable row digest and re-verifies through `hydrate_historical_control`.
    // Drift fence: byte-equality to the `hydrate_historical_control` row path for
    // every control-entry kind (the row path is itself the certified drift fence
    // vs the append-time minters). Pure-crypto, corpus-independent.
    // -----------------------------------------------------------------------

    #[test]
    fn historical_control_from_durable_bytes_matches_row_path_per_kind() {
        let cases = build_cases();
        assert_eq!(cases.len(), 13);
        for case in &cases {
            let auth = HistoricalRehydrationAuthority::new(case.cid, case.seq + 1_000_000).unwrap();
            // Certified reference: the `PersistedControlRow` path.
            let from_row = auth
                .hydrate_historical_control(case.row(), &case.public_key)
                .unwrap_or_else(|e| panic!("row path failed for {}: {e:?}", case.entry_kind));
            // Loader seam: the same authority, re-derived from durable bytes only.
            let from_bytes = auth
                .hydrate_historical_control_from_durable_bytes(
                    case.public_row_json.clone(),
                    case.raw_wrapper.clone(),
                    &case.public_key,
                )
                .unwrap_or_else(|e| {
                    panic!("durable-bytes path failed for {}: {e:?}", case.entry_kind)
                });
            assert_eq!(from_bytes, from_row, "kind {}", case.entry_kind);
        }
    }

    #[test]
    fn historical_control_from_durable_bytes_fails_closed() {
        let cases = build_cases();
        let case = cases
            .iter()
            .find(|c| c.entry_kind.ends_with("commitEntry"))
            .expect("commit control vector present");
        let auth = HistoricalRehydrationAuthority::new(case.cid, case.seq + 10).unwrap();

        // Wrong historical key: signature verification fails during decode.
        assert_eq!(
            auth.hydrate_historical_control_from_durable_bytes(
                case.public_row_json.clone(),
                case.raw_wrapper.clone(),
                &[0x11_u8; 32],
            ),
            Err(StateMachineError::InvalidHydrationAuthority)
        );

        // Tampered public row: corrupting the leading `{` breaks JSON decoding.
        let mut tampered = case.public_row_json.clone();
        tampered[0] ^= 0xff;
        assert_eq!(
            auth.hydrate_historical_control_from_durable_bytes(
                tampered,
                case.raw_wrapper.clone(),
                &case.public_key,
            ),
            Err(StateMachineError::InvalidHydrationAuthority)
        );

        // Control-only global constraint delegated to `hydrate_historical_control`:
        // an entry seq NOT strictly below the head fails closed.
        let at_head = HistoricalRehydrationAuthority::new(case.cid, case.seq).unwrap();
        assert_eq!(
            at_head.hydrate_historical_control_from_durable_bytes(
                case.public_row_json.clone(),
                case.raw_wrapper.clone(),
                &case.public_key,
            ),
            Err(StateMachineError::InvalidHydrationAuthority)
        );
    }

    /// The G1b-2 participant classifiers fail closed on a real, fully re-verified
    /// control transition whose body does NOT attest the queried provenance: a
    /// policy transition that neither changes nor adds a stranger's role is not
    /// that stranger's role producer, and an acceptance is neither a role
    /// producer nor a foreign principal's acceptance. (The Some-arm — a policy
    /// role change that IS the producer — needs the multi-participant real-signed
    /// fixture and is the mandatory G1b-2 follow-up sub-seal.)
    #[test]
    fn participant_classifiers_reject_non_attesting_evidence() {
        let cases = build_cases();
        let stranger = PrincipalId::new(b"did:plc:strangerstrangerst00".to_vec()).unwrap();

        let policy = cases
            .iter()
            .find(|c| c.entry_kind.ends_with("policyEntry"))
            .expect("policy control vector present");
        let policy_evidence = match HistoricalRehydrationAuthority::new(policy.cid, policy.seq + 1)
            .unwrap()
            .hydrate_historical_control(policy.row(), &policy.public_key)
            .expect("policy entry re-hydrates")
        {
            PersistedControlAuthority::Transition(evidence) => evidence,
            PersistedControlAuthority::Request(_) => panic!("policy entry is a transition"),
        };
        // A policy without a matching change for this stranger is not its role
        // producer.
        assert!(
            classify_role_producer(policy_evidence, &stranger, ParticipantRole::Member).is_err()
        );

        let acceptance = cases
            .iter()
            .find(|c| c.entry_kind.ends_with("participantAcceptanceEntry"))
            .expect("acceptance control vector present");
        let acceptance_evidence =
            match HistoricalRehydrationAuthority::new(acceptance.cid, acceptance.seq + 1)
                .unwrap()
                .hydrate_historical_control(acceptance.row(), &acceptance.public_key)
                .expect("acceptance entry re-hydrates")
            {
                PersistedControlAuthority::Transition(evidence) => evidence,
                PersistedControlAuthority::Request(_) => panic!("acceptance entry is a transition"),
            };
        // An acceptance is an unexpected kind for a role producer.
        assert!(classify_role_producer(
            acceptance_evidence.clone(),
            &stranger,
            ParticipantRole::Member
        )
        .is_err());
        // ...and it is not a foreign principal's acceptance.
        assert!(classify_acceptance(acceptance_evidence, &stranger).is_err());
    }
}

// ===========================================================================
// G1b-2 — durable control-entry evidence loader (core.rs
// `load_historical_control_evidence`): the DB read half of the loader atom.
//
// Seeds a coherent committed group graph whose seq-1 creation entry carries the
// REAL, ed25519-signed creation-entry bytes from `build_real_creation_entry`
// (rewritten to the graph's fresh conversationId), with the acting device's
// `chat.device_keys` signing key set to the fixture test key so the JOINed key
// verifies the entry. The loader reads `accepted_payload_bytes` +
// `signed_request_bytes` + the JOINed key and re-verifies through the crypto
// seam; its output must byte-equal the in-memory
// `hydrate_historical_control_from_durable_bytes` over the same bytes.
// ===========================================================================
mod historical_control_loader {
    use chrono::{DateTime, Utc};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::historical_control_path::{build_real_creation_entry, RealCreationEntry};
    use crate::chat_protocol::public_state::encode_public_tree_summary;
    use crate::chat_protocol::repository::core::{
        load_historical_control_evidence, load_interval_hydration_rows, load_metadata_provenance,
        load_participant_hydration_rows, load_producer_transition_evidence,
        ControlEvidenceLoadError, IntervalHydrationError, MetadataHydrationError,
        ParticipantHydrationError, ProducerHydrationError,
    };
    use crate::chat_protocol::snapshot::{
        PublicGroupSnapshotLeaf, PublicGroupSnapshotLifecycle, PublicGroupSnapshotTreeSummary,
    };
    use crate::chat_protocol::state_machine::{
        metadata_binding_of_transition, DeviceIdentity, HistoricalRehydrationAuthority,
        MetadataSnapshotBinding, OpeningKind, ParticipantRole, ParticipantStatus, PrincipalId,
    };
    use crate::common;

    async fn clock_now(pool: &PgPool) -> DateTime<Utc> {
        sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(pool)
            .await
            .expect("sample trusted database clock")
    }

    /// Seed a coherent committed GROUP conversation whose genesis (seq 1) entry
    /// carries `entry`'s real creation bytes. The acting device's signing key is
    /// the fixture test key that signed those bytes. Returns the fresh
    /// `transition_id` the entry (and current generation-state) is bound to.
    fn signed_creation_transition_id(entry: &RealCreationEntry) -> Uuid {
        let wrapper: Value =
            serde_json::from_slice(&entry.raw_wrapper).expect("creation wrapper JSON");
        Uuid::parse_str(
            wrapper["body"]["transitionId"]
                .as_str()
                .expect("creation transitionId"),
        )
        .expect("creation transitionId UUID")
    }

    async fn seed_real_creation_graph(pool: &PgPool, entry: &RealCreationEntry) -> Uuid {
        seed_real_creation_graph_with_transition_id(
            pool,
            entry,
            signed_creation_transition_id(entry),
        )
        .await
    }

    async fn seed_real_creation_graph_with_transition_id(
        pool: &PgPool,
        entry: &RealCreationEntry,
        creation_transition_id: Uuid,
    ) -> Uuid {
        let conversation_id = Uuid::from_bytes(entry.cid);
        let participant_period_id = Uuid::new_v4();
        let leaf_period_id = Uuid::new_v4();
        let metadata_snapshot_id = Uuid::new_v4();
        let actor_did = &entry.actor_did;
        let actor_device_id = entry.actor_device_id;
        let actor_key_id = &entry.actor_key_id;
        let actor_public_key = entry.public_key.clone();
        let group_id = vec![1_u8; 32];
        let group_context_hash = vec![2_u8; 32];
        let confirmation_tag = vec![3_u8; 32];
        let group_info = vec![4_u8; 8];
        let unsigned_projection = vec![8_u8; 8];
        let signing_transcript = vec![9_u8; 8];
        // The entry <-> transition mapping trigger requires the entry's
        // signed_request_bytes / request_digest / signature to EQUAL the producing
        // transition's; both rows carry the entry's real signed wrapper. The
        // transition's request_digest must equal sha256(signing_transcript_bytes)
        // (transitions_signature_check), and the entry mirrors that value (its own
        // request_digest/signature columns are shape-only and loader-ignored).
        let signed_request = entry.raw_wrapper.clone();
        let request_digest = Sha256::digest(&signing_transcript).to_vec();
        let signature = vec![0x5c_u8; 64];
        let metadata_ciphertext = vec![13_u8; 16];
        let (snapshot, snapshot_sha256) = {
            let snapshot = vec![0x5a_u8; 64];
            let sha: Vec<u8> = Sha256::digest(&snapshot).to_vec();
            (snapshot, sha)
        };
        let basic_credential = format!("{actor_did}#{actor_device_id}").into_bytes();
        let tree = PublicGroupSnapshotTreeSummary::new(
            [0x63_u8; 32],
            vec![PublicGroupSnapshotLeaf::new(
                0,
                basic_credential.clone(),
                actor_public_key.clone(),
                vec![0x64_u8; 1_216],
            )],
        );
        let (tree_summary, tree_summary_sha) = encode_public_tree_summary(&tree)
            .expect("genesis tree summary is canonical")
            .into_parts();
        // Entry columns: the real bytes drive the loader; the shape-only columns
        // (request_digest / signature / server_fields_bytes) are never read by it.
        let entry_payload = entry.public_row_json.clone();
        let entry_payload_sha = Sha256::digest(&entry_payload).to_vec();
        let entry_outer_fingerprint = entry.outer_entry_fingerprint.to_vec();
        let at = clock_now(pool).await;

        let mut tx = pool.begin().await.expect("begin real creation");
        sqlx::query(
            "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(actor_did)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert principal");
        sqlx::query(
            "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
             VALUES($1,$2,'loader-actor','active',$3,1,chat.protocol_capabilities(),$4,$4) ON CONFLICT DO NOTHING",
        )
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(actor_key_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert device");
        sqlx::query(
            "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
             VALUES($1,$2,$3,$4,1,$5) ON CONFLICT DO NOTHING",
        )
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(actor_key_id)
        .bind(&actor_public_key)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert device key");
        sqlx::query(
            "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'group','active',0,0,2,$2)",
        )
        .bind(conversation_id)
        .bind(at)
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
        .bind(at)
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
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(actor_key_id)
        .bind(&signed_request)
        .bind(&unsigned_projection)
        .bind(&signing_transcript)
        .bind(&request_digest)
        .bind(&signature)
        .bind(metadata_snapshot_id)
        .bind(at)
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
        .bind(&snapshot_sha256)
        .bind(&tree_summary)
        .bind(&tree_summary_sha)
        .bind(at)
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
        .bind(actor_did)
        .bind(creation_transition_id)
        .bind(at)
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
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(&basic_credential)
        .bind(&actor_public_key)
        .bind(actor_key_id)
        .bind(creation_transition_id)
        .bind(at)
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
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(actor_key_id)
        .bind(&actor_public_key)
        .bind(at)
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
        .bind(entry.entry_id)
        .bind(&entry_payload)
        .bind(&entry_payload_sha)
        .bind(&signed_request)
        .bind(&request_digest)
        .bind(&signature)
        .bind(vec![0_u8])
        .bind(&entry_outer_fingerprint)
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(actor_key_id)
        .bind(creation_transition_id)
        .bind(at)
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
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(&entry_outer_fingerprint)
        .bind(&group_id)
        .bind(&group_context_hash)
        .bind(&confirmation_tag)
        .bind(leaf_period_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert creation interval");
        tx.commit().await.expect("commit real creation");
        creation_transition_id
    }

    /// The loader reads the durable entry + JOINed key and re-verifies through the
    /// crypto seam; its output byte-equals the in-memory path over the same bytes.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn loader_reproduces_in_memory_historical_control_evidence() {
        let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
        let cid = Uuid::new_v4();
        let entry = build_real_creation_entry(*cid.as_bytes());
        let transition_id = seed_real_creation_graph(&pool, &entry).await;

        let authority =
            HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();
        // In-memory reference: the same bytes straight through the crypto seam.
        let reference = authority
            .hydrate_historical_control_from_durable_bytes(
                entry.public_row_json.clone(),
                entry.raw_wrapper.clone(),
                &entry.public_key,
            )
            .expect("in-memory historical control evidence");

        let mut tx = pool.begin().await.expect("begin");
        let loaded = load_historical_control_evidence(&mut tx, &authority, cid, transition_id)
            .await
            .expect("loader reproduces evidence");
        tx.commit().await.expect("commit");

        assert_eq!(loaded, reference);
    }

    /// A transition id with no durable entry fails closed with `EntryMissing`,
    /// never a fabricated evidence value.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn loader_absent_entry_fails_closed() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        let cid = Uuid::new_v4();
        let entry = build_real_creation_entry(*cid.as_bytes());
        let _seeded = seed_real_creation_graph(&pool, &entry).await;
        let authority =
            HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();

        let mut tx = pool.begin().await.expect("begin");
        let result =
            load_historical_control_evidence(&mut tx, &authority, cid, Uuid::new_v4()).await;
        tx.rollback().await.expect("rollback");

        assert!(matches!(
            result,
            Err(ControlEvidenceLoadError::EntryMissing)
        ));
    }

    // -----------------------------------------------------------------------
    // G1b-2 sub-seal 1b — participant-membership hydration leg.
    //
    // The genesis real-creation graph seeds exactly ONE participant: the creator,
    // status=active / role=admin / role_transition_id=creation, invitation +
    // acceptance NULL (see `seed_real_creation_graph`). So the None-provenance
    // arms of the classifiers are live-exercised here; the Some-arms
    // (policy-role-change producer, invitation, acceptance) require the richer
    // multi-participant real-signed fixture that is the MANDATORY G1b-2 follow-up
    // sub-seal. Fail-closed cases constructible on the genesis graph (dangling
    // provenance id, evidence bound to a foreign conversation) are exercised now;
    // the "policy without matching change" classifier failure is exercised
    // directly in `historical_control_path` against a real policy vector.
    // -----------------------------------------------------------------------

    /// The genesis admin participant hydrates from its real creation evidence:
    /// role established by creation (`role_producer == None`), no invitation, no
    /// acceptance.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn participant_leg_hydrates_the_genesis_admin() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        let cid = Uuid::new_v4();
        let entry = build_real_creation_entry(*cid.as_bytes());
        let _creation = seed_real_creation_graph(&pool, &entry).await;
        let authority =
            HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();

        let mut tx = pool.begin().await.expect("begin");
        let participants = load_participant_hydration_rows(&mut tx, &authority, cid)
            .await
            .expect("genesis participant hydrates");
        tx.commit().await.expect("commit");

        assert_eq!(participants.len(), 1);
        let participant = &participants[0];
        assert_eq!(participant.principal.as_bytes(), entry.actor_did.as_bytes());
        assert_eq!(participant.status, ParticipantStatus::Active);
        assert_eq!(participant.role, ParticipantRole::Admin);
        assert!(participant.role_producer.is_none());
        assert!(participant.invitation.is_none());
        assert!(participant.acceptance.is_none());
    }

    /// The participant leg fails CLOSED on a provenance transition that has no
    /// durable entry (`ProvenanceMissing`) and on one that fails read-time
    /// re-verification (`InvalidProvenance`) — never a fabricated provenance. The
    /// absence path is otherwise structurally guarded in a coherent roster by
    /// `participants_role_transition_fk` (role_transition_id MUST reference a real
    /// transition) plus the entry<->transition mapping (every accepted transition
    /// has an entry), so it cannot be provoked by mutating a coherent genesis
    /// graph; the sealed `loader_absent_entry_fails_closed` proves the underlying
    /// `load_historical_control_evidence` absence, and this asserts the loader's
    /// fail-closed mapping of it.
    #[test]
    fn participant_provenance_load_errors_map_fail_closed() {
        assert!(matches!(
            ParticipantHydrationError::from(ControlEvidenceLoadError::EntryMissing),
            ParticipantHydrationError::ProvenanceMissing
        ));
        assert!(matches!(
            ParticipantHydrationError::from(ControlEvidenceLoadError::InvalidEvidence),
            ParticipantHydrationError::InvalidProvenance
        ));
    }

    /// A read-time authority bound to a DIFFERENT conversation must reject the
    /// participant's provenance: the re-verified entry carries its own
    /// conversation_id, which the authority requires to equal the locked one.
    /// Fails closed with `InvalidProvenance` (never coerced into evidence).
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn participant_leg_fails_closed_when_provenance_binds_a_foreign_conversation() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        let cid = Uuid::new_v4();
        let entry = build_real_creation_entry(*cid.as_bytes());
        let _creation = seed_real_creation_graph(&pool, &entry).await;

        let foreign_cid = *Uuid::new_v4().as_bytes();
        let authority =
            HistoricalRehydrationAuthority::new(foreign_cid, entry.head_next_entry_seq).unwrap();
        let mut tx = pool.begin().await.expect("begin");
        let result = load_participant_hydration_rows(&mut tx, &authority, cid).await;
        tx.rollback().await.expect("rollback");

        assert!(matches!(
            result,
            Err(ParticipantHydrationError::InvalidProvenance)
        ));
    }

    // -----------------------------------------------------------------------
    // G1b-2 sub-seal 2a — application-interval hydration leg.
    //
    // The genesis real-creation graph seeds exactly ONE application interval:
    // the creator's OPEN interval, opening_kind='creation', opening_transition
    // = the creation entry, no close. So the open-interval / Creation-opening
    // path is live-exercised here; closed intervals and the Add/Reset opening
    // kinds require the richer multi-transition fixtures that populate later
    // legs. Fail-closed cases constructible on the genesis graph (opening
    // evidence bound to a foreign conversation) are exercised now.
    // -----------------------------------------------------------------------

    /// The genesis creation interval hydrates from its real opening evidence:
    /// recipient = the creator device, opening_kind = Creation, the opening
    /// context is the Active genesis coordinate, and the interval is still open
    /// (`end == None`). The opening evidence byte-equals the directly loaded
    /// historical control transition.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn interval_leg_hydrates_the_genesis_creation_interval() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        let cid = Uuid::new_v4();
        let entry = build_real_creation_entry(*cid.as_bytes());
        let creation = seed_real_creation_graph(&pool, &entry).await;
        let authority =
            HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();

        let mut tx = pool.begin().await.expect("begin");
        let reference = load_historical_control_evidence(&mut tx, &authority, cid, creation)
            .await
            .expect("opening evidence loads")
            .into_transition()
            .expect("opening is a transition");
        let intervals = load_interval_hydration_rows(&mut tx, &authority, cid)
            .await
            .expect("genesis interval hydrates");
        tx.commit().await.expect("commit");

        assert_eq!(
            intervals.len(),
            1,
            "exactly the one genesis creation interval"
        );
        let interval = &intervals[0];
        let expected_recipient = DeviceIdentity::new(
            PrincipalId::new(entry.actor_did.clone().into_bytes()).expect("principal"),
            *entry.actor_device_id.as_bytes(),
        )
        .expect("device identity");
        assert_eq!(interval.recipient, expected_recipient, "creator device");
        assert_eq!(interval.generation, 0);
        assert_eq!(interval.opening_kind, OpeningKind::Creation);
        assert!(interval.end.is_none(), "genesis interval is still open");
        assert_eq!(interval.opening, reference, "opening evidence re-verified");
        let context = &interval.opening_context;
        assert_eq!(context.conversation_id(), &entry.cid);
        assert_eq!(context.generation(), 0);
        assert_eq!(context.state_version(), 0);
        assert_eq!(context.epoch(), 0);
        assert_eq!(context.group_id(), &[1_u8; 32]);
        assert_eq!(context.group_context_hash(), &[2_u8; 32]);
        assert_eq!(context.confirmation_tag(), &[3_u8; 32]);
        assert_eq!(context.lifecycle(), PublicGroupSnapshotLifecycle::Active);
    }

    /// A read-time authority bound to a DIFFERENT conversation must reject the
    /// interval's opening provenance: the re-verified entry carries its own
    /// conversation_id, which the authority requires to equal the locked one.
    /// Fails closed with `InvalidProvenance` (never coerced into evidence).
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn interval_leg_fails_closed_when_opening_provenance_binds_a_foreign_conversation() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        let cid = Uuid::new_v4();
        let entry = build_real_creation_entry(*cid.as_bytes());
        let _creation = seed_real_creation_graph(&pool, &entry).await;

        let foreign_cid = *Uuid::new_v4().as_bytes();
        let authority =
            HistoricalRehydrationAuthority::new(foreign_cid, entry.head_next_entry_seq).unwrap();
        let mut tx = pool.begin().await.expect("begin");
        let result = load_interval_hydration_rows(&mut tx, &authority, cid).await;
        tx.rollback().await.expect("rollback");

        assert!(matches!(
            result,
            Err(IntervalHydrationError::InvalidProvenance)
        ));
    }

    /// The interval leg maps the loader-atom failure modes fail-closed: an absent
    /// boundary entry to `ProvenanceMissing`, a re-verification failure to
    /// `InvalidProvenance`. The absence path is otherwise structurally guarded in
    /// a coherent graph by `application_intervals_opening_transition_fk` +
    /// the entry<->transition mapping, so it cannot be provoked by mutating a
    /// coherent genesis interval.
    #[test]
    fn interval_provenance_load_errors_map_fail_closed() {
        assert!(matches!(
            IntervalHydrationError::from(ControlEvidenceLoadError::EntryMissing),
            IntervalHydrationError::ProvenanceMissing
        ));
        assert!(matches!(
            IntervalHydrationError::from(ControlEvidenceLoadError::InvalidEvidence),
            IntervalHydrationError::InvalidProvenance
        ));
    }

    /// The current-state producer leg reads `generation_states.producing_transition_id`
    /// for the current coordinate and re-verifies it as a transition. On the
    /// genesis seed that is the creation transition; the evidence byte-equals the
    /// directly loaded historical control transition (same loader atom, same key).
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn producer_leg_hydrates_the_genesis_creation_transition() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        let cid = Uuid::new_v4();
        let entry = build_real_creation_entry(*cid.as_bytes());
        let creation = seed_real_creation_graph(&pool, &entry).await;
        let authority =
            HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();

        let mut tx = pool.begin().await.expect("begin");
        let reference = load_historical_control_evidence(&mut tx, &authority, cid, creation)
            .await
            .expect("producer evidence loads")
            .into_transition()
            .expect("producer is a transition");
        let producer = load_producer_transition_evidence(&mut tx, &authority, cid)
            .await
            .expect("genesis producer hydrates");
        tx.commit().await.expect("commit");

        assert_eq!(
            producer, reference,
            "current-state producer re-verified byte-for-byte"
        );
    }

    /// A read-time authority bound to a DIFFERENT conversation must reject the
    /// producer's transition: the re-verified entry carries its own
    /// conversation_id, which the authority requires to equal the locked one.
    /// Fails closed with `InvalidProvenance`.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn producer_leg_fails_closed_when_authority_binds_a_foreign_conversation() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        let cid = Uuid::new_v4();
        let entry = build_real_creation_entry(*cid.as_bytes());
        let _creation = seed_real_creation_graph(&pool, &entry).await;

        let foreign_cid = *Uuid::new_v4().as_bytes();
        let authority =
            HistoricalRehydrationAuthority::new(foreign_cid, entry.head_next_entry_seq).unwrap();
        let mut tx = pool.begin().await.expect("begin");
        let result = load_producer_transition_evidence(&mut tx, &authority, cid).await;
        tx.rollback().await.expect("rollback");

        assert!(matches!(
            result,
            Err(ProducerHydrationError::InvalidProvenance)
        ));
    }

    /// A conversation id with no row (hence no current generation-state) fails
    /// closed with `ConversationMissing`, never a fabricated producer.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn producer_leg_fails_closed_when_conversation_is_absent() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        let cid = Uuid::new_v4();
        let entry = build_real_creation_entry(*cid.as_bytes());
        let _creation = seed_real_creation_graph(&pool, &entry).await;

        let absent = Uuid::new_v4();
        let authority =
            HistoricalRehydrationAuthority::new(*absent.as_bytes(), entry.head_next_entry_seq)
                .unwrap();
        let mut tx = pool.begin().await.expect("begin");
        let result = load_producer_transition_evidence(&mut tx, &authority, absent).await;
        tx.rollback().await.expect("rollback");

        assert!(matches!(
            result,
            Err(ProducerHydrationError::ConversationMissing)
        ));
    }

    /// The producer leg maps the loader-atom failure modes fail-closed: an absent
    /// producing entry to `ProvenanceMissing`, a re-verification failure to
    /// `InvalidProvenance`. In a coherent graph the absence path is not provokable
    /// by mutating a genesis generation-state: `producing_transition_id` is NOT
    /// NULL + UUID-v4-checked and is set to a real accepted transition, every
    /// accepted transition carries an entry (the entry<->transition mapping), and
    /// `chat.entries` is append-only + immutable — so the mapping is exercised
    /// directly here (the sealed `loader_absent_entry_fails_closed` already proves
    /// the underlying loader-atom absence).
    #[test]
    fn producer_provenance_load_errors_map_fail_closed() {
        assert!(matches!(
            ProducerHydrationError::from(ControlEvidenceLoadError::EntryMissing),
            ProducerHydrationError::ProvenanceMissing
        ));
        assert!(matches!(
            ProducerHydrationError::from(ControlEvidenceLoadError::InvalidEvidence),
            ProducerHydrationError::InvalidProvenance
        ));
    }

    /// The metadata provenance leg reads `metadata_snapshots.producing_transition_id`
    /// for the current coordinate (pinned to the generation-state producer),
    /// re-verifies it as a transition, and DERIVES the metadata binding from that
    /// transition's verified body — exactly as the append-time path sets
    /// `state.metadata = transition_metadata(&producer).cloned()`. On the genesis
    /// seed the producer is the creation transition; the leg's producer byte-equals
    /// the directly loaded historical control transition and the leg's metadata
    /// byte-equals that transition's body metadata (`metadata_version == 1`).
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn metadata_leg_hydrates_the_genesis_creation_metadata() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        let cid = Uuid::new_v4();
        let entry = build_real_creation_entry(*cid.as_bytes());
        let creation = seed_real_creation_graph(&pool, &entry).await;
        let authority =
            HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();

        let mut tx = pool.begin().await.expect("begin");
        let reference_producer =
            load_historical_control_evidence(&mut tx, &authority, cid, creation)
                .await
                .expect("producer evidence loads")
                .into_transition()
                .expect("producer is a transition");
        let reference_metadata = metadata_binding_of_transition(&reference_producer)
            .expect("genesis creation body carries metadata");

        let (metadata, metadata_producer) = load_metadata_provenance(&mut tx, &authority, cid)
            .await
            .expect("genesis metadata provenance hydrates");
        tx.commit().await.expect("commit");

        assert_eq!(
            metadata_producer,
            Some(reference_producer),
            "metadata producer re-verified byte-for-byte"
        );
        assert_eq!(
            metadata
                .as_ref()
                .map(MetadataSnapshotBinding::metadata_version),
            Some(1),
            "genesis metadata is version 1"
        );
        assert_eq!(
            metadata,
            Some(reference_metadata),
            "metadata binding derived from the producer body byte-for-byte"
        );
    }

    /// A read-time authority bound to a DIFFERENT conversation must reject the
    /// metadata producer's transition: the re-verified entry carries its own
    /// conversation_id, which the authority requires to equal the locked one.
    /// Fails closed with `InvalidProvenance`.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn metadata_leg_fails_closed_when_authority_binds_a_foreign_conversation() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        let cid = Uuid::new_v4();
        let entry = build_real_creation_entry(*cid.as_bytes());
        let _creation = seed_real_creation_graph(&pool, &entry).await;

        let foreign_cid = *Uuid::new_v4().as_bytes();
        let authority =
            HistoricalRehydrationAuthority::new(foreign_cid, entry.head_next_entry_seq).unwrap();
        let mut tx = pool.begin().await.expect("begin");
        let result = load_metadata_provenance(&mut tx, &authority, cid).await;
        tx.rollback().await.expect("rollback");

        assert!(matches!(
            result,
            Err(MetadataHydrationError::InvalidProvenance)
        ));
    }

    /// A conversation id with no current metadata snapshot yields the legal
    /// `(None, None)` validator arm — never a fabricated binding or producer. On a
    /// coherent conversation this arm is structurally unreachable (creation always
    /// mints metadata and `chat.transitions.metadata_snapshot_id` FK-pins it), so
    /// the absence is modeled here with a conversation id that has no rows at all.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn metadata_leg_returns_none_when_no_metadata_snapshot_exists() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        let cid = Uuid::new_v4();
        let entry = build_real_creation_entry(*cid.as_bytes());
        let _creation = seed_real_creation_graph(&pool, &entry).await;

        let absent = Uuid::new_v4();
        let authority =
            HistoricalRehydrationAuthority::new(*absent.as_bytes(), entry.head_next_entry_seq)
                .unwrap();
        let mut tx = pool.begin().await.expect("begin");
        let (metadata, metadata_producer) = load_metadata_provenance(&mut tx, &authority, absent)
            .await
            .expect("absent metadata resolves to the (None, None) arm");
        tx.rollback().await.expect("rollback");

        assert!(metadata.is_none() && metadata_producer.is_none());
    }

    /// The metadata leg maps the loader-atom failure modes fail-closed: an absent
    /// producing entry to `ProvenanceMissing`, a re-verification failure to
    /// `InvalidProvenance`. The absence path is not provokable by mutating a
    /// coherent graph (`producing_transition_id` is NOT NULL + UUID-checked +
    /// FK/uniqueness-pinned to a real accepted transition whose entry exists, and
    /// `chat.entries` is append-only + immutable), so the mapping is exercised
    /// directly (the sealed `loader_absent_entry_fails_closed` proves the
    /// underlying loader-atom absence).
    #[test]
    fn metadata_provenance_load_errors_map_fail_closed() {
        assert!(matches!(
            MetadataHydrationError::from(ControlEvidenceLoadError::EntryMissing),
            MetadataHydrationError::ProvenanceMissing
        ));
        assert!(matches!(
            MetadataHydrationError::from(ControlEvidenceLoadError::InvalidEvidence),
            MetadataHydrationError::InvalidProvenance
        ));
    }

    // -----------------------------------------------------------------------
    // G1b-2 sub-seal — leaf-recovery work hydration leg (the recovery PAIR).
    //
    // Seeds a coherent OPEN leaf-recovery request + its ACTIVE key-package
    // reservation on the genesis real-creation graph: a genuinely ed25519-signed
    // `requestLeafRecovery` mutation (signed by the SAME test key that signed the
    // creation entry, so its requester `keyId` JOINs the seeded `chat.device_keys`
    // row) whose `prior` coordinate binds the fresh conversation id. The loader
    // pairs the two tables 1:1, re-mints the request ORIGIN through the signed-path
    // loader seam, and byte-equals the direct in-memory re-mint. The terminal
    // (`fulfilled`/`consumed`) and `acceptConversation` arms are the NEXT-STEP
    // follow-up — this leg fails CLOSED on them (`UnsupportedTerminal` /
    // `UnsupportedSource`), asserted live here so the scope boundary is real.
    // -----------------------------------------------------------------------
    mod recovery_leg {
        use base64::{
            engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
            Engine,
        };
        use chrono::{DateTime, Utc};
        use ed25519_dalek::{Signer, SigningKey};
        use serde_json::{json, Value};
        use sha2::{Digest, Sha256};
        use sqlx::{PgPool, Postgres, Transaction};
        use uuid::Uuid;

        use super::super::historical_control_path::{build_real_creation_entry, RealCreationEntry};
        use super::seed_real_creation_graph;
        use crate::chat_protocol::public_state::{encode_public_tree_summary, ActivePublicState};
        use crate::chat_protocol::repository::core::{
            hydrate_locked_public_state, load_interval_hydration_rows, load_leaf_hydration_rows,
            load_leave_request_hydration_rows, load_metadata_provenance,
            load_participant_hydration_rows, load_producer_transition_evidence,
            load_recovery_work_hydration_rows, load_reset_request_hydration_rows,
            load_welcome_hydration_rows, select_fulfilled_recovery_terminal,
            select_welcome_terminal, FulfilledRecoveryTerminalColumns, RecoveryHydrationError,
            WelcomeTerminalColumns, WelcomeTerminalSelection,
        };
        use crate::chat_protocol::snapshot::{
            PublicGroupSnapshotCoordinate, PublicGroupSnapshotLeaf, PublicGroupSnapshotLifecycle,
            PublicGroupSnapshotTreeSummary,
        };
        use crate::chat_protocol::state_machine::{
            recovery_fulfillment_terminal_matches, ConversationKind, ConversationStateHydration,
            DeviceIdentity, HistoricalRehydrationAuthority, LeafRecoveryKind, PrincipalId,
            RecoveryOriginHydrationRow, RecoveryRequestStatus, RecoverySource, ReservationStatus,
            ServerTimestamp, WelcomeStatus, WorkTerminalHydrationRow,
        };
        use crate::chat_protocol::transcript::{
            decode_and_verify_control_entry, decode_canonical_signed_mutation, SignedMutationKind,
        };
        use crate::chat_protocol::validation::ed25519_key_id;
        use crate::common;

        // Fixed millisecond instants (the state machine's `CanonicalTimestamp`
        // grammar is `...T...Z` at millisecond precision, which round-trips
        // losslessly through Postgres microsecond storage). `EXPIRES_AT` is
        // exactly `LEAST(REQUESTED_AT + 5min, KP.not_after)`, the expiry the
        // deferred `assert_recovery_fulfillment_mapping` constraint requires.
        const REQUESTED_AT: &str = "2030-01-01T00:00:00.000Z";
        const EXPIRES_AT: &str = "2030-01-01T00:05:00.000Z";
        const KP_NOT_BEFORE: &str = "2029-12-31T23:59:00.000Z";
        const KP_NOT_AFTER: &str = "2030-01-01T00:11:00.000Z";
        const SIGNED_AT: &str = "2029-12-31T23:59:59.000Z";
        const FULFILLMENT_SIGNED_AT: &str = "2030-01-01T00:00:59.000Z";
        const FULFILLED_AT: &str = "2030-01-01T00:01:00.000Z";

        fn instant(text: &str) -> DateTime<Utc> {
            DateTime::parse_from_rfc3339(text)
                .expect("canonical instant")
                .with_timezone(&Utc)
        }

        fn uuid_v4_bytes(byte: u8) -> [u8; 16] {
            let mut value = [byte; 16];
            value[6] = 0x40 | (byte & 0x0f);
            value[8] = 0x80 | (byte & 0x3f);
            value
        }

        fn genesis_coordinate_json(cid: [u8; 16]) -> Value {
            // Matches `seed_real_creation_graph`'s genesis active coordinate.
            json!({
                "conversationId": Uuid::from_bytes(cid).hyphenated().to_string(),
                "generation": 0,
                "stateVersion": 0,
                "groupId": STANDARD.encode([1_u8; 32]),
                "epoch": 0,
                "groupContextHash": STANDARD.encode([2_u8; 32]),
                "confirmationTag": STANDARD.encode([3_u8; 32]),
                "lifecycle": "active",
            })
        }

        /// The exact bytes of a genuinely-signed `requestLeafRecovery` mutation and
        /// the shape-only transcript/digest/signature columns the DB CHECK needs.
        struct SignedRecoveryRequest {
            raw_wrapper: Vec<u8>,
            signing_transcript: Vec<u8>,
            request_digest: Vec<u8>,
            signature: Vec<u8>,
        }

        fn build_signed_recovery_request(
            entry: &RealCreationEntry,
            request_id: [u8; 16],
        ) -> SignedRecoveryRequest {
            let signing_key = entry.signing_key();
            let verifying = signing_key.verifying_key().to_bytes();
            // The creation entry signed with this same key, so its device-keys row
            // carries exactly this verifying key under `entry.actor_key_id`.
            assert_eq!(entry.public_key, verifying.to_vec());
            assert_eq!(
                entry.actor_key_id,
                ed25519_key_id(&verifying).unwrap().as_str()
            );

            let kind = SignedMutationKind::LeafRecoveryRequest;
            let body = json!({
                "$type": kind.type_id(),
                "signatureDomain": String::from_utf8(kind.domain().to_vec()).unwrap(),
                "actorDid": entry.actor_did,
                "actorDeviceId": entry.actor_device_id.hyphenated().to_string(),
                "keyId": ed25519_key_id(&verifying).unwrap().as_str(),
                "authGeneration": 1,
                "idempotencyKey": Uuid::from_bytes(uuid_v4_bytes(0x6d)).hyphenated().to_string(),
                "signedAt": SIGNED_AT,
                "recoveryRequestId": Uuid::from_bytes(request_id).hyphenated().to_string(),
                "prior": genesis_coordinate_json(entry.cid),
                "recoveryKind": "replace",
            });
            let mut wrapper = json!({ "body": body, "signature": "" });
            wrapper["signature"] = Value::String(STANDARD.encode([0u8; 64]));
            let unsigned = serde_json::to_vec(&wrapper).unwrap();
            let canonical = decode_canonical_signed_mutation(&unsigned).unwrap();
            let signing_transcript = canonical.transcript_bytes().to_vec();
            let signature = signing_key.sign(&signing_transcript).to_bytes();
            wrapper["signature"] = Value::String(STANDARD.encode(signature));
            let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
            SignedRecoveryRequest {
                raw_wrapper,
                request_digest: Sha256::digest(&signing_transcript).to_vec(),
                signature: signature.to_vec(),
                signing_transcript,
            }
        }

        struct RecoverySeed {
            request_id: [u8; 16],
            key_package_ref: [u8; 32],
            raw_wrapper: Vec<u8>,
            creation_transition_id: Uuid,
            replaced_leaf_period_id: Uuid,
        }

        /// Seed an OPEN leaf-recovery request + its ACTIVE key-package reservation
        /// on top of a committed genesis graph, coherent under the deferred
        /// `assert_recovery_fulfillment_mapping` constraint. `source` drives only
        /// the request's `source` column (the loader classifies it before touching
        /// the bytes, so `acceptConversation` reuses the same signed request).
        ///
        /// The genesis creator is already a leaf, so the request is a `replace`
        /// (its `replaced_leaf_period_id` is the creator's `leaf_period_id`, which
        /// the constraint requires to reference a live member device); an `add`
        /// would be rejected because the requester's leaf already exists.
        async fn seed_recovery_pair(
            pool: &PgPool,
            entry: &RealCreationEntry,
            source: &str,
        ) -> RecoverySeed {
            let creation_transition_id = seed_real_creation_graph(pool, entry).await;
            let conversation_id = Uuid::from_bytes(entry.cid);
            // The gate DB is shared and never reset (rows are immutable), so every
            // recovery identifier is fresh per run (derived from a fresh request id)
            // to avoid PK / UNIQUE collisions across tests.
            let request_uuid = Uuid::new_v4();
            let request_id = *request_uuid.as_bytes();
            let key_package_ref =
                Sha256::digest([b"recovery-kp".as_ref(), &request_id].concat()).to_vec();
            let init_key =
                Sha256::digest([b"recovery-init".as_ref(), &request_id].concat()).to_vec();
            let wrapper_bytes = vec![0x79_u8; 32];
            let signed = build_signed_recovery_request(entry, request_id);

            // The creator's live leaf period, to bind the `replace` request.
            let replaced_leaf_period_id: Uuid = sqlx::query_scalar(
                "SELECT leaf_period_id FROM chat.member_devices \
                 WHERE conversation_id=$1 AND user_did=$2 AND device_id=$3 AND active",
            )
            .bind(conversation_id)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .fetch_one(pool)
            .await
            .expect("creator leaf period");

            let mut tx = pool.begin().await.expect("begin recovery pair");
            sqlx::query(
                r#"INSERT INTO chat.key_packages(
                    key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,
                    owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,
                    status,created_at
                ) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'reserved',$10)"#,
            )
            .bind(&key_package_ref)
            .bind(&wrapper_bytes)
            .bind(Sha256::digest(&wrapper_bytes).to_vec())
            .bind(&init_key)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(instant(KP_NOT_BEFORE))
            .bind(instant(KP_NOT_AFTER))
            .bind(instant(REQUESTED_AT))
            .execute(&mut *tx)
            .await
            .expect("insert key package");
            sqlx::query(
                r#"INSERT INTO chat.key_package_reservations(
                    recovery_request_id,key_package_ref,conversation_id,generation,requester_did,
                    requester_device_id,requester_key_id,requester_auth_generation,recipient_did,
                    recipient_device_id,bound_state_version,bound_group_id,bound_epoch,
                    bound_group_context_hash,bound_confirmation_tag,purpose,expires_at,status,created_at
                ) VALUES($1,$2,$3,0,$4,$5,$6,1,$4,$5,0,$7,0,$8,$9,'leafRecovery',$10,'active',$11)"#,
            )
            .bind(request_uuid)
            .bind(&key_package_ref)
            .bind(conversation_id)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(vec![1_u8; 32])
            .bind(vec![2_u8; 32])
            .bind(vec![3_u8; 32])
            .bind(instant(EXPIRES_AT))
            .bind(instant(REQUESTED_AT))
            .execute(&mut *tx)
            .await
            .expect("insert reservation");
            sqlx::query(
                r#"INSERT INTO chat.leaf_recovery_requests(
                    recovery_request_id,conversation_id,generation,requester_did,requester_device_id,
                    requester_key_id,requester_auth_generation,recovery_kind,source,bound_state_version,
                    bound_group_id,bound_epoch,bound_group_context_hash,bound_confirmation_tag,
                    reservation_request_id,replaced_leaf_period_id,status,signed_request_bytes,
                    signing_transcript_bytes,request_digest,signature,requested_at,expires_at
                ) VALUES($1,$2,0,$3,$4,$5,1,'replace',$6,0,$7,0,$8,$9,$1,$10,'open',$11,$12,$13,$14,$15,$16)"#,
            )
            .bind(request_uuid)
            .bind(conversation_id)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(source)
            .bind(vec![1_u8; 32])
            .bind(vec![2_u8; 32])
            .bind(vec![3_u8; 32])
            .bind(replaced_leaf_period_id)
            .bind(&signed.raw_wrapper)
            .bind(&signed.signing_transcript)
            .bind(&signed.request_digest)
            .bind(&signed.signature)
            .bind(instant(REQUESTED_AT))
            .bind(instant(EXPIRES_AT))
            .execute(&mut *tx)
            .await
            .expect("insert leaf recovery request");
            tx.commit().await.expect("commit recovery pair");

            RecoverySeed {
                request_id,
                key_package_ref: <[u8; 32]>::try_from(key_package_ref.as_slice()).unwrap(),
                raw_wrapper: signed.raw_wrapper,
                creation_transition_id,
                replaced_leaf_period_id,
            }
        }

        struct RealLeafRecoveryFulfillmentEntry {
            entry_id: Uuid,
            transition_id: Uuid,
            welcome_id: Uuid,
            public_row_json: Vec<u8>,
            raw_wrapper: Vec<u8>,
            canonical_projection: Vec<u8>,
            signing_transcript: Vec<u8>,
            request_digest: Vec<u8>,
            signature: Vec<u8>,
            server_fields_dag_cbor: Vec<u8>,
            outer_entry_fingerprint: [u8; 32],
            opaque_welcome: Vec<u8>,
        }

        fn encoded_fixture_tree_summary(entry: &RealCreationEntry) -> (Vec<u8>, [u8; 32]) {
            let basic_credential =
                format!("{}#{}", entry.actor_did, entry.actor_device_id).into_bytes();
            let tree = PublicGroupSnapshotTreeSummary::new(
                [0x63; 32],
                vec![PublicGroupSnapshotLeaf::new(
                    0,
                    basic_credential,
                    entry.public_key.clone(),
                    vec![0x64; 1_216],
                )],
            );
            encode_public_tree_summary(&tree)
                .expect("fixture tree summary is canonical")
                .into_parts()
        }

        fn next_coordinate_json(cid: [u8; 16]) -> Value {
            json!({
                "conversationId": Uuid::from_bytes(cid).hyphenated().to_string(),
                "generation": 0,
                "stateVersion": 1,
                "groupId": STANDARD.encode([1_u8; 32]),
                "epoch": 1,
                "groupContextHash": STANDARD.encode([4_u8; 32]),
                "confirmationTag": STANDARD.encode([5_u8; 32]),
                "lifecycle": "active",
            })
        }

        /// Build a genuinely Ed25519-signed leaf-recovery fulfillment control
        /// entry. The same-device Replace manifest is ordered by the canonical
        /// full leaf-change key: exact DID bytes, UUID bytes, then Remove before
        /// Add. The opaque Welcome is synthetic only at the protocol's opaque
        /// boundary and is bound by its exact SHA-256.
        fn build_real_leaf_recovery_fulfillment_entry(
            entry: &RealCreationEntry,
            seed: &RecoverySeed,
        ) -> RealLeafRecoveryFulfillmentEntry {
            build_real_leaf_recovery_fulfillment_entry_with_mutation(entry, seed, |_| {})
        }

        /// Rebuild and sign a fulfillment after applying one body substitution.
        /// Adversarial predicate cases use this seam so every candidate still
        /// crosses canonical decoding, Ed25519 verification, and historical
        /// transition re-hydration before it is treated as evidence.
        fn build_real_leaf_recovery_fulfillment_entry_with_mutation(
            entry: &RealCreationEntry,
            seed: &RecoverySeed,
            mutate_body: impl FnOnce(&mut Value),
        ) -> RealLeafRecoveryFulfillmentEntry {
            build_real_leaf_recovery_fulfillment_entry_with_shape(
                entry,
                seed,
                2,
                genesis_coordinate_json(entry.cid),
                next_coordinate_json(entry.cid),
                json!({
                    "conversationId": STANDARD.encode(entry.cid),
                    "generation": 0,
                    "stateVersion": 0,
                    "groupId": STANDARD.encode([1_u8; 32]),
                    "epoch": 0,
                    "groupContextHash": STANDARD.encode([2_u8; 32]),
                    "confirmationTag": STANDARD.encode([3_u8; 32]),
                    "lifecycle": "active",
                }),
                1,
                [4_u8; 32],
                [5_u8; 32],
                FULFILLED_AT,
                mutate_body,
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn build_real_leaf_recovery_fulfillment_entry_with_shape(
            entry: &RealCreationEntry,
            seed: &RecoverySeed,
            seq: u64,
            prior: Value,
            next: Value,
            aad_prior: Value,
            next_epoch: u64,
            next_group_context_hash: [u8; 32],
            next_confirmation_tag: [u8; 32],
            received_at: &str,
            mutate_body: impl FnOnce(&mut Value),
        ) -> RealLeafRecoveryFulfillmentEntry {
            let signing_key = entry.signing_key();
            let verifying = signing_key.verifying_key().to_bytes();
            assert_eq!(entry.public_key, verifying.to_vec());

            let transition_id = Uuid::new_v4();
            let entry_id = Uuid::new_v4();
            let welcome_id = Uuid::new_v4();
            let idempotency_key = Uuid::new_v4();
            let request_id = Uuid::from_bytes(seed.request_id);
            let commit_bytes = [0x31_u8; 8];
            let metadata_ciphertext = [0x32_u8; 16];
            let opaque_welcome = vec![0x41_u8; 8];
            let metadata_snapshot = json!({
                "coordinate": {
                    "conversationId": STANDARD.encode(entry.cid),
                    "generation": 0,
                    "groupId": STANDARD.encode([1_u8; 32]),
                    "epoch": next_epoch,
                    "groupContextHash": STANDARD.encode(next_group_context_hash),
                    "confirmationTag": STANDARD.encode(next_confirmation_tag),
                },
                "originTransitionId": seed.creation_transition_id.hyphenated().to_string(),
                "metadataVersion": 1,
                "nonce": STANDARD.encode([0x26_u8; 12]),
                "ciphertext": STANDARD.encode(metadata_ciphertext),
                "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
                "ciphertextSize": 16,
                "authorProof": {
                    "authorDid": entry.actor_did,
                    "authorDeviceId": entry.actor_device_id.hyphenated().to_string(),
                    "authorKeyId": entry.actor_key_id,
                    "signaturePublicKey": STANDARD.encode(&entry.public_key),
                    "authGenerationAtOrigin": 1,
                    "originTransitionId": seed.creation_transition_id.hyphenated().to_string(),
                    "originSeq": 1,
                    "roleAtOrigin": "admin",
                    "deviceStatusAtOrigin": "active",
                }
            });
            let leaf_changes = vec![
                json!({
                    "$type": "blue.catbird.chat.defs#removeLeaf",
                    "userDid": entry.actor_did,
                    "deviceId": entry.actor_device_id.hyphenated().to_string(),
                }),
                json!({
                    "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                    "userDid": entry.actor_did,
                    "deviceId": entry.actor_device_id.hyphenated().to_string(),
                    "recoveryRequestId": request_id.hyphenated().to_string(),
                    "keyPackageRef": STANDARD.encode(seed.key_package_ref),
                }),
            ];
            let mut body = json!({
                "$type": SignedMutationKind::LeafRecoveryFulfillment.type_id(),
                "signatureDomain": String::from_utf8(
                    SignedMutationKind::LeafRecoveryFulfillment.domain().to_vec()
                ).unwrap(),
                "transitionId": transition_id.hyphenated().to_string(),
                "actorDid": entry.actor_did,
                "actorDeviceId": entry.actor_device_id.hyphenated().to_string(),
                "keyId": entry.actor_key_id,
                "authGeneration": 1,
                "prior": prior,
                "next": next,
                "aad": {
                    "protocolVersion": "1",
                    "conversationId": STANDARD.encode(entry.cid),
                    "generation": 0,
                    "transitionId": STANDARD.encode(transition_id.as_bytes()),
                    "prior": aad_prior,
                },
                "manifest": {
                    "participantChanges": [],
                    "leafChanges": leaf_changes,
                    "leafRecoveryRequestId": request_id.hyphenated().to_string(),
                    "welcomeBundle": {
                        "welcomeId": welcome_id.hyphenated().to_string(),
                        "framing": "mlsMessage",
                        "contentType": "welcome",
                        "opaqueWelcome": STANDARD.encode(&opaque_welcome),
                        "sha256": STANDARD.encode(Sha256::digest(&opaque_welcome)),
                        "deliveries": [{
                            "recipientDid": entry.actor_did,
                            "recipientDeviceId": entry.actor_device_id.hyphenated().to_string(),
                            "provenance": {
                                "recoveryRequestId": request_id.hyphenated().to_string(),
                                "keyPackageRef": STANDARD.encode(seed.key_package_ref),
                            }
                        }]
                    }
                },
                "commit": {
                    "framing": "mlsMessage",
                    "contentType": "publicMessageCommit",
                    "bytes": STANDARD.encode(commit_bytes),
                    "sha256": STANDARD.encode(Sha256::digest(commit_bytes)),
                },
                "metadataSnapshot": metadata_snapshot,
                "recoveryRequestId": request_id.hyphenated().to_string(),
                "idempotencyKey": idempotency_key.hyphenated().to_string(),
                "signedAt": FULFILLMENT_SIGNED_AT,
            });
            mutate_body(&mut body);
            let mut wrapper = json!({ "body": body, "signature": STANDARD.encode([0_u8; 64]) });
            let unsigned = serde_json::to_vec(&wrapper).unwrap();
            let unsigned_canonical = decode_canonical_signed_mutation(&unsigned)
                .expect("unsigned fulfillment canonicalizes");
            let signature = signing_key
                .sign(unsigned_canonical.transcript_bytes())
                .to_bytes();
            wrapper["signature"] = Value::String(STANDARD.encode(signature));
            let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
            let canonical = decode_canonical_signed_mutation(&raw_wrapper)
                .expect("signed fulfillment canonicalizes");
            let public_row_json = serde_json::to_vec(&json!({
                "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
                "entryId": entry_id.hyphenated().to_string(),
                "conversationId": Uuid::from_bytes(entry.cid).hyphenated().to_string(),
                "seq": seq,
                "signedRequest": wrapper,
                "receivedAt": received_at,
            }))
            .unwrap();
            let decoded = decode_and_verify_control_entry(&public_row_json, &verifying)
                .expect("real fulfillment entry verifies");

            RealLeafRecoveryFulfillmentEntry {
                entry_id,
                transition_id,
                welcome_id,
                public_row_json,
                raw_wrapper,
                canonical_projection: canonical.canonical_projection().to_vec(),
                signing_transcript: canonical.transcript_bytes().to_vec(),
                request_digest: canonical.request_digest().to_vec(),
                signature: canonical.signature().to_vec(),
                server_fields_dag_cbor: decoded.server_fields_dag_cbor().unwrap(),
                outer_entry_fingerprint: *decoded.outer_control_fingerprint(),
                opaque_welcome,
            }
        }

        /// Advance the committed open recovery pair through the complete durable
        /// fulfillment atom. This intentionally uses the production schema as
        /// the integration oracle: both reciprocal fulfillment/Welcome mapping
        /// triggers run at COMMIT, and callers hydrate only in a fresh transaction.
        async fn commit_recovery_fulfillment_graph(
            pool: &PgPool,
            entry: &RealCreationEntry,
            seed: &RecoverySeed,
            fulfillment: &RealLeafRecoveryFulfillmentEntry,
        ) {
            let cid = Uuid::from_bytes(entry.cid);
            let at = instant(FULFILLED_AT);
            let metadata_snapshot_id = Uuid::new_v4();
            let new_leaf_period_id = Uuid::new_v4();
            let participant_period_id: Uuid = sqlx::query_scalar(
                "SELECT participant_period_id FROM chat.participants \
                 WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
            )
            .bind(cid)
            .bind(&entry.actor_did)
            .fetch_one(pool)
            .await
            .expect("active participant period");
            let public_snapshot = vec![0x61_u8; 64];
            let (tree_summary, tree_summary_sha256) = encoded_fixture_tree_summary(entry);
            let metadata_ciphertext = vec![0x32_u8; 16];
            let basic_credential =
                format!("{}#{}", entry.actor_did, entry.actor_device_id).into_bytes();

            let mut tx = pool.begin().await.expect("begin fulfillment graph");
            sqlx::query(
                "UPDATE chat.conversations \
                 SET current_state_version=1,next_entry_seq=3 \
                 WHERE conversation_id=$1 AND current_generation=0 \
                   AND current_state_version=0 AND next_entry_seq=2",
            )
            .bind(cid)
            .execute(&mut *tx)
            .await
            .expect("advance conversation head");
            sqlx::query(
                "UPDATE chat.generations SET current_state_version=1 \
                 WHERE conversation_id=$1 AND generation=0 AND current_state_version=0",
            )
            .bind(cid)
            .execute(&mut *tx)
            .await
            .expect("advance generation head");
            sqlx::query(
                r#"INSERT INTO chat.transitions(
                    transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
                    actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
                    unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
                    prior_generation,prior_state_version,next_generation,next_state_version,
                    metadata_snapshot_id,entry_seq,accepted_at
                ) VALUES($1,$2,'leafRecovery',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,
                    0,0,0,1,$11,2,$12)"#,
            )
            .bind(fulfillment.transition_id)
            .bind(cid)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(&fulfillment.raw_wrapper)
            .bind(&fulfillment.canonical_projection)
            .bind(&fulfillment.signing_transcript)
            .bind(&fulfillment.request_digest)
            .bind(&fulfillment.signature)
            .bind(metadata_snapshot_id)
            .bind(at)
            .execute(&mut *tx)
            .await
            .expect("insert fulfillment transition");
            sqlx::query(
                r#"INSERT INTO chat.generation_states(
                    conversation_id,generation,state_version,group_id,epoch,group_context_hash,
                    confirmation_tag,lifecycle,state_kind,producing_transition_id,
                    public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,
                    leaf_count,created_at
                ) VALUES($1,0,1,$2,1,$3,$4,'active','commit',$5,$6,$7,$8,$9,1,$10)"#,
            )
            .bind(cid)
            .bind(vec![1_u8; 32])
            .bind(vec![4_u8; 32])
            .bind(vec![5_u8; 32])
            .bind(fulfillment.transition_id)
            .bind(&public_snapshot)
            .bind(Sha256::digest(&public_snapshot).to_vec())
            .bind(&tree_summary)
            .bind(tree_summary_sha256.to_vec())
            .bind(at)
            .execute(&mut *tx)
            .await
            .expect("insert successor generation state");
            sqlx::query(
                r#"INSERT INTO chat.metadata_snapshots(
                    metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,
                    group_context_hash,confirmation_tag,producing_transition_id,
                    origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,
                    ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,
                    author_auth_generation,author_origin_seq,author_role,author_device_status,created_at
                ) VALUES($1,$2,0,1,$3,1,$4,$5,$6,$7,1,$8,$9,$10,16,$11,$12,$13,$14,
                    1,1,'admin','active',$15)"#,
            )
            .bind(metadata_snapshot_id)
            .bind(cid)
            .bind(vec![1_u8; 32])
            .bind(vec![4_u8; 32])
            .bind(vec![5_u8; 32])
            .bind(fulfillment.transition_id)
            .bind(seed.creation_transition_id)
            .bind(vec![0x26_u8; 12])
            .bind(&metadata_ciphertext)
            .bind(Sha256::digest(&metadata_ciphertext).to_vec())
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(&entry.public_key)
            .bind(at)
            .execute(&mut *tx)
            .await
            .expect("insert re-encrypted metadata");
            sqlx::query(
                r#"INSERT INTO chat.entries(
                    conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
                    accepted_payload_sha256,signed_request_bytes,request_digest,signature,
                    server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
                    actor_key_id,actor_auth_generation,generation,state_version,transition_id,
                    received_at
                ) VALUES($1,2,$2,'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry',
                    $3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,1,$13,$14)"#,
            )
            .bind(cid)
            .bind(fulfillment.entry_id)
            .bind(&fulfillment.public_row_json)
            .bind(Sha256::digest(&fulfillment.public_row_json).to_vec())
            .bind(&fulfillment.raw_wrapper)
            .bind(&fulfillment.request_digest)
            .bind(&fulfillment.signature)
            .bind(&fulfillment.server_fields_dag_cbor)
            .bind(fulfillment.outer_entry_fingerprint.to_vec())
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(fulfillment.transition_id)
            .bind(at)
            .execute(&mut *tx)
            .await
            .expect("insert fulfillment entry");
            sqlx::query(
                r#"INSERT INTO chat.entry_recipients(
                    conversation_id,seq,user_did,device_id,entitlement_kind
                ) VALUES($1,2,$2,$3,'intervalClose')"#,
            )
            .bind(cid)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .execute(&mut *tx)
            .await
            .expect("route fulfillment to replaced interval");

            sqlx::query(
                r#"UPDATE chat.member_devices SET
                    removed_state_version=1,removed_transition_id=$1,removed_seq=2,
                    removed_at=$2,active=false
                   WHERE leaf_period_id=$3 AND active"#,
            )
            .bind(fulfillment.transition_id)
            .bind(at)
            .bind(seed.replaced_leaf_period_id)
            .execute(&mut *tx)
            .await
            .expect("close replaced leaf");
            sqlx::query(
                r#"UPDATE chat.application_intervals SET
                    terminal_seq=2,closing_state_version=1,closing_transition_id=$1,
                    closing_outer_entry_fingerprint=$2,closing_kind='replace',
                    closing_leaf_period_id=$3,removed_at=$4
                   WHERE opening_leaf_period_id=$3 AND terminal_seq IS NULL"#,
            )
            .bind(fulfillment.transition_id)
            .bind(fulfillment.outer_entry_fingerprint.to_vec())
            .bind(seed.replaced_leaf_period_id)
            .bind(at)
            .execute(&mut *tx)
            .await
            .expect("close replaced application interval");
            sqlx::query(
                r#"INSERT INTO chat.member_devices(
                    leaf_period_id,participant_period_id,conversation_id,generation,user_did,
                    device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,
                    leaf_auth_generation,origin,join_key_package_ref,joined_state_version,
                    joined_transition_id,joined_seq,active,created_at
                ) VALUES($1,$2,$3,0,$4,$5,0,$6,$7,$8,1,'keyPackage',$9,1,$10,2,true,$11)"#,
            )
            .bind(new_leaf_period_id)
            .bind(participant_period_id)
            .bind(cid)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&basic_credential)
            .bind(&entry.public_key)
            .bind(&entry.actor_key_id)
            .bind(seed.key_package_ref.to_vec())
            .bind(fulfillment.transition_id)
            .bind(at)
            .execute(&mut *tx)
            .await
            .expect("insert recovered leaf");
            sqlx::query(
                r#"INSERT INTO chat.application_intervals(
                    membership_interval_id,conversation_id,generation,recipient_did,
                    recipient_device_id,start_seq,opening_kind,opening_transition_id,
                    opening_outer_entry_fingerprint,opening_state_version,opening_group_id,
                    opening_epoch,opening_group_context_hash,opening_confirmation_tag,
                    opening_leaf_period_id,created_at
                ) VALUES($1,$2,0,$3,$4,2,'add',$1,$5,1,$6,1,$7,$8,$9,$10)"#,
            )
            .bind(fulfillment.transition_id)
            .bind(cid)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(fulfillment.outer_entry_fingerprint.to_vec())
            .bind(vec![1_u8; 32])
            .bind(vec![4_u8; 32])
            .bind(vec![5_u8; 32])
            .bind(new_leaf_period_id)
            .bind(at)
            .execute(&mut *tx)
            .await
            .expect("open recovered application interval");

            sqlx::query(
                "UPDATE chat.leaf_recovery_requests SET \
                 status='fulfilled',fulfilling_transition_id=$1,terminal_at=$2 \
                 WHERE recovery_request_id=$3 AND status='open'",
            )
            .bind(fulfillment.transition_id)
            .bind(at)
            .bind(Uuid::from_bytes(seed.request_id))
            .execute(&mut *tx)
            .await
            .expect("fulfill request");
            sqlx::query(
                "UPDATE chat.key_package_reservations SET \
                 status='consumed',consumed_transition_id=$1,terminal_at=$2 \
                 WHERE recovery_request_id=$3 AND status='active'",
            )
            .bind(fulfillment.transition_id)
            .bind(at)
            .bind(Uuid::from_bytes(seed.request_id))
            .execute(&mut *tx)
            .await
            .expect("consume reservation");
            sqlx::query(
                "UPDATE chat.key_packages SET \
                 status='consumed',terminal_transition_id=$1,terminal_at=$2 \
                 WHERE key_package_ref=$3 AND status='reserved'",
            )
            .bind(fulfillment.transition_id)
            .bind(at)
            .bind(seed.key_package_ref.to_vec())
            .execute(&mut *tx)
            .await
            .expect("consume key package");
            sqlx::query(
                r#"INSERT INTO chat.welcome_bundles(
                    welcome_id,conversation_id,transition_id,entry_seq,generation,state_version,
                    group_id,epoch,group_context_hash,confirmation_tag,wrapper_bytes,
                    wrapper_sha256,created_at
                ) VALUES($1,$2,$3,2,0,1,$4,1,$5,$6,$7,$8,$9)"#,
            )
            .bind(fulfillment.welcome_id)
            .bind(cid)
            .bind(fulfillment.transition_id)
            .bind(vec![1_u8; 32])
            .bind(vec![4_u8; 32])
            .bind(vec![5_u8; 32])
            .bind(&fulfillment.opaque_welcome)
            .bind(Sha256::digest(&fulfillment.opaque_welcome).to_vec())
            .bind(at)
            .execute(&mut *tx)
            .await
            .expect("insert welcome bundle");
            sqlx::query(
                r#"INSERT INTO chat.welcome_deliveries(
                    welcome_id,recipient_did,recipient_device_id,recovery_request_id,
                    key_package_ref,expires_at,status
                ) VALUES($1,$2,$3,$4,$5,$6,'pending')"#,
            )
            .bind(fulfillment.welcome_id)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(Uuid::from_bytes(seed.request_id))
            .bind(seed.key_package_ref.to_vec())
            .bind(instant(KP_NOT_AFTER))
            .execute(&mut *tx)
            .await
            .expect("insert welcome delivery");

            tx.commit()
                .await
                .expect("fulfillment graph crosses deferred mappings");
        }

        /// A committed fulfilled request and consumed reservation must hydrate
        /// the exact same re-verified leafRecovery transition in a fresh
        /// transaction. This catches the current unsupported-terminal branch.
        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn recovery_pair_hydrates_the_fulfilled_transition_terminal() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let seed = seed_recovery_pair(&pool, &entry, "requestLeafRecovery").await;
            let fulfillment = build_real_leaf_recovery_fulfillment_entry(&entry, &seed);
            commit_recovery_fulfillment_graph(&pool, &entry, &seed, &fulfillment).await;

            let authority = HistoricalRehydrationAuthority::new(entry.cid, 3).unwrap();
            let expected = authority
                .hydrate_historical_control_from_durable_bytes(
                    fulfillment.public_row_json.clone(),
                    fulfillment.raw_wrapper.clone(),
                    &entry.public_key,
                )
                .expect("direct fulfillment re-verification")
                .into_transition()
                .expect("leaf recovery fulfillment is a transition");

            let mut tx = pool.begin().await.expect("fresh hydration transaction");
            let (requests, reservations) =
                load_recovery_work_hydration_rows(&mut tx, &authority, cid)
                    .await
                    .expect("fulfilled recovery pair hydrates");
            tx.commit()
                .await
                .expect("commit fresh hydration transaction");

            assert_eq!(requests.len(), 1);
            assert_eq!(reservations.len(), 1);
            assert_eq!(requests[0].status, RecoveryRequestStatus::Fulfilled);
            assert_eq!(reservations[0].status, ReservationStatus::Consumed);
            assert_eq!(
                requests[0].terminal,
                Some(WorkTerminalHydrationRow::Transition(expected.clone()))
            );
            assert_eq!(
                reservations[0].terminal,
                Some(WorkTerminalHydrationRow::Transition(expected))
            );
        }

        /// Characterize the exact signed-body predicate used by fulfilled
        /// recovery hydration. Scalar/coordinate substitutions exercise its
        /// read-side inputs, while the Welcome cases rebuild and sign canonical
        /// evidence whose malformed binding is still independently decoded and
        /// historically reverified. The wrong-kind candidate is the real signed
        /// Creation transition, not a synthetic authority/body enum.
        #[test]
        fn recovery_fulfillment_terminal_predicate_rejects_binding_substitutions() {
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let seed = RecoverySeed {
                request_id: *Uuid::new_v4().as_bytes(),
                key_package_ref: Sha256::digest(Uuid::new_v4().as_bytes()).into(),
                raw_wrapper: Vec::new(),
                creation_transition_id: Uuid::new_v4(),
                replaced_leaf_period_id: Uuid::new_v4(),
            };
            let authority = HistoricalRehydrationAuthority::new(entry.cid, 3).unwrap();
            let fulfillment = build_real_leaf_recovery_fulfillment_entry(&entry, &seed);
            let evidence = authority
                .hydrate_historical_control_from_durable_bytes(
                    fulfillment.public_row_json.clone(),
                    fulfillment.raw_wrapper.clone(),
                    &entry.public_key,
                )
                .expect("baseline fulfillment re-verifies")
                .into_transition()
                .expect("baseline fulfillment is a transition");
            let target = DeviceIdentity::new(
                PrincipalId::new(entry.actor_did.clone().into_bytes()).unwrap(),
                *entry.actor_device_id.as_bytes(),
            )
            .unwrap();
            let bound_coordinate = PublicGroupSnapshotCoordinate::new(
                entry.cid,
                0,
                0,
                [1; 32],
                0,
                [2; 32],
                [3; 32],
                PublicGroupSnapshotLifecycle::Active,
            );
            let terminal_at = ServerTimestamp::from_canonical_stored(FULFILLED_AT).unwrap();
            fn terminal_matches(
                candidate: &crate::chat_protocol::state_machine::TransitionEvidence,
                request_id: &[u8; 16],
                candidate_target: &DeviceIdentity,
                kind: LeafRecoveryKind,
                coordinate: &PublicGroupSnapshotCoordinate,
                key_package_ref: &[u8; 32],
                at: ServerTimestamp,
            ) -> bool {
                recovery_fulfillment_terminal_matches(
                    candidate,
                    request_id,
                    candidate_target,
                    kind,
                    coordinate,
                    key_package_ref,
                    at,
                )
            }

            assert!(terminal_matches(
                &evidence,
                &seed.request_id,
                &target,
                LeafRecoveryKind::Replace,
                &bound_coordinate,
                &seed.key_package_ref,
                terminal_at,
            ));

            let foreign_coordinate = PublicGroupSnapshotCoordinate::new(
                *Uuid::new_v4().as_bytes(),
                0,
                0,
                [1; 32],
                0,
                [2; 32],
                [3; 32],
                PublicGroupSnapshotLifecycle::Active,
            );
            let stale_coordinate = PublicGroupSnapshotCoordinate::new(
                entry.cid,
                0,
                1,
                [1; 32],
                1,
                [4; 32],
                [5; 32],
                PublicGroupSnapshotLifecycle::Active,
            );
            let wrong_request_id = *Uuid::new_v4().as_bytes();
            let wrong_target =
                DeviceIdentity::new(target.principal().clone(), *Uuid::new_v4().as_bytes())
                    .unwrap();
            let wrong_key_package_ref = [0xa5; 32];
            let wrong_terminal_at =
                ServerTimestamp::from_canonical_stored("2030-01-01T00:01:01.000Z").unwrap();
            let scalar_and_coordinate_cases = [
                (
                    "foreign conversation authority",
                    &seed.request_id,
                    &target,
                    LeafRecoveryKind::Replace,
                    &foreign_coordinate,
                    &seed.key_package_ref,
                    terminal_at,
                ),
                (
                    "stale prior coordinate",
                    &seed.request_id,
                    &target,
                    LeafRecoveryKind::Replace,
                    &stale_coordinate,
                    &seed.key_package_ref,
                    terminal_at,
                ),
                (
                    "wrong recovery request id",
                    &wrong_request_id,
                    &target,
                    LeafRecoveryKind::Replace,
                    &bound_coordinate,
                    &seed.key_package_ref,
                    terminal_at,
                ),
                (
                    "wrong target device",
                    &seed.request_id,
                    &wrong_target,
                    LeafRecoveryKind::Replace,
                    &bound_coordinate,
                    &seed.key_package_ref,
                    terminal_at,
                ),
                (
                    "wrong key-package ref",
                    &seed.request_id,
                    &target,
                    LeafRecoveryKind::Replace,
                    &bound_coordinate,
                    &wrong_key_package_ref,
                    terminal_at,
                ),
                (
                    "wrong Add-vs-Replace shape",
                    &seed.request_id,
                    &target,
                    LeafRecoveryKind::Add,
                    &bound_coordinate,
                    &seed.key_package_ref,
                    terminal_at,
                ),
                (
                    "wrong terminal timestamp",
                    &seed.request_id,
                    &target,
                    LeafRecoveryKind::Replace,
                    &bound_coordinate,
                    &seed.key_package_ref,
                    wrong_terminal_at,
                ),
            ];
            for (label, request_id, candidate_target, kind, coordinate, key_package_ref, at) in
                scalar_and_coordinate_cases
            {
                assert!(
                    !terminal_matches(
                        &evidence,
                        request_id,
                        candidate_target,
                        kind,
                        coordinate,
                        key_package_ref,
                        at,
                    ),
                    "{label} must fail closed"
                );
            }

            let creation_evidence = authority
                .hydrate_historical_control_from_durable_bytes(
                    entry.public_row_json.clone(),
                    entry.raw_wrapper.clone(),
                    &entry.public_key,
                )
                .expect("real signed Creation evidence re-verifies")
                .into_transition()
                .expect("Creation is a transition");
            assert!(
                !terminal_matches(
                    &creation_evidence,
                    &seed.request_id,
                    &target,
                    LeafRecoveryKind::Replace,
                    &bound_coordinate,
                    &seed.key_package_ref,
                    terminal_at,
                ),
                "wrong signed mutation/body kind must fail closed"
            );

            enum WelcomeBindingMutation {
                Recipient,
                Request,
                KeyPackage,
            }
            let malformed_welcome_mutations = [
                ("recipient", WelcomeBindingMutation::Recipient),
                ("request", WelcomeBindingMutation::Request),
                ("key-package", WelcomeBindingMutation::KeyPackage),
            ];
            for (label, mutation) in malformed_welcome_mutations {
                let malformed = build_real_leaf_recovery_fulfillment_entry_with_mutation(
                    &entry,
                    &seed,
                    |body| match mutation {
                        WelcomeBindingMutation::Recipient => {
                            body["manifest"]["welcomeBundle"]["deliveries"][0]
                                ["recipientDeviceId"] =
                                Value::String(Uuid::new_v4().hyphenated().to_string());
                        }
                        WelcomeBindingMutation::Request => {
                            body["manifest"]["welcomeBundle"]["deliveries"][0]["provenance"]
                                ["recoveryRequestId"] =
                                Value::String(Uuid::new_v4().hyphenated().to_string());
                        }
                        WelcomeBindingMutation::KeyPackage => {
                            body["manifest"]["welcomeBundle"]["deliveries"][0]["provenance"]
                                ["keyPackageRef"] = Value::String(STANDARD.encode([0xb6; 32]));
                        }
                    },
                );
                let malformed_evidence = authority
                    .hydrate_historical_control_from_durable_bytes(
                        malformed.public_row_json,
                        malformed.raw_wrapper,
                        &entry.public_key,
                    )
                    .unwrap_or_else(|error| {
                        panic!("signed malformed Welcome {label} must reverify: {error:?}")
                    })
                    .into_transition()
                    .expect("malformed Welcome fulfillment remains a transition");
                assert!(
                    !terminal_matches(
                        &malformed_evidence,
                        &seed.request_id,
                        &target,
                        LeafRecoveryKind::Replace,
                        &bound_coordinate,
                        &seed.key_package_ref,
                        terminal_at,
                    ),
                    "malformed Welcome {label} binding must fail closed"
                );
            }
        }

        /// A coherent fulfilled graph read under a foreign conversation
        /// authority fails at terminal evidence reconstruction, before the
        /// request origin can be accepted under that authority.
        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn recovery_pair_rejects_foreign_fulfillment_evidence_as_invalid_terminal() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let seed = seed_recovery_pair(&pool, &entry, "requestLeafRecovery").await;
            let fulfillment = build_real_leaf_recovery_fulfillment_entry(&entry, &seed);
            commit_recovery_fulfillment_graph(&pool, &entry, &seed, &fulfillment).await;

            let authority =
                HistoricalRehydrationAuthority::new(*Uuid::new_v4().as_bytes(), 3).unwrap();
            let mut tx = pool.begin().await.expect("fresh hydration transaction");
            let result = load_recovery_work_hydration_rows(&mut tx, &authority, cid).await;
            tx.rollback().await.expect("rollback");

            assert!(matches!(
                result,
                Err(RecoveryHydrationError::InvalidTerminal)
            ));
        }

        mod welcome_leg {
            use super::*;

            const WELCOME_TERMINAL_AT: &str = "2030-01-01T00:10:00.000Z";
            const LATER_TRANSITION_AT: &str = "2030-01-01T00:02:00.000Z";

            #[derive(Clone, Copy, Debug)]
            enum AggregateWelcomeArm {
                Pending,
                Acknowledged,
                Rejected,
                Expired,
                TransitionSuperseded,
                RevocationSuperseded,
            }

            struct SignedWelcomeResponse {
                raw_wrapper: Vec<u8>,
                signing_transcript: Vec<u8>,
                request_digest: Vec<u8>,
                signature: Vec<u8>,
            }

            struct SignedWelcomeRevocation {
                revocation_id: Uuid,
                raw_wrapper: Vec<u8>,
                signing_transcript: Vec<u8>,
                request_digest: Vec<u8>,
                signature: Vec<u8>,
            }

            struct WelcomeRevocationActor {
                device_id: Uuid,
                key_id: String,
                signing_key: SigningKey,
            }

            struct RealLaterCommitEntry {
                entry_id: Uuid,
                transition_id: Uuid,
                public_row_json: Vec<u8>,
                raw_wrapper: Vec<u8>,
                canonical_projection: Vec<u8>,
                signing_transcript: Vec<u8>,
                request_digest: Vec<u8>,
                signature: Vec<u8>,
                server_fields_dag_cbor: Vec<u8>,
                outer_entry_fingerprint: [u8; 32],
            }

            fn build_signed_welcome_revocation(
                entry: &RealCreationEntry,
                actor: &WelcomeRevocationActor,
            ) -> SignedWelcomeRevocation {
                let revocation_id = Uuid::new_v4();
                let body = json!({
                    "$type": SignedMutationKind::DeviceRevocation.type_id(),
                    "signatureDomain": String::from_utf8(
                        SignedMutationKind::DeviceRevocation.domain().to_vec()
                    ).unwrap(),
                    "actorDid": entry.actor_did,
                    "actorDeviceId": actor.device_id.hyphenated().to_string(),
                    "keyId": actor.key_id,
                    "authGeneration": 1,
                    "targetDeviceId": entry.actor_device_id.hyphenated().to_string(),
                    "targetAuthGeneration": 1,
                    "idempotencyKey": revocation_id.hyphenated().to_string(),
                    "signedAt": "2030-01-01T00:09:59.000Z",
                });
                let mut wrapper = json!({ "body": body, "signature": STANDARD.encode([0_u8; 64]) });
                let unsigned = serde_json::to_vec(&wrapper).unwrap();
                let canonical = decode_canonical_signed_mutation(&unsigned)
                    .expect("unsigned Welcome revocation canonicalizes");
                let signing_transcript = canonical.transcript_bytes().to_vec();
                let signature = actor.signing_key.sign(&signing_transcript).to_bytes();
                wrapper["signature"] = Value::String(STANDARD.encode(signature));
                let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
                SignedWelcomeRevocation {
                    revocation_id,
                    raw_wrapper,
                    request_digest: Sha256::digest(&signing_transcript).to_vec(),
                    signature: signature.to_vec(),
                    signing_transcript,
                }
            }

            async fn seed_welcome_revocation_actor(
                pool: &PgPool,
                entry: &RealCreationEntry,
            ) -> WelcomeRevocationActor {
                let device_id = Uuid::new_v4();
                let signing_seed: [u8; 32] = Sha256::digest(device_id.as_bytes()).into();
                let signing_key = SigningKey::from_bytes(&signing_seed);
                let public_key = signing_key.verifying_key().to_bytes();
                let key_id = ed25519_key_id(&public_key).unwrap().as_str().to_owned();
                let dpop_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(device_id.as_bytes()));
                let created_at = instant("2029-12-31T23:58:00.000Z");
                let mut tx = pool.begin().await.expect("begin revocation actor");
                sqlx::query(
                    r#"INSERT INTO chat.devices(
                        user_did,device_id,device_name,status,dpop_jkt,auth_generation,
                        capabilities,created_at,updated_at
                    ) VALUES($1,$2,'welcome-revocation-actor','active',$3,1,
                        chat.protocol_capabilities(),$4,$4)"#,
                )
                .bind(&entry.actor_did)
                .bind(device_id)
                .bind(dpop_jkt)
                .bind(created_at)
                .execute(&mut *tx)
                .await
                .expect("insert Welcome revocation actor device");
                sqlx::query(
                    r#"INSERT INTO chat.device_keys(
                        user_did,device_id,key_id,signing_public_key,
                        enrollment_auth_generation,created_at
                    ) VALUES($1,$2,$3,$4,1,$5)"#,
                )
                .bind(&entry.actor_did)
                .bind(device_id)
                .bind(&key_id)
                .bind(public_key.to_vec())
                .bind(created_at)
                .execute(&mut *tx)
                .await
                .expect("insert Welcome revocation actor key");
                tx.commit().await.expect("commit Welcome revocation actor");
                WelcomeRevocationActor {
                    device_id,
                    key_id,
                    signing_key,
                }
            }

            async fn commit_welcome_revocation_supersession(
                pool: &PgPool,
                entry: &RealCreationEntry,
                fulfillment: &RealLeafRecoveryFulfillmentEntry,
                actor: &WelcomeRevocationActor,
                revocation: &SignedWelcomeRevocation,
            ) {
                let terminal_at = instant(WELCOME_TERMINAL_AT);
                let signed_at = instant("2030-01-01T00:09:59.000Z");
                let response_bytes = b"welcome-revocation-ok".to_vec();
                let mut tx = pool.begin().await.expect("begin Welcome revocation graph");
                sqlx::query(
                    r#"INSERT INTO chat.device_revocations(
                        revocation_id,actor_did,actor_device_id,actor_key_id,
                        actor_auth_generation,target_did,target_device_id,
                        target_auth_generation,accepted_request_bytes,
                        signing_transcript_bytes,request_digest,signature,signed_at,accepted_at
                    ) VALUES($1,$2,$3,$4,1,$2,$5,1,$6,$7,$8,$9,$10,$11)"#,
                )
                .bind(revocation.revocation_id)
                .bind(&entry.actor_did)
                .bind(actor.device_id)
                .bind(&actor.key_id)
                .bind(entry.actor_device_id)
                .bind(&revocation.raw_wrapper)
                .bind(&revocation.signing_transcript)
                .bind(&revocation.request_digest)
                .bind(&revocation.signature)
                .bind(signed_at)
                .bind(terminal_at)
                .execute(&mut *tx)
                .await
                .expect("insert exact Welcome revocation");
                sqlx::query(
                    r#"UPDATE chat.devices
                       SET status='revoked',revoked_at=$3,revocation_id=$4,updated_at=$3
                       WHERE user_did=$1 AND device_id=$2 AND status='active'
                         AND auth_generation=1"#,
                )
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(terminal_at)
                .bind(revocation.revocation_id)
                .execute(&mut *tx)
                .await
                .expect("revoke Welcome recipient device");
                sqlx::query(
                    r#"UPDATE chat.device_keys SET revoked_at=$3,revocation_id=$4
                       WHERE user_did=$1 AND device_id=$2 AND revoked_at IS NULL"#,
                )
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(terminal_at)
                .bind(revocation.revocation_id)
                .execute(&mut *tx)
                .await
                .expect("revoke Welcome recipient key");
                sqlx::query(
                    r#"INSERT INTO chat.idempotency_records(
                        principal_did,endpoint_nsid,operation_id,request_digest,
                        accepted_request_bytes,signing_transcript_bytes,signature,
                        completed_status,response_bytes,response_sha256,event_position,
                        historical_jkt,current_jkt,completed_at
                    ) VALUES($1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,200,
                        $7,$8,NULL,$9,NULL,$10)"#,
                )
                .bind(&entry.actor_did)
                .bind(revocation.revocation_id)
                .bind(&revocation.request_digest)
                .bind(&revocation.raw_wrapper)
                .bind(&revocation.signing_transcript)
                .bind(&revocation.signature)
                .bind(&response_bytes)
                .bind(Sha256::digest(&response_bytes).to_vec())
                .bind(&actor.key_id)
                .bind(terminal_at)
                .execute(&mut *tx)
                .await
                .expect("insert Welcome revocation receipt");
                insert_uncommitted_superseded_disposition(
                    &mut tx,
                    entry,
                    fulfillment,
                    terminal_at,
                    None,
                    Some(revocation.revocation_id),
                )
                .await;
                let event_position: i64 = sqlx::query_scalar(
                    "SELECT event_position FROM chat.welcome_dispositions WHERE welcome_id=$1",
                )
                .bind(fulfillment.welcome_id)
                .fetch_one(&mut *tx)
                .await
                .expect("Welcome revocation disposition event");
                let predecessor: Option<i64> = sqlx::query_scalar(
                    r#"SELECT MAX(event_position) FROM chat.event_recipients
                       WHERE user_did=$1 AND device_id=$2"#,
                )
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .fetch_one(&mut *tx)
                .await
                .expect("Welcome revocation audience predecessor");
                sqlx::query(
                    r#"INSERT INTO chat.event_recipients(
                        event_position,user_did,device_id,entitlement_kind,
                        audience_predecessor_position
                    ) VALUES($1,$2,$3,'welcome',$4)"#,
                )
                .bind(event_position)
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(predecessor)
                .execute(&mut *tx)
                .await
                .expect("insert Welcome revocation audience");
                sqlx::query(
                    r#"INSERT INTO chat.outbox(
                        outbox_id,event_position,work_kind,status,next_attempt_at,created_at
                    ) VALUES($1,$2,'stream','pending',$3,$3)"#,
                )
                .bind(Uuid::new_v4())
                .bind(event_position)
                .bind(terminal_at)
                .execute(&mut *tx)
                .await
                .expect("insert Welcome revocation outbox");
                tx.commit()
                    .await
                    .expect("Welcome revocation crosses every deferred constraint");
            }

            async fn insert_uncommitted_superseded_disposition(
                transaction: &mut Transaction<'_, Postgres>,
                entry: &RealCreationEntry,
                fulfillment: &RealLeafRecoveryFulfillmentEntry,
                terminal_at: DateTime<Utc>,
                terminal_transition_id: Option<Uuid>,
                terminal_revocation_id: Option<Uuid>,
            ) {
                sqlx::query(
                    r#"INSERT INTO chat.protocol_instances(
                        singleton,protocol_instance_id,cursor_key_id,created_at
                    ) VALUES(TRUE,$1,$2,$3)
                    ON CONFLICT (singleton) DO NOTHING"#,
                )
                .bind(Uuid::new_v4())
                .bind(&entry.actor_key_id)
                .bind(terminal_at)
                .execute(&mut **transaction)
                .await
                .expect("ensure supersession protocol instance");
                let protocol_instance_id: Uuid =
                    sqlx::query_scalar("SELECT protocol_instance_id FROM chat.protocol_instances")
                        .fetch_one(&mut **transaction)
                        .await
                        .expect("supersession protocol instance");
                let payload = vec![0x83_u8; 8];
                let event_position: i64 = sqlx::query_scalar(
                    r#"INSERT INTO chat.events(
                        event_id,event_kind,payload_bytes,payload_sha256,created_at,
                        protocol_instance_id
                    ) VALUES($1,'welcomeDisposition',$2,$3,$4,$5)
                    RETURNING event_position"#,
                )
                .bind(Uuid::new_v4())
                .bind(&payload)
                .bind(Sha256::digest(&payload).to_vec())
                .bind(terminal_at)
                .bind(protocol_instance_id)
                .fetch_one(&mut **transaction)
                .await
                .expect("insert supersession event");
                sqlx::query(
                    "UPDATE chat.welcome_deliveries SET status='superseded',terminal_at=$2 \
                     WHERE welcome_id=$1 AND status='pending'",
                )
                .bind(fulfillment.welcome_id)
                .bind(terminal_at)
                .execute(&mut **transaction)
                .await
                .expect("supersede pending Welcome");
                sqlx::query(
                    r#"INSERT INTO chat.welcome_dispositions(
                        welcome_id,winner_kind,signed_request_bytes,signing_transcript_bytes,
                        request_digest,signature,rejection_reason,terminal_at,event_position,
                        terminal_transition_id,terminal_revocation_id
                    ) VALUES($1,'superseded',NULL,NULL,NULL,NULL,NULL,$2,$3,$4,$5)"#,
                )
                .bind(fulfillment.welcome_id)
                .bind(terminal_at)
                .bind(event_position)
                .bind(terminal_transition_id)
                .bind(terminal_revocation_id)
                .execute(&mut **transaction)
                .await
                .expect("insert direct-cause supersession disposition");
            }

            async fn insert_uncommitted_signed_disposition(
                transaction: &mut Transaction<'_, Postgres>,
                entry: &RealCreationEntry,
                fulfillment: &RealLeafRecoveryFulfillmentEntry,
                winner: &str,
                response: &SignedWelcomeResponse,
                stored_signature: &[u8],
                stored_rejection_reason: Option<&str>,
            ) {
                let terminal_at = instant(WELCOME_TERMINAL_AT);
                sqlx::query(
                    r#"INSERT INTO chat.protocol_instances(
                        singleton,protocol_instance_id,cursor_key_id,created_at
                    ) VALUES(TRUE,$1,$2,$3)
                    ON CONFLICT (singleton) DO NOTHING"#,
                )
                .bind(Uuid::new_v4())
                .bind(&entry.actor_key_id)
                .bind(terminal_at)
                .execute(&mut **transaction)
                .await
                .expect("ensure malformed-response protocol instance");
                let protocol_instance_id: Uuid =
                    sqlx::query_scalar("SELECT protocol_instance_id FROM chat.protocol_instances")
                        .fetch_one(&mut **transaction)
                        .await
                        .expect("malformed-response protocol instance");
                let payload = vec![0x84_u8; 8];
                let event_position: i64 = sqlx::query_scalar(
                    r#"INSERT INTO chat.events(
                        event_id,event_kind,payload_bytes,payload_sha256,created_at,
                        protocol_instance_id
                    ) VALUES($1,'welcomeDisposition',$2,$3,$4,$5)
                    RETURNING event_position"#,
                )
                .bind(Uuid::new_v4())
                .bind(&payload)
                .bind(Sha256::digest(&payload).to_vec())
                .bind(terminal_at)
                .bind(protocol_instance_id)
                .fetch_one(&mut **transaction)
                .await
                .expect("insert malformed-response event");
                sqlx::query(
                    "UPDATE chat.welcome_deliveries SET status=$2,terminal_at=$3 \
                     WHERE welcome_id=$1 AND status='pending'",
                )
                .bind(fulfillment.welcome_id)
                .bind(winner)
                .bind(terminal_at)
                .execute(&mut **transaction)
                .await
                .expect("terminalize malformed-response Welcome");
                sqlx::query(
                    r#"INSERT INTO chat.welcome_dispositions(
                        welcome_id,winner_kind,signed_request_bytes,signing_transcript_bytes,
                        request_digest,signature,rejection_reason,terminal_at,event_position,
                        terminal_transition_id,terminal_revocation_id
                    ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,NULL)"#,
                )
                .bind(fulfillment.welcome_id)
                .bind(winner)
                .bind(&response.raw_wrapper)
                .bind(&response.signing_transcript)
                .bind(&response.request_digest)
                .bind(stored_signature)
                .bind(stored_rejection_reason)
                .bind(terminal_at)
                .bind(event_position)
                .execute(&mut **transaction)
                .await
                .expect("insert malformed signed disposition");
            }

            fn build_signed_welcome_response(
                entry: &RealCreationEntry,
                fulfillment: &RealLeafRecoveryFulfillmentEntry,
                kind: SignedMutationKind,
            ) -> SignedWelcomeResponse {
                assert!(matches!(
                    kind,
                    SignedMutationKind::WelcomeAcknowledgement
                        | SignedMutationKind::WelcomeRejection
                ));
                let signing_key = entry.signing_key();
                let mut body = json!({
                    "$type": kind.type_id(),
                    "signatureDomain": String::from_utf8(kind.domain().to_vec()).unwrap(),
                    "actorDid": entry.actor_did,
                    "actorDeviceId": entry.actor_device_id.hyphenated().to_string(),
                    "keyId": entry.actor_key_id,
                    "authGeneration": 1,
                    "idempotencyKey": Uuid::new_v4().hyphenated().to_string(),
                    "signedAt": "2030-01-01T00:09:59.000Z",
                    "welcomeId": fulfillment.welcome_id.hyphenated().to_string(),
                    "coordinates": next_coordinate_json(entry.cid),
                    "transitionSeq": 2,
                });
                if kind == SignedMutationKind::WelcomeRejection {
                    body["reason"] = Value::String("invalidWelcome".to_owned());
                }
                let mut wrapper = json!({ "body": body, "signature": STANDARD.encode([0_u8; 64]) });
                let unsigned = serde_json::to_vec(&wrapper).unwrap();
                let canonical = decode_canonical_signed_mutation(&unsigned)
                    .expect("unsigned Welcome response canonicalizes");
                let signature = signing_key.sign(canonical.transcript_bytes()).to_bytes();
                wrapper["signature"] = Value::String(STANDARD.encode(signature));
                let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
                let verified = decode_canonical_signed_mutation(&raw_wrapper)
                    .expect("signed Welcome response canonicalizes");
                SignedWelcomeResponse {
                    raw_wrapper,
                    signing_transcript: verified.transcript_bytes().to_vec(),
                    request_digest: verified.request_digest().to_vec(),
                    signature: verified.signature().to_vec(),
                }
            }

            fn build_real_later_commit(
                entry: &RealCreationEntry,
                seed: &RecoverySeed,
            ) -> RealLaterCommitEntry {
                let signing_key = entry.signing_key();
                let transition_id = Uuid::new_v4();
                let entry_id = Uuid::new_v4();
                let commit_bytes = [0x71_u8; 8];
                let metadata_ciphertext = [0x72_u8; 16];
                let prior = next_coordinate_json(entry.cid);
                let next = json!({
                        "conversationId": Uuid::from_bytes(entry.cid).hyphenated().to_string(),
                        "generation": 0,
                        "stateVersion": 2,
                        "groupId": STANDARD.encode([1_u8; 32]),
                        "epoch": 2,
                        "groupContextHash": STANDARD.encode([6_u8; 32]),
                        "confirmationTag": STANDARD.encode([7_u8; 32]),
                        "lifecycle": "active",
                });
                let aad_prior = json!({
                        "conversationId": STANDARD.encode(entry.cid),
                        "generation": 0,
                        "stateVersion": 1,
                        "groupId": STANDARD.encode([1_u8; 32]),
                        "epoch": 1,
                        "groupContextHash": STANDARD.encode([4_u8; 32]),
                        "confirmationTag": STANDARD.encode([5_u8; 32]),
                        "lifecycle": "active",
                });
                let body = json!({
                    "$type": SignedMutationKind::CommitTransition.type_id(),
                    "signatureDomain": String::from_utf8(
                        SignedMutationKind::CommitTransition.domain().to_vec()
                    ).unwrap(),
                    "transitionId": transition_id.hyphenated().to_string(),
                    "actorDid": entry.actor_did,
                    "actorDeviceId": entry.actor_device_id.hyphenated().to_string(),
                    "keyId": entry.actor_key_id,
                    "authGeneration": 1,
                    "prior": prior,
                    "next": next,
                    "aad": {
                        "protocolVersion": "1",
                        "conversationId": STANDARD.encode(entry.cid),
                        "generation": 0,
                        "transitionId": STANDARD.encode(transition_id.as_bytes()),
                        "prior": aad_prior,
                    },
                    "manifest": {
                        "participantChanges": [],
                        "leafChanges": [],
                    },
                    "commit": {
                        "framing": "mlsMessage",
                        "contentType": "publicMessageCommit",
                        "bytes": STANDARD.encode(commit_bytes),
                        "sha256": STANDARD.encode(Sha256::digest(commit_bytes)),
                    },
                    "metadataSnapshot": {
                        "coordinate": {
                            "conversationId": STANDARD.encode(entry.cid),
                            "generation": 0,
                            "groupId": STANDARD.encode([1_u8; 32]),
                            "epoch": 2,
                            "groupContextHash": STANDARD.encode([6_u8; 32]),
                            "confirmationTag": STANDARD.encode([7_u8; 32]),
                        },
                        "originTransitionId": seed.creation_transition_id.hyphenated().to_string(),
                        "metadataVersion": 1,
                        "nonce": STANDARD.encode([0x73_u8; 12]),
                        "ciphertext": STANDARD.encode(metadata_ciphertext),
                        "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
                        "ciphertextSize": metadata_ciphertext.len(),
                        "authorProof": {
                            "authorDid": entry.actor_did,
                            "authorDeviceId": entry.actor_device_id.hyphenated().to_string(),
                            "authorKeyId": entry.actor_key_id,
                            "signaturePublicKey": STANDARD.encode(&entry.public_key),
                            "authGenerationAtOrigin": 1,
                            "originTransitionId":
                                seed.creation_transition_id.hyphenated().to_string(),
                            "originSeq": 1,
                            "roleAtOrigin": "admin",
                            "deviceStatusAtOrigin": "active",
                        },
                    },
                    "idempotencyKey": Uuid::new_v4().hyphenated().to_string(),
                    "signedAt": "2030-01-01T00:01:59.000Z",
                });
                let mut wrapper = json!({ "body": body, "signature": STANDARD.encode([0_u8; 64]) });
                let unsigned = serde_json::to_vec(&wrapper).unwrap();
                let canonical = decode_canonical_signed_mutation(&unsigned)
                    .expect("unsigned later Commit canonicalizes");
                let signature = signing_key.sign(canonical.transcript_bytes()).to_bytes();
                wrapper["signature"] = Value::String(STANDARD.encode(signature));
                let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
                let canonical = decode_canonical_signed_mutation(&raw_wrapper)
                    .expect("signed later Commit canonicalizes");
                let public_row_json = serde_json::to_vec(&json!({
                    "$type": "blue.catbird.chat.defs#commitEntry",
                    "entryId": entry_id.hyphenated().to_string(),
                    "conversationId": Uuid::from_bytes(entry.cid).hyphenated().to_string(),
                    "seq": 3,
                    "signedRequest": wrapper,
                    "receivedAt": LATER_TRANSITION_AT,
                }))
                .unwrap();
                let decoded = decode_and_verify_control_entry(
                    &public_row_json,
                    signing_key.verifying_key().as_bytes(),
                )
                .expect("real later Commit entry verifies");
                RealLaterCommitEntry {
                    entry_id,
                    transition_id,
                    public_row_json,
                    raw_wrapper,
                    canonical_projection: canonical.canonical_projection().to_vec(),
                    signing_transcript: canonical.transcript_bytes().to_vec(),
                    request_digest: canonical.request_digest().to_vec(),
                    signature: canonical.signature().to_vec(),
                    server_fields_dag_cbor: decoded.server_fields_dag_cbor().unwrap(),
                    outer_entry_fingerprint: *decoded.outer_control_fingerprint(),
                }
            }

            async fn commit_later_transition_supersession(
                pool: &PgPool,
                entry: &RealCreationEntry,
                seed: &RecoverySeed,
                fulfillment: &RealLeafRecoveryFulfillmentEntry,
                transition: &RealLaterCommitEntry,
            ) {
                let cid = Uuid::from_bytes(entry.cid);
                let at = instant(LATER_TRANSITION_AT);
                let metadata_snapshot_id = Uuid::new_v4();
                let public_snapshot = vec![0x74_u8; 64];
                let (tree_summary, tree_summary_sha256) = encoded_fixture_tree_summary(entry);
                let metadata_ciphertext = vec![0x72_u8; 16];
                let mut transaction = pool.begin().await.expect("begin later Commit graph");
                sqlx::query(
                    r#"UPDATE chat.conversations
                       SET current_state_version=2,next_entry_seq=4
                       WHERE conversation_id=$1 AND current_generation=0
                         AND current_state_version=1 AND next_entry_seq=3"#,
                )
                .bind(cid)
                .execute(&mut *transaction)
                .await
                .expect("advance conversation through later Commit");
                sqlx::query(
                    r#"UPDATE chat.generations SET current_state_version=2
                       WHERE conversation_id=$1 AND generation=0
                         AND current_state_version=1"#,
                )
                .bind(cid)
                .execute(&mut *transaction)
                .await
                .expect("advance generation through later Commit");
                sqlx::query(
                    r#"INSERT INTO chat.transitions(
                        transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
                        actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
                        unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
                        prior_generation,prior_state_version,next_generation,next_state_version,
                        metadata_snapshot_id,entry_seq,accepted_at
                    ) VALUES($1,$2,'commit',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,
                        0,1,0,2,$11,3,$12)"#,
                )
                .bind(transition.transition_id)
                .bind(cid)
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(&entry.actor_key_id)
                .bind(&transition.raw_wrapper)
                .bind(&transition.canonical_projection)
                .bind(&transition.signing_transcript)
                .bind(&transition.request_digest)
                .bind(&transition.signature)
                .bind(metadata_snapshot_id)
                .bind(at)
                .execute(&mut *transaction)
                .await
                .expect("insert later consuming transition");
                sqlx::query(
                    r#"INSERT INTO chat.generation_states(
                        conversation_id,generation,state_version,group_id,epoch,group_context_hash,
                        confirmation_tag,lifecycle,state_kind,producing_transition_id,
                        public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,
                        leaf_count,created_at
                    ) VALUES($1,0,2,$2,2,$3,$4,'active','commit',$5,$6,$7,$8,$9,1,$10)"#,
                )
                .bind(cid)
                .bind(vec![1_u8; 32])
                .bind(vec![6_u8; 32])
                .bind(vec![7_u8; 32])
                .bind(transition.transition_id)
                .bind(&public_snapshot)
                .bind(Sha256::digest(&public_snapshot).to_vec())
                .bind(&tree_summary)
                .bind(tree_summary_sha256.to_vec())
                .bind(at)
                .execute(&mut *transaction)
                .await
                .expect("insert later Commit generation state");
                sqlx::query(
                    r#"INSERT INTO chat.metadata_snapshots(
                        metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,
                        group_context_hash,confirmation_tag,producing_transition_id,
                        origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,
                        ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,
                        author_auth_generation,author_origin_seq,author_role,author_device_status,
                        created_at
                    ) VALUES($1,$2,0,2,$3,2,$4,$5,$6,$7,1,$8,$9,$10,16,$11,$12,$13,$14,
                        1,1,'admin','active',$15)"#,
                )
                .bind(metadata_snapshot_id)
                .bind(cid)
                .bind(vec![1_u8; 32])
                .bind(vec![6_u8; 32])
                .bind(vec![7_u8; 32])
                .bind(transition.transition_id)
                .bind(seed.creation_transition_id)
                .bind(vec![0x73_u8; 12])
                .bind(&metadata_ciphertext)
                .bind(Sha256::digest(&metadata_ciphertext).to_vec())
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(&entry.actor_key_id)
                .bind(&entry.public_key)
                .bind(at)
                .execute(&mut *transaction)
                .await
                .expect("insert later Commit metadata");
                sqlx::query(
                    r#"INSERT INTO chat.entries(
                        conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
                        accepted_payload_sha256,signed_request_bytes,request_digest,signature,
                        server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
                        actor_key_id,actor_auth_generation,generation,state_version,transition_id,
                        received_at
                    ) VALUES($1,3,$2,'blue.catbird.chat.defs#commitEntry',
                        $3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,2,$13,$14)"#,
                )
                .bind(cid)
                .bind(transition.entry_id)
                .bind(&transition.public_row_json)
                .bind(Sha256::digest(&transition.public_row_json).to_vec())
                .bind(&transition.raw_wrapper)
                .bind(&transition.request_digest)
                .bind(&transition.signature)
                .bind(&transition.server_fields_dag_cbor)
                .bind(transition.outer_entry_fingerprint.to_vec())
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(&entry.actor_key_id)
                .bind(transition.transition_id)
                .bind(at)
                .execute(&mut *transaction)
                .await
                .expect("insert later consuming entry");
                sqlx::query(
                    r#"INSERT INTO chat.entry_recipients(
                        conversation_id,seq,user_did,device_id,entitlement_kind
                    ) VALUES($1,3,$2,$3,'control')"#,
                )
                .bind(cid)
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .execute(&mut *transaction)
                .await
                .expect("route later Commit to active control interval");
                insert_uncommitted_superseded_disposition(
                    &mut transaction,
                    entry,
                    fulfillment,
                    at,
                    Some(transition.transition_id),
                    None,
                )
                .await;
                let event_position: i64 = sqlx::query_scalar(
                    "SELECT event_position FROM chat.welcome_dispositions WHERE welcome_id=$1",
                )
                .bind(fulfillment.welcome_id)
                .fetch_one(&mut *transaction)
                .await
                .expect("later Commit Welcome disposition event");
                let predecessor: Option<i64> = sqlx::query_scalar(
                    r#"SELECT MAX(event_position) FROM chat.event_recipients
                       WHERE user_did=$1 AND device_id=$2"#,
                )
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .fetch_one(&mut *transaction)
                .await
                .expect("later Commit Welcome audience predecessor");
                sqlx::query(
                    r#"INSERT INTO chat.event_recipients(
                        event_position,user_did,device_id,entitlement_kind,
                        audience_predecessor_position
                    ) VALUES($1,$2,$3,'welcome',$4)"#,
                )
                .bind(event_position)
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(predecessor)
                .execute(&mut *transaction)
                .await
                .expect("insert later Commit Welcome audience");
                sqlx::query(
                    r#"INSERT INTO chat.outbox(
                        outbox_id,event_position,work_kind,status,next_attempt_at,created_at
                    ) VALUES($1,$2,'stream','pending',$3,$3)"#,
                )
                .bind(Uuid::new_v4())
                .bind(event_position)
                .bind(at)
                .execute(&mut *transaction)
                .await
                .expect("insert later Commit Welcome outbox");
                transaction
                    .commit()
                    .await
                    .expect("later Commit supersession crosses every deferred constraint");
            }

            async fn commit_signed_welcome_disposition(
                pool: &PgPool,
                entry: &RealCreationEntry,
                fulfillment: &RealLeafRecoveryFulfillmentEntry,
                kind: SignedMutationKind,
                response: &SignedWelcomeResponse,
            ) {
                let winner = match kind {
                    SignedMutationKind::WelcomeAcknowledgement => "acknowledged",
                    SignedMutationKind::WelcomeRejection => "rejected",
                    _ => unreachable!(),
                };
                let at = instant(WELCOME_TERMINAL_AT);
                let cid = Uuid::from_bytes(entry.cid);
                sqlx::query(
                    r#"INSERT INTO chat.protocol_instances(
                        singleton,protocol_instance_id,cursor_key_id,created_at
                    ) VALUES(TRUE,$1,$2,$3)
                    ON CONFLICT (singleton) DO NOTHING"#,
                )
                .bind(Uuid::new_v4())
                .bind(&entry.actor_key_id)
                .bind(at)
                .execute(pool)
                .await
                .expect("ensure singleton protocol instance");
                let protocol_instance_id: Uuid =
                    sqlx::query_scalar("SELECT protocol_instance_id FROM chat.protocol_instances")
                        .fetch_one(pool)
                        .await
                        .expect("singleton protocol instance");
                let payload = vec![0x81_u8; 8];

                let mut tx = pool.begin().await.expect("begin Welcome disposition");
                sqlx::query(
                    "UPDATE chat.welcome_deliveries SET status=$2,terminal_at=$3 \
                     WHERE welcome_id=$1 AND status='pending'",
                )
                .bind(fulfillment.welcome_id)
                .bind(winner)
                .bind(at)
                .execute(&mut *tx)
                .await
                .expect("terminalize pending Welcome");
                let event_position: i64 = sqlx::query_scalar(
                    r#"INSERT INTO chat.events(
                        event_id,event_kind,payload_bytes,payload_sha256,created_at,
                        protocol_instance_id
                    ) VALUES($1,'welcomeDisposition',$2,$3,$4,$5)
                    RETURNING event_position"#,
                )
                .bind(Uuid::new_v4())
                .bind(&payload)
                .bind(Sha256::digest(&payload).to_vec())
                .bind(at)
                .bind(protocol_instance_id)
                .fetch_one(&mut *tx)
                .await
                .expect("insert disposition event");
                let audience_predecessor_position: Option<i64> = sqlx::query_scalar(
                    r#"SELECT MAX(event_position)
                       FROM chat.event_recipients
                       WHERE user_did=$1 AND device_id=$2"#,
                )
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .fetch_one(&mut *tx)
                .await
                .expect("read current event-recipient predecessor");
                sqlx::query(
                    r#"INSERT INTO chat.event_recipients(
                        event_position,user_did,device_id,entitlement_kind,
                        audience_predecessor_position
                    ) VALUES($1,$2,$3,'welcome',$4)"#,
                )
                .bind(event_position)
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(audience_predecessor_position)
                .execute(&mut *tx)
                .await
                .expect("insert disposition event recipient");
                sqlx::query(
                    r#"INSERT INTO chat.outbox(
                        outbox_id,event_position,work_kind,status,next_attempt_at,created_at
                    ) VALUES($1,$2,'stream','pending',$3,$3)"#,
                )
                .bind(Uuid::new_v4())
                .bind(event_position)
                .bind(at)
                .execute(&mut *tx)
                .await
                .expect("insert disposition outbox");
                sqlx::query(
                    r#"INSERT INTO chat.welcome_dispositions(
                        welcome_id,winner_kind,signed_request_bytes,signing_transcript_bytes,
                        request_digest,signature,rejection_reason,terminal_at,event_position,
                        terminal_transition_id,terminal_revocation_id
                    ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,NULL)"#,
                )
                .bind(fulfillment.welcome_id)
                .bind(winner)
                .bind(&response.raw_wrapper)
                .bind(&response.signing_transcript)
                .bind(&response.request_digest)
                .bind(&response.signature)
                .bind((winner == "rejected").then_some("invalidWelcome"))
                .bind(at)
                .bind(event_position)
                .execute(&mut *tx)
                .await
                .expect("insert signed Welcome disposition");
                if winner == "rejected" {
                    sqlx::query(
                        r#"INSERT INTO chat.recovery_work_items(
                            recovery_work_id,conversation_id,recipient_did,recipient_device_id,
                            source_kind,source_id,generation,state_version,status,created_at
                        ) VALUES($1,$2,$3,$4,'welcomeRejected',$5,0,1,'pending',$6)"#,
                    )
                    .bind(Uuid::new_v4())
                    .bind(cid)
                    .bind(&entry.actor_did)
                    .bind(entry.actor_device_id)
                    .bind(fulfillment.welcome_id)
                    .bind(at)
                    .execute(&mut *tx)
                    .await
                    .expect("insert rejected-Welcome recovery work");
                }
                tx.commit()
                    .await
                    .expect("signed Welcome disposition crosses deferred mappings");
            }

            async fn commit_expired_welcome_disposition(
                pool: &PgPool,
                entry: &RealCreationEntry,
                fulfillment: &RealLeafRecoveryFulfillmentEntry,
            ) {
                let at = instant(KP_NOT_AFTER);
                let cid = Uuid::from_bytes(entry.cid);
                sqlx::query(
                    r#"INSERT INTO chat.protocol_instances(
                        singleton,protocol_instance_id,cursor_key_id,created_at
                    ) VALUES(TRUE,$1,$2,$3)
                    ON CONFLICT (singleton) DO NOTHING"#,
                )
                .bind(Uuid::new_v4())
                .bind(&entry.actor_key_id)
                .bind(at)
                .execute(pool)
                .await
                .expect("ensure singleton protocol instance");
                let protocol_instance_id: Uuid =
                    sqlx::query_scalar("SELECT protocol_instance_id FROM chat.protocol_instances")
                        .fetch_one(pool)
                        .await
                        .expect("singleton protocol instance");
                let payload = vec![0x82_u8; 8];
                let mut tx = pool.begin().await.expect("begin Welcome expiry");
                sqlx::query(
                    "UPDATE chat.welcome_deliveries SET status='expired',terminal_at=$2 \
                     WHERE welcome_id=$1 AND status='pending'",
                )
                .bind(fulfillment.welcome_id)
                .bind(at)
                .execute(&mut *tx)
                .await
                .expect("expire pending Welcome");
                let event_position: i64 = sqlx::query_scalar(
                    r#"INSERT INTO chat.events(
                        event_id,event_kind,payload_bytes,payload_sha256,created_at,
                        protocol_instance_id
                    ) VALUES($1,'welcomeDisposition',$2,$3,$4,$5)
                    RETURNING event_position"#,
                )
                .bind(Uuid::new_v4())
                .bind(&payload)
                .bind(Sha256::digest(&payload).to_vec())
                .bind(at)
                .bind(protocol_instance_id)
                .fetch_one(&mut *tx)
                .await
                .expect("insert expiry event");
                let predecessor: Option<i64> = sqlx::query_scalar(
                    r#"SELECT MAX(event_position) FROM chat.event_recipients
                       WHERE user_did=$1 AND device_id=$2"#,
                )
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .fetch_one(&mut *tx)
                .await
                .expect("read expiry audience predecessor");
                sqlx::query(
                    r#"INSERT INTO chat.event_recipients(
                        event_position,user_did,device_id,entitlement_kind,
                        audience_predecessor_position
                    ) VALUES($1,$2,$3,'welcome',$4)"#,
                )
                .bind(event_position)
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(predecessor)
                .execute(&mut *tx)
                .await
                .expect("insert expiry recipient");
                sqlx::query(
                    r#"INSERT INTO chat.outbox(
                        outbox_id,event_position,work_kind,status,next_attempt_at,created_at
                    ) VALUES($1,$2,'stream','pending',$3,$3)"#,
                )
                .bind(Uuid::new_v4())
                .bind(event_position)
                .bind(at)
                .execute(&mut *tx)
                .await
                .expect("insert expiry outbox");
                sqlx::query(
                    r#"INSERT INTO chat.welcome_dispositions(
                        welcome_id,winner_kind,signed_request_bytes,signing_transcript_bytes,
                        request_digest,signature,rejection_reason,terminal_at,event_position,
                        terminal_transition_id,terminal_revocation_id
                    ) VALUES($1,'expired',NULL,NULL,NULL,NULL,NULL,$2,$3,NULL,NULL)"#,
                )
                .bind(fulfillment.welcome_id)
                .bind(at)
                .bind(event_position)
                .execute(&mut *tx)
                .await
                .expect("insert expiry disposition");
                sqlx::query(
                    r#"INSERT INTO chat.recovery_work_items(
                        recovery_work_id,conversation_id,recipient_did,recipient_device_id,
                        source_kind,source_id,generation,state_version,status,created_at
                    ) VALUES($1,$2,$3,$4,'welcomeExpired',$5,0,1,'pending',$6)"#,
                )
                .bind(Uuid::new_v4())
                .bind(cid)
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(fulfillment.welcome_id)
                .bind(at)
                .execute(&mut *tx)
                .await
                .expect("insert expired-Welcome recovery work");
                tx.commit()
                    .await
                    .expect("expired Welcome crosses deferred mappings");
            }

            async fn commit_aggregate_welcome_fixture(
                pool: &PgPool,
                arm: AggregateWelcomeArm,
            ) -> RealCreationEntry {
                let cid = Uuid::new_v4();
                let entry = build_real_creation_entry(*cid.as_bytes());
                let seed = seed_recovery_pair(pool, &entry, "requestLeafRecovery").await;
                let fulfillment = build_real_leaf_recovery_fulfillment_entry(&entry, &seed);
                commit_recovery_fulfillment_graph(pool, &entry, &seed, &fulfillment).await;
                match arm {
                    AggregateWelcomeArm::Pending => {}
                    AggregateWelcomeArm::Acknowledged => {
                        let response = build_signed_welcome_response(
                            &entry,
                            &fulfillment,
                            SignedMutationKind::WelcomeAcknowledgement,
                        );
                        commit_signed_welcome_disposition(
                            pool,
                            &entry,
                            &fulfillment,
                            SignedMutationKind::WelcomeAcknowledgement,
                            &response,
                        )
                        .await;
                    }
                    AggregateWelcomeArm::Rejected => {
                        let response = build_signed_welcome_response(
                            &entry,
                            &fulfillment,
                            SignedMutationKind::WelcomeRejection,
                        );
                        commit_signed_welcome_disposition(
                            pool,
                            &entry,
                            &fulfillment,
                            SignedMutationKind::WelcomeRejection,
                            &response,
                        )
                        .await;
                    }
                    AggregateWelcomeArm::Expired => {
                        commit_expired_welcome_disposition(pool, &entry, &fulfillment).await;
                    }
                    AggregateWelcomeArm::TransitionSuperseded => {
                        let later = build_real_later_commit(&entry, &seed);
                        commit_later_transition_supersession(
                            pool,
                            &entry,
                            &seed,
                            &fulfillment,
                            &later,
                        )
                        .await;
                    }
                    AggregateWelcomeArm::RevocationSuperseded => {
                        let actor = seed_welcome_revocation_actor(pool, &entry).await;
                        let revocation = build_signed_welcome_revocation(&entry, &actor);
                        commit_welcome_revocation_supersession(
                            pool,
                            &entry,
                            &fulfillment,
                            &actor,
                            &revocation,
                        )
                        .await;
                    }
                }
                entry
            }

            async fn load_aggregate_hydration_rows(
                pool: &PgPool,
                entry: &RealCreationEntry,
            ) -> ConversationStateHydration {
                let cid = Uuid::from_bytes(entry.cid);
                let next_entry_seq: i64 = sqlx::query_scalar(
                    "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
                )
                .bind(cid)
                .fetch_one(pool)
                .await
                .expect("read aggregate head");
                let historical = HistoricalRehydrationAuthority::new(
                    entry.cid,
                    u64::try_from(next_entry_seq).expect("head is in protocol domain"),
                )
                .expect("historical aggregate authority");

                let mut tx = pool.begin().await.expect("begin aggregate load");
                let guard = hydrate_locked_public_state(&mut tx, cid, instant(WELCOME_TERMINAL_AT))
                    .await
                    .expect("locked public-state rows hydrate");
                let (
                    _transaction_id,
                    _conversation_id,
                    coordinate,
                    snapshot,
                    binding,
                    _encoded_tree_summary,
                    _tree_summary_sha256,
                    _locked_at,
                    _generation_digest,
                ) = guard.into_parts();
                assert_eq!(
                    &coordinate,
                    binding.coordinate(),
                    "locked coordinate and binding are one row"
                );
                let leaves = load_leaf_hydration_rows(&mut tx, cid, &binding)
                    .await
                    .expect("aggregate leaf rows hydrate");
                let public_state =
                    ActivePublicState::for_test_from_persisted_binding(snapshot, binding)
                        .expect("persisted snapshot/binding pair remains digest-bound");
                let producer = load_producer_transition_evidence(&mut tx, &historical, cid)
                    .await
                    .expect("aggregate producer hydrates");
                let (metadata, metadata_producer) =
                    load_metadata_provenance(&mut tx, &historical, cid)
                        .await
                        .expect("aggregate metadata hydrates");
                let participants = load_participant_hydration_rows(&mut tx, &historical, cid)
                    .await
                    .expect("aggregate participants hydrate");
                let intervals = load_interval_hydration_rows(&mut tx, &historical, cid)
                    .await
                    .expect("aggregate intervals hydrate");
                let (recovery_requests, recovery_reservations) =
                    load_recovery_work_hydration_rows(&mut tx, &historical, cid)
                        .await
                        .expect("aggregate recovery work hydrates");
                let reset_requests = load_reset_request_hydration_rows(&mut tx, &historical, cid)
                    .await
                    .expect("aggregate reset work hydrates");
                let leave_requests = load_leave_request_hydration_rows(&mut tx, &historical, cid)
                    .await
                    .expect("aggregate leave work hydrates");
                let welcomes = load_welcome_hydration_rows(&mut tx, &historical, cid)
                    .await
                    .expect("aggregate Welcome work hydrates");
                tx.rollback().await.expect("rollback aggregate read");

                ConversationStateHydration {
                    kind: ConversationKind::Group,
                    coordinate,
                    producer,
                    public_state: Some(public_state),
                    metadata,
                    metadata_producer,
                    participants,
                    leaves,
                    intervals,
                    terminal_proofs: Vec::new(),
                    recovery_requests,
                    recovery_reservations,
                    reset_requests,
                    leave_requests,
                    welcomes,
                }
            }

            #[test]
            fn welcome_terminal_selector_requires_exact_status_and_direct_cause() {
                let terminal_at = instant("2030-01-01T00:10:00.000Z");
                let other_at = instant("2030-01-01T00:10:01.000Z");
                let expires_at = instant(KP_NOT_AFTER);
                let transition_id = Uuid::new_v4();
                let revocation_id = Uuid::new_v4();
                let signed = [0x31_u8; 8];
                let transcript = [0x32_u8; 8];
                let digest = [0x33_u8; 32];
                let signature = [0x34_u8; 64];

                let pending = WelcomeTerminalColumns {
                    status: "pending",
                    expires_at,
                    delivery_terminal_at: None,
                    disposition_present: false,
                    disposition_matches_welcome: false,
                    winner_kind: None,
                    signed_request_bytes: None,
                    signing_transcript_bytes: None,
                    request_digest: None,
                    signature: None,
                    rejection_reason: None,
                    disposition_terminal_at: None,
                    event_position: None,
                    terminal_transition_id: None,
                    terminal_revocation_id: None,
                };
                assert_eq!(
                    select_welcome_terminal(pending).unwrap(),
                    WelcomeTerminalSelection::Pending
                );

                let acknowledged = WelcomeTerminalColumns {
                    status: "acknowledged",
                    delivery_terminal_at: Some(terminal_at),
                    disposition_present: true,
                    disposition_matches_welcome: true,
                    winner_kind: Some("acknowledged"),
                    signed_request_bytes: Some(&signed),
                    signing_transcript_bytes: Some(&transcript),
                    request_digest: Some(&digest),
                    signature: Some(&signature),
                    disposition_terminal_at: Some(terminal_at),
                    event_position: Some(1),
                    ..pending
                };
                assert_eq!(
                    select_welcome_terminal(acknowledged).unwrap(),
                    WelcomeTerminalSelection::Acknowledged { terminal_at }
                );
                let rejected = WelcomeTerminalColumns {
                    status: "rejected",
                    winner_kind: Some("rejected"),
                    rejection_reason: Some("invalidWelcome"),
                    ..acknowledged
                };
                assert_eq!(
                    select_welcome_terminal(rejected).unwrap(),
                    WelcomeTerminalSelection::Rejected { terminal_at }
                );
                let expired = WelcomeTerminalColumns {
                    status: "expired",
                    delivery_terminal_at: Some(expires_at),
                    disposition_present: true,
                    disposition_matches_welcome: true,
                    winner_kind: Some("expired"),
                    disposition_terminal_at: Some(expires_at),
                    event_position: Some(1),
                    ..pending
                };
                assert_eq!(
                    select_welcome_terminal(expired).unwrap(),
                    WelcomeTerminalSelection::Expired {
                        terminal_at: expires_at
                    }
                );
                let superseded_transition = WelcomeTerminalColumns {
                    status: "superseded",
                    delivery_terminal_at: Some(terminal_at),
                    disposition_present: true,
                    disposition_matches_welcome: true,
                    winner_kind: Some("superseded"),
                    disposition_terminal_at: Some(terminal_at),
                    event_position: Some(1),
                    terminal_transition_id: Some(transition_id),
                    ..pending
                };
                assert_eq!(
                    select_welcome_terminal(superseded_transition).unwrap(),
                    WelcomeTerminalSelection::Transition {
                        transition_id,
                        terminal_at,
                    }
                );
                let superseded_revocation = WelcomeTerminalColumns {
                    terminal_transition_id: None,
                    terminal_revocation_id: Some(revocation_id),
                    ..superseded_transition
                };
                assert_eq!(
                    select_welcome_terminal(superseded_revocation).unwrap(),
                    WelcomeTerminalSelection::DeviceRevocation {
                        revocation_id,
                        terminal_at,
                    }
                );

                let malformed = [
                    WelcomeTerminalColumns {
                        disposition_present: true,
                        ..pending
                    },
                    WelcomeTerminalColumns {
                        signed_request_bytes: None,
                        ..acknowledged
                    },
                    WelcomeTerminalColumns {
                        winner_kind: Some("rejected"),
                        ..acknowledged
                    },
                    WelcomeTerminalColumns {
                        rejection_reason: Some("invalidWelcome"),
                        ..acknowledged
                    },
                    WelcomeTerminalColumns {
                        rejection_reason: None,
                        ..rejected
                    },
                    WelcomeTerminalColumns {
                        delivery_terminal_at: Some(other_at),
                        ..acknowledged
                    },
                    WelcomeTerminalColumns {
                        terminal_transition_id: Some(transition_id),
                        ..acknowledged
                    },
                    WelcomeTerminalColumns {
                        signed_request_bytes: Some(&signed),
                        ..expired
                    },
                    WelcomeTerminalColumns {
                        delivery_terminal_at: Some(terminal_at),
                        ..expired
                    },
                    WelcomeTerminalColumns {
                        terminal_transition_id: None,
                        ..superseded_transition
                    },
                    WelcomeTerminalColumns {
                        terminal_revocation_id: Some(revocation_id),
                        ..superseded_transition
                    },
                    WelcomeTerminalColumns {
                        disposition_terminal_at: Some(other_at),
                        ..superseded_transition
                    },
                    WelcomeTerminalColumns {
                        status: "acknowledged",
                        ..superseded_transition
                    },
                ];
                for columns in malformed {
                    assert!(matches!(
                        select_welcome_terminal(columns),
                        Err(crate::chat_protocol::repository::core::WelcomeHydrationError::TerminalMismatch)
                    ));
                }
            }

            /// Removing the Welcome query, omitting pending rows, or projecting
            /// bundle/delivery columns from the wrong source makes this live
            /// loader test fail. Every expected value is hand-derived from the
            /// committed fixture rather than from the loader under test.
            #[tokio::test]
            #[ignore = "requires the dedicated gate database"]
            async fn empty_and_pending_welcome_rows_hydrate_exact_bundle() {
                let pool = common::chat_protocol::setup_chat_protocol_db(2).await;

                let empty_cid = Uuid::new_v4();
                let empty_entry = build_real_creation_entry(*empty_cid.as_bytes());
                seed_real_creation_graph(&pool, &empty_entry).await;
                let empty_authority = HistoricalRehydrationAuthority::new(empty_entry.cid, 2)
                    .expect("empty conversation authority");
                let mut empty_tx = pool.begin().await.expect("begin empty load");
                let empty = load_welcome_hydration_rows(&mut empty_tx, &empty_authority, empty_cid)
                    .await
                    .expect("conversation without Welcomes hydrates empty");
                empty_tx.rollback().await.expect("rollback empty load");
                assert!(empty.is_empty());

                let cid = Uuid::new_v4();
                let entry = build_real_creation_entry(*cid.as_bytes());
                let seed = seed_recovery_pair(&pool, &entry, "requestLeafRecovery").await;
                let fulfillment = build_real_leaf_recovery_fulfillment_entry(&entry, &seed);
                commit_recovery_fulfillment_graph(&pool, &entry, &seed, &fulfillment).await;
                let authority =
                    HistoricalRehydrationAuthority::new(entry.cid, 3).expect("fulfilled authority");

                let mut tx = pool.begin().await.expect("begin pending load");
                let rows = load_welcome_hydration_rows(&mut tx, &authority, cid)
                    .await
                    .expect("pending Welcome hydrates");
                tx.rollback().await.expect("rollback pending load");

                assert_eq!(rows.len(), 1);
                let row = &rows[0];
                assert_eq!(row.welcome_id, *fulfillment.welcome_id.as_bytes());
                assert_eq!(
                    row.recipient,
                    DeviceIdentity::new(
                        PrincipalId::new(entry.actor_did.clone().into_bytes()).unwrap(),
                        *entry.actor_device_id.as_bytes(),
                    )
                    .unwrap()
                );
                assert_eq!(row.transition_seq, 2);
                assert_eq!(
                    row.coordinate,
                    PublicGroupSnapshotCoordinate::new(
                        entry.cid,
                        0,
                        1,
                        [1; 32],
                        1,
                        [4; 32],
                        [5; 32],
                        PublicGroupSnapshotLifecycle::Active,
                    )
                );
                assert_eq!(row.recovery_request_id, seed.request_id);
                assert_eq!(row.key_package_ref, seed.key_package_ref);
                assert_eq!(row.opaque_welcome, fulfillment.opaque_welcome);
                assert_eq!(
                    row.sha256,
                    <[u8; 32]>::from(Sha256::digest(&fulfillment.opaque_welcome))
                );
                assert_eq!(
                    row.expires_at,
                    ServerTimestamp::from_canonical_stored(KP_NOT_AFTER).unwrap()
                );
                assert_eq!(row.status, WelcomeStatus::Pending);
                assert!(row.terminal.is_none());
            }

            #[tokio::test]
            #[ignore = "requires the dedicated gate database"]
            async fn signed_acknowledgement_and_rejection_hydrate_request_terminals() {
                let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
                for (kind, expected_status) in [
                    (
                        SignedMutationKind::WelcomeAcknowledgement,
                        WelcomeStatus::Acknowledged,
                    ),
                    (
                        SignedMutationKind::WelcomeRejection,
                        WelcomeStatus::Rejected,
                    ),
                ] {
                    let cid = Uuid::new_v4();
                    let entry = build_real_creation_entry(*cid.as_bytes());
                    let seed = seed_recovery_pair(&pool, &entry, "requestLeafRecovery").await;
                    let fulfillment = build_real_leaf_recovery_fulfillment_entry(&entry, &seed);
                    commit_recovery_fulfillment_graph(&pool, &entry, &seed, &fulfillment).await;
                    let response = build_signed_welcome_response(&entry, &fulfillment, kind);
                    commit_signed_welcome_disposition(&pool, &entry, &fulfillment, kind, &response)
                        .await;

                    let authority =
                        HistoricalRehydrationAuthority::new(entry.cid, 3).expect("authority");
                    let mut tx = pool.begin().await.expect("begin terminal load");
                    let rows = load_welcome_hydration_rows(&mut tx, &authority, cid)
                        .await
                        .expect("signed Welcome terminal hydrates");
                    tx.rollback().await.expect("rollback terminal load");

                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0].status, expected_status);
                    let Some(WorkTerminalHydrationRow::Request(evidence)) =
                        rows[0].terminal.as_ref()
                    else {
                        panic!("signed Welcome terminal must be Request evidence");
                    };
                    let expected_kind = match kind {
                        SignedMutationKind::WelcomeAcknowledgement => {
                            crate::chat_protocol::state_machine::RequestEntryKind::WelcomeAcknowledgement
                        }
                        SignedMutationKind::WelcomeRejection => {
                            crate::chat_protocol::state_machine::RequestEntryKind::WelcomeRejection
                        }
                        _ => unreachable!(),
                    };
                    assert_eq!(evidence.kind(), expected_kind);
                    assert_eq!(evidence.conversation_id(), &entry.cid);
                    assert_eq!(evidence.request_id(), fulfillment.welcome_id.as_bytes());
                    assert_eq!(
                        evidence.actor(),
                        &DeviceIdentity::new(
                            PrincipalId::new(entry.actor_did.clone().into_bytes()).unwrap(),
                            *entry.actor_device_id.as_bytes(),
                        )
                        .unwrap()
                    );
                    assert_eq!(
                        evidence.received_at(),
                        ServerTimestamp::from_canonical_stored(WELCOME_TERMINAL_AT).unwrap()
                    );
                }
            }

            #[tokio::test]
            #[ignore = "requires the dedicated gate database"]
            async fn signed_welcome_terminal_rejects_wrong_kind_and_signature_tamper() {
                let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
                for tamper_signature in [false, true] {
                    let cid = Uuid::new_v4();
                    let entry = build_real_creation_entry(*cid.as_bytes());
                    let seed = seed_recovery_pair(&pool, &entry, "requestLeafRecovery").await;
                    let fulfillment = build_real_leaf_recovery_fulfillment_entry(&entry, &seed);
                    commit_recovery_fulfillment_graph(&pool, &entry, &seed, &fulfillment).await;
                    let signed_kind = if tamper_signature {
                        SignedMutationKind::WelcomeAcknowledgement
                    } else {
                        SignedMutationKind::WelcomeRejection
                    };
                    let response = build_signed_welcome_response(&entry, &fulfillment, signed_kind);
                    let mut stored_signature = response.signature.clone();
                    if tamper_signature {
                        stored_signature[0] ^= 0x01;
                    }

                    let authority =
                        HistoricalRehydrationAuthority::new(entry.cid, 3).expect("authority");
                    let mut tx = pool.begin().await.expect("begin malformed response");
                    insert_uncommitted_signed_disposition(
                        &mut tx,
                        &entry,
                        &fulfillment,
                        "acknowledged",
                        &response,
                        &stored_signature,
                        None,
                    )
                    .await;
                    let result = load_welcome_hydration_rows(&mut tx, &authority, cid).await;
                    tx.rollback().await.expect("rollback malformed response");
                    assert!(
                        matches!(
                            result,
                            Err(crate::chat_protocol::repository::core::WelcomeHydrationError::InvalidTerminal)
                        ),
                        "wrong signed kind or durable signature tamper must fail closed"
                    );
                }
            }

            #[tokio::test]
            #[ignore = "requires the dedicated gate database"]
            async fn signed_rejection_reason_must_equal_the_durable_reason() {
                let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
                let cid = Uuid::new_v4();
                let entry = build_real_creation_entry(*cid.as_bytes());
                let seed = seed_recovery_pair(&pool, &entry, "requestLeafRecovery").await;
                let fulfillment = build_real_leaf_recovery_fulfillment_entry(&entry, &seed);
                commit_recovery_fulfillment_graph(&pool, &entry, &seed, &fulfillment).await;
                let response = build_signed_welcome_response(
                    &entry,
                    &fulfillment,
                    SignedMutationKind::WelcomeRejection,
                );
                let authority =
                    HistoricalRehydrationAuthority::new(entry.cid, 3).expect("authority");
                let mut tx = pool.begin().await.expect("begin reason mismatch");
                insert_uncommitted_signed_disposition(
                    &mut tx,
                    &entry,
                    &fulfillment,
                    "rejected",
                    &response,
                    &response.signature,
                    Some("noMatchingKeyPackage"),
                )
                .await;
                let result = load_welcome_hydration_rows(&mut tx, &authority, cid).await;
                tx.rollback().await.expect("rollback reason mismatch");

                assert!(
                    matches!(
                        result,
                        Err(crate::chat_protocol::repository::core::WelcomeHydrationError::InvalidTerminal)
                    ),
                    "a validly signed body reason must not be relabelled by the durable reason"
                );
            }

            #[tokio::test]
            #[ignore = "requires the dedicated gate database"]
            async fn expired_welcome_hydrates_exact_expiry_terminal() {
                let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
                let cid = Uuid::new_v4();
                let entry = build_real_creation_entry(*cid.as_bytes());
                let seed = seed_recovery_pair(&pool, &entry, "requestLeafRecovery").await;
                let fulfillment = build_real_leaf_recovery_fulfillment_entry(&entry, &seed);
                commit_recovery_fulfillment_graph(&pool, &entry, &seed, &fulfillment).await;
                commit_expired_welcome_disposition(&pool, &entry, &fulfillment).await;

                let authority =
                    HistoricalRehydrationAuthority::new(entry.cid, 3).expect("authority");
                let mut tx = pool.begin().await.expect("begin expiry load");
                let rows = load_welcome_hydration_rows(&mut tx, &authority, cid)
                    .await
                    .expect("expired Welcome terminal hydrates");
                tx.rollback().await.expect("rollback expiry load");

                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].status, WelcomeStatus::Expired);
                let Some(WorkTerminalHydrationRow::Expiry(terminal_at)) = rows[0].terminal.as_ref()
                else {
                    panic!("expired Welcome terminal must be Expiry evidence");
                };
                assert_eq!(
                    terminal_at,
                    &ServerTimestamp::from_canonical_stored(KP_NOT_AFTER).unwrap()
                );
            }

            #[tokio::test]
            #[ignore = "requires the dedicated gate database"]
            async fn transition_supersession_uses_only_the_direct_transition_cause() {
                let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
                let cid = Uuid::new_v4();
                let entry = build_real_creation_entry(*cid.as_bytes());
                let seed = seed_recovery_pair(&pool, &entry, "requestLeafRecovery").await;
                let fulfillment = build_real_leaf_recovery_fulfillment_entry(&entry, &seed);
                commit_recovery_fulfillment_graph(&pool, &entry, &seed, &fulfillment).await;
                let later = build_real_later_commit(&entry, &seed);
                commit_later_transition_supersession(&pool, &entry, &seed, &fulfillment, &later)
                    .await;

                let authority =
                    HistoricalRehydrationAuthority::new(entry.cid, 4).expect("authority");
                let mut tx = pool
                    .begin()
                    .await
                    .expect("fresh transition supersession load");
                let rows = load_welcome_hydration_rows(&mut tx, &authority, cid)
                    .await
                    .expect("transition-superseded Welcome hydrates");
                tx.rollback().await.expect("rollback read transaction");

                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].status, WelcomeStatus::Superseded);
                let Some(WorkTerminalHydrationRow::Transition(evidence)) =
                    rows[0].terminal.as_ref()
                else {
                    panic!("transition supersession must hydrate Transition evidence");
                };
                assert_eq!(evidence.transition_id(), later.transition_id.as_bytes());
                assert!(evidence.seq() > rows[0].transition_seq);
                assert_eq!(
                    evidence.received_at(),
                    ServerTimestamp::from_canonical_stored(LATER_TRANSITION_AT).unwrap()
                );
            }

            #[tokio::test]
            #[ignore = "requires the dedicated gate database"]
            async fn revocation_supersession_uses_only_the_direct_revocation_cause() {
                let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
                let cid = Uuid::new_v4();
                let entry = build_real_creation_entry(*cid.as_bytes());
                let seed = seed_recovery_pair(&pool, &entry, "requestLeafRecovery").await;
                let fulfillment = build_real_leaf_recovery_fulfillment_entry(&entry, &seed);
                commit_recovery_fulfillment_graph(&pool, &entry, &seed, &fulfillment).await;
                let actor = seed_welcome_revocation_actor(&pool, &entry).await;
                let revocation = build_signed_welcome_revocation(&entry, &actor);
                commit_welcome_revocation_supersession(
                    &pool,
                    &entry,
                    &fulfillment,
                    &actor,
                    &revocation,
                )
                .await;

                let authority =
                    HistoricalRehydrationAuthority::new(entry.cid, 3).expect("authority");
                let mut tx = pool
                    .begin()
                    .await
                    .expect("fresh revocation supersession load");
                let rows = load_welcome_hydration_rows(&mut tx, &authority, cid)
                    .await
                    .expect("revocation-superseded Welcome hydrates");
                tx.rollback().await.expect("rollback read transaction");

                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].status, WelcomeStatus::Superseded);
                let Some(WorkTerminalHydrationRow::DeviceRevocation(evidence)) =
                    rows[0].terminal.as_ref()
                else {
                    panic!("revocation supersession must hydrate DeviceRevocation evidence");
                };
                assert_eq!(
                    evidence.revocation_id(),
                    revocation.revocation_id.as_bytes()
                );
                assert_eq!(
                    evidence.target(),
                    &DeviceIdentity::new(
                        PrincipalId::new(entry.actor_did.clone().into_bytes()).unwrap(),
                        *entry.actor_device_id.as_bytes(),
                    )
                    .unwrap()
                );
                assert_eq!(
                    evidence.accepted_at(),
                    ServerTimestamp::from_canonical_stored(WELCOME_TERMINAL_AT).unwrap()
                );
            }

            #[tokio::test]
            #[ignore = "requires the dedicated gate database"]
            async fn aggregate_hydration_validates_every_welcome_arm_and_rejects_spliced_work() {
                let pool = common::chat_protocol::setup_chat_protocol_db(4).await;

                for arm in [
                    AggregateWelcomeArm::Pending,
                    AggregateWelcomeArm::Acknowledged,
                    AggregateWelcomeArm::Rejected,
                    AggregateWelcomeArm::Expired,
                    AggregateWelcomeArm::TransitionSuperseded,
                    AggregateWelcomeArm::RevocationSuperseded,
                ] {
                    let entry = commit_aggregate_welcome_fixture(&pool, arm).await;
                    let rows = load_aggregate_hydration_rows(&pool, &entry).await;
                    let authority =
                        crate::chat_protocol::state_machine::HydrationAuthority::new(entry.cid)
                            .expect("aggregate authority");
                    crate::chat_protocol::state_machine::hydrate_conversation_state(
                        &authority, rows,
                    )
                    .unwrap_or_else(|error| panic!("{arm:?} aggregate must hydrate: {error:?}"));
                }

                let base_entry =
                    commit_aggregate_welcome_fixture(&pool, AggregateWelcomeArm::Pending).await;
                let base = load_aggregate_hydration_rows(&pool, &base_entry).await;

                let foreign_transition_entry = commit_aggregate_welcome_fixture(
                    &pool,
                    AggregateWelcomeArm::TransitionSuperseded,
                )
                .await;
                let foreign_transition =
                    load_aggregate_hydration_rows(&pool, &foreign_transition_entry).await;
                let mut non_consuming = base.clone();
                non_consuming.welcomes[0].status = WelcomeStatus::Superseded;
                non_consuming.welcomes[0].terminal = Some(WorkTerminalHydrationRow::Transition(
                    foreign_transition.producer,
                ));
                let authority =
                    crate::chat_protocol::state_machine::HydrationAuthority::new(base_entry.cid)
                        .expect("base aggregate authority");
                assert!(matches!(
                    crate::chat_protocol::state_machine::hydrate_conversation_state(
                        &authority,
                        non_consuming,
                    ),
                    Err(crate::chat_protocol::state_machine::StateMachineError::InvariantViolation)
                ));

                let foreign_revocation_entry = commit_aggregate_welcome_fixture(
                    &pool,
                    AggregateWelcomeArm::RevocationSuperseded,
                )
                .await;
                let foreign_revocation =
                    load_aggregate_hydration_rows(&pool, &foreign_revocation_entry).await;
                let mut wrong_target = base.clone();
                wrong_target.welcomes[0].status = WelcomeStatus::Superseded;
                wrong_target.welcomes[0].terminal = foreign_revocation.welcomes[0].terminal.clone();
                assert!(matches!(
                    crate::chat_protocol::state_machine::hydrate_conversation_state(
                        &authority,
                        wrong_target,
                    ),
                    Err(crate::chat_protocol::state_machine::StateMachineError::InvariantViolation)
                ));

                let mut incomplete_recovery = base;
                incomplete_recovery.recovery_reservations.clear();
                assert!(matches!(
                    crate::chat_protocol::state_machine::hydrate_conversation_state(
                        &authority,
                        incomplete_recovery,
                    ),
                    Err(crate::chat_protocol::state_machine::StateMachineError::InvariantViolation)
                ));
            }
        }

        /// The fulfilled/consumed status arms select only one exact transition
        /// terminal across request, reservation, package, and durable transition.
        /// These malformed combinations are structurally prohibited from
        /// committing by CHECK/FK/mapping/immutability constraints, so the shared
        /// pure selector is their read-side drift fence.
        #[test]
        fn recovery_fulfillment_terminal_columns_select_only_the_exact_arm() {
            let transition_id = Uuid::new_v4();
            let other_transition_id = Uuid::new_v4();
            let terminal_at = instant(FULFILLED_AT);
            let other_at = instant("2030-01-01T00:01:01.000Z");
            let exact = FulfilledRecoveryTerminalColumns {
                request_fulfilling_transition_id: Some(transition_id),
                request_has_unrelated_terminal: false,
                request_terminal_at: Some(terminal_at),
                request_reservation_binding_matches: true,
                reservation_status: "consumed",
                reservation_consumed_transition_id: Some(transition_id),
                reservation_has_unrelated_terminal: false,
                reservation_terminal_at: Some(terminal_at),
                package_status: "consumed",
                package_terminal_transition_id: Some(transition_id),
                package_terminal_revocation_id: None,
                package_terminal_at: Some(terminal_at),
                durable_transition_kind: Some("leafRecovery"),
                durable_transition_accepted_at: Some(terminal_at),
            };
            assert_eq!(
                select_fulfilled_recovery_terminal(exact).unwrap(),
                (transition_id, terminal_at)
            );

            let malformed = [
                FulfilledRecoveryTerminalColumns {
                    request_fulfilling_transition_id: None,
                    ..exact
                },
                FulfilledRecoveryTerminalColumns {
                    request_has_unrelated_terminal: true,
                    ..exact
                },
                FulfilledRecoveryTerminalColumns {
                    request_reservation_binding_matches: false,
                    ..exact
                },
                FulfilledRecoveryTerminalColumns {
                    reservation_consumed_transition_id: Some(other_transition_id),
                    ..exact
                },
                FulfilledRecoveryTerminalColumns {
                    reservation_has_unrelated_terminal: true,
                    ..exact
                },
                FulfilledRecoveryTerminalColumns {
                    reservation_terminal_at: Some(other_at),
                    ..exact
                },
                FulfilledRecoveryTerminalColumns {
                    package_status: "reserved",
                    ..exact
                },
                FulfilledRecoveryTerminalColumns {
                    package_terminal_transition_id: Some(other_transition_id),
                    ..exact
                },
                FulfilledRecoveryTerminalColumns {
                    package_terminal_revocation_id: Some(Uuid::new_v4()),
                    ..exact
                },
                FulfilledRecoveryTerminalColumns {
                    package_terminal_at: Some(other_at),
                    ..exact
                },
                FulfilledRecoveryTerminalColumns {
                    durable_transition_kind: Some("commit"),
                    ..exact
                },
                FulfilledRecoveryTerminalColumns {
                    durable_transition_kind: None,
                    durable_transition_accepted_at: None,
                    ..exact
                },
            ];
            for columns in malformed {
                assert!(matches!(
                    select_fulfilled_recovery_terminal(columns),
                    Err(RecoveryHydrationError::TerminalMismatch)
                ));
            }
        }

        /// The open recovery pair hydrates 1:1: the reservation supplies the
        /// request's `key_package_ref` + `package_not_after`, and the request origin
        /// re-mints byte-equal to the direct in-memory signed-path re-hydration.
        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn recovery_pair_hydrates_the_open_request() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let seed = seed_recovery_pair(&pool, &entry, "requestLeafRecovery").await;
            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();

            let reference = authority
                .hydrate_historical_signed_request_from_durable_bytes(
                    entry.cid,
                    REQUESTED_AT,
                    &seed.raw_wrapper,
                    &entry.public_key,
                )
                .expect("in-memory recovery origin");

            let mut tx = pool.begin().await.expect("begin");
            let (requests, reservations) =
                load_recovery_work_hydration_rows(&mut tx, &authority, cid)
                    .await
                    .expect("recovery pair hydrates");
            tx.commit().await.expect("commit");

            let target = DeviceIdentity::new(
                PrincipalId::new(entry.actor_did.clone().into_bytes()).unwrap(),
                *entry.actor_device_id.as_bytes(),
            )
            .unwrap();

            assert_eq!(requests.len(), 1);
            assert_eq!(reservations.len(), 1);
            let request = &requests[0];
            let reservation = &reservations[0];

            assert_eq!(request.request_id, seed.request_id);
            assert_eq!(request.target, target);
            assert_eq!(request.kind, LeafRecoveryKind::Replace);
            assert_eq!(request.source, RecoverySource::Request);
            assert_eq!(request.status, RecoveryRequestStatus::Open);
            assert_eq!(request.key_package_ref, seed.key_package_ref);
            assert!(request.terminal.is_none());
            assert_eq!(
                request.origin,
                RecoveryOriginHydrationRow::Request(reference)
            );

            assert_eq!(reservation.request_id, seed.request_id);
            assert_eq!(reservation.target, target);
            assert_eq!(reservation.key_package_ref, seed.key_package_ref);
            assert_eq!(reservation.status, ReservationStatus::Active);
            assert!(reservation.terminal.is_none());
            // The pair binds the same coordinate + received_at (the 1:1 fields
            // `validate_recovery_work` cross-checks at assembly).
            assert_eq!(reservation.bound_coordinate, request.bound_coordinate);
            assert_eq!(reservation.received_at, request.received_at);
            assert_eq!(reservation.expires_at, request.expires_at);
        }

        /// The recovery leg fails CLOSED when the read-time authority binds a
        /// different conversation: the signed request's embedded `prior`
        /// conversation id mismatches, so the origin re-verification rejects it
        /// (`InvalidProvenance`) — never a fabricated origin.
        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn recovery_pair_fails_closed_when_authority_binds_a_foreign_conversation() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let _seed = seed_recovery_pair(&pool, &entry, "requestLeafRecovery").await;
            // Authority bound to a different conversation than the seeded rows.
            let foreign = Uuid::new_v4();
            let authority =
                HistoricalRehydrationAuthority::new(*foreign.as_bytes(), entry.head_next_entry_seq)
                    .unwrap();

            let mut tx = pool.begin().await.expect("begin");
            let result = load_recovery_work_hydration_rows(&mut tx, &authority, cid).await;
            tx.rollback().await.expect("rollback");

            assert!(matches!(
                result,
                Err(RecoveryHydrationError::InvalidProvenance)
            ));
        }

        /// The `acceptConversation` source (an `Acceptance` transition origin) is
        /// the NEXT-STEP follow-up: the leg fails CLOSED (`UnsupportedSource`)
        /// rather than mis-minting a signed-request origin for it.
        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn recovery_pair_fails_closed_on_accept_conversation_source() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let _seed = seed_recovery_pair(&pool, &entry, "acceptConversation").await;
            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();

            let mut tx = pool.begin().await.expect("begin");
            let result = load_recovery_work_hydration_rows(&mut tx, &authority, cid).await;
            tx.rollback().await.expect("rollback");

            assert!(matches!(
                result,
                Err(RecoveryHydrationError::UnsupportedSource)
            ));
        }

        // Fulfilled/consumed terminal reconstruction is live-exercised above by a
        // fully coherent graph crossing every deferred fulfillment/Welcome
        // mapping. The remaining cancelled/released, expired, and
        // superseded/released status families stay fail-closed behind
        // `UnsupportedTerminal` until their separately owned signed fixtures land.
    }

    // -----------------------------------------------------------------------
    // G1b-2 sub-seal — reset/leave request hydration leg (pending arm).
    //
    // The reset/leave origin is a CONTROL request (a `resetRequestEntry` /
    // `leaveRequestEntry` in `chat.entries`, `transition_id = NULL`), NOT a
    // standalone signed request — so it is re-minted through the control pipeline
    // and located by the JOIN ruling `(conversation_id, entry_kind,
    // request_digest)` + byte-equal `signed_request_bytes` (see the
    // `load_reset_request_hydration_rows` module header).
    //
    // The seed appends a real, ed25519-signed reset/leave request entry at seq 2
    // on top of the genesis creation graph (seq 1), signed by the SAME test key as
    // the creation actor (so the requester is a live registered device and the
    // `chat.device_keys` JOIN yields the verifying key), plus its coherent
    // `chat.reset_requests` / `chat.leave_requests` projection row — byte-matching
    // the entry as the reciprocal deferred mapping triggers require. The head is
    // advanced to `next_entry_seq = 3` so the request entry (seq 2) sits strictly
    // below the locked head.
    //
    // The structurally-guarded JOIN-ruling fail-closed arms (0-match
    // `OriginMissing`, >1-match `OriginAmbiguous`, byte-mismatch `BindingMismatch`)
    // are NOT constructible on a coherent gate DB (the reciprocal 1:1 entry<->row
    // mapping triggers, see the loader module header), so they are exercised as a
    // PURE decision test over synthetic row sets
    // (`resolve_single_control_request_origin_covers_join_ruling_arms`) — the same
    // structural-guard resolution the participant leg uses. The constructible
    // live arms — the pending happy path, the foreign-conversation
    // `InvalidOrigin`, and the empty collection — are live on the gate DB.
    // -----------------------------------------------------------------------
    pub(super) mod reset_leave_leg {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use chrono::{DateTime, Duration, Utc};
        use ed25519_dalek::Signer;
        use serde_json::{json, Value};
        use sha2::{Digest, Sha256};
        use sqlx::{PgPool, Postgres, Transaction};
        use uuid::Uuid;

        use super::super::historical_control_path::{build_real_creation_entry, RealCreationEntry};
        use super::seed_real_creation_graph;
        use crate::chat_protocol::public_state::{encode_public_tree_summary, ActivePublicState};
        use crate::chat_protocol::repository::core::{
            hydrate_locked_public_state, load_interval_hydration_rows, load_leaf_hydration_rows,
            load_leave_request_hydration_rows, load_metadata_provenance,
            load_participant_hydration_rows, load_producer_transition_evidence,
            load_recovery_work_hydration_rows, load_reset_request_hydration_rows,
            load_welcome_hydration_rows, resolve_single_control_request_origin,
            select_leave_terminal, select_reset_terminal, LeaveTerminalColumns,
            ResetLeaveHydrationError, ResetTerminalColumns,
        };
        use crate::chat_protocol::repository::transition::{
            terminalize_leave_request, terminalize_reset_request, LeaveRequestTermination,
            ResetRequestTermination,
        };
        use crate::chat_protocol::snapshot::{
            PublicGroupSnapshotLeaf, PublicGroupSnapshotTreeSummary,
        };
        use crate::chat_protocol::state_machine::{
            ConversationKind, ConversationStateHydration, DeviceIdentity,
            HistoricalRehydrationAuthority, HydrationAuthority, LeaveRequestStatus, PrincipalId,
            ResetRequestStatus, ServerTimestamp, WorkTerminalHydrationRow,
        };
        use crate::chat_protocol::transcript::{
            decode_and_verify_control_entry, decode_canonical_signed_mutation, SignedMutationKind,
        };
        use crate::chat_protocol::validation::ed25519_key_id;
        use crate::common;

        pub(super) const RESET_ENTRY_KIND: &str = "blue.catbird.chat.defs#resetRequestEntry";
        pub(super) const LEAVE_ENTRY_KIND: &str = "blue.catbird.chat.defs#leaveRequestEntry";
        const RECEIVED_AT: &str = "2030-02-01T00:00:00.000Z";
        const SIGNED_AT: &str = "2030-01-31T23:59:59.000Z";
        const STALE_AT: &str = "2030-02-01T00:01:00.000Z";

        fn instant(text: &str) -> DateTime<Utc> {
            DateTime::parse_from_rfc3339(text)
                .expect("canonical instant")
                .with_timezone(&Utc)
        }

        fn uuid_v4_bytes(byte: u8) -> [u8; 16] {
            let mut value = [byte; 16];
            value[6] = 0x40 | (byte & 0x0f);
            value[8] = 0x80 | (byte & 0x3f);
            value
        }

        /// The genesis active coordinate `seed_real_creation_graph` commits — the
        /// `prior` a pending reset/leave request binds (its `bound_coordinate ==
        /// state.coordinate`).
        fn genesis_coordinate_json(cid: [u8; 16]) -> Value {
            active_coordinate_json(cid, 0)
        }

        fn active_coordinate_json(cid: [u8; 16], state_version: u64) -> Value {
            let (epoch, context_byte, confirmation_byte) = match state_version {
                0 => (0, 2, 3),
                1 => (1, 4, 5),
                2 => (2, 6, 7),
                _ => panic!("test commit coordinate outside fixture domain"),
            };
            json!({
                "conversationId": Uuid::from_bytes(cid).hyphenated().to_string(),
                "generation": 0,
                "stateVersion": state_version,
                "groupId": STANDARD.encode([1_u8; 32]),
                "epoch": epoch,
                "groupContextHash": STANDARD.encode([context_byte; 32]),
                "confirmationTag": STANDARD.encode([confirmation_byte; 32]),
                "lifecycle": "active",
            })
        }

        fn active_aad_coordinate_json(cid: [u8; 16], state_version: u64) -> Value {
            let mut coordinate = active_coordinate_json(cid, state_version);
            coordinate["conversationId"] = json!(STANDARD.encode(cid));
            coordinate
        }

        /// A genuinely-signed reset/leave request CONTROL entry: the outer control
        /// row envelope (`accepted_payload_bytes`) + the inner signed mutation
        /// wrapper (`signed_request_bytes`) + the shape/mapping columns the seed's
        /// entry and projection rows must carry byte-identically.
        pub(super) struct RealControlRequestEntry {
            pub(super) request_id: [u8; 16],
            pub(super) entry_id: Uuid,
            pub(super) seq: u64,
            pub(super) public_row_json: Vec<u8>,
            pub(super) raw_wrapper: Vec<u8>,
            pub(super) signing_transcript: Vec<u8>,
            pub(super) request_digest: Vec<u8>,
            pub(super) signature: Vec<u8>,
            pub(super) outer_entry_fingerprint: Vec<u8>,
        }

        struct RealStalingCommit {
            entry_id: Uuid,
            transition_id: Uuid,
            public_row_json: Vec<u8>,
            raw_wrapper: Vec<u8>,
            canonical_projection: Vec<u8>,
            signing_transcript: Vec<u8>,
            request_digest: Vec<u8>,
            signature: Vec<u8>,
            server_fields_dag_cbor: Vec<u8>,
            outer_entry_fingerprint: Vec<u8>,
        }

        fn build_real_staling_commit(
            entry: &RealCreationEntry,
            origin_transition_id: Uuid,
        ) -> RealStalingCommit {
            build_real_commit(entry, origin_transition_id, 3, STALE_AT, 0, 1)
        }

        fn build_real_commit(
            entry: &RealCreationEntry,
            origin_transition_id: Uuid,
            entry_seq: u64,
            received_at: &str,
            prior_state_version: u64,
            next_state_version: u64,
        ) -> RealStalingCommit {
            let signing_key = entry.signing_key();
            let transition_id = Uuid::new_v4();
            let entry_id = Uuid::new_v4();
            let commit_bytes = [0x90_u8.wrapping_add(next_state_version as u8); 8];
            let metadata_ciphertext = [0x91_u8.wrapping_add(next_state_version as u8); 16];
            let prior = active_coordinate_json(entry.cid, prior_state_version);
            let next = active_coordinate_json(entry.cid, next_state_version);
            let (_, next_context_byte, next_confirmation_byte) = match next_state_version {
                1 => (1_u64, 4_u8, 5_u8),
                2 => (2_u64, 6_u8, 7_u8),
                _ => panic!("test commit successor outside fixture domain"),
            };
            let body = json!({
                "$type": SignedMutationKind::CommitTransition.type_id(),
                "signatureDomain": String::from_utf8(
                    SignedMutationKind::CommitTransition.domain().to_vec()
                ).unwrap(),
                "transitionId": transition_id.hyphenated().to_string(),
                "actorDid": entry.actor_did,
                "actorDeviceId": entry.actor_device_id.hyphenated().to_string(),
                "keyId": entry.actor_key_id,
                "authGeneration": 1,
                "prior": prior,
                "next": next,
                "aad": {
                    "protocolVersion": "1",
                    "conversationId": STANDARD.encode(entry.cid),
                    "generation": 0,
                    "transitionId": STANDARD.encode(transition_id.as_bytes()),
                    "prior": active_aad_coordinate_json(entry.cid, prior_state_version),
                },
                "manifest": {
                    "participantChanges": [],
                    "leafChanges": [],
                },
                "commit": {
                    "framing": "mlsMessage",
                    "contentType": "publicMessageCommit",
                    "bytes": STANDARD.encode(commit_bytes),
                    "sha256": STANDARD.encode(Sha256::digest(commit_bytes)),
                },
                "metadataSnapshot": {
                    "coordinate": {
                        "conversationId": STANDARD.encode(entry.cid),
                        "generation": 0,
                        "groupId": STANDARD.encode([1_u8; 32]),
                        "epoch": next_state_version,
                        "groupContextHash": STANDARD.encode([next_context_byte; 32]),
                        "confirmationTag": STANDARD.encode([next_confirmation_byte; 32]),
                    },
                    "originTransitionId": origin_transition_id.hyphenated().to_string(),
                    "metadataVersion": 1,
                    "nonce": STANDARD.encode([0x93_u8; 12]),
                    "ciphertext": STANDARD.encode(metadata_ciphertext),
                    "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
                    "ciphertextSize": metadata_ciphertext.len(),
                    "authorProof": {
                        "authorDid": entry.actor_did,
                        "authorDeviceId": entry.actor_device_id.hyphenated().to_string(),
                        "authorKeyId": entry.actor_key_id,
                        "signaturePublicKey": STANDARD.encode(&entry.public_key),
                        "authGenerationAtOrigin": 1,
                        "originTransitionId": origin_transition_id.hyphenated().to_string(),
                        "originSeq": 1,
                        "roleAtOrigin": "admin",
                        "deviceStatusAtOrigin": "active",
                    },
                },
                "idempotencyKey": Uuid::new_v4().hyphenated().to_string(),
                "signedAt": "2030-02-01T00:00:59.000Z",
            });
            let mut wrapper = json!({ "body": body, "signature": STANDARD.encode([0_u8; 64]) });
            let unsigned = serde_json::to_vec(&wrapper).unwrap();
            let canonical = decode_canonical_signed_mutation(&unsigned)
                .expect("unsigned staling Commit canonicalizes");
            let signature = signing_key.sign(canonical.transcript_bytes()).to_bytes();
            wrapper["signature"] = Value::String(STANDARD.encode(signature));
            let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
            let canonical = decode_canonical_signed_mutation(&raw_wrapper)
                .expect("signed staling Commit canonicalizes");
            let public_row_json = serde_json::to_vec(&json!({
                "$type": "blue.catbird.chat.defs#commitEntry",
                "entryId": entry_id.hyphenated().to_string(),
                "conversationId": Uuid::from_bytes(entry.cid).hyphenated().to_string(),
                "seq": entry_seq,
                "signedRequest": wrapper,
                "receivedAt": received_at,
            }))
            .unwrap();
            let decoded = decode_and_verify_control_entry(
                &public_row_json,
                signing_key.verifying_key().as_bytes(),
            )
            .expect("real staling Commit entry verifies");
            RealStalingCommit {
                entry_id,
                transition_id,
                public_row_json,
                raw_wrapper,
                canonical_projection: canonical.canonical_projection().to_vec(),
                signing_transcript: canonical.transcript_bytes().to_vec(),
                request_digest: canonical.request_digest().to_vec(),
                signature: canonical.signature().to_vec(),
                server_fields_dag_cbor: decoded.server_fields_dag_cbor().unwrap(),
                outer_entry_fingerprint: decoded.outer_control_fingerprint().to_vec(),
            }
        }

        /// Build a real reset (`kind = ResetRequest`) or leave (`kind =
        /// LeaveRequest`) request entry, signed by the creation actor's test key,
        /// bound to the genesis coordinate, at `seq`. Mirrors
        /// `build_signed_recovery_request`'s direct-body construction wrapped in the
        /// `build_real_creation_entry`-style control envelope.
        pub(super) fn build_real_control_request_entry(
            entry: &RealCreationEntry,
            kind: SignedMutationKind,
            entry_kind: &str,
            seq: u64,
        ) -> RealControlRequestEntry {
            build_real_control_request_entry_with_id(entry, kind, entry_kind, seq, Uuid::new_v4())
        }

        /// Build a real leaveCancellation CONTROL entry whose signed body names
        /// the exact already-pending leave request. The request id is injected
        /// before canonical transcript derivation and signing; the signed wrapper
        /// is never mutated afterward.
        pub(super) fn build_real_leave_cancellation_entry(
            entry: &RealCreationEntry,
            leave_request_id: [u8; 16],
            entry_kind: &str,
            seq: u64,
        ) -> RealControlRequestEntry {
            build_real_leave_cancellation_entry_at(
                entry,
                leave_request_id,
                entry_kind,
                seq,
                RECEIVED_AT,
            )
        }

        pub(super) fn build_real_leave_cancellation_entry_at(
            entry: &RealCreationEntry,
            leave_request_id: [u8; 16],
            entry_kind: &str,
            seq: u64,
            received_at: &str,
        ) -> RealControlRequestEntry {
            build_real_control_request_entry_with_id_at(
                entry,
                SignedMutationKind::LeaveCancellation,
                entry_kind,
                seq,
                Uuid::from_bytes(leave_request_id),
                received_at,
            )
        }

        pub(super) fn build_real_control_request_entry_with_id(
            entry: &RealCreationEntry,
            kind: SignedMutationKind,
            entry_kind: &str,
            seq: u64,
            request_uuid: Uuid,
        ) -> RealControlRequestEntry {
            build_real_control_request_entry_with_id_at(
                entry,
                kind,
                entry_kind,
                seq,
                request_uuid,
                RECEIVED_AT,
            )
        }

        fn build_real_control_request_entry_with_id_at(
            entry: &RealCreationEntry,
            kind: SignedMutationKind,
            entry_kind: &str,
            seq: u64,
            request_uuid: Uuid,
            received_at: &str,
        ) -> RealControlRequestEntry {
            let signing_key = entry.signing_key();
            let verifying = signing_key.verifying_key().to_bytes();
            // The creation entry signed with this same key, so its device-keys row
            // carries exactly this verifying key under `entry.actor_key_id`.
            assert_eq!(entry.public_key, verifying.to_vec());
            assert_eq!(
                entry.actor_key_id,
                ed25519_key_id(&verifying).unwrap().as_str()
            );

            let request_id = *request_uuid.as_bytes();
            let request_id_field = if matches!(kind, SignedMutationKind::ResetRequest) {
                "resetRequestId"
            } else {
                "leaveRequestId"
            };
            let mut body = serde_json::Map::new();
            body.insert("$type".into(), json!(kind.type_id()));
            body.insert(
                "signatureDomain".into(),
                json!(String::from_utf8(kind.domain().to_vec()).unwrap()),
            );
            body.insert(
                request_id_field.into(),
                json!(request_uuid.hyphenated().to_string()),
            );
            body.insert("actorDid".into(), json!(entry.actor_did));
            body.insert(
                "actorDeviceId".into(),
                json!(entry.actor_device_id.hyphenated().to_string()),
            );
            body.insert(
                "keyId".into(),
                json!(ed25519_key_id(&verifying).unwrap().as_str()),
            );
            body.insert("authGeneration".into(), json!(1));
            if matches!(kind, SignedMutationKind::LeaveCancellation) {
                body.insert(
                    "conversationId".into(),
                    json!(Uuid::from_bytes(entry.cid).hyphenated().to_string()),
                );
            } else {
                body.insert("prior".into(), genesis_coordinate_json(entry.cid));
            }
            if matches!(kind, SignedMutationKind::ResetRequest) {
                body.insert("reason".into(), json!("manualRecovery"));
            }
            body.insert(
                "idempotencyKey".into(),
                json!(Uuid::from_bytes(uuid_v4_bytes(0x7a))
                    .hyphenated()
                    .to_string()),
            );
            body.insert("signedAt".into(), json!(SIGNED_AT));

            // Sign the inner mutation over the exact canonical transcript the strict
            // decoder derives (mirrors `build_signed_recovery_request`).
            let mut wrapper = json!({ "body": Value::Object(body), "signature": "" });
            wrapper["signature"] = Value::String(STANDARD.encode([0u8; 64]));
            let unsigned = serde_json::to_vec(&wrapper).unwrap();
            let canonical = decode_canonical_signed_mutation(&unsigned).unwrap();
            let signing_transcript = canonical.transcript_bytes().to_vec();
            let signature = signing_key.sign(&signing_transcript).to_bytes();
            wrapper["signature"] = Value::String(STANDARD.encode(signature));
            let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
            let signed_request: Value = serde_json::from_slice(&raw_wrapper).unwrap();

            // Wrap in the control-entry envelope (empty serverFields, like creation).
            let entry_id = Uuid::new_v4();
            let row = json!({
                "$type": entry_kind,
                "entryId": entry_id.hyphenated().to_string(),
                "conversationId": Uuid::from_bytes(entry.cid).hyphenated().to_string(),
                "seq": seq,
                "signedRequest": signed_request,
                "receivedAt": received_at,
            });
            let public_row_json = serde_json::to_vec(&row).unwrap();

            // Fail fast on drift: it must decode + verify under the test key, bound
            // to the fresh conversation; the outer fingerprint is the durable column.
            let decoded = decode_and_verify_control_entry(&public_row_json, &verifying)
                .expect("request entry decodes under the test key");
            assert_eq!(decoded.conversation_id().as_bytes(), &entry.cid);

            RealControlRequestEntry {
                request_id,
                entry_id,
                seq,
                public_row_json,
                raw_wrapper,
                request_digest: Sha256::digest(&signing_transcript).to_vec(),
                signature: signature.to_vec(),
                signing_transcript,
                outer_entry_fingerprint: decoded.outer_control_fingerprint().to_vec(),
            }
        }

        /// Append a pending reset/leave request (entry at seq 2 + coherent
        /// projection row) on top of a committed genesis graph, advancing the head
        /// to `next_entry_seq = 3`. Returns the built request entry (its bytes are
        /// the in-memory re-mint reference).
        pub(super) async fn seed_control_request(
            pool: &PgPool,
            entry: &RealCreationEntry,
            kind: SignedMutationKind,
            entry_kind: &str,
        ) -> RealControlRequestEntry {
            seed_real_creation_graph(pool, entry).await;
            let conversation_id = Uuid::from_bytes(entry.cid);
            let request = build_real_control_request_entry(entry, kind, entry_kind, 2);
            let request_uuid = Uuid::from_bytes(request.request_id);
            let received_at = instant(RECEIVED_AT);
            let expires_at = received_at + Duration::hours(24);
            let payload_sha = Sha256::digest(&request.public_row_json).to_vec();

            let mut tx = pool.begin().await.expect("begin control request");
            // The request entry: transition_id / generation / state_version NULL
            // (apply_reset_request / apply_leave_request set exactly these), request
            // digest + signature = the real signed material (the reciprocal mapping
            // trigger requires the entry and projection row to byte-match).
            sqlx::query(
                r#"INSERT INTO chat.entries(
                    conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
                    accepted_payload_sha256,signed_request_bytes,request_digest,signature,
                    server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
                    actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at
                ) VALUES($1,2,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1,NULL,NULL,NULL,$14)"#,
            )
            .bind(conversation_id)
            .bind(request.entry_id)
            .bind(entry_kind)
            .bind(&request.public_row_json)
            .bind(&payload_sha)
            .bind(&request.raw_wrapper)
            .bind(&request.request_digest)
            .bind(&request.signature)
            .bind(vec![0_u8])
            .bind(&request.outer_entry_fingerprint)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(received_at)
            .execute(&mut *tx)
            .await
            .expect("insert request entry");

            if matches!(kind, SignedMutationKind::ResetRequest) {
                sqlx::query(
                    r#"INSERT INTO chat.reset_requests(
                        reset_request_id,conversation_id,requester_did,requester_device_id,
                        requester_key_id,requester_auth_generation,prior_generation,prior_state_version,
                        prior_group_id,prior_epoch,prior_group_context_hash,prior_confirmation_tag,
                        reason,status,signed_request_bytes,signing_transcript_bytes,request_digest,
                        signature,received_at,expires_at
                    ) VALUES($1,$2,$3,$4,$5,1,0,0,$6,0,$7,$8,'manualRecovery','pending',$9,$10,$11,$12,$13,$14)"#,
                )
                .bind(request_uuid)
                .bind(conversation_id)
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(&entry.actor_key_id)
                .bind(vec![1_u8; 32])
                .bind(vec![2_u8; 32])
                .bind(vec![3_u8; 32])
                .bind(&request.raw_wrapper)
                .bind(&request.signing_transcript)
                .bind(&request.request_digest)
                .bind(&request.signature)
                .bind(received_at)
                .bind(expires_at)
                .execute(&mut *tx)
                .await
                .expect("insert reset request");
            } else {
                sqlx::query(
                    r#"INSERT INTO chat.leave_requests(
                        leave_request_id,conversation_id,requester_did,requester_device_id,
                        requester_key_id,requester_auth_generation,prior_generation,prior_state_version,
                        prior_group_id,prior_epoch,prior_group_context_hash,prior_confirmation_tag,
                        status,signed_request_bytes,signing_transcript_bytes,request_digest,
                        signature,received_at,expires_at
                    ) VALUES($1,$2,$3,$4,$5,1,0,0,$6,0,$7,$8,'pending',$9,$10,$11,$12,$13,$14)"#,
                )
                .bind(request_uuid)
                .bind(conversation_id)
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(&entry.actor_key_id)
                .bind(vec![1_u8; 32])
                .bind(vec![2_u8; 32])
                .bind(vec![3_u8; 32])
                .bind(&request.raw_wrapper)
                .bind(&request.signing_transcript)
                .bind(&request.request_digest)
                .bind(&request.signature)
                .bind(received_at)
                .bind(expires_at)
                .execute(&mut *tx)
                .await
                .expect("insert leave request");
            }

            // Advance the head so the request entry (seq 2) is strictly below it.
            sqlx::query(
                "UPDATE chat.conversations SET next_entry_seq = 3 WHERE conversation_id = $1",
            )
            .bind(conversation_id)
            .execute(&mut *tx)
            .await
            .expect("advance head");
            tx.commit().await.expect("commit control request");
            request
        }

        fn fixture_coordinate_columns(state_version: u64) -> (i64, Vec<u8>, Vec<u8>) {
            match state_version {
                0 => (0, vec![2_u8; 32], vec![3_u8; 32]),
                1 => (1, vec![4_u8; 32], vec![5_u8; 32]),
                2 => (2, vec![6_u8; 32], vec![7_u8; 32]),
                _ => panic!("test commit coordinate outside fixture domain"),
            }
        }

        #[allow(clippy::too_many_arguments)]
        async fn insert_real_commit(
            transaction: &mut Transaction<'_, Postgres>,
            entry: &RealCreationEntry,
            transition: &RealStalingCommit,
            origin_transition_id: Uuid,
            entry_seq: i64,
            at: DateTime<Utc>,
            prior_state_version: i64,
            next_state_version: i64,
        ) {
            let cid = Uuid::from_bytes(entry.cid);
            let metadata_snapshot_id = Uuid::new_v4();
            let public_snapshot =
                vec![0x93_u8.wrapping_add(u8::try_from(next_state_version).unwrap()); 64];
            let metadata_ciphertext =
                vec![0x91_u8.wrapping_add(u8::try_from(next_state_version).unwrap()); 16];
            let (next_epoch, next_context_hash, next_confirmation_tag) =
                fixture_coordinate_columns(u64::try_from(next_state_version).unwrap());
            let basic_credential =
                format!("{}#{}", entry.actor_did, entry.actor_device_id).into_bytes();
            let tree = PublicGroupSnapshotTreeSummary::new(
                [0x63_u8; 32],
                vec![PublicGroupSnapshotLeaf::new(
                    0,
                    basic_credential,
                    entry.public_key.clone(),
                    vec![0x64_u8; 1_216],
                )],
            );
            let (tree_summary, tree_summary_sha256) = encode_public_tree_summary(&tree)
                .expect("staling tree summary canonical")
                .into_parts();

            sqlx::query(
                r#"UPDATE chat.conversations
                   SET current_state_version=$2,next_entry_seq=$3
                   WHERE conversation_id=$1 AND current_generation=0
                     AND current_state_version=$4 AND next_entry_seq=$5"#,
            )
            .bind(cid)
            .bind(next_state_version)
            .bind(entry_seq + 1)
            .bind(prior_state_version)
            .bind(entry_seq)
            .execute(&mut **transaction)
            .await
            .expect("advance conversation through staling Commit");
            sqlx::query(
                r#"UPDATE chat.generations SET current_state_version=$2
                   WHERE conversation_id=$1 AND generation=0 AND current_state_version=$3"#,
            )
            .bind(cid)
            .bind(next_state_version)
            .bind(prior_state_version)
            .execute(&mut **transaction)
            .await
            .expect("advance generation through staling Commit");
            sqlx::query(
                r#"INSERT INTO chat.transitions(
                    transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
                    actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
                    unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
                    prior_generation,prior_state_version,next_generation,next_state_version,
                    metadata_snapshot_id,entry_seq,accepted_at
                ) VALUES($1,$2,'commit',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,
                    0,$11,0,$12,$13,$14,$15)"#,
            )
            .bind(transition.transition_id)
            .bind(cid)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(&transition.raw_wrapper)
            .bind(&transition.canonical_projection)
            .bind(&transition.signing_transcript)
            .bind(&transition.request_digest)
            .bind(&transition.signature)
            .bind(prior_state_version)
            .bind(next_state_version)
            .bind(metadata_snapshot_id)
            .bind(entry_seq)
            .bind(at)
            .execute(&mut **transaction)
            .await
            .expect("insert staling transition");
            sqlx::query(
                r#"INSERT INTO chat.generation_states(
                    conversation_id,generation,state_version,group_id,epoch,group_context_hash,
                    confirmation_tag,lifecycle,state_kind,producing_transition_id,
                    public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,
                    leaf_count,created_at
                ) VALUES($1,0,$2,$3,$4,$5,$6,'active','commit',$7,$8,$9,$10,$11,1,$12)"#,
            )
            .bind(cid)
            .bind(next_state_version)
            .bind(vec![1_u8; 32])
            .bind(next_epoch)
            .bind(&next_context_hash)
            .bind(&next_confirmation_tag)
            .bind(transition.transition_id)
            .bind(&public_snapshot)
            .bind(Sha256::digest(&public_snapshot).to_vec())
            .bind(&tree_summary)
            .bind(tree_summary_sha256.to_vec())
            .bind(at)
            .execute(&mut **transaction)
            .await
            .expect("insert staling generation state");
            sqlx::query(
                r#"INSERT INTO chat.metadata_snapshots(
                    metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,
                    group_context_hash,confirmation_tag,producing_transition_id,
                    origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,
                    ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,
                    author_auth_generation,author_origin_seq,author_role,author_device_status,
                    created_at
                ) VALUES($1,$2,0,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,16,$14,$15,$16,$17,
                    1,1,'admin','active',$18)"#,
            )
            .bind(metadata_snapshot_id)
            .bind(cid)
            .bind(next_state_version)
            .bind(vec![1_u8; 32])
            .bind(next_epoch)
            .bind(&next_context_hash)
            .bind(&next_confirmation_tag)
            .bind(transition.transition_id)
            .bind(origin_transition_id)
            .bind(1_i64)
            .bind(vec![
                0x92_u8.wrapping_add(
                    u8::try_from(next_state_version).unwrap()
                );
                12
            ])
            .bind(&metadata_ciphertext)
            .bind(Sha256::digest(&metadata_ciphertext).to_vec())
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(&entry.public_key)
            .bind(at)
            .execute(&mut **transaction)
            .await
            .expect("insert staling metadata");
            sqlx::query(
                r#"INSERT INTO chat.entries(
                    conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
                    accepted_payload_sha256,signed_request_bytes,request_digest,signature,
                    server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
                    actor_key_id,actor_auth_generation,generation,state_version,transition_id,
                    received_at
                ) VALUES($1,$2,$3,'blue.catbird.chat.defs#commitEntry',$4,$5,$6,$7,$8,$9,$10,
                    $11,$12,$13,1,0,$14,$15,$16)"#,
            )
            .bind(cid)
            .bind(entry_seq)
            .bind(transition.entry_id)
            .bind(&transition.public_row_json)
            .bind(Sha256::digest(&transition.public_row_json).to_vec())
            .bind(&transition.raw_wrapper)
            .bind(&transition.request_digest)
            .bind(&transition.signature)
            .bind(&transition.server_fields_dag_cbor)
            .bind(&transition.outer_entry_fingerprint)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(next_state_version)
            .bind(transition.transition_id)
            .bind(at)
            .execute(&mut **transaction)
            .await
            .expect("insert staling entry");
            sqlx::query(
                r#"INSERT INTO chat.entry_recipients(
                    conversation_id,seq,user_did,device_id,entitlement_kind
                ) VALUES($1,$2,$3,$4,'control')"#,
            )
            .bind(cid)
            .bind(entry_seq)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .execute(&mut **transaction)
            .await
            .expect("route staling entry");
        }

        async fn commit_staling_transition(
            pool: &PgPool,
            entry: &RealCreationEntry,
            request: &RealControlRequestEntry,
            kind: SignedMutationKind,
        ) -> RealStalingCommit {
            commit_staling_transition_at(pool, entry, request, kind, STALE_AT).await
        }

        async fn commit_staling_transition_at(
            pool: &PgPool,
            entry: &RealCreationEntry,
            request: &RealControlRequestEntry,
            kind: SignedMutationKind,
            terminal_at: &str,
        ) -> RealStalingCommit {
            let cid = Uuid::from_bytes(entry.cid);
            let origin_transition_id: Uuid = sqlx::query_scalar(
                r#"SELECT producing_transition_id FROM chat.generation_states
                   WHERE conversation_id=$1 AND generation=0 AND state_version=0"#,
            )
            .bind(cid)
            .fetch_one(pool)
            .await
            .expect("creation transition id");
            let transition = build_real_commit(entry, origin_transition_id, 3, terminal_at, 0, 1);
            let at = instant(terminal_at);
            let mut tx = pool.begin().await.expect("begin staling transition");
            insert_real_commit(
                &mut tx,
                entry,
                &transition,
                origin_transition_id,
                3,
                at,
                0,
                1,
            )
            .await;

            if kind == SignedMutationKind::ResetRequest {
                terminalize_reset_request(
                    &mut tx,
                    Uuid::from_bytes(request.request_id),
                    &ResetRequestTermination::Stale {
                        terminal_transition_id: transition.transition_id,
                        terminal_at: at,
                    },
                )
                .await
                .expect("terminalize stale reset");
            } else {
                terminalize_leave_request(
                    &mut tx,
                    Uuid::from_bytes(request.request_id),
                    &LeaveRequestTermination::Stale {
                        terminal_request_digest: transition.request_digest.clone(),
                        terminal_transition_id: transition.transition_id,
                        terminal_at: at,
                    },
                )
                .await
                .expect("terminalize stale leave");
            }
            tx.commit()
                .await
                .expect("staling graph crosses every deferred constraint");
            transition
        }

        async fn commit_followup_transition(
            pool: &PgPool,
            entry: &RealCreationEntry,
        ) -> RealStalingCommit {
            let cid = Uuid::from_bytes(entry.cid);
            let origin_transition_id: Uuid = sqlx::query_scalar(
                r#"SELECT origin_transition_id FROM chat.metadata_snapshots
                   WHERE conversation_id=$1 AND generation=0 AND state_version=1"#,
            )
            .bind(cid)
            .fetch_one(pool)
            .await
            .expect("metadata origin transition id");
            const FOLLOWUP_AT: &str = "2030-02-01T00:02:00.000Z";
            let transition = build_real_commit(entry, origin_transition_id, 4, FOLLOWUP_AT, 1, 2);
            let mut tx = pool.begin().await.expect("begin followup transition");
            insert_real_commit(
                &mut tx,
                entry,
                &transition,
                origin_transition_id,
                4,
                instant(FOLLOWUP_AT),
                1,
                2,
            )
            .await;
            tx.commit()
                .await
                .expect("followup graph crosses every deferred constraint");
            transition
        }

        /// Commit a DDL-valid stale row whose terminal transition is seq 2 and
        /// whose genuine signed request origin is seq 3. The mapper deliberately
        /// does not compare terminal sequence to origin sequence, leaving the
        /// aggregate validator to reject this otherwise exact graph.
        async fn commit_transition_before_stale_request(
            pool: &PgPool,
            entry: &RealCreationEntry,
            kind: SignedMutationKind,
            entry_kind: &str,
        ) -> RealControlRequestEntry {
            let origin_transition_id = seed_real_creation_graph(pool, entry).await;
            let transition = build_real_commit(entry, origin_transition_id, 2, STALE_AT, 0, 1);
            let request = build_real_control_request_entry(entry, kind, entry_kind, 3);
            let cid = Uuid::from_bytes(entry.cid);
            let received_at = instant(RECEIVED_AT);
            let expires_at = received_at + Duration::hours(24);
            let terminal_at = instant(STALE_AT);
            let payload_sha = Sha256::digest(&request.public_row_json).to_vec();

            let mut tx = pool
                .begin()
                .await
                .expect("begin transition-before-request graph");
            insert_real_commit(
                &mut tx,
                entry,
                &transition,
                origin_transition_id,
                2,
                terminal_at,
                0,
                1,
            )
            .await;
            sqlx::query(
                r#"INSERT INTO chat.entries(
                    conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
                    accepted_payload_sha256,signed_request_bytes,request_digest,signature,
                    server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
                    actor_key_id,actor_auth_generation,generation,state_version,transition_id,
                    received_at
                ) VALUES($1,3,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1,NULL,NULL,NULL,$14)"#,
            )
            .bind(cid)
            .bind(request.entry_id)
            .bind(entry_kind)
            .bind(&request.public_row_json)
            .bind(&payload_sha)
            .bind(&request.raw_wrapper)
            .bind(&request.request_digest)
            .bind(&request.signature)
            .bind(vec![0_u8])
            .bind(&request.outer_entry_fingerprint)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(received_at)
            .execute(&mut *tx)
            .await
            .expect("insert later request entry");

            if kind == SignedMutationKind::ResetRequest {
                sqlx::query(
                    r#"INSERT INTO chat.reset_requests(
                        reset_request_id,conversation_id,requester_did,requester_device_id,
                        requester_key_id,requester_auth_generation,prior_generation,
                        prior_state_version,prior_group_id,prior_epoch,prior_group_context_hash,
                        prior_confirmation_tag,reason,status,signed_request_bytes,
                        signing_transcript_bytes,request_digest,signature,terminal_transition_id,
                        received_at,expires_at,terminal_at
                    ) VALUES($1,$2,$3,$4,$5,1,0,0,$6,0,$7,$8,'manualRecovery','stale',
                        $9,$10,$11,$12,$13,$14,$15,$16)"#,
                )
                .bind(Uuid::from_bytes(request.request_id))
                .bind(cid)
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(&entry.actor_key_id)
                .bind(vec![1_u8; 32])
                .bind(vec![2_u8; 32])
                .bind(vec![3_u8; 32])
                .bind(&request.raw_wrapper)
                .bind(&request.signing_transcript)
                .bind(&request.request_digest)
                .bind(&request.signature)
                .bind(transition.transition_id)
                .bind(received_at)
                .bind(expires_at)
                .bind(terminal_at)
                .execute(&mut *tx)
                .await
                .expect("insert later stale reset row");
            } else {
                sqlx::query(
                    r#"INSERT INTO chat.leave_requests(
                        leave_request_id,conversation_id,requester_did,requester_device_id,
                        requester_key_id,requester_auth_generation,prior_generation,
                        prior_state_version,prior_group_id,prior_epoch,prior_group_context_hash,
                        prior_confirmation_tag,status,signed_request_bytes,
                        signing_transcript_bytes,request_digest,signature,terminal_request_digest,
                        terminal_transition_id,received_at,expires_at,terminal_at
                    ) VALUES($1,$2,$3,$4,$5,1,0,0,$6,0,$7,$8,'stale',$9,$10,$11,$12,
                        $13,$14,$15,$16,$17)"#,
                )
                .bind(Uuid::from_bytes(request.request_id))
                .bind(cid)
                .bind(&entry.actor_did)
                .bind(entry.actor_device_id)
                .bind(&entry.actor_key_id)
                .bind(vec![1_u8; 32])
                .bind(vec![2_u8; 32])
                .bind(vec![3_u8; 32])
                .bind(&request.raw_wrapper)
                .bind(&request.signing_transcript)
                .bind(&request.request_digest)
                .bind(&request.signature)
                .bind(&transition.request_digest)
                .bind(transition.transition_id)
                .bind(received_at)
                .bind(expires_at)
                .bind(terminal_at)
                .execute(&mut *tx)
                .await
                .expect("insert later stale leave row");
            }
            sqlx::query(
                r#"UPDATE chat.conversations SET next_entry_seq=4
                   WHERE conversation_id=$1 AND current_state_version=1 AND next_entry_seq=3"#,
            )
            .bind(cid)
            .execute(&mut *tx)
            .await
            .expect("advance head past later request");
            tx.commit()
                .await
                .expect("commit transition-before-request graph");
            request
        }

        pub(super) async fn load_aggregate_hydration(
            pool: &PgPool,
            entry: &RealCreationEntry,
        ) -> ConversationStateHydration {
            let cid = Uuid::from_bytes(entry.cid);
            let next_entry_seq: i64 = sqlx::query_scalar(
                "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
            )
            .bind(cid)
            .fetch_one(pool)
            .await
            .expect("read aggregate head");
            let historical = HistoricalRehydrationAuthority::new(
                entry.cid,
                u64::try_from(next_entry_seq).expect("head in protocol domain"),
            )
            .expect("historical aggregate authority");

            let mut tx = pool.begin().await.expect("begin aggregate load");
            let guard = hydrate_locked_public_state(&mut tx, cid, instant(STALE_AT))
                .await
                .expect("locked public-state rows hydrate");
            let (
                _transaction_id,
                _conversation_id,
                coordinate,
                snapshot,
                binding,
                _encoded_tree_summary,
                _tree_summary_sha256,
                _locked_at,
                _generation_digest,
            ) = guard.into_parts();
            assert_eq!(&coordinate, binding.coordinate());
            let leaves = load_leaf_hydration_rows(&mut tx, cid, &binding)
                .await
                .expect("aggregate leaves hydrate");
            let public_state =
                ActivePublicState::for_test_from_persisted_binding(snapshot, binding)
                    .expect("snapshot remains digest-bound");
            let producer = load_producer_transition_evidence(&mut tx, &historical, cid)
                .await
                .expect("aggregate producer hydrates");
            let (metadata, metadata_producer) = load_metadata_provenance(&mut tx, &historical, cid)
                .await
                .expect("aggregate metadata hydrates");
            let participants = load_participant_hydration_rows(&mut tx, &historical, cid)
                .await
                .expect("aggregate participants hydrate");
            let intervals = load_interval_hydration_rows(&mut tx, &historical, cid)
                .await
                .expect("aggregate intervals hydrate");
            let (recovery_requests, recovery_reservations) =
                load_recovery_work_hydration_rows(&mut tx, &historical, cid)
                    .await
                    .expect("aggregate recovery work hydrates");
            let reset_requests = load_reset_request_hydration_rows(&mut tx, &historical, cid)
                .await
                .expect("aggregate reset work hydrates");
            let leave_requests = load_leave_request_hydration_rows(&mut tx, &historical, cid)
                .await
                .expect("aggregate leave work hydrates");
            let welcomes = load_welcome_hydration_rows(&mut tx, &historical, cid)
                .await
                .expect("aggregate Welcome work hydrates");
            tx.rollback().await.expect("rollback aggregate read");

            ConversationStateHydration {
                kind: ConversationKind::Group,
                coordinate,
                producer,
                public_state: Some(public_state),
                metadata,
                metadata_producer,
                participants,
                leaves,
                intervals,
                terminal_proofs: Vec::new(),
                recovery_requests,
                recovery_reservations,
                reset_requests,
                leave_requests,
                welcomes,
            }
        }

        fn assert_aggregate_hydrates(entry: &RealCreationEntry, rows: ConversationStateHydration) {
            let authority = HydrationAuthority::new(entry.cid).expect("aggregate authority");
            crate::chat_protocol::state_machine::hydrate_conversation_state(&authority, rows)
                .expect("production aggregate hydration accepts durable terminal");
        }

        fn creator_device(entry: &RealCreationEntry) -> DeviceIdentity {
            DeviceIdentity::new(
                PrincipalId::new(entry.actor_did.clone().into_bytes()).unwrap(),
                *entry.actor_device_id.as_bytes(),
            )
            .unwrap()
        }

        /// The pure JOIN-ruling decision covers every fail-closed arm the coherent
        /// gate DB cannot construct (the reciprocal entry<->row mapping triggers
        /// force EXACTLY-1:1): 0-match => missing, >1-match => ambiguous (never
        /// picks), digest-hit-but-byte-mismatch => binding mismatch, and the
        /// single-exact-byte match => the located entry.
        #[test]
        fn resolve_single_control_request_origin_covers_join_ruling_arms() {
            let signed = b"the-exact-signed-wrapper".to_vec();
            let located = |signed: &[u8]| {
                (
                    b"payload".to_vec(),
                    signed.to_vec(),
                    b"signing-key".to_vec(),
                )
            };

            // 0 matches -> fail-closed missing.
            assert!(matches!(
                resolve_single_control_request_origin(Vec::new(), &signed),
                Err(ResetLeaveHydrationError::OriginMissing)
            ));
            // >1 match -> fail-closed ambiguous (NEVER picks one).
            assert!(matches!(
                resolve_single_control_request_origin(
                    vec![located(&signed), located(&signed)],
                    &signed,
                ),
                Err(ResetLeaveHydrationError::OriginAmbiguous)
            ));
            // Exactly 1 but bytes differ (digest hit only) -> binding mismatch.
            assert!(matches!(
                resolve_single_control_request_origin(vec![located(b"other-bytes")], &signed),
                Err(ResetLeaveHydrationError::BindingMismatch)
            ));
            // Exactly 1, exact bytes -> the located entry.
            let (payload, bytes, key) =
                resolve_single_control_request_origin(vec![located(&signed)], &signed)
                    .expect("single exact-byte match resolves");
            assert_eq!(payload, b"payload");
            assert_eq!(bytes, signed);
            assert_eq!(key, b"signing-key");
        }

        #[test]
        fn reset_terminal_selector_is_closed_over_every_known_status_shape() {
            let expires_at = instant("2030-02-02T00:00:00.000Z");
            let terminal_at = instant("2030-02-01T00:01:00.000Z");
            let transition_id = Uuid::new_v4();
            let columns = |status, transition, terminal| ResetTerminalColumns {
                status,
                terminal_transition_id: transition,
                terminal_at: terminal,
                expires_at,
            };

            assert!(select_reset_terminal(columns("pending", None, None)).is_ok());
            assert!(select_reset_terminal(columns(
                "stale",
                Some(transition_id),
                Some(terminal_at)
            ))
            .is_ok());
            assert!(select_reset_terminal(columns("expired", None, Some(expires_at))).is_ok());
            assert!(matches!(
                select_reset_terminal(columns("consumed", Some(transition_id), Some(terminal_at))),
                Err(ResetLeaveHydrationError::UnsupportedTerminal)
            ));

            for malformed in [
                columns("pending", Some(transition_id), None),
                columns("pending", None, Some(terminal_at)),
                columns("stale", None, Some(terminal_at)),
                columns("stale", Some(transition_id), None),
                columns("consumed", None, Some(terminal_at)),
                columns("consumed", Some(transition_id), None),
                columns("expired", Some(transition_id), Some(expires_at)),
                columns("expired", None, Some(terminal_at)),
            ] {
                assert!(matches!(
                    select_reset_terminal(malformed),
                    Err(ResetLeaveHydrationError::TerminalMismatch)
                ));
            }
            assert!(matches!(
                select_reset_terminal(columns("future-status", None, None)),
                Err(ResetLeaveHydrationError::OutOfDomain)
            ));
        }

        #[test]
        fn leave_terminal_selector_is_closed_over_every_known_status_shape() {
            let expires_at = instant("2030-02-02T00:00:00.000Z");
            let terminal_at = instant("2030-02-01T00:01:00.000Z");
            let transition_id = Uuid::new_v4();
            let digest = [0x51_u8; 32];
            let columns = |status, request_digest, transition, terminal| LeaveTerminalColumns {
                status,
                terminal_request_digest: request_digest,
                terminal_transition_id: transition,
                terminal_at: terminal,
                expires_at,
            };

            assert!(select_leave_terminal(columns("pending", None, None, None)).is_ok());
            assert!(select_leave_terminal(columns(
                "stale",
                Some(&digest),
                Some(transition_id),
                Some(terminal_at),
            ))
            .is_ok());
            assert!(select_leave_terminal(columns(
                "cancelled",
                Some(&digest),
                None,
                Some(terminal_at),
            ))
            .is_ok());
            assert!(
                select_leave_terminal(columns("expired", None, None, Some(expires_at))).is_ok()
            );
            assert!(matches!(
                select_leave_terminal(columns(
                    "fulfilled",
                    Some(&digest),
                    Some(transition_id),
                    Some(terminal_at),
                )),
                Err(ResetLeaveHydrationError::UnsupportedTerminal)
            ));

            for malformed in [
                columns("pending", Some(&digest), None, None),
                columns("pending", None, Some(transition_id), None),
                columns("pending", None, None, Some(terminal_at)),
                columns("stale", None, Some(transition_id), Some(terminal_at)),
                columns("stale", Some(&digest), None, Some(terminal_at)),
                columns("stale", Some(&digest), Some(transition_id), None),
                columns("fulfilled", None, Some(transition_id), Some(terminal_at)),
                columns("fulfilled", Some(&digest), None, Some(terminal_at)),
                columns("cancelled", None, None, Some(terminal_at)),
                columns(
                    "cancelled",
                    Some(&digest),
                    Some(transition_id),
                    Some(terminal_at),
                ),
                columns("cancelled", Some(&digest), None, None),
                columns("expired", Some(&digest), None, Some(expires_at)),
                columns("expired", None, Some(transition_id), Some(expires_at)),
                columns("expired", None, None, Some(terminal_at)),
            ] {
                assert!(matches!(
                    select_leave_terminal(malformed),
                    Err(ResetLeaveHydrationError::TerminalMismatch)
                ));
            }
            assert!(matches!(
                select_leave_terminal(columns("future-status", None, None, None)),
                Err(ResetLeaveHydrationError::OutOfDomain)
            ));
        }

        /// The pending reset request hydrates: its control-request origin re-mints
        /// byte-equal to the direct in-memory control-path re-hydration, bound to
        /// the genesis active coordinate, terminal `None`.
        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn reset_request_leg_hydrates_the_pending_request() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let request = seed_control_request(
                &pool,
                &entry,
                SignedMutationKind::ResetRequest,
                RESET_ENTRY_KIND,
            )
            .await;
            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, request.seq + 1).unwrap();

            let reference = authority
                .hydrate_historical_control_from_durable_bytes(
                    request.public_row_json.clone(),
                    request.raw_wrapper.clone(),
                    &entry.public_key,
                )
                .expect("in-memory control authority")
                .into_request()
                .expect("reset origin is a control request");

            let mut tx = pool.begin().await.expect("begin");
            let rows = load_reset_request_hydration_rows(&mut tx, &authority, cid)
                .await
                .expect("reset request hydrates");
            tx.commit().await.expect("commit");

            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request_id, request.request_id);
            assert_eq!(row.requester, creator_device(&entry));
            assert_eq!(row.status, ResetRequestStatus::Pending);
            assert!(row.terminal.is_none());
            assert_eq!(row.origin, reference);
        }

        /// A committed reset expiry is selected from the exact durable expiry
        /// shape and re-enters as `Expiry(expires_at)`, never as inferred
        /// transition evidence.
        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn reset_request_leg_hydrates_the_committed_expiry_terminal() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let request = seed_control_request(
                &pool,
                &entry,
                SignedMutationKind::ResetRequest,
                RESET_ENTRY_KIND,
            )
            .await;
            let expires_at = instant(RECEIVED_AT) + Duration::hours(24);

            let mut write = pool.begin().await.expect("begin reset expiry");
            terminalize_reset_request(
                &mut write,
                Uuid::from_bytes(request.request_id),
                &ResetRequestTermination::Expired {
                    terminal_at: expires_at,
                },
            )
            .await
            .expect("terminalize reset as expired");
            write
                .commit()
                .await
                .expect("commit production-valid reset expiry");

            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, request.seq + 1).unwrap();
            let mut read = pool
                .begin()
                .await
                .expect("begin fresh reset expiry hydration");
            let rows = load_reset_request_hydration_rows(&mut read, &authority, cid)
                .await
                .expect("expired reset request hydrates");
            read.rollback().await.expect("rollback read transaction");

            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].status, ResetRequestStatus::Expired);
            assert_eq!(
                rows[0].terminal,
                Some(WorkTerminalHydrationRow::Expiry(
                    ServerTimestamp::from_canonical_stored("2030-02-02T00:00:00.000Z").unwrap(),
                ))
            );
            let aggregate = load_aggregate_hydration(&pool, &entry).await;
            assert_aggregate_hydrates(&entry, aggregate);
        }

        /// The pending leave request hydrates the same way through the leave table +
        /// `leaveRequestEntry` origin.
        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn leave_request_leg_hydrates_the_pending_request() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let request = seed_control_request(
                &pool,
                &entry,
                SignedMutationKind::LeaveRequest,
                LEAVE_ENTRY_KIND,
            )
            .await;
            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, request.seq + 1).unwrap();

            let reference = authority
                .hydrate_historical_control_from_durable_bytes(
                    request.public_row_json.clone(),
                    request.raw_wrapper.clone(),
                    &entry.public_key,
                )
                .expect("in-memory control authority")
                .into_request()
                .expect("leave origin is a control request");

            let mut tx = pool.begin().await.expect("begin");
            let rows = load_leave_request_hydration_rows(&mut tx, &authority, cid)
                .await
                .expect("leave request hydrates");
            tx.commit().await.expect("commit");

            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request_id, request.request_id);
            assert_eq!(row.requester, creator_device(&entry));
            assert_eq!(row.status, LeaveRequestStatus::Pending);
            assert!(row.terminal.is_none());
            assert_eq!(row.origin, reference);
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn leave_request_leg_hydrates_the_committed_expiry_terminal() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let request = seed_control_request(
                &pool,
                &entry,
                SignedMutationKind::LeaveRequest,
                LEAVE_ENTRY_KIND,
            )
            .await;
            let expires_at = instant(RECEIVED_AT) + Duration::hours(24);

            let mut write = pool.begin().await.expect("begin leave expiry");
            terminalize_leave_request(
                &mut write,
                Uuid::from_bytes(request.request_id),
                &LeaveRequestTermination::Expired {
                    terminal_at: expires_at,
                },
            )
            .await
            .expect("terminalize leave as expired");
            write
                .commit()
                .await
                .expect("commit production-valid leave expiry");

            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, request.seq + 1).unwrap();
            let mut read = pool
                .begin()
                .await
                .expect("begin fresh leave expiry hydration");
            let rows = load_leave_request_hydration_rows(&mut read, &authority, cid)
                .await
                .expect("expired leave request hydrates");
            read.rollback().await.expect("rollback read transaction");

            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].status, LeaveRequestStatus::Expired);
            assert_eq!(
                rows[0].terminal,
                Some(WorkTerminalHydrationRow::Expiry(
                    ServerTimestamp::from_canonical_stored("2030-02-02T00:00:00.000Z").unwrap(),
                ))
            );
            let aggregate = load_aggregate_hydration(&pool, &entry).await;
            assert_aggregate_hydrates(&entry, aggregate);
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn reset_and_leave_stale_loaders_use_the_exact_committed_transition() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            for (kind, entry_kind) in [
                (SignedMutationKind::ResetRequest, RESET_ENTRY_KIND),
                (SignedMutationKind::LeaveRequest, LEAVE_ENTRY_KIND),
            ] {
                let cid = Uuid::new_v4();
                let entry = build_real_creation_entry(*cid.as_bytes());
                let request = seed_control_request(&pool, &entry, kind, entry_kind).await;
                let transition = commit_staling_transition(&pool, &entry, &request, kind).await;
                let authority =
                    HistoricalRehydrationAuthority::new(entry.cid, 4).expect("authority");
                let mut read = pool.begin().await.expect("begin fresh stale hydration");
                let terminal = if kind == SignedMutationKind::ResetRequest {
                    let rows = load_reset_request_hydration_rows(&mut read, &authority, cid)
                        .await
                        .expect("stale reset hydrates");
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0].status, ResetRequestStatus::Stale);
                    rows[0].terminal.clone()
                } else {
                    let rows = load_leave_request_hydration_rows(&mut read, &authority, cid)
                        .await
                        .expect("stale leave hydrates");
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0].status, LeaveRequestStatus::Stale);
                    rows[0].terminal.clone()
                };
                read.rollback().await.expect("rollback read transaction");
                let Some(WorkTerminalHydrationRow::Transition(evidence)) = terminal else {
                    panic!("stale request must carry transition evidence");
                };
                assert_eq!(
                    evidence.transition_id(),
                    transition.transition_id.as_bytes()
                );
                assert_eq!(
                    evidence.received_at(),
                    ServerTimestamp::from_canonical_stored(STALE_AT).unwrap()
                );
                let aggregate = load_aggregate_hydration(&pool, &entry).await;
                assert_aggregate_hydrates(&entry, aggregate);
            }
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn stale_aggregate_rejects_wrong_prior_sequence_and_ttl_for_both_families() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            for (kind, entry_kind) in [
                (SignedMutationKind::ResetRequest, RESET_ENTRY_KIND),
                (SignedMutationKind::LeaveRequest, LEAVE_ENTRY_KIND),
            ] {
                // Wrong prior: the subject request is production-valid and
                // terminalized by the first Commit consuming state0. A second
                // genuine committed Commit consumes state1. Replacing only the
                // terminal with that independently loaded current producer keeps
                // request id/requester/origin/TTL and seq/time valid, isolating
                // the consumed-coordinate predicate.
                let cid = Uuid::new_v4();
                let entry = build_real_creation_entry(*cid.as_bytes());
                let request = seed_control_request(&pool, &entry, kind, entry_kind).await;
                commit_staling_transition(&pool, &entry, &request, kind).await;
                commit_followup_transition(&pool, &entry).await;
                let rows = load_aggregate_hydration(&pool, &entry).await;
                let authority = HydrationAuthority::new(entry.cid).expect("aggregate authority");
                assert_aggregate_hydrates(&entry, rows.clone());
                let mut wrong_prior = rows.clone();
                if kind == SignedMutationKind::ResetRequest {
                    wrong_prior.reset_requests[0].terminal =
                        Some(WorkTerminalHydrationRow::Transition(rows.producer.clone()));
                } else {
                    wrong_prior.leave_requests[0].terminal =
                        Some(WorkTerminalHydrationRow::Transition(rows.producer.clone()));
                }
                assert!(matches!(
                    crate::chat_protocol::state_machine::hydrate_conversation_state(
                        &authority,
                        wrong_prior,
                    ),
                    Err(crate::chat_protocol::state_machine::StateMachineError::InvariantViolation)
                ));

                // Wrong sequence: this entire graph commits across the deferred
                // mapper. The transition at seq2 genuinely consumes state0; the
                // later signed request at seq3 is unchanged and bound to state0.
                // Fresh loaders therefore succeed, while aggregate validation
                // rejects only terminal.seq > origin.seq.
                let sequence_cid = Uuid::new_v4();
                let sequence_entry = build_real_creation_entry(*sequence_cid.as_bytes());
                commit_transition_before_stale_request(&pool, &sequence_entry, kind, entry_kind)
                    .await;
                let wrong_sequence = load_aggregate_hydration(&pool, &sequence_entry).await;
                let sequence_authority =
                    HydrationAuthority::new(sequence_entry.cid).expect("sequence authority");
                if kind == SignedMutationKind::ResetRequest {
                    let request = &wrong_sequence.reset_requests[0];
                    let Some(WorkTerminalHydrationRow::Transition(terminal)) = &request.terminal
                    else {
                        panic!("stale reset terminal");
                    };
                    assert!(terminal.seq() <= request.origin.control_seq().unwrap());
                } else {
                    let request = &wrong_sequence.leave_requests[0];
                    let Some(WorkTerminalHydrationRow::Transition(terminal)) = &request.terminal
                    else {
                        panic!("stale leave terminal");
                    };
                    assert!(terminal.seq() <= request.origin.control_seq().unwrap());
                }
                assert!(matches!(
                    crate::chat_protocol::state_machine::hydrate_conversation_state(
                        &sequence_authority,
                        wrong_sequence,
                    ),
                    Err(crate::chat_protocol::state_machine::StateMachineError::InvariantViolation)
                ));

                // Wrong TTL: DDL pins the terminal row, transition accepted_at,
                // and control envelope receivedAt to the exact same instant but
                // does not impose the consent window. Commit at expires_at; the
                // request retains its exact 24-hour expiry and every other
                // terminal predicate remains valid.
                let ttl_cid = Uuid::new_v4();
                let ttl_entry = build_real_creation_entry(*ttl_cid.as_bytes());
                let ttl_request = seed_control_request(&pool, &ttl_entry, kind, entry_kind).await;
                commit_staling_transition_at(
                    &pool,
                    &ttl_entry,
                    &ttl_request,
                    kind,
                    "2030-02-02T00:00:00.000Z",
                )
                .await;
                let wrong_ttl = load_aggregate_hydration(&pool, &ttl_entry).await;
                let ttl_authority = HydrationAuthority::new(ttl_entry.cid).expect("TTL authority");
                if kind == SignedMutationKind::ResetRequest {
                    let request = &wrong_ttl.reset_requests[0];
                    let Some(WorkTerminalHydrationRow::Transition(terminal)) = &request.terminal
                    else {
                        panic!("stale reset terminal");
                    };
                    assert_eq!(terminal.received_at(), request.expires_at);
                } else {
                    let request = &wrong_ttl.leave_requests[0];
                    let Some(WorkTerminalHydrationRow::Transition(terminal)) = &request.terminal
                    else {
                        panic!("stale leave terminal");
                    };
                    assert_eq!(terminal.received_at(), request.expires_at);
                }
                assert!(matches!(
                    crate::chat_protocol::state_machine::hydrate_conversation_state(
                        &ttl_authority,
                        wrong_ttl,
                    ),
                    Err(crate::chat_protocol::state_machine::StateMachineError::InvariantViolation)
                ));
            }
        }

        /// The reset leg fails CLOSED when the read-time authority binds a different
        /// conversation: the located origin entry's own conversation id mismatches
        /// at re-verification (`InvalidOrigin`) — never a fabricated origin.
        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn reset_request_leg_fails_closed_when_authority_binds_a_foreign_conversation() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let _request = seed_control_request(
                &pool,
                &entry,
                SignedMutationKind::ResetRequest,
                RESET_ENTRY_KIND,
            )
            .await;
            let foreign = Uuid::new_v4();
            let authority = HistoricalRehydrationAuthority::new(*foreign.as_bytes(), 3).unwrap();

            let mut tx = pool.begin().await.expect("begin");
            let result = load_reset_request_hydration_rows(&mut tx, &authority, cid).await;
            tx.rollback().await.expect("rollback");

            assert!(matches!(
                result,
                Err(ResetLeaveHydrationError::InvalidOrigin)
            ));
        }

        /// A conversation with no reset/leave requests hydrates an EMPTY collection
        /// (not an error) — the natural no-pending case.
        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn reset_and_leave_legs_hydrate_empty_when_no_requests() {
            let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            seed_real_creation_graph(&pool, &entry).await;
            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();

            let mut tx = pool.begin().await.expect("begin");
            let reset = load_reset_request_hydration_rows(&mut tx, &authority, cid)
                .await
                .expect("empty reset collection");
            let leave = load_leave_request_hydration_rows(&mut tx, &authority, cid)
                .await
                .expect("empty leave collection");
            tx.commit().await.expect("commit");

            assert!(reset.is_empty());
            assert!(leave.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // T4-H2-pre terminal-family sub-seal A — shared terminal reconstruction
    // atom. The first RED is the new global DeviceRevocation arm: a real,
    // Ed25519-signed revokeDevice wrapper is persisted in
    // `chat.device_revocations`, then the production loader must re-read every
    // durable field and return evidence byte-equal to append-time admission.
    // -----------------------------------------------------------------------
    mod terminal_family_atom {
        use base64::{
            engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
            Engine,
        };
        use chrono::{DateTime, Utc};
        use ed25519_dalek::{Signer, SigningKey};
        use serde_json::{json, Value};
        use sha2::{Digest, Sha256};
        use sqlx::{PgPool, Postgres, Transaction};
        use uuid::Uuid;

        use super::super::historical_control_path::{build_real_creation_entry, RealCreationEntry};
        use super::super::historical_signed_path::{
            all_kinds as all_signed_request_wrappers, sample_actor, sample_coordinate,
            trusted_received_at, RECEIVED_AT as SIGNED_REQUEST_RECEIVED_AT,
        };
        use super::reset_leave_leg::{
            build_real_control_request_entry_with_id, build_real_leave_cancellation_entry,
            build_real_leave_cancellation_entry_at, load_aggregate_hydration, seed_control_request,
            RealControlRequestEntry, LEAVE_ENTRY_KIND, RESET_ENTRY_KIND,
        };
        use super::seed_real_creation_graph;
        use crate::chat_protocol::repository::core::{
            load_leave_request_hydration_rows, load_work_terminal_hydration_row,
            resolve_single_terminal_candidate, WorkTerminalHydrationError, WorkTerminalLocator,
            WorkTerminalRequestSource,
        };
        use crate::chat_protocol::repository::{
            delivery::{append_entry_at, AppendEntry},
            transition::{
                cas_conversation_head, cas_registration_revoke, insert_device_revocation,
                terminalize_leave_request, ConversationHeadCas, LeaveRequestTermination,
                NewDeviceRevocation, RegistrationRevoke,
            },
        };
        use crate::chat_protocol::state_machine::{
            DurableSignedRequestEnvelope, HistoricalRehydrationAuthority, HydrationAuthority,
            LeaveRequestStatus, RequestEntryKind, ServerTimestamp, WorkTerminalHydrationRow,
        };
        use crate::chat_protocol::transcript::{
            decode_and_verify_control_entry, decode_and_verify_signed_mutation,
            decode_canonical_signed_mutation, SignedMutationKind, VerifiedMutationProjection,
        };
        use crate::chat_protocol::validation::{
            ed25519_key_id, CanonicalTimestamp, TrustedRequestInstant,
        };
        use crate::common;

        const SIGNED_AT: &str = "2030-03-01T00:00:00.000Z";
        const ACCEPTED_AT: &str = "2030-03-01T00:00:01.000Z";

        struct RealDeviceRevocation {
            revocation_id: Uuid,
            target_device_id: Uuid,
            raw_wrapper: Vec<u8>,
            signing_transcript: Vec<u8>,
            request_digest: Vec<u8>,
            signature: Vec<u8>,
        }

        fn instant(text: &str) -> DateTime<Utc> {
            DateTime::parse_from_rfc3339(text)
                .expect("canonical instant")
                .with_timezone(&Utc)
        }

        #[allow(clippy::too_many_arguments)]
        async fn append_control_entry_fixture(
            transaction: &mut Transaction<'_, Postgres>,
            signer: &RealCreationEntry,
            control: &RealControlRequestEntry,
            entry_kind: &str,
            seq: u64,
            stored_signed_request_bytes: &[u8],
            stored_request_digest: &[u8],
            received_at: DateTime<Utc>,
        ) {
            let decoded =
                decode_and_verify_control_entry(&control.public_row_json, &signer.public_key)
                    .expect("fixture control envelope verifies");
            append_entry_at(
                transaction,
                &AppendEntry {
                    conversation_id: Uuid::from_bytes(signer.cid),
                    entry_id: control.entry_id,
                    entry_kind: entry_kind.to_owned(),
                    accepted_payload_bytes: control.public_row_json.clone(),
                    accepted_payload_sha256: Sha256::digest(&control.public_row_json).to_vec(),
                    signed_request_bytes: stored_signed_request_bytes.to_vec(),
                    request_digest: stored_request_digest.to_vec(),
                    signature: control.signature.clone(),
                    server_fields_bytes: decoded.server_fields_dag_cbor().unwrap(),
                    outer_entry_fingerprint: control.outer_entry_fingerprint.clone(),
                    actor_did: signer.actor_did.clone(),
                    actor_device_id: signer.actor_device_id,
                    actor_key_id: signer.actor_key_id.clone(),
                    actor_auth_generation: 1,
                    generation: None,
                    state_version: None,
                    transition_id: None,
                    message_id: None,
                    received_at,
                },
                seq,
            )
            .await
            .expect("append control fixture");
        }

        #[allow(clippy::too_many_arguments)]
        async fn commit_cancelled_leave_entry(
            pool: &PgPool,
            signer: &RealCreationEntry,
            leave: &RealControlRequestEntry,
            cancellation: &RealControlRequestEntry,
            stored_signed_request_bytes: &[u8],
            stored_request_digest: &[u8],
            entry_received_at: DateTime<Utc>,
            terminal_at: DateTime<Utc>,
        ) {
            let cid = Uuid::from_bytes(signer.cid);
            let mut tx = pool.begin().await.expect("begin cancelled leave fixture");
            cas_conversation_head(
                &mut tx,
                &ConversationHeadCas {
                    conversation_id: cid,
                    expected_generation: 0,
                    expected_state_version: 0,
                    expected_next_entry_seq: 3,
                    successor_generation: 0,
                    successor_state_version: 0,
                    successor_next_entry_seq: 4,
                    close: None,
                },
            )
            .await
            .expect("advance cancellation fixture head");
            append_control_entry_fixture(
                &mut tx,
                signer,
                cancellation,
                "blue.catbird.chat.defs#leaveCancellationEntry",
                3,
                stored_signed_request_bytes,
                stored_request_digest,
                entry_received_at,
            )
            .await;
            terminalize_leave_request(
                &mut tx,
                Uuid::from_bytes(leave.request_id),
                &LeaveRequestTermination::Cancelled {
                    terminal_request_digest: stored_request_digest.to_vec(),
                    terminal_at,
                },
            )
            .await
            .expect("terminalize cancellation fixture");
            tx.commit()
                .await
                .expect("commit complete cancelled leave fixture");
        }

        async fn commit_cancellation_before_leave_origin(
            pool: &PgPool,
            entry: &RealCreationEntry,
        ) -> RealControlRequestEntry {
            const CANCELLATION_ENTRY_KIND: &str = "blue.catbird.chat.defs#leaveCancellationEntry";
            seed_real_creation_graph(pool, entry).await;
            let request_id = Uuid::new_v4();
            let cancellation = build_real_leave_cancellation_entry(
                entry,
                *request_id.as_bytes(),
                CANCELLATION_ENTRY_KIND,
                2,
            );
            let leave = build_real_control_request_entry_with_id(
                entry,
                SignedMutationKind::LeaveRequest,
                LEAVE_ENTRY_KIND,
                3,
                request_id,
            );
            let cid = Uuid::from_bytes(entry.cid);
            let received_at = instant("2030-02-01T00:00:00.000Z");
            let expires_at = instant("2030-02-02T00:00:00.000Z");

            let mut tx = pool
                .begin()
                .await
                .expect("begin cancellation-before-origin graph");
            cas_conversation_head(
                &mut tx,
                &ConversationHeadCas {
                    conversation_id: cid,
                    expected_generation: 0,
                    expected_state_version: 0,
                    expected_next_entry_seq: 2,
                    successor_generation: 0,
                    successor_state_version: 0,
                    successor_next_entry_seq: 4,
                    close: None,
                },
            )
            .await
            .expect("advance head over cancellation and origin");
            append_control_entry_fixture(
                &mut tx,
                entry,
                &cancellation,
                CANCELLATION_ENTRY_KIND,
                2,
                &cancellation.raw_wrapper,
                &cancellation.request_digest,
                received_at,
            )
            .await;
            append_control_entry_fixture(
                &mut tx,
                entry,
                &leave,
                LEAVE_ENTRY_KIND,
                3,
                &leave.raw_wrapper,
                &leave.request_digest,
                received_at,
            )
            .await;
            sqlx::query(
                r#"INSERT INTO chat.leave_requests(
                    leave_request_id,conversation_id,requester_did,requester_device_id,
                    requester_key_id,requester_auth_generation,prior_generation,
                    prior_state_version,prior_group_id,prior_epoch,prior_group_context_hash,
                    prior_confirmation_tag,status,signed_request_bytes,signing_transcript_bytes,
                    request_digest,signature,terminal_request_digest,received_at,expires_at,
                    terminal_at
                ) VALUES($1,$2,$3,$4,$5,1,0,0,$6,0,$7,$8,'cancelled',$9,$10,$11,$12,
                    $13,$14,$15,$14)"#,
            )
            .bind(request_id)
            .bind(cid)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(vec![1_u8; 32])
            .bind(vec![2_u8; 32])
            .bind(vec![3_u8; 32])
            .bind(&leave.raw_wrapper)
            .bind(&leave.signing_transcript)
            .bind(&leave.request_digest)
            .bind(&leave.signature)
            .bind(&cancellation.request_digest)
            .bind(received_at)
            .bind(expires_at)
            .execute(&mut *tx)
            .await
            .expect("insert cancelled leave with earlier terminal");
            tx.commit()
                .await
                .expect("commit cancellation-before-origin graph");
            leave
        }

        fn build_real_device_revocation(
            entry: &RealCreationEntry,
            target_device_id: Uuid,
        ) -> RealDeviceRevocation {
            let signing_key = entry.signing_key();
            let verifying = signing_key.verifying_key().to_bytes();
            assert_eq!(entry.public_key, verifying);
            assert_eq!(
                entry.actor_key_id,
                ed25519_key_id(&verifying).unwrap().as_str()
            );

            let revocation_id = Uuid::new_v4();
            let body = json!({
                "$type": SignedMutationKind::DeviceRevocation.type_id(),
                "signatureDomain":
                    String::from_utf8(SignedMutationKind::DeviceRevocation.domain().to_vec())
                        .unwrap(),
                "actorDid": entry.actor_did,
                "actorDeviceId": entry.actor_device_id.hyphenated().to_string(),
                "keyId": entry.actor_key_id,
                "authGeneration": 1,
                "targetDeviceId": target_device_id.hyphenated().to_string(),
                "targetAuthGeneration": 1,
                "idempotencyKey": revocation_id.hyphenated().to_string(),
                "signedAt": SIGNED_AT,
            });
            let mut wrapper = json!({ "body": body, "signature": "" });
            wrapper["signature"] = Value::String(STANDARD.encode([0_u8; 64]));
            let unsigned = serde_json::to_vec(&wrapper).unwrap();
            let canonical = decode_canonical_signed_mutation(&unsigned).unwrap();
            let signing_transcript = canonical.transcript_bytes().to_vec();
            let signature = signing_key.sign(&signing_transcript).to_bytes();
            wrapper["signature"] = Value::String(STANDARD.encode(signature));
            let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();

            decode_and_verify_signed_mutation(&raw_wrapper, &verifying)
                .expect("device-revocation wrapper is genuinely signed");

            RealDeviceRevocation {
                revocation_id,
                target_device_id,
                raw_wrapper,
                request_digest: Sha256::digest(&signing_transcript).to_vec(),
                signature: signature.to_vec(),
                signing_transcript,
            }
        }

        async fn seed_revocation_target_device(pool: &PgPool, entry: &RealCreationEntry) -> Uuid {
            let target_device_id = Uuid::new_v4();
            let mut target_secret = [0_u8; 32];
            target_secret[..16].copy_from_slice(target_device_id.as_bytes());
            target_secret[16..].copy_from_slice(Uuid::new_v4().as_bytes());
            let target_public_key = SigningKey::from_bytes(&target_secret)
                .verifying_key()
                .to_bytes();
            let target_key_id = ed25519_key_id(&target_public_key)
                .unwrap()
                .as_str()
                .to_owned();
            let target_dpop_jkt =
                URL_SAFE_NO_PAD.encode(Sha256::digest(target_device_id.as_bytes()));
            let created_at = instant("2030-02-28T00:00:00.000Z");

            let mut tx = pool.begin().await.expect("begin target registration");
            sqlx::query(
                r#"INSERT INTO chat.devices(
                    user_did,device_id,device_name,status,dpop_jkt,auth_generation,
                    capabilities,created_at,updated_at
                ) VALUES($1,$2,'terminal-revocation-target','active',$3,1,
                    chat.protocol_capabilities(),$4,$4)"#,
            )
            .bind(&entry.actor_did)
            .bind(target_device_id)
            .bind(target_dpop_jkt)
            .bind(created_at)
            .execute(&mut *tx)
            .await
            .expect("insert isolated target device");
            sqlx::query(
                r#"INSERT INTO chat.device_keys(
                    user_did,device_id,key_id,signing_public_key,
                    enrollment_auth_generation,created_at
                ) VALUES($1,$2,$3,$4,1,$5)"#,
            )
            .bind(&entry.actor_did)
            .bind(target_device_id)
            .bind(target_key_id)
            .bind(target_public_key.to_vec())
            .bind(created_at)
            .execute(&mut *tx)
            .await
            .expect("insert isolated target device key");
            tx.commit()
                .await
                .expect("commit isolated target registration");

            target_device_id
        }

        async fn insert_uncommitted_device_revocation_fixture(
            transaction: &mut Transaction<'_, Postgres>,
            entry: &RealCreationEntry,
            revocation: &RealDeviceRevocation,
            actor_auth_generation: i64,
            stored_signature: &[u8],
        ) {
            sqlx::query(
                r#"INSERT INTO chat.device_revocations(
                    revocation_id,actor_did,actor_device_id,actor_key_id,
                    actor_auth_generation,target_did,target_device_id,
                    target_auth_generation,accepted_request_bytes,
                    signing_transcript_bytes,request_digest,signature,signed_at,accepted_at
                ) VALUES($1,$2,$3,$4,$5,$2,$3,1,$6,$7,$8,$9,$10,$11)"#,
            )
            .bind(revocation.revocation_id)
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(actor_auth_generation)
            .bind(&revocation.raw_wrapper)
            .bind(&revocation.signing_transcript)
            .bind(&revocation.request_digest)
            .bind(stored_signature)
            .bind(instant(SIGNED_AT))
            .bind(instant(ACCEPTED_AT))
            .execute(&mut **transaction)
            .await
            .expect("insert exact durable device revocation");
        }

        async fn commit_device_revocation_footprint(
            pool: &PgPool,
            entry: &RealCreationEntry,
            revocation: &RealDeviceRevocation,
        ) {
            let accepted_at = instant(ACCEPTED_AT);
            let mut tx = pool.begin().await.expect("begin complete revocation");

            insert_device_revocation(
                &mut tx,
                &NewDeviceRevocation {
                    revocation_id: revocation.revocation_id,
                    actor_did: entry.actor_did.clone(),
                    actor_device_id: entry.actor_device_id,
                    actor_key_id: entry.actor_key_id.clone(),
                    actor_auth_generation: 1,
                    target_did: entry.actor_did.clone(),
                    target_device_id: revocation.target_device_id,
                    target_auth_generation: 1,
                    accepted_request_bytes: revocation.raw_wrapper.clone(),
                    signing_transcript_bytes: revocation.signing_transcript.clone(),
                    request_digest: revocation.request_digest.clone(),
                    signature: revocation.signature.clone(),
                    signed_at: instant(SIGNED_AT),
                    accepted_at,
                },
            )
            .await
            .expect("production revocation row writer");
            cas_registration_revoke(
                &mut tx,
                &RegistrationRevoke {
                    target_did: entry.actor_did.clone(),
                    target_device_id: revocation.target_device_id,
                    expected_auth_generation: 1,
                    revocation_id: revocation.revocation_id,
                    revoked_at: accepted_at,
                },
            )
            .await
            .expect("production registration revoke writer");

            let response_bytes = b"terminal-family-revoke-ok".to_vec();
            sqlx::query(
                r#"INSERT INTO chat.idempotency_records(
                    principal_did,endpoint_nsid,operation_id,request_digest,
                    accepted_request_bytes,signing_transcript_bytes,signature,
                    completed_status,response_bytes,response_sha256,event_position,
                    historical_jkt,current_jkt,completed_at
                ) VALUES($1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,200,$7,$8,NULL,$9,NULL,$10)"#,
            )
            .bind(&entry.actor_did)
            .bind(revocation.revocation_id)
            .bind(&revocation.request_digest)
            .bind(&revocation.raw_wrapper)
            .bind(&revocation.signing_transcript)
            .bind(&revocation.signature)
            .bind(&response_bytes)
            .bind(Sha256::digest(&response_bytes).to_vec())
            .bind(&entry.actor_key_id)
            .bind(accepted_at)
            .execute(&mut *tx)
            .await
            .expect("exact revokeDevice completion receipt");

            tx.commit()
                .await
                .expect("commit complete production-valid revocation footprint");
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn device_revocation_terminal_reconstructs_the_exact_verified_row() {
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            seed_real_creation_graph(&pool, &entry).await;
            let target_device_id = seed_revocation_target_device(&pool, &entry).await;
            let revocation = build_real_device_revocation(&entry, target_device_id);

            let mutation =
                decode_and_verify_signed_mutation(&revocation.raw_wrapper, &entry.public_key)
                    .expect("reference mutation verifies");
            let accepted_at = TrustedRequestInstant::from_canonical_for_test(
                CanonicalTimestamp::parse(ACCEPTED_AT).unwrap(),
            );
            let expected = HydrationAuthority::new(entry.cid)
                .unwrap()
                .device_revocation(mutation, &accepted_at)
                .expect("append-time revocation evidence");
            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();

            commit_device_revocation_footprint(&pool, &entry, &revocation).await;

            let mut tx = pool
                .begin()
                .await
                .expect("begin fresh hydration transaction");
            let loaded = load_work_terminal_hydration_row(
                &mut tx,
                &authority,
                cid,
                WorkTerminalLocator::DeviceRevocation {
                    revocation_id: revocation.revocation_id,
                },
            )
            .await
            .expect("device revocation terminal reconstructs");
            tx.commit().await.expect("commit read transaction");

            assert_eq!(
                loaded,
                WorkTerminalHydrationRow::DeviceRevocation(expected),
                "the durable row re-enters as the exact append-time evidence",
            );
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn device_revocation_terminal_fails_closed_on_stored_signature_tamper() {
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            seed_real_creation_graph(&pool, &entry).await;
            let revocation = build_real_device_revocation(&entry, entry.actor_device_id);
            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();
            let mut tampered_signature = revocation.signature.clone();
            tampered_signature[0] ^= 0x01;

            let mut tx = pool.begin().await.expect("begin");
            insert_uncommitted_device_revocation_fixture(
                &mut tx,
                &entry,
                &revocation,
                1,
                &tampered_signature,
            )
            .await;
            let loaded = load_work_terminal_hydration_row(
                &mut tx,
                &authority,
                cid,
                WorkTerminalLocator::DeviceRevocation {
                    revocation_id: revocation.revocation_id,
                },
            )
            .await;
            tx.rollback()
                .await
                .expect("rollback deferred fixture graph");

            assert!(
                loaded.is_err(),
                "a signed-field mismatch between wrapper and durable row must fail closed",
            );
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn device_revocation_terminal_fails_closed_on_durable_generation_tamper() {
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            seed_real_creation_graph(&pool, &entry).await;
            let revocation = build_real_device_revocation(&entry, entry.actor_device_id);
            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();

            let mut tx = pool.begin().await.expect("begin");
            insert_uncommitted_device_revocation_fixture(
                &mut tx,
                &entry,
                &revocation,
                2,
                &revocation.signature,
            )
            .await;
            let loaded = load_work_terminal_hydration_row(
                &mut tx,
                &authority,
                cid,
                WorkTerminalLocator::DeviceRevocation {
                    revocation_id: revocation.revocation_id,
                },
            )
            .await;
            tx.rollback()
                .await
                .expect("rollback deferred fixture graph");

            assert!(
                loaded.is_err(),
                "a durable actor-generation mismatch must fail closed",
            );
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn transition_terminal_reconstructs_only_the_exact_verified_transition() {
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let transition_id = seed_real_creation_graph(&pool, &entry).await;
            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();

            let mut tx = pool.begin().await.expect("begin");
            let expected = authority
                .hydrate_historical_control_from_durable_bytes(
                    entry.public_row_json.clone(),
                    entry.raw_wrapper.clone(),
                    &entry.public_key,
                )
                .expect("independent in-memory control re-verification")
                .into_transition()
                .expect("creation is transition evidence");
            let loaded = load_work_terminal_hydration_row(
                &mut tx,
                &authority,
                cid,
                WorkTerminalLocator::Transition { transition_id },
            )
            .await
            .expect("transition terminal reconstructs");
            tx.commit().await.expect("commit");

            assert_eq!(loaded, WorkTerminalHydrationRow::Transition(expected));
        }

        /// A locator names the durable direct cause, not merely an entry lookup
        /// key. The frozen DDL permits a complete committed graph whose transition
        /// and entry columns use X while the genuinely signed control body attests
        /// Y; the shared atom must reject that mismatch after re-verification.
        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn transition_terminal_rejects_committed_durable_id_signed_as_another_transition() {
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let signed_transition_id = super::signed_creation_transition_id(&entry);
            let durable_transition_id = Uuid::new_v4();
            assert_ne!(durable_transition_id, signed_transition_id);
            super::seed_real_creation_graph_with_transition_id(
                &pool,
                &entry,
                durable_transition_id,
            )
            .await;
            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();

            let mut tx = pool
                .begin()
                .await
                .expect("begin fresh mismatched transition read");
            let loaded = load_work_terminal_hydration_row(
                &mut tx,
                &authority,
                cid,
                WorkTerminalLocator::Transition {
                    transition_id: durable_transition_id,
                },
            )
            .await;
            tx.rollback().await.expect("rollback read transaction");

            assert!(matches!(
                loaded,
                Err(WorkTerminalHydrationError::InvalidEvidence)
            ));
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn expiry_terminal_preserves_only_the_typed_timestamp_arm() {
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(1).await;
            let cid = Uuid::new_v4();
            let authority = HistoricalRehydrationAuthority::new(*cid.as_bytes(), 2).unwrap();
            let terminal_at = instant(ACCEPTED_AT);
            let expected = ServerTimestamp::from_canonical_stored(ACCEPTED_AT).unwrap();

            let mut tx = pool.begin().await.expect("begin");
            let loaded = load_work_terminal_hydration_row(
                &mut tx,
                &authority,
                cid,
                WorkTerminalLocator::Expiry { terminal_at },
            )
            .await
            .expect("expiry terminal reconstructs");
            tx.rollback().await.expect("rollback");

            assert_eq!(loaded, WorkTerminalHydrationRow::Expiry(expected));
            assert!(
                !matches!(
                    loaded,
                    WorkTerminalHydrationRow::Transition(_)
                        | WorkTerminalHydrationRow::Request(_)
                        | WorkTerminalHydrationRow::DeviceRevocation(_)
                ),
                "expiry cannot be confused with an evidence-bearing arm",
            );
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn control_request_terminal_uses_the_control_verifier_for_reset_and_leave() {
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
            for (signed_kind, request_kind, entry_kind) in [
                (
                    SignedMutationKind::ResetRequest,
                    RequestEntryKind::ResetRequest,
                    RESET_ENTRY_KIND,
                ),
                (
                    SignedMutationKind::LeaveRequest,
                    RequestEntryKind::LeaveRequest,
                    LEAVE_ENTRY_KIND,
                ),
            ] {
                let cid = Uuid::new_v4();
                let entry = build_real_creation_entry(*cid.as_bytes());
                let request = seed_control_request(&pool, &entry, signed_kind, entry_kind).await;
                let authority =
                    HistoricalRehydrationAuthority::new(entry.cid, request.seq + 1).unwrap();
                let expected = authority
                    .hydrate_historical_control_from_durable_bytes(
                        request.public_row_json.clone(),
                        request.raw_wrapper.clone(),
                        &entry.public_key,
                    )
                    .expect("reference control evidence")
                    .into_request()
                    .expect("control request");

                let mut tx = pool.begin().await.expect("begin");
                let loaded = load_work_terminal_hydration_row(
                    &mut tx,
                    &authority,
                    cid,
                    WorkTerminalLocator::Request {
                        kind: request_kind,
                        source: WorkTerminalRequestSource::Control {
                            request_digest: &request.request_digest,
                            signed_request_bytes: &request.raw_wrapper,
                        },
                    },
                )
                .await
                .expect("control request terminal reconstructs");
                tx.commit().await.expect("commit");

                assert_eq!(loaded, WorkTerminalHydrationRow::Request(expected));
            }
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn leave_cancellation_terminal_uses_the_control_entry_verifier() {
            const CANCELLATION_ENTRY_KIND: &str = "blue.catbird.chat.defs#leaveCancellationEntry";

            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let leave = seed_control_request(
                &pool,
                &entry,
                SignedMutationKind::LeaveRequest,
                LEAVE_ENTRY_KIND,
            )
            .await;
            let cancellation = build_real_leave_cancellation_entry(
                &entry,
                leave.request_id,
                CANCELLATION_ENTRY_KIND,
                3,
            );
            let verified_cancellation =
                decode_and_verify_signed_mutation(&cancellation.raw_wrapper, &entry.public_key)
                    .expect("cancellation wrapper is genuinely signed");
            let signed_leave_request_id = match verified_cancellation.projection() {
                VerifiedMutationProjection::LeaveCancellation(body) => {
                    *body.leave_request_id().as_bytes()
                }
                _ => panic!("fixture must be a leave cancellation"),
            };
            assert_eq!(
                signed_leave_request_id, leave.request_id,
                "the signed cancellation body must name the exact pending leave request",
            );
            let authority = HistoricalRehydrationAuthority::new(entry.cid, 4).unwrap();
            let expected = authority
                .hydrate_historical_control_from_durable_bytes(
                    cancellation.public_row_json.clone(),
                    cancellation.raw_wrapper.clone(),
                    &entry.public_key,
                )
                .expect("reference cancellation control evidence")
                .into_request()
                .expect("leave cancellation is a control request");

            commit_cancelled_leave_entry(
                &pool,
                &entry,
                &leave,
                &cancellation,
                &cancellation.raw_wrapper,
                &cancellation.request_digest,
                instant("2030-02-01T00:00:00.000Z"),
                instant("2030-02-01T00:00:00.000Z"),
            )
            .await;

            let mut tx = pool
                .begin()
                .await
                .expect("begin fresh hydration transaction");
            let loaded = load_work_terminal_hydration_row(
                &mut tx,
                &authority,
                cid,
                WorkTerminalLocator::Request {
                    kind: RequestEntryKind::LeaveCancellation,
                    source: WorkTerminalRequestSource::Control {
                        request_digest: &cancellation.request_digest,
                        signed_request_bytes: &cancellation.raw_wrapper,
                    },
                },
            )
            .await
            .expect("leave cancellation terminal reconstructs");
            tx.commit().await.expect("commit read transaction");

            assert_eq!(loaded, WorkTerminalHydrationRow::Request(expected.clone()));

            let mut tx = pool
                .begin()
                .await
                .expect("begin fresh cancelled leave hydration");
            let rows = load_leave_request_hydration_rows(&mut tx, &authority, cid)
                .await
                .expect("cancelled leave request hydrates");
            tx.rollback().await.expect("rollback read transaction");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].status, LeaveRequestStatus::Cancelled);
            assert_eq!(
                rows[0].terminal,
                Some(WorkTerminalHydrationRow::Request(expected.clone()))
            );
            let aggregate = super::reset_leave_leg::load_aggregate_hydration(&pool, &entry).await;
            let authority = HydrationAuthority::new(entry.cid).expect("aggregate authority");
            crate::chat_protocol::state_machine::hydrate_conversation_state(&authority, aggregate)
                .expect("cancelled leave passes production aggregate hydration");

            // The frozen DDL intentionally permits more than one committed
            // leaveCancellationEntry to map to the same cancelled leave row.
            // Append a second immutable control envelope carrying the same signed
            // cancellation/digest; the production lookup must fetch-all and fail
            // closed rather than select either candidate.
            let duplicate_entry_id = Uuid::new_v4();
            let duplicate_wrapper: Value =
                serde_json::from_slice(&cancellation.raw_wrapper).unwrap();
            let duplicate_payload = serde_json::to_vec(&json!({
                "$type": CANCELLATION_ENTRY_KIND,
                "entryId": duplicate_entry_id.hyphenated().to_string(),
                "conversationId": cid.hyphenated().to_string(),
                "seq": 4,
                "signedRequest": duplicate_wrapper,
                "receivedAt": "2030-02-01T00:00:00.000Z",
            }))
            .unwrap();
            let duplicate_decoded =
                decode_and_verify_control_entry(&duplicate_payload, &entry.public_key)
                    .expect("duplicate cancellation envelope verifies");
            let mut write = pool.begin().await.expect("begin duplicate cancellation");
            cas_conversation_head(
                &mut write,
                &ConversationHeadCas {
                    conversation_id: cid,
                    expected_generation: 0,
                    expected_state_version: 0,
                    expected_next_entry_seq: 4,
                    successor_generation: 0,
                    successor_state_version: 0,
                    successor_next_entry_seq: 5,
                    close: None,
                },
            )
            .await
            .expect("advance head for duplicate cancellation");
            append_entry_at(
                &mut write,
                &AppendEntry {
                    conversation_id: cid,
                    entry_id: duplicate_entry_id,
                    entry_kind: CANCELLATION_ENTRY_KIND.to_owned(),
                    accepted_payload_bytes: duplicate_payload.clone(),
                    accepted_payload_sha256: Sha256::digest(&duplicate_payload).to_vec(),
                    signed_request_bytes: cancellation.raw_wrapper.clone(),
                    request_digest: cancellation.request_digest.clone(),
                    signature: cancellation.signature.clone(),
                    server_fields_bytes: duplicate_decoded.server_fields_dag_cbor().unwrap(),
                    outer_entry_fingerprint: duplicate_decoded.outer_control_fingerprint().to_vec(),
                    actor_did: entry.actor_did.clone(),
                    actor_device_id: entry.actor_device_id,
                    actor_key_id: entry.actor_key_id.clone(),
                    actor_auth_generation: 1,
                    generation: None,
                    state_version: None,
                    transition_id: None,
                    message_id: None,
                    received_at: instant("2030-02-01T00:00:00.000Z"),
                },
                4,
            )
            .await
            .expect("append duplicate cancellation");
            write
                .commit()
                .await
                .expect("commit DDL-permitted duplicate cancellation");

            let ambiguous_authority =
                HistoricalRehydrationAuthority::new(entry.cid, 5).expect("advanced authority");
            let mut read = pool
                .begin()
                .await
                .expect("begin ambiguous cancellation read");
            let ambiguous =
                load_leave_request_hydration_rows(&mut read, &ambiguous_authority, cid).await;
            read.rollback().await.expect("rollback read transaction");
            assert!(matches!(
                ambiguous,
                Err(crate::chat_protocol::repository::core::ResetLeaveHydrationError::InvalidTerminal)
            ));
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn cancelled_leave_aggregate_isolates_target_sequence_ttl_kind_and_principal() {
            const CANCELLATION_ENTRY_KIND: &str = "blue.catbird.chat.defs#leaveCancellationEntry";
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;

            // Wrong target is commit-valid: DDL maps actor/digest/time but cannot
            // inspect the genuinely signed cancellation body's leaveRequestId.
            let target_cid = Uuid::new_v4();
            let target_entry = build_real_creation_entry(*target_cid.as_bytes());
            let target_leave = seed_control_request(
                &pool,
                &target_entry,
                SignedMutationKind::LeaveRequest,
                LEAVE_ENTRY_KIND,
            )
            .await;
            let wrong_target_cancellation = build_real_leave_cancellation_entry(
                &target_entry,
                *Uuid::new_v4().as_bytes(),
                CANCELLATION_ENTRY_KIND,
                3,
            );
            commit_cancelled_leave_entry(
                &pool,
                &target_entry,
                &target_leave,
                &wrong_target_cancellation,
                &wrong_target_cancellation.raw_wrapper,
                &wrong_target_cancellation.request_digest,
                instant("2030-02-01T00:00:00.000Z"),
                instant("2030-02-01T00:00:00.000Z"),
            )
            .await;
            let wrong_target = load_aggregate_hydration(&pool, &target_entry).await;
            let target_authority =
                HydrationAuthority::new(target_entry.cid).expect("target authority");
            let Some(WorkTerminalHydrationRow::Request(target_terminal)) =
                &wrong_target.leave_requests[0].terminal
            else {
                panic!("cancelled target terminal");
            };
            assert_ne!(
                target_terminal.request_id(),
                &wrong_target.leave_requests[0].request_id
            );
            assert!(matches!(
                crate::chat_protocol::state_machine::hydrate_conversation_state(
                    &target_authority,
                    wrong_target,
                ),
                Err(crate::chat_protocol::state_machine::StateMachineError::InvariantViolation)
            ));

            // Wrong sequence is also commit-valid: the cancellation entry is seq2
            // and the exact signed leave origin is seq3. All immutable request
            // fields and the cancellation's target/principal/time remain exact.
            let sequence_cid = Uuid::new_v4();
            let sequence_entry = build_real_creation_entry(*sequence_cid.as_bytes());
            commit_cancellation_before_leave_origin(&pool, &sequence_entry).await;
            let wrong_sequence = load_aggregate_hydration(&pool, &sequence_entry).await;
            let sequence_authority =
                HydrationAuthority::new(sequence_entry.cid).expect("sequence authority");
            let sequence_request = &wrong_sequence.leave_requests[0];
            let Some(WorkTerminalHydrationRow::Request(sequence_terminal)) =
                &sequence_request.terminal
            else {
                panic!("cancelled sequence terminal");
            };
            assert!(
                sequence_terminal.control_seq().unwrap()
                    <= sequence_request.origin.control_seq().unwrap()
            );
            assert!(matches!(
                crate::chat_protocol::state_machine::hydrate_conversation_state(
                    &sequence_authority,
                    wrong_sequence,
                ),
                Err(crate::chat_protocol::state_machine::StateMachineError::InvariantViolation)
            ));

            // Wrong TTL commits because DDL equates the terminal row and entry
            // column times but does not compare them with the consent expiry. The
            // signed outer envelope also carries expires_at exactly, so the loader
            // succeeds and only the strict aggregate time window rejects it.
            let ttl_cid = Uuid::new_v4();
            let ttl_entry = build_real_creation_entry(*ttl_cid.as_bytes());
            let ttl_leave = seed_control_request(
                &pool,
                &ttl_entry,
                SignedMutationKind::LeaveRequest,
                LEAVE_ENTRY_KIND,
            )
            .await;
            let ttl_cancellation = build_real_leave_cancellation_entry_at(
                &ttl_entry,
                ttl_leave.request_id,
                CANCELLATION_ENTRY_KIND,
                3,
                "2030-02-02T00:00:00.000Z",
            );
            let expires_at = instant("2030-02-02T00:00:00.000Z");
            commit_cancelled_leave_entry(
                &pool,
                &ttl_entry,
                &ttl_leave,
                &ttl_cancellation,
                &ttl_cancellation.raw_wrapper,
                &ttl_cancellation.request_digest,
                expires_at,
                expires_at,
            )
            .await;
            let wrong_ttl = load_aggregate_hydration(&pool, &ttl_entry).await;
            let ttl_authority = HydrationAuthority::new(ttl_entry.cid).expect("TTL authority");
            let ttl_request = &wrong_ttl.leave_requests[0];
            let Some(WorkTerminalHydrationRow::Request(ttl_terminal)) = &ttl_request.terminal
            else {
                panic!("cancelled TTL terminal");
            };
            assert_eq!(ttl_terminal.received_at(), ttl_request.expires_at);
            assert!(matches!(
                crate::chat_protocol::state_machine::hydrate_conversation_state(
                    &ttl_authority,
                    wrong_ttl,
                ),
                Err(crate::chat_protocol::state_machine::StateMachineError::InvariantViolation)
            ));

            // Wrong kind cannot commit as the cancelled row's direct mapping:
            // the reciprocal mapper requires leaveCancellationEntry. Produce the
            // independently verified same-conversation/same-target/later Reset
            // evidence in a fresh transaction, then splice only the terminal.
            let kind_cid = Uuid::new_v4();
            let kind_entry = build_real_creation_entry(*kind_cid.as_bytes());
            let kind_leave = seed_control_request(
                &pool,
                &kind_entry,
                SignedMutationKind::LeaveRequest,
                LEAVE_ENTRY_KIND,
            )
            .await;
            let valid_kind_cancellation = build_real_leave_cancellation_entry(
                &kind_entry,
                kind_leave.request_id,
                CANCELLATION_ENTRY_KIND,
                3,
            );
            commit_cancelled_leave_entry(
                &pool,
                &kind_entry,
                &kind_leave,
                &valid_kind_cancellation,
                &valid_kind_cancellation.raw_wrapper,
                &valid_kind_cancellation.request_digest,
                instant("2030-02-01T00:00:00.000Z"),
                instant("2030-02-01T00:00:00.000Z"),
            )
            .await;
            let mut wrong_kind = load_aggregate_hydration(&pool, &kind_entry).await;
            let reset_evidence_entry = build_real_control_request_entry_with_id(
                &kind_entry,
                SignedMutationKind::ResetRequest,
                RESET_ENTRY_KIND,
                4,
                Uuid::from_bytes(kind_leave.request_id),
            );
            let mut kind_tx = pool.begin().await.expect("begin wrong-kind evidence");
            append_control_entry_fixture(
                &mut kind_tx,
                &kind_entry,
                &reset_evidence_entry,
                RESET_ENTRY_KIND,
                4,
                &reset_evidence_entry.raw_wrapper,
                &reset_evidence_entry.request_digest,
                instant("2030-02-01T00:00:00.000Z"),
            )
            .await;
            let kind_historical = HistoricalRehydrationAuthority::new(kind_entry.cid, 5).unwrap();
            let wrong_kind_terminal = load_work_terminal_hydration_row(
                &mut kind_tx,
                &kind_historical,
                kind_cid,
                WorkTerminalLocator::Request {
                    kind: RequestEntryKind::ResetRequest,
                    source: WorkTerminalRequestSource::Control {
                        request_digest: &reset_evidence_entry.request_digest,
                        signed_request_bytes: &reset_evidence_entry.raw_wrapper,
                    },
                },
            )
            .await
            .expect("production-load wrong-kind evidence");
            kind_tx
                .rollback()
                .await
                .expect("rollback schema-impossible wrong-kind mapping");
            wrong_kind.leave_requests[0].terminal = Some(wrong_kind_terminal);
            let kind_authority = HydrationAuthority::new(kind_entry.cid).expect("kind authority");
            assert!(matches!(
                crate::chat_protocol::state_machine::hydrate_conversation_state(
                    &kind_authority,
                    wrong_kind,
                ),
                Err(crate::chat_protocol::state_machine::StateMachineError::InvariantViolation)
            ));

            // Wrong principal is likewise excluded by the reciprocal mapper.
            // Register a distinct real signer in the same conversation, load its
            // genuine same-target cancellation from a fresh transaction, and
            // splice only that terminal onto the unchanged durable request.
            let principal_cid = Uuid::new_v4();
            let principal_entry = build_real_creation_entry(*principal_cid.as_bytes());
            let principal_leave = seed_control_request(
                &pool,
                &principal_entry,
                SignedMutationKind::LeaveRequest,
                LEAVE_ENTRY_KIND,
            )
            .await;
            let valid_principal_cancellation = build_real_leave_cancellation_entry(
                &principal_entry,
                principal_leave.request_id,
                CANCELLATION_ENTRY_KIND,
                3,
            );
            commit_cancelled_leave_entry(
                &pool,
                &principal_entry,
                &principal_leave,
                &valid_principal_cancellation,
                &valid_principal_cancellation.raw_wrapper,
                &valid_principal_cancellation.request_digest,
                instant("2030-02-01T00:00:00.000Z"),
                instant("2030-02-01T00:00:00.000Z"),
            )
            .await;
            let mut wrong_principal = load_aggregate_hydration(&pool, &principal_entry).await;
            let mut other_signer = build_real_creation_entry(*Uuid::new_v4().as_bytes());
            other_signer.cid = principal_entry.cid;
            assert_ne!(other_signer.actor_did, principal_entry.actor_did);
            let registered_at = instant("2030-01-31T23:59:58.000Z");
            let mut registration = pool.begin().await.expect("begin other signer registration");
            sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
                .bind(&other_signer.actor_did)
                .bind(registered_at)
                .execute(&mut *registration)
                .await
                .expect("insert other principal");
            sqlx::query(
                r#"INSERT INTO chat.devices(
                    user_did,device_id,device_name,status,dpop_jkt,auth_generation,
                    capabilities,created_at,updated_at
                ) VALUES($1,$2,'other-cancellation-signer','active',$3,1,
                    chat.protocol_capabilities(),$4,$4)"#,
            )
            .bind(&other_signer.actor_did)
            .bind(other_signer.actor_device_id)
            .bind(&other_signer.actor_key_id)
            .bind(registered_at)
            .execute(&mut *registration)
            .await
            .expect("insert other signer device");
            sqlx::query(
                r#"INSERT INTO chat.device_keys(
                    user_did,device_id,key_id,signing_public_key,
                    enrollment_auth_generation,created_at
                ) VALUES($1,$2,$3,$4,1,$5)"#,
            )
            .bind(&other_signer.actor_did)
            .bind(other_signer.actor_device_id)
            .bind(&other_signer.actor_key_id)
            .bind(&other_signer.public_key)
            .bind(registered_at)
            .execute(&mut *registration)
            .await
            .expect("insert other signer key");
            registration
                .commit()
                .await
                .expect("commit other signer registration");
            let other_cancellation = build_real_leave_cancellation_entry(
                &other_signer,
                principal_leave.request_id,
                CANCELLATION_ENTRY_KIND,
                4,
            );
            let mut principal_tx = pool.begin().await.expect("begin other-principal evidence");
            append_control_entry_fixture(
                &mut principal_tx,
                &other_signer,
                &other_cancellation,
                CANCELLATION_ENTRY_KIND,
                4,
                &other_cancellation.raw_wrapper,
                &other_cancellation.request_digest,
                instant("2030-02-01T00:00:00.000Z"),
            )
            .await;
            let principal_historical =
                HistoricalRehydrationAuthority::new(principal_entry.cid, 5).unwrap();
            let wrong_principal_terminal = load_work_terminal_hydration_row(
                &mut principal_tx,
                &principal_historical,
                principal_cid,
                WorkTerminalLocator::Request {
                    kind: RequestEntryKind::LeaveCancellation,
                    source: WorkTerminalRequestSource::Control {
                        request_digest: &other_cancellation.request_digest,
                        signed_request_bytes: &other_cancellation.raw_wrapper,
                    },
                },
            )
            .await
            .expect("production-load wrong-principal evidence");
            principal_tx
                .rollback()
                .await
                .expect("rollback schema-impossible wrong-principal mapping");
            wrong_principal.leave_requests[0].terminal = Some(wrong_principal_terminal);
            let principal_authority =
                HydrationAuthority::new(principal_entry.cid).expect("principal authority");
            assert!(matches!(
                crate::chat_protocol::state_machine::hydrate_conversation_state(
                    &principal_authority,
                    wrong_principal,
                ),
                Err(crate::chat_protocol::state_machine::StateMachineError::InvariantViolation)
            ));
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn cancelled_leave_loader_rejects_committed_time_digest_and_signed_bytes_drift() {
            const CANCELLATION_ENTRY_KIND: &str = "blue.catbird.chat.defs#leaveCancellationEntry";
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;

            // The mapper compares terminal_at to the entry column, not the signed
            // outer envelope. Commit a different column/terminal instant; fresh
            // hydration must compare the re-verified evidence time and reject it.
            let time_cid = Uuid::new_v4();
            let time_entry = build_real_creation_entry(*time_cid.as_bytes());
            let time_leave = seed_control_request(
                &pool,
                &time_entry,
                SignedMutationKind::LeaveRequest,
                LEAVE_ENTRY_KIND,
            )
            .await;
            let time_cancellation = build_real_leave_cancellation_entry(
                &time_entry,
                time_leave.request_id,
                CANCELLATION_ENTRY_KIND,
                3,
            );
            let wrong_terminal_at = instant("2030-02-01T00:01:00.000Z");
            commit_cancelled_leave_entry(
                &pool,
                &time_entry,
                &time_leave,
                &time_cancellation,
                &time_cancellation.raw_wrapper,
                &time_cancellation.request_digest,
                wrong_terminal_at,
                wrong_terminal_at,
            )
            .await;
            let mut time_read = pool.begin().await.expect("begin wrong-time read");
            let wrong_time = load_leave_request_hydration_rows(
                &mut time_read,
                &HistoricalRehydrationAuthority::new(time_entry.cid, 4).unwrap(),
                time_cid,
            )
            .await;
            time_read
                .rollback()
                .await
                .expect("rollback wrong-time read");
            assert!(matches!(
                wrong_time,
                Err(crate::chat_protocol::repository::core::ResetLeaveHydrationError::InvalidTerminal)
            ));

            // Stored digest D is the mapper's direct key and can differ from the
            // genuinely signed wrapper's digest A. The fetch succeeds by D, then
            // the signed-authority digest comparison must reject it.
            let digest_cid = Uuid::new_v4();
            let digest_entry = build_real_creation_entry(*digest_cid.as_bytes());
            let digest_leave = seed_control_request(
                &pool,
                &digest_entry,
                SignedMutationKind::LeaveRequest,
                LEAVE_ENTRY_KIND,
            )
            .await;
            let digest_cancellation = build_real_leave_cancellation_entry(
                &digest_entry,
                digest_leave.request_id,
                CANCELLATION_ENTRY_KIND,
                3,
            );
            let stored_digest = vec![0xd5_u8; 32];
            assert_ne!(stored_digest, digest_cancellation.request_digest);
            commit_cancelled_leave_entry(
                &pool,
                &digest_entry,
                &digest_leave,
                &digest_cancellation,
                &digest_cancellation.raw_wrapper,
                &stored_digest,
                instant("2030-02-01T00:00:00.000Z"),
                instant("2030-02-01T00:00:00.000Z"),
            )
            .await;
            let mut digest_read = pool.begin().await.expect("begin wrong-digest read");
            let wrong_digest = load_leave_request_hydration_rows(
                &mut digest_read,
                &HistoricalRehydrationAuthority::new(digest_entry.cid, 4).unwrap(),
                digest_cid,
            )
            .await;
            digest_read
                .rollback()
                .await
                .expect("rollback wrong-digest read");
            assert!(matches!(
                wrong_digest,
                Err(crate::chat_protocol::repository::core::ResetLeaveHydrationError::InvalidTerminal)
            ));

            // The mapper does not compare accepted_payload_bytes with the stored
            // signed_request_bytes. Keep envelope/digest/signature A, but store a
            // separately valid same-key/same-target cancellation wrapper B with a
            // different idempotency key. Historical rebinding must reject A/B.
            let bytes_cid = Uuid::new_v4();
            let bytes_entry = build_real_creation_entry(*bytes_cid.as_bytes());
            let bytes_leave = seed_control_request(
                &pool,
                &bytes_entry,
                SignedMutationKind::LeaveRequest,
                LEAVE_ENTRY_KIND,
            )
            .await;
            let bytes_cancellation = build_real_leave_cancellation_entry(
                &bytes_entry,
                bytes_leave.request_id,
                CANCELLATION_ENTRY_KIND,
                3,
            );
            let mut wrapper_b: Value =
                serde_json::from_slice(&bytes_cancellation.raw_wrapper).unwrap();
            wrapper_b["body"]["idempotencyKey"] = json!(Uuid::new_v4().hyphenated().to_string());
            wrapper_b["signature"] = Value::String(STANDARD.encode([0_u8; 64]));
            let unsigned_b = serde_json::to_vec(&wrapper_b).unwrap();
            let canonical_b = decode_canonical_signed_mutation(&unsigned_b).unwrap();
            wrapper_b["signature"] = Value::String(
                STANDARD.encode(
                    bytes_entry
                        .signing_key()
                        .sign(canonical_b.transcript_bytes())
                        .to_bytes(),
                ),
            );
            let signed_bytes_b = serde_json::to_vec(&wrapper_b).unwrap();
            decode_and_verify_signed_mutation(&signed_bytes_b, &bytes_entry.public_key)
                .expect("alternate same-target cancellation wrapper verifies");
            assert_ne!(signed_bytes_b, bytes_cancellation.raw_wrapper);
            commit_cancelled_leave_entry(
                &pool,
                &bytes_entry,
                &bytes_leave,
                &bytes_cancellation,
                &signed_bytes_b,
                &bytes_cancellation.request_digest,
                instant("2030-02-01T00:00:00.000Z"),
                instant("2030-02-01T00:00:00.000Z"),
            )
            .await;
            let mut bytes_read = pool.begin().await.expect("begin wrong-bytes read");
            let wrong_bytes = load_leave_request_hydration_rows(
                &mut bytes_read,
                &HistoricalRehydrationAuthority::new(bytes_entry.cid, 4).unwrap(),
                bytes_cid,
            )
            .await;
            bytes_read
                .rollback()
                .await
                .expect("rollback wrong-bytes read");
            assert!(matches!(
                wrong_bytes,
                Err(crate::chat_protocol::repository::core::ResetLeaveHydrationError::InvalidTerminal)
            ));
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn signed_request_terminal_uses_the_signed_verifier_for_recovery_and_welcome() {
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(1).await;
            let cid = Uuid::new_v4();
            let signing_key = SigningKey::from_bytes(&[0x42; 32]);
            let verifying_key = signing_key.verifying_key().to_bytes();
            let actor = sample_actor();
            let coordinate = sample_coordinate(*cid.as_bytes());
            let append = HydrationAuthority::new(*cid.as_bytes()).unwrap();
            let historical = HistoricalRehydrationAuthority::new(*cid.as_bytes(), 2).unwrap();

            for (kind, raw) in [
                RequestEntryKind::LeafRecoveryRequest,
                RequestEntryKind::LeafRecoveryCancellation,
                RequestEntryKind::WelcomeAcknowledgement,
                RequestEntryKind::WelcomeRejection,
            ]
            .into_iter()
            .zip(all_signed_request_wrappers(
                &coordinate,
                &actor,
                &signing_key,
            )) {
                let mutation = decode_and_verify_signed_mutation(&raw, &verifying_key)
                    .expect("reference signed mutation verifies");
                let signing_transcript = mutation.transcript_bytes().to_vec();
                let request_digest = *mutation.request_digest();
                let signature = *mutation.signature();
                let envelope =
                    DurableSignedRequestEnvelope::new(*cid.as_bytes(), &trusted_received_at())
                        .unwrap();
                let expected = append
                    .signed_request(envelope, mutation)
                    .expect("append-time signed request evidence");

                let mut tx = pool.begin().await.expect("begin");
                let loaded = load_work_terminal_hydration_row(
                    &mut tx,
                    &historical,
                    cid,
                    WorkTerminalLocator::Request {
                        kind,
                        source: WorkTerminalRequestSource::Signed {
                            received_at: instant(SIGNED_REQUEST_RECEIVED_AT),
                            signed_request_bytes: &raw,
                            signing_transcript_bytes: &signing_transcript,
                            request_digest,
                            signature,
                            signing_public_key: &verifying_key,
                        },
                    },
                )
                .await
                .expect("signed request terminal reconstructs");
                tx.rollback().await.expect("rollback");

                assert_eq!(loaded, WorkTerminalHydrationRow::Request(expected));
            }
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn request_terminal_fails_closed_on_mismatched_path_or_signed_kind() {
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(1).await;
            let cid = Uuid::new_v4();
            let signing_key = SigningKey::from_bytes(&[0x42; 32]);
            let verifying_key = signing_key.verifying_key().to_bytes();
            let actor = sample_actor();
            let coordinate = sample_coordinate(*cid.as_bytes());
            let raw = all_signed_request_wrappers(&coordinate, &actor, &signing_key)
                .into_iter()
                .next()
                .expect("leaf-recovery request wrapper");
            let verified = decode_and_verify_signed_mutation(&raw, &verifying_key)
                .expect("signed fixture verifies");
            let signing_transcript = verified.transcript_bytes().to_vec();
            let request_digest = *verified.request_digest();
            let signature = *verified.signature();
            let authority = HistoricalRehydrationAuthority::new(*cid.as_bytes(), 2).unwrap();

            let mut tx = pool.begin().await.expect("begin");
            let signed_on_control_kind = load_work_terminal_hydration_row(
                &mut tx,
                &authority,
                cid,
                WorkTerminalLocator::Request {
                    kind: RequestEntryKind::ResetRequest,
                    source: WorkTerminalRequestSource::Signed {
                        received_at: instant(SIGNED_REQUEST_RECEIVED_AT),
                        signed_request_bytes: &raw,
                        signing_transcript_bytes: &signing_transcript,
                        request_digest,
                        signature,
                        signing_public_key: &verifying_key,
                    },
                },
            )
            .await;
            assert!(matches!(
                signed_on_control_kind,
                Err(WorkTerminalHydrationError::RequestPathMismatch)
            ));

            let control_on_signed_kind = load_work_terminal_hydration_row(
                &mut tx,
                &authority,
                cid,
                WorkTerminalLocator::Request {
                    kind: RequestEntryKind::LeafRecoveryRequest,
                    source: WorkTerminalRequestSource::Control {
                        request_digest: &[0x44; 32],
                        signed_request_bytes: &raw,
                    },
                },
            )
            .await;
            assert!(matches!(
                control_on_signed_kind,
                Err(WorkTerminalHydrationError::RequestPathMismatch)
            ));

            let wrong_signed_kind = load_work_terminal_hydration_row(
                &mut tx,
                &authority,
                cid,
                WorkTerminalLocator::Request {
                    kind: RequestEntryKind::WelcomeAcknowledgement,
                    source: WorkTerminalRequestSource::Signed {
                        received_at: instant(SIGNED_REQUEST_RECEIVED_AT),
                        signed_request_bytes: &raw,
                        signing_transcript_bytes: &signing_transcript,
                        request_digest,
                        signature,
                        signing_public_key: &verifying_key,
                    },
                },
            )
            .await;
            tx.rollback().await.expect("rollback");
            assert!(
                matches!(
                    wrong_signed_kind,
                    Err(WorkTerminalHydrationError::InvalidEvidence)
                ),
                "a valid signed request of the wrong kind must not be relabelled",
            );
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn signed_request_terminal_fails_closed_on_durable_digest_tamper() {
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(1).await;
            let cid = Uuid::new_v4();
            let signing_key = SigningKey::from_bytes(&[0x42; 32]);
            let verifying_key = signing_key.verifying_key().to_bytes();
            let actor = sample_actor();
            let coordinate = sample_coordinate(*cid.as_bytes());
            let raw = all_signed_request_wrappers(&coordinate, &actor, &signing_key)
                .into_iter()
                .next()
                .expect("leaf-recovery request wrapper");
            let verified = decode_and_verify_signed_mutation(&raw, &verifying_key)
                .expect("signed fixture verifies");
            let signing_transcript = verified.transcript_bytes().to_vec();
            let mut request_digest = *verified.request_digest();
            request_digest[0] ^= 0x01;
            let signature = *verified.signature();
            let authority = HistoricalRehydrationAuthority::new(*cid.as_bytes(), 2).unwrap();

            let mut tx = pool.begin().await.expect("begin");
            let result = load_work_terminal_hydration_row(
                &mut tx,
                &authority,
                cid,
                WorkTerminalLocator::Request {
                    kind: RequestEntryKind::LeafRecoveryRequest,
                    source: WorkTerminalRequestSource::Signed {
                        received_at: instant(SIGNED_REQUEST_RECEIVED_AT),
                        signed_request_bytes: &raw,
                        signing_transcript_bytes: &signing_transcript,
                        request_digest,
                        signature,
                        signing_public_key: &verifying_key,
                    },
                },
            )
            .await;
            tx.rollback().await.expect("rollback");

            assert!(matches!(
                result,
                Err(WorkTerminalHydrationError::InvalidEvidence)
            ));
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn signed_request_terminal_fails_closed_on_foreign_conversation_binding() {
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(1).await;
            let signed_conversation_id = Uuid::new_v4();
            let foreign_conversation_id = Uuid::new_v4();
            let signing_key = SigningKey::from_bytes(&[0x42; 32]);
            let verifying_key = signing_key.verifying_key().to_bytes();
            let actor = sample_actor();
            let coordinate = sample_coordinate(*signed_conversation_id.as_bytes());
            let raw = all_signed_request_wrappers(&coordinate, &actor, &signing_key)
                .into_iter()
                .next()
                .expect("real signed leaf-recovery request");
            let verified = decode_and_verify_signed_mutation(&raw, &verifying_key)
                .expect("foreign-bound fixture is genuinely signed");
            let signing_transcript = verified.transcript_bytes().to_vec();
            let request_digest = *verified.request_digest();
            let signature = *verified.signature();
            let foreign_authority =
                HistoricalRehydrationAuthority::new(*foreign_conversation_id.as_bytes(), 2)
                    .unwrap();

            let mut tx = pool.begin().await.expect("begin");
            let result = load_work_terminal_hydration_row(
                &mut tx,
                &foreign_authority,
                foreign_conversation_id,
                WorkTerminalLocator::Request {
                    kind: RequestEntryKind::LeafRecoveryRequest,
                    source: WorkTerminalRequestSource::Signed {
                        received_at: instant(SIGNED_REQUEST_RECEIVED_AT),
                        signed_request_bytes: &raw,
                        signing_transcript_bytes: &signing_transcript,
                        request_digest,
                        signature,
                        signing_public_key: &verifying_key,
                    },
                },
            )
            .await;
            tx.rollback().await.expect("rollback");

            assert!(
                matches!(result, Err(WorkTerminalHydrationError::InvalidEvidence)),
                "a genuinely signed request cannot cross its embedded conversation binding",
            );
        }

        #[test]
        fn terminal_candidate_resolution_never_selects_missing_or_ambiguous_rows() {
            assert!(matches!(
                resolve_single_terminal_candidate::<u8>(Vec::new()),
                Err(WorkTerminalHydrationError::EvidenceMissing)
            ));
            assert!(matches!(
                resolve_single_terminal_candidate(vec![1_u8, 2_u8]),
                Err(WorkTerminalHydrationError::EvidenceAmbiguous)
            ));
            assert_eq!(
                resolve_single_terminal_candidate(vec![7_u8]).expect("single row resolves"),
                7,
            );
        }

        #[tokio::test]
        #[ignore = "requires the dedicated gate database"]
        async fn terminal_lookup_fails_closed_on_missing_or_wrong_conversation_evidence() {
            let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
            let cid = Uuid::new_v4();
            let entry = build_real_creation_entry(*cid.as_bytes());
            let transition_id = seed_real_creation_graph(&pool, &entry).await;
            let authority =
                HistoricalRehydrationAuthority::new(entry.cid, entry.head_next_entry_seq).unwrap();
            let foreign = Uuid::new_v4();

            let mut tx = pool.begin().await.expect("begin");
            for locator in [
                WorkTerminalLocator::Transition {
                    transition_id: Uuid::new_v4(),
                },
                WorkTerminalLocator::Transition { transition_id },
                WorkTerminalLocator::DeviceRevocation {
                    revocation_id: Uuid::new_v4(),
                },
            ] {
                let lookup_cid = if matches!(
                    &locator,
                    WorkTerminalLocator::Transition {
                        transition_id: id
                    } if *id == transition_id
                ) {
                    foreign
                } else {
                    cid
                };
                let result =
                    load_work_terminal_hydration_row(&mut tx, &authority, lookup_cid, locator)
                        .await;
                assert!(matches!(
                    result,
                    Err(WorkTerminalHydrationError::EvidenceMissing)
                ));
            }
            tx.rollback().await.expect("rollback");
        }
    }
}

// ===========================================================================
// G1b-2 sub-seal 1a — leaf-membership hydration leg (FINDING-1 correction:
// leaf crypto is authoritative in the tree summary, NOT chat.member_devices).
//
// The genesis coherent-leaf seed builds a tree summary whose single leaf's
// basic_credential + signature_key MATCH the genesis member_devices row (unlike
// `canonical_tree_summary`, built for the snapshot-leg test, whose opaque leaf
// crypto deliberately does not). The loader binds the durable member_devices row
// to the authenticated tree leaf and carries the tree leaf's crypto verbatim.
// ===========================================================================
mod leaf_hydration_leg {
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::{
        canonical_snapshot, clock_now_millis, commit_coherent_group_creation, seed_actor, seed_base,
    };
    use crate::chat_protocol::public_state::encode_public_tree_summary;
    use crate::chat_protocol::repository::core::{
        hydrate_locked_public_state, load_leaf_hydration_rows, LeafHydrationError,
    };
    use crate::chat_protocol::snapshot::{PublicGroupSnapshotLeaf, PublicGroupSnapshotTreeSummary};
    use crate::chat_protocol::state_machine::{DeviceIdentity, PrincipalId};
    use crate::common;

    struct CoherentLeafGroup {
        conversation_id: Uuid,
        actor_did: String,
        actor_device_id: Uuid,
        signature_key: Vec<u8>,
        encryption_key: Vec<u8>,
    }

    /// Seed a genesis GROUP whose one tree-summary leaf carries the SAME
    /// basic_credential (`did#device_id`) and signature key (the actor's Ed25519
    /// public key) as its `chat.member_devices` row, so the leg's durable-vs-tree
    /// correspondence holds. `encryption_key` lives ONLY in the tree leaf.
    async fn seed_coherent_leaf_group(pool: &PgPool) -> CoherentLeafGroup {
        let (actor_did, actor_device_id, actor_key_id) = seed_actor(pool).await;
        let actor_public_key: Vec<u8> =
            sqlx::query_scalar("SELECT signing_public_key FROM chat.device_keys WHERE key_id=$1")
                .bind(&actor_key_id)
                .fetch_one(pool)
                .await
                .expect("read actor public key");
        let basic_credential = format!("{actor_did}#{actor_device_id}").into_bytes();
        let encryption_key = vec![0x46_u8; 1216];
        let (snapshot, snapshot_sha256) = canonical_snapshot();
        let summary = PublicGroupSnapshotTreeSummary::new(
            [0x33_u8; 32],
            vec![PublicGroupSnapshotLeaf::new(
                0,
                basic_credential.clone(),
                actor_public_key.clone(),
                encryption_key.clone(),
            )],
        );
        let (tree_summary_bytes, tree_summary_sha256) = encode_public_tree_summary(&summary)
            .expect("coherent tree summary encodes")
            .into_parts();
        let conversation_id = commit_coherent_group_creation(
            pool,
            &actor_did,
            actor_device_id,
            &actor_key_id,
            &actor_public_key,
            &snapshot,
            &snapshot_sha256,
            &tree_summary_bytes,
            &tree_summary_sha256,
        )
        .await;
        CoherentLeafGroup {
            conversation_id,
            actor_did,
            actor_device_id,
            signature_key: actor_public_key,
            encryption_key,
        }
    }

    /// Happy path: the active leaf hydrates from the authenticated tree summary
    /// (crypto verbatim), bound to the durable member_devices device identity,
    /// with the genesis `join_key_package_ref` absent.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn leaf_leg_hydrates_the_genesis_leaf_from_the_tree_summary() {
        let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
        let group = seed_coherent_leaf_group(&pool).await;
        let locked_at = clock_now_millis(&pool).await;

        let mut tx = pool.begin().await.expect("begin");
        let guard = hydrate_locked_public_state(&mut tx, group.conversation_id, locked_at)
            .await
            .expect("public state hydrates");
        let (_txid, _cid, _coordinate, _snapshot, binding, _encoded_tree, _tree_sha, _at, _digest) =
            guard.into_parts();
        let leaves = load_leaf_hydration_rows(&mut tx, group.conversation_id, &binding)
            .await
            .expect("leaf leg hydrates");
        tx.commit().await.expect("commit");

        assert_eq!(leaves.len(), 1, "exactly the one active genesis leaf");
        let leaf = &leaves[0];
        let expected_device = DeviceIdentity::new(
            PrincipalId::new(group.actor_did.clone().into_bytes()).expect("principal"),
            *group.actor_device_id.as_bytes(),
        )
        .expect("device identity");
        assert_eq!(leaf.device, expected_device, "durable device identity");
        assert_eq!(leaf.leaf_index, 0);
        assert_eq!(
            leaf.basic_credential,
            format!("{}#{}", group.actor_did, group.actor_device_id).into_bytes(),
            "basic credential carried from the tree leaf",
        );
        assert_eq!(
            leaf.signature_key, group.signature_key,
            "signature key carried from the tree leaf",
        );
        assert_eq!(
            leaf.encryption_key, group.encryption_key,
            "encryption key sourced ONLY from the tree leaf (no member_devices column)",
        );
        assert_eq!(
            leaf.key_package_ref, None,
            "genesis leaf has no join package"
        );
    }

    /// Fail-closed: when the persisted tree summary's leaf crypto does NOT match
    /// the durable member_devices row (the `seed_base` fixture pairs an opaque
    /// tree leaf with a real `did#device_id` membership row), the leg errors with
    /// `TreeMismatch` rather than laundering a leaf whose durable binding and
    /// authenticated tree disagree.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn leaf_leg_fails_closed_when_tree_summary_disagrees_with_member_devices() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        let base = seed_base(&pool).await;
        let locked_at = clock_now_millis(&pool).await;

        let mut tx = pool.begin().await.expect("begin");
        let guard = hydrate_locked_public_state(&mut tx, base.conversation_id, locked_at)
            .await
            .expect("public state hydrates");
        let (_txid, _cid, _coordinate, _snapshot, binding, _encoded_tree, _tree_sha, _at, _digest) =
            guard.into_parts();
        let result = load_leaf_hydration_rows(&mut tx, base.conversation_id, &binding).await;
        tx.rollback().await.expect("rollback");

        assert!(matches!(result, Err(LeafHydrationError::TreeMismatch)));
    }
}

// ===========================================================================
// G1b-2 — COMBINED real-GroupInfo genesis seed (Option-B scope, coordinator
// ruling "combined-seed STOP" cb07f54c).
//
// The prior leaf-leg fixture pairs a REAL `did#device`/signature-key
// `chat.member_devices` row with an OPAQUE snapshot + tree summary: it exercises
// the leaf leg against the STORED tree summary, but the snapshot blob never
// decodes and no real `ActivePublicState` is ever reloaded. This seed replaces
// the opaque coordinate with the FROZEN corpus genesis:
//
//   * `public_snapshot_bytes` = the frozen `genesis-public-state.bin`
//     (kind `publicGroupSnapshot`), so the production reload
//     `load_persisted_active_snapshot` -> `decode_public_group_snapshot`
//     hydrates a REAL `ActivePublicState` (alice's corpus one-leaf public group);
//   * `tree_summary_bytes` = the tree summary STRUCTURALLY derived from that same
//     snapshot (records parsed, tree hash + one leaf's basic credential /
//     signature key / X-Wing encryption key extracted — NO OpenMLS reprocessing,
//     NO credential-lifetime check), so the leaf leg's coherent-leaf happy path
//     runs on the REAL authenticated tree;
//   * the outer coordinate (group id / genesis group-context hash / genesis
//     confirmation tag / epoch 0) = the frozen manifest `chain` values the
//     decode re-derives and binds.
//
// CORPUS-LIFETIME-INDEPENDENCE (binding condition, coordinator-accepted): the
// only crypto path here is `decode_public_group_snapshot` — structural record
// decode + SHA-256 digest + ratchet-tree-hash + tree-summary equality, with NO
// `now`/lifetime argument anywhere. `verify_genesis_group_info` /
// `validate_group_info` (which DO call `validate_clean_leaf_profile(now)`) are
// never touched, so this seed stays green regardless of corpus lifetime age —
// the same posture the interim gate requires, and the same structural path the
// green `chat_protocol_snapshot::frozen_public_group_snapshots_...` suite uses.
//
// NAMED REMAINDER (coordinator condition 3 — REJECT-class if it silently
// disappears, same teeth as task #26): the assembly-through-`validate_state`
// happy path and the producer / metadata provenance RE-VERIFICATION on this real
// tree are NOT delivered here. They require the creation CONTROL entry to
// re-verify under the actor's `chat.device_keys` row, and `device_keys` PK
// `(user_did, device_id)` + `member_devices_signing_key_fk` pin that one key to
// the MLS leaf key (42fc27cd… / keyId ekxBMK9K…), whose private half the corpus
// deliberately withholds (`manifest.generator.signingKeys` = "no private key
// material is emitted"). So a genuinely-signed creation entry whose actor is the
// corpus genesis leaf is unbuildable until Option A lands (generator emits
// alice's genesis creation entry signed by her real seed). Per coordinator
// condition 4, this seed carries a PLACEHOLDER-signed creation transition/entry
// ONLY for FK/CHECK coherence, and NO entry-verifying leg is run against it here;
// the real-tree assembly happy path stays blocked (not faked) until Option A.
// ===========================================================================
mod real_tree_genesis_seed {
    use std::{fs, path::PathBuf};

    use sha2::{Digest, Sha256};
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::{clock_now, clock_now_millis, random_plc_did};
    use crate::chat_protocol::public_state::{
        encode_public_tree_summary, load_persisted_active_snapshot,
    };
    use crate::chat_protocol::repository::core::{
        hydrate_locked_public_state, load_leaf_hydration_rows, LeafHydrationError,
    };
    use crate::chat_protocol::snapshot::{PublicGroupSnapshotLeaf, PublicGroupSnapshotTreeSummary};
    use crate::chat_protocol::state_machine::{DeviceIdentity, PrincipalId};
    use crate::common;

    // --- Frozen corpus access (structural decode + digest only) -------------

    fn corpus_file(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/generated-artifacts/mls-chat-v1/crypto-wire")
            .join(name);
        fs::read(path).expect("read frozen crypto-wire corpus artifact")
    }

    fn corpus_manifest() -> serde_json::Value {
        serde_json::from_slice(&corpus_file("manifest.json")).expect("parse frozen manifest")
    }

    fn manifest_hex<const N: usize>(value: &serde_json::Value) -> [u8; N] {
        hex::decode(value.as_str().expect("hex string"))
            .expect("valid corpus hex")
            .try_into()
            .unwrap_or_else(|_| panic!("expected {N}-byte corpus value"))
    }

    /// The frozen genesis outer coordinate the decode re-derives and binds.
    struct GenesisCoordinate {
        group_id: [u8; 32],
        group_context_hash: [u8; 32],
        confirmation_tag: [u8; 32],
        epoch: u64,
    }

    fn genesis_coordinate() -> GenesisCoordinate {
        let manifest = corpus_manifest();
        let chain = &manifest["chain"];
        GenesisCoordinate {
            group_id: manifest_hex::<32>(&chain["groupIdHex"]),
            group_context_hash: manifest_hex::<32>(&chain["genesisGroupContextHashHex"]),
            confirmation_tag: manifest_hex::<32>(&chain["genesisConfirmationTagHex"]),
            epoch: chain["genesisEpoch"].as_u64().expect("genesis epoch"),
        }
    }

    // --- Structural tree-summary derivation (no OpenMLS reprocessing) -------
    //
    // Decodes the frozen `CBPGSNAP` snapshot envelope and reads the tree hash
    // (GroupContext record) + the single leaf's basic credential / signature key
    // / X-Wing encryption key (Tree record) straight out of the stored JSON —
    // exactly as `chat_protocol_snapshot::trusted_tree_summary` does, and NOT via
    // any credential-lifetime-validating parse. This is the value the production
    // `hydrate_locked_public_state` would re-decode from `tree_summary_bytes`, so
    // seeding it makes the leaf leg run on the authenticated real tree.

    fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> &'a [u8] {
        let end = offset.checked_add(length).expect("snapshot offset");
        let value = bytes.get(*offset..end).expect("valid snapshot slice");
        *offset = end;
        value
    }

    fn take_u16(bytes: &[u8], offset: &mut usize) -> u16 {
        u16::from_be_bytes(take(bytes, offset, 2).try_into().expect("two bytes"))
    }

    fn take_u32(bytes: &[u8], offset: &mut usize) -> u32 {
        u32::from_be_bytes(take(bytes, offset, 4).try_into().expect("four bytes"))
    }

    fn snapshot_records(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut offset = 0;
        let _magic: [u8; 8] = take(bytes, &mut offset, 8).try_into().expect("magic");
        let _schema = take_u16(bytes, &mut offset);
        let openmls_len = usize::from(take_u16(bytes, &mut offset));
        let _openmls = take(bytes, &mut offset, openmls_len).to_vec();
        let storage_len = usize::from(take_u16(bytes, &mut offset));
        let _storage = take(bytes, &mut offset, storage_len).to_vec();
        let count = usize::try_from(take_u32(bytes, &mut offset)).expect("record count");
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let key_len = usize::try_from(take_u32(bytes, &mut offset)).expect("key length");
            let key = take(bytes, &mut offset, key_len).to_vec();
            let value_len = usize::try_from(take_u32(bytes, &mut offset)).expect("value length");
            let value = take(bytes, &mut offset, value_len).to_vec();
            records.push((key, value));
        }
        assert_eq!(offset, bytes.len(), "frozen snapshot is exact");
        records
    }

    fn json_bytes(value: &serde_json::Value) -> Vec<u8> {
        value
            .as_array()
            .expect("byte array")
            .iter()
            .map(|byte| u8::try_from(byte.as_u64().expect("byte")).expect("u8"))
            .collect()
    }

    fn structural_genesis_tree_summary(encoded: &[u8]) -> PublicGroupSnapshotTreeSummary {
        let records = snapshot_records(encoded);
        let group_context: serde_json::Value = records
            .iter()
            .find(|(key, _)| key.starts_with(b"GroupContext"))
            .map(|(_, value)| serde_json::from_slice(value).expect("GroupContext json"))
            .expect("GroupContext record");
        let tree_hash: [u8; 32] = json_bytes(&group_context["tree_hash"]["vec"])
            .try_into()
            .expect("32-byte tree hash");
        let tree: serde_json::Value = records
            .iter()
            .find(|(key, _)| key.starts_with(b"Tree"))
            .map(|(_, value)| serde_json::from_slice(value).expect("Tree json"))
            .expect("Tree record");
        let leaves = tree["tree"]["leaf_nodes"]
            .as_array()
            .expect("leaf array")
            .iter()
            .enumerate()
            .filter_map(|(leaf_index, stored)| {
                let node = stored.get("node")?;
                if node.is_null() {
                    return None;
                }
                let payload = &node["payload"];
                assert_eq!(payload["credential"]["credential_type"], "Basic");
                Some(PublicGroupSnapshotLeaf::new(
                    u32::try_from(leaf_index).expect("leaf index"),
                    json_bytes(&payload["credential"]["serialized_credential_content"]["vec"]),
                    json_bytes(&payload["signature_key"]["value"]["vec"]),
                    json_bytes(&payload["encryption_key"]["key"]["vec"]),
                ))
            })
            .collect();
        PublicGroupSnapshotTreeSummary::new(tree_hash, leaves)
    }

    // --- Seeder -------------------------------------------------------------

    struct RealTreeGenesis {
        conversation_id: Uuid,
        member_did: String,
        member_device_id: Uuid,
        snapshot: Vec<u8>,
        tree_summary: PublicGroupSnapshotTreeSummary,
        group_id: [u8; 32],
    }

    /// Seed a genesis GROUP whose current generation-state carries the FROZEN
    /// corpus snapshot + its structurally-derived tree summary + the frozen
    /// genesis coordinate. The sole membership row is `(member_did,
    /// member_device_id, leaf_signature_key)`: pass the corpus leaf's own
    /// identity + real key for the coherent happy path, or any divergent identity
    /// / key to drive the leaf leg's `TreeMismatch` against the real tree.
    ///
    /// The membership `dpop_jkt` is the member's derived key id (a fresh, valid
    /// base64url-SHA-256) so it never collides on the `(user_did, dpop_jkt)`
    /// unique index with other seeders sharing a DID on the gate database.
    ///
    /// The creation transition/entry/metadata rows carry PLACEHOLDER crypto for
    /// FK/CHECK coherence only; no entry-verifying leg is exercised against this
    /// graph (see the NAMED REMAINDER note above).
    async fn commit_real_tree_genesis(
        pool: &PgPool,
        member_did: &str,
        member_device_id: Uuid,
        leaf_signature_key: &[u8],
    ) -> RealTreeGenesis {
        let snapshot = corpus_file("genesis-public-state.bin");
        let snapshot_sha256 = Sha256::digest(&snapshot).to_vec();
        let tree_summary = structural_genesis_tree_summary(&snapshot);
        let (tree_summary_bytes, tree_summary_sha256) = encode_public_tree_summary(&tree_summary)
            .expect("structural tree summary encodes")
            .into_parts();
        let coordinate = genesis_coordinate();

        let member_did = member_did.to_owned();
        let member_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
            .bind(leaf_signature_key)
            .fetch_one(pool)
            .await
            .expect("derive leaf key id");

        let conversation_id = Uuid::new_v4();
        let creation_transition_id = Uuid::new_v4();
        let creation_entry_id = Uuid::new_v4();
        let participant_period_id = Uuid::new_v4();
        let leaf_period_id = Uuid::new_v4();
        let metadata_snapshot_id = Uuid::new_v4();
        let group_id = coordinate.group_id.to_vec();
        let group_context_hash = coordinate.group_context_hash.to_vec();
        let confirmation_tag = coordinate.confirmation_tag.to_vec();
        let group_info = vec![4_u8; 8];
        let signed_request = vec![7_u8; 8];
        let unsigned_projection = vec![8_u8; 8];
        let signing_transcript = vec![9_u8; 8];
        let request_digest = Sha256::digest(&signing_transcript).to_vec();
        let signature = vec![10_u8; 64];
        let accepted_payload = vec![11_u8; 8];
        let creation_fingerprint = vec![12_u8; 32];
        let metadata_ciphertext = vec![13_u8; 16];
        let basic_credential = format!("{member_did}#{member_device_id}").into_bytes();
        let at = clock_now(pool).await;

        let mut tx = pool.begin().await.expect("begin real-tree genesis");
        sqlx::query(
            "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(&member_did)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert principal");
        sqlx::query(
            "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
             VALUES($1,$2,'real-tree-actor','active',$3,1,chat.protocol_capabilities(),$4,$4) ON CONFLICT DO NOTHING",
        )
        .bind(&member_did)
        .bind(member_device_id)
        .bind(&member_key_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert device");
        sqlx::query(
            "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
             VALUES($1,$2,$3,$4,1,$5) ON CONFLICT DO NOTHING",
        )
        .bind(&member_did)
        .bind(member_device_id)
        .bind(&member_key_id)
        .bind(leaf_signature_key)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert device key");
        sqlx::query(
            "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'group','active',0,0,2,$2)",
        )
        .bind(conversation_id)
        .bind(at)
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
        .bind(at)
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
        .bind(&member_did)
        .bind(member_device_id)
        .bind(&member_key_id)
        .bind(&signed_request)
        .bind(&unsigned_projection)
        .bind(&signing_transcript)
        .bind(&request_digest)
        .bind(&signature)
        .bind(metadata_snapshot_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert creation transition");
        sqlx::query(
            r#"INSERT INTO chat.generation_states(
                conversation_id,generation,state_version,group_id,epoch,group_context_hash,
                confirmation_tag,lifecycle,state_kind,producing_transition_id,
                public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,
                leaf_count,created_at
            ) VALUES($1,0,0,$2,$3,$4,$5,'active','creation',$6,$7,$8,$9,$10,1,$11)"#,
        )
        .bind(conversation_id)
        .bind(&group_id)
        .bind(i64::try_from(coordinate.epoch).expect("epoch fits i64"))
        .bind(&group_context_hash)
        .bind(&confirmation_tag)
        .bind(creation_transition_id)
        .bind(&snapshot)
        .bind(&snapshot_sha256)
        .bind(&tree_summary_bytes)
        .bind(tree_summary_sha256.as_slice())
        .bind(at)
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
        .bind(&member_did)
        .bind(creation_transition_id)
        .bind(at)
        .bind(member_device_id)
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
        .bind(&member_did)
        .bind(member_device_id)
        .bind(&basic_credential)
        .bind(leaf_signature_key)
        .bind(&member_key_id)
        .bind(creation_transition_id)
        .bind(at)
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
            ) VALUES($1,$2,0,0,$3,$4,$5,$6,$7,$7,1,$8,$9,$10,16,$11,$12,$13,$14,1,1,'admin','active',$15)"#,
        )
        .bind(metadata_snapshot_id)
        .bind(conversation_id)
        .bind(&group_id)
        .bind(i64::try_from(coordinate.epoch).expect("epoch fits i64"))
        .bind(&group_context_hash)
        .bind(&confirmation_tag)
        .bind(creation_transition_id)
        .bind(vec![14_u8; 12])
        .bind(&metadata_ciphertext)
        .bind(Sha256::digest(&metadata_ciphertext).to_vec())
        .bind(&member_did)
        .bind(member_device_id)
        .bind(&member_key_id)
        .bind(leaf_signature_key)
        .bind(at)
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
        .bind(&member_did)
        .bind(member_device_id)
        .bind(&member_key_id)
        .bind(creation_transition_id)
        .bind(at)
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
            ) VALUES($1,$2,0,$3,$4,1,'creation',$1,$5,0,$6,$7,$8,$9,$10,$11)"#,
        )
        .bind(creation_transition_id)
        .bind(conversation_id)
        .bind(&member_did)
        .bind(member_device_id)
        .bind(&creation_fingerprint)
        .bind(&group_id)
        .bind(i64::try_from(coordinate.epoch).expect("epoch fits i64"))
        .bind(&group_context_hash)
        .bind(&confirmation_tag)
        .bind(leaf_period_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert creation interval");
        tx.commit().await.expect("commit real-tree genesis");

        RealTreeGenesis {
            conversation_id,
            member_did,
            member_device_id,
            snapshot,
            tree_summary,
            group_id: coordinate.group_id,
        }
    }

    /// Happy path (success criterion 1): the G1a snapshot leg reloads a REAL
    /// `ActivePublicState` from the frozen corpus snapshot — structural decode,
    /// no lifetime reprocessing — bound to the seeded genesis coordinate.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn snapshot_leg_reloads_a_real_active_public_state_from_the_corpus_genesis() {
        let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
        let (member_did, member_device, leaf_key) = corpus_leaf_identity();
        let genesis = commit_real_tree_genesis(&pool, &member_did, member_device, &leaf_key).await;
        let locked_at = clock_now_millis(&pool).await;

        let mut tx = pool.begin().await.expect("begin");
        let guard = hydrate_locked_public_state(&mut tx, genesis.conversation_id, locked_at)
            .await
            .expect("public state hydrates");
        let (_txid, _cid, _coordinate, snapshot, binding, encoded_tree, tree_sha, _at, _digest) =
            guard.into_parts();
        // The full production reload: DECODES the real corpus snapshot into a
        // real active public state (never reached by the opaque-snapshot leaf
        // fixture).
        let state = load_persisted_active_snapshot(&snapshot, &binding, &encoded_tree, &tree_sha)
            .expect("real corpus snapshot reloads a real ActivePublicState");
        tx.commit().await.expect("commit");

        assert_eq!(
            state.snapshot(),
            genesis.snapshot.as_slice(),
            "reloaded snapshot is the exact frozen corpus bytes",
        );
        assert_eq!(
            state.snapshot_sha256(),
            &<[u8; 32]>::from(Sha256::digest(&genesis.snapshot)),
            "snapshot digest binds the frozen corpus bytes",
        );
        let coordinate = state.coordinate();
        assert_eq!(
            coordinate.conversation_id(),
            genesis.conversation_id.as_bytes(),
            "bound to the freshly seeded conversation",
        );
        assert_eq!(coordinate.group_id(), &genesis.group_id, "corpus group id");
        assert_eq!(coordinate.epoch(), 0, "genesis epoch");
        assert_eq!(
            state.binding().tree_summary().leaves().len(),
            1,
            "corpus genesis is a one-leaf public group",
        );
    }

    /// Happy path (success criterion 2): the leaf leg hydrates the sole active
    /// leaf from the REAL authenticated tree summary — crypto carried verbatim
    /// from the corpus tree, bound to the durable member-device identity.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn leaf_leg_hydrates_the_corpus_genesis_leaf_from_the_real_tree() {
        let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
        let (member_did, member_device, leaf_key) = corpus_leaf_identity();
        let genesis = commit_real_tree_genesis(&pool, &member_did, member_device, &leaf_key).await;
        let locked_at = clock_now_millis(&pool).await;

        let mut tx = pool.begin().await.expect("begin");
        let guard = hydrate_locked_public_state(&mut tx, genesis.conversation_id, locked_at)
            .await
            .expect("public state hydrates");
        let (_txid, _cid, _coordinate, _snapshot, binding, _encoded_tree, _tree_sha, _at, _digest) =
            guard.into_parts();
        let leaves = load_leaf_hydration_rows(&mut tx, genesis.conversation_id, &binding)
            .await
            .expect("leaf leg hydrates on the real tree");
        tx.commit().await.expect("commit");

        assert_eq!(leaves.len(), 1, "exactly the one active genesis leaf");
        let leaf = &leaves[0];
        let tree_leaf = &genesis.tree_summary.leaves()[0];
        let expected_device = DeviceIdentity::new(
            PrincipalId::new(genesis.member_did.clone().into_bytes()).expect("principal"),
            *genesis.member_device_id.as_bytes(),
        )
        .expect("device identity");
        assert_eq!(leaf.device, expected_device, "durable device identity");
        assert_eq!(leaf.leaf_index, 0);
        assert_eq!(
            leaf.basic_credential.as_slice(),
            tree_leaf.basic_credential(),
            "basic credential carried from the real tree leaf",
        );
        assert_eq!(
            leaf.signature_key.as_slice(),
            tree_leaf.signature_key(),
            "signature key carried from the real tree leaf",
        );
        assert_eq!(
            leaf.encryption_key.as_slice(),
            tree_leaf.encryption_key(),
            "X-Wing encryption key sourced ONLY from the real tree leaf",
        );
        assert_eq!(
            leaf.key_package_ref, None,
            "genesis leaf has no join package"
        );
    }

    /// Fail-closed (coordinator condition 2): when the durable member-device row
    /// carries a signature key that DISAGREES with the real authenticated tree
    /// leaf, the leg refuses to launder the mismatch and errors `TreeMismatch`.
    #[tokio::test]
    #[ignore = "requires the dedicated gate database"]
    async fn leaf_leg_fails_closed_when_member_key_disagrees_with_the_real_tree() {
        let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
        // The real corpus tree leaf carries alice's credential + MLS key; seed a
        // membership row for a DIFFERENT device identity + key, so the durable
        // binding disagrees with the authenticated real tree leaf on both the
        // basic credential and the signature key.
        let (_corpus_did, _corpus_device, corpus_key) = corpus_leaf_identity();
        // Fresh 32 random bytes so the derived `device_keys.key_id` (globally
        // unique) never collides with a prior run on the shared gate database.
        let mut divergent_key = Vec::with_capacity(32);
        divergent_key.extend_from_slice(Uuid::new_v4().as_bytes());
        divergent_key.extend_from_slice(Uuid::new_v4().as_bytes());
        assert_ne!(
            divergent_key, corpus_key,
            "the fail-closed key must differ from the real tree leaf",
        );
        let genesis =
            commit_real_tree_genesis(&pool, &random_plc_did(), Uuid::new_v4(), &divergent_key)
                .await;
        let locked_at = clock_now_millis(&pool).await;

        let mut tx = pool.begin().await.expect("begin");
        let guard = hydrate_locked_public_state(&mut tx, genesis.conversation_id, locked_at)
            .await
            .expect("public state hydrates");
        let (_txid, _cid, _coordinate, _snapshot, binding, _encoded_tree, _tree_sha, _at, _digest) =
            guard.into_parts();
        let result = load_leaf_hydration_rows(&mut tx, genesis.conversation_id, &binding).await;
        tx.rollback().await.expect("rollback");

        assert!(matches!(result, Err(LeafHydrationError::TreeMismatch)));
    }

    /// The real corpus genesis leaf's durable identity — bare DID, device UUID,
    /// and Ed25519 signature key — read STRUCTURALLY from the frozen snapshot's
    /// tree summary (the coherent happy-path membership). The leaf's basic
    /// credential is `did#device`; split it back to seed the matching row.
    fn corpus_leaf_identity() -> (String, Uuid, Vec<u8>) {
        let snapshot = corpus_file("genesis-public-state.bin");
        let tree_summary = structural_genesis_tree_summary(&snapshot);
        let leaf = &tree_summary.leaves()[0];
        let credential =
            String::from_utf8(leaf.basic_credential().to_vec()).expect("utf-8 basic credential");
        let (did, device_text) = credential
            .split_once('#')
            .expect("`did#device` basic credential");
        (
            did.to_owned(),
            Uuid::parse_str(device_text).expect("device uuid"),
            leaf.signature_key().to_vec(),
        )
    }
}
