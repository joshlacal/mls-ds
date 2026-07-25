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

    const RECEIVED_AT: &str = "2030-01-01T00:00:00.000Z";

    fn uuid_v4_bytes(byte: u8) -> [u8; 16] {
        let mut value = [byte; 16];
        value[6] = 0x40 | (byte & 0x0f);
        value[8] = 0x80 | (byte & 0x3f);
        value
    }

    fn sample_coordinate(conversation_id: [u8; 16]) -> PublicGroupSnapshotCoordinate {
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

    fn sample_actor() -> DeviceIdentity {
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

    fn all_kinds(
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

    fn trusted_received_at() -> TrustedRequestInstant {
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
        pub(super) head_next_entry_seq: u64,
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

    pub(super) fn build_real_creation_entry(fresh_cid: [u8; 16]) -> RealCreationEntry {
        let fixture: Value = serde_json::from_str(CONTRACT_VECTORS).unwrap();
        let contract: Value = serde_json::from_str(LEXICON).unwrap();
        let definitions = contract["defs"].as_object().unwrap();
        let cef = &fixture["controlEntryFingerprints"];

        let signing_key = SigningKey::from_bytes(&[0x24; 32]);
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

        let actor_did = signing_body["actorDid"].as_str().unwrap().to_owned();
        let actor_device_id =
            Uuid::parse_str(signing_body["actorDeviceId"].as_str().unwrap()).unwrap();
        let actor_key_id = ed25519_key_id(&verifying).unwrap().as_str().to_owned();

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
    use sha2::{Digest, Sha256};
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::historical_control_path::{build_real_creation_entry, RealCreationEntry};
    use crate::chat_protocol::repository::core::{
        load_historical_control_evidence, load_interval_hydration_rows, load_metadata_provenance,
        load_participant_hydration_rows, load_producer_transition_evidence,
        ControlEvidenceLoadError, IntervalHydrationError, MetadataHydrationError,
        ParticipantHydrationError, ProducerHydrationError,
    };
    use crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle;
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
    async fn seed_real_creation_graph(pool: &PgPool, entry: &RealCreationEntry) -> Uuid {
        let conversation_id = Uuid::from_bytes(entry.cid);
        let creation_transition_id = Uuid::new_v4();
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
        let tree_summary = vec![0x26_u8; 8];
        let tree_summary_sha = Sha256::digest(&tree_summary).to_vec();
        let basic_credential = format!("{actor_did}#{actor_device_id}").into_bytes();
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
        .bind(format!("{:042}A", 0_u128))
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
        use base64::{engine::general_purpose::STANDARD, Engine};
        use chrono::{DateTime, Utc};
        use ed25519_dalek::{Signer, SigningKey};
        use serde_json::{json, Value};
        use sha2::{Digest, Sha256};
        use sqlx::PgPool;
        use uuid::Uuid;

        use super::super::historical_control_path::{build_real_creation_entry, RealCreationEntry};
        use super::seed_real_creation_graph;
        use crate::chat_protocol::repository::core::{
            load_recovery_work_hydration_rows, RecoveryHydrationError,
        };
        use crate::chat_protocol::state_machine::{
            DeviceIdentity, HistoricalRehydrationAuthority, LeafRecoveryKind, PrincipalId,
            RecoveryOriginHydrationRow, RecoveryRequestStatus, RecoverySource, ReservationStatus,
        };
        use crate::chat_protocol::transcript::{
            decode_canonical_signed_mutation, SignedMutationKind,
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
            let signing_key = SigningKey::from_bytes(&[0x24; 32]);
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
            seed_real_creation_graph(pool, entry).await;
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

        // NOTE: the terminal-status fail-closed (`UnsupportedTerminal`, a non-`open`
        // request / non-`active` reservation) is NOT live-exercised here: the
        // deferred `assert_recovery_fulfillment_mapping` constraint requires a
        // FULLY coherent terminal graph (a real `leafRecovery` fulfilling
        // transition, a matching `consumed` key package, a `welcome_deliveries`
        // row, and a removed member device) to even COMMIT a `fulfilled`/`consumed`
        // pair. That coherent terminal seed is the same one the terminal
        // `WorkTerminalHydrationRow` reconstruction follow-up must build, so the
        // fail-closed boundary is asserted there. The status match arm fails closed
        // structurally in the meantime (it never fabricates a terminal).
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
