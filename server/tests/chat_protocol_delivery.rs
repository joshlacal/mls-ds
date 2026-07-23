//! Live-PostgreSQL repository test for the clean-chat append-log entry
//! allocator (`chat_protocol::repository::delivery::append_entry`).
//!
//! This is the first executor primitive that actually writes `chat.entries`.
//! It proves the row-lock-serialized seq allocation is unique, contiguous among
//! committed rows, race-safe under concurrent appends, and that the append-log
//! primary key rejects a duplicate seq.
//!
//! The production repository module is gated `#[cfg(not(test))]` (see
//! `src/chat_protocol/repository/mod.rs`), so — mirroring the sibling
//! repository harnesses — this test `include!`s it directly. Live cases require
//! the dedicated clean-chat database and are `#[ignore]`d by default; run with
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_delivery -- --ignored

#![allow(dead_code)]

mod common;

mod repository {
    pub(crate) mod delivery {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/delivery.rs"
        ));
    }
}

use std::time::Duration;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use repository::delivery::{append_entry, AppendEntry, DeliveryRepositoryError};

const APPLICATION_ENTRY_KIND: &str = "blue.catbird.chat.defs#applicationEntry";

// ---------------------------------------------------------------------------
// Fixture: a fully coherent conversation the append-log can extend.
// ---------------------------------------------------------------------------

/// Everything the append-log needs: a committed conversation whose genesis
/// creation entry occupies seq 1 (so `next_entry_seq` starts at 2), plus the
/// actor's `chat.device_keys` row that `chat.entries.actor_key_fk` requires.
struct DeliveryFixture {
    conversation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
}

/// Generate a fresh, valid `did:plc:[a-z2-7]{24}` per run. The clean-chat test
/// database is not truncated between runs, so every fixture must own unique
/// identities to stay independent and idempotent.
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

async fn next_entry_seq(pool: &PgPool, conversation_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT next_entry_seq FROM chat.conversations WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_one(pool)
        .await
        .expect("read conversation append counter")
}

async fn committed_entry_seqs(pool: &PgPool, conversation_id: Uuid) -> Vec<i64> {
    sqlx::query_scalar("SELECT seq FROM chat.entries WHERE conversation_id = $1 ORDER BY seq")
        .bind(conversation_id)
        .fetch_all(pool)
        .await
        .expect("read committed entry seqs")
}

/// Seed a principal + device + device key + the coherent conversation graph.
/// Adapted from `tests/chat_protocol_schema.rs::create_conversation_fixture`,
/// reduced to the minimum the append-log allocator depends on.
async fn seed_fixture(pool: &PgPool) -> DeliveryFixture {
    let actor_did = random_plc_did();
    let actor_device_id = Uuid::new_v4();
    // Unique per fixture: `chat.device_keys.key_id` is globally unique and the
    // test database is not truncated between fixtures or runs.
    let mut actor_public_key = Uuid::new_v4().as_bytes().to_vec();
    actor_public_key.extend_from_slice(Uuid::new_v4().as_bytes());
    let actor_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&actor_public_key)
        .fetch_one(pool)
        .await
        .expect("derive actor key id");

    let admitted_at = clock_now(pool).await;

    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(&actor_did)
        .bind(admitted_at)
        .execute(pool)
        .await
        .expect("insert principal");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'append-log-actor','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(&actor_did)
    .bind(actor_device_id)
    .bind(format!("{:042}A", 0_u128))
    .bind(admitted_at)
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
    .bind(admitted_at)
    .execute(pool)
    .await
    .expect("insert actor device key");

    let conversation_id = create_conversation_fixture(
        pool,
        &actor_did,
        actor_device_id,
        &actor_key_id,
        &actor_public_key,
    )
    .await;

    DeliveryFixture {
        conversation_id,
        actor_did,
        actor_device_id,
        actor_key_id,
    }
}

/// Insert a coherent creation graph. The genesis creation entry occupies seq 1
/// and the conversation's `next_entry_seq` is initialized to 2 (it accounts for
/// the genesis), matching the schema-test fixture exactly.
async fn create_conversation_fixture(
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

    let mut tx = pool.begin().await.expect("begin coherent creation fixture");
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
    .bind(principal)
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
    .bind(principal)
    .bind(actor_device_id)
    .bind(&basic_credential)
    .bind(actor_public_key)
    .bind(actor_key_id)
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
    .bind(principal)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .bind(actor_public_key)
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
    .bind(principal)
    .bind(actor_device_id)
    .bind(actor_key_id)
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
    .expect("insert creation application interval");
    tx.commit().await.expect("commit coherent creation fixture");

    conversation_id
}

// ---------------------------------------------------------------------------
// Coherent application send: the entry the allocator inserts plus the exact
// `chat.message_sends` row the deferred delivery invariants require at commit.
// ---------------------------------------------------------------------------

struct CoherentSend {
    entry: AppendEntry,
    signing_transcript_bytes: Vec<u8>,
    outcome_bytes: Vec<u8>,
}

fn coherent_application_send(
    fixture: &DeliveryFixture,
    received_at: DateTime<Utc>,
    salt: u8,
) -> CoherentSend {
    let payload = vec![salt; 8];
    let signing_transcript = vec![salt ^ 0x5a; 8];
    let request_digest = Sha256::digest(&signing_transcript).to_vec();
    let signed_request = vec![salt ^ 0x33; 8];
    let signature = vec![salt; 64];
    let outcome = vec![salt ^ 0x0f; 8];

    let entry = AppendEntry {
        conversation_id: fixture.conversation_id,
        entry_id: Uuid::new_v4(),
        entry_kind: APPLICATION_ENTRY_KIND.to_owned(),
        accepted_payload_bytes: payload.clone(),
        accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
        signed_request_bytes: signed_request,
        request_digest,
        signature,
        server_fields_bytes: vec![salt; 1],
        outer_entry_fingerprint: vec![salt; 32],
        actor_did: fixture.actor_did.clone(),
        actor_device_id: fixture.actor_device_id,
        actor_key_id: fixture.actor_key_id.clone(),
        actor_auth_generation: 1,
        generation: Some(0),
        state_version: Some(0),
        transition_id: None,
        message_id: Some(Uuid::new_v4()),
        received_at,
    };

    CoherentSend {
        entry,
        signing_transcript_bytes: signing_transcript,
        outcome_bytes: outcome,
    }
}

/// Insert the `chat.message_sends` row that binds an accepted application send
/// to the entry the allocator just wrote at `seq`. Every crypto column mirrors
/// the entry so the deferred `assert_message_send_mapping` invariant holds.
async fn insert_accepted_message_send(
    tx: &mut Transaction<'_, Postgres>,
    send: &CoherentSend,
    seq: u64,
) {
    let entry = &send.entry;
    sqlx::query(
        r#"
        INSERT INTO chat.message_sends(
            conversation_id,message_id,signed_request_bytes,signing_transcript_bytes,
            request_digest,signature,status,accepted_entry_seq,outcome_bytes,outcome_sha256,received_at
        ) VALUES($1,$2,$3,$4,$5,$6,'accepted',$7,$8,$9,$10)
        "#,
    )
    .bind(entry.conversation_id)
    .bind(entry.message_id.expect("application send carries a message id"))
    .bind(&entry.signed_request_bytes)
    .bind(&send.signing_transcript_bytes)
    .bind(&entry.request_digest)
    .bind(&entry.signature)
    .bind(i64::try_from(seq).expect("seq fits i64"))
    .bind(&send.outcome_bytes)
    .bind(Sha256::digest(&send.outcome_bytes).to_vec())
    .bind(entry.received_at)
    .execute(&mut **tx)
    .await
    .expect("insert accepted message send");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// K sequential appends in one transaction allocate unique, gap-free seqs that
/// start at the conversation's current `next_entry_seq` (2, past the genesis)
/// and leave the append counter and committed log contiguous.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn append_allocates_unique_and_contiguous_seqs() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let received_at = clock_now(&pool).await;

    assert_eq!(
        next_entry_seq(&pool, fixture.conversation_id).await,
        2,
        "genesis creation entry leaves the append counter at 2"
    );

    let mut tx = pool.begin().await.expect("begin append batch");
    let mut allocated = Vec::new();
    for salt in [10_u8, 11, 12, 13] {
        let send = coherent_application_send(&fixture, received_at, salt);
        let seq = append_entry(&mut tx, &send.entry)
            .await
            .expect("append application entry");
        insert_accepted_message_send(&mut tx, &send, seq).await;
        allocated.push(seq);
    }
    tx.commit().await.expect("commit append batch");

    assert_eq!(
        allocated,
        vec![2, 3, 4, 5],
        "appends must allocate unique, contiguous seqs from next_entry_seq"
    );
    assert_eq!(
        next_entry_seq(&pool, fixture.conversation_id).await,
        6,
        "append counter advances once per committed entry"
    );
    assert_eq!(
        committed_entry_seqs(&pool, fixture.conversation_id).await,
        vec![1, 2, 3, 4, 5],
        "committed append-log is contiguous including the genesis entry"
    );
}

/// Two concurrent append transactions serialize on the conversation row lock:
/// while transaction one holds it, transaction two blocks inside `append_entry`
/// and can only proceed after the first commits — yielding distinct, adjacent
/// seqs with no gap or duplicate.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn concurrent_appends_serialize_without_gap_or_dup() {
    let pool = common::chat_protocol::setup_chat_protocol_db(5).await;
    let fixture = seed_fixture(&pool).await;
    let received_at = clock_now(&pool).await;

    // Transaction one appends and holds the conversation row lock (uncommitted).
    let first_send = coherent_application_send(&fixture, received_at, 20);
    let mut first_tx = pool.begin().await.expect("begin first append tx");
    let first_seq = append_entry(&mut first_tx, &first_send.entry)
        .await
        .expect("first append allocates a seq");
    insert_accepted_message_send(&mut first_tx, &first_send, first_seq).await;

    // Transaction two races for the same conversation; it must block on the lock
    // held by transaction one until that transaction commits.
    let second_send = coherent_application_send(&fixture, received_at, 21);
    let second_pool = pool.clone();
    let second_task = tokio::spawn(async move {
        let mut second_tx = second_pool.begin().await.expect("begin second append tx");
        let second_seq = append_entry(&mut second_tx, &second_send.entry)
            .await
            .expect("second append allocates a seq");
        insert_accepted_message_send(&mut second_tx, &second_send, second_seq).await;
        second_tx.commit().await.expect("commit second append tx");
        second_seq
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !second_task.is_finished(),
        "second append must block behind the row lock until the first commits"
    );

    first_tx.commit().await.expect("commit first append tx");

    let second_seq = tokio::time::timeout(Duration::from_secs(5), second_task)
        .await
        .expect("second append completed after the lock released")
        .expect("second append task joined");

    assert_eq!(first_seq, 2, "first append takes the genesis-successor seq");
    assert_eq!(
        second_seq,
        first_seq + 1,
        "serialized appends take distinct, adjacent seqs with no gap or duplicate"
    );
    assert_eq!(
        next_entry_seq(&pool, fixture.conversation_id).await,
        4,
        "append counter reflects exactly two serialized appends"
    );
    assert_eq!(
        committed_entry_seqs(&pool, fixture.conversation_id).await,
        vec![1, 2, 3],
        "concurrent appends leave a contiguous committed log"
    );
}

/// The append-log primary key `(conversation_id, seq)` rejects a second row at
/// an already-occupied seq — the invariant the row-lock allocation upholds.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn primary_key_rejects_duplicate_seq() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let received_at = clock_now(&pool).await;

    // A well-formed application entry aimed at seq 1 — already held by the
    // committed genesis creation entry — must fail on the primary key alone.
    let collision = coherent_application_send(&fixture, received_at, 30);
    let entry = &collision.entry;
    let mut tx = pool.begin().await.expect("begin duplicate-seq probe");
    let duplicate = sqlx::query(
        r#"
        INSERT INTO chat.entries(
            conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
            accepted_payload_sha256,signed_request_bytes,request_digest,signature,
            server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
            actor_key_id,actor_auth_generation,generation,state_version,transition_id,message_id,received_at
        ) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NULL,$17,$18)
        "#,
    )
    .bind(entry.conversation_id)
    .bind(entry.entry_id)
    .bind(&entry.entry_kind)
    .bind(&entry.accepted_payload_bytes)
    .bind(&entry.accepted_payload_sha256)
    .bind(&entry.signed_request_bytes)
    .bind(&entry.request_digest)
    .bind(&entry.signature)
    .bind(&entry.server_fields_bytes)
    .bind(&entry.outer_entry_fingerprint)
    .bind(&entry.actor_did)
    .bind(entry.actor_device_id)
    .bind(&entry.actor_key_id)
    .bind(entry.actor_auth_generation)
    .bind(entry.generation)
    .bind(entry.state_version)
    .bind(entry.message_id)
    .bind(entry.received_at)
    .execute(&mut *tx)
    .await
    .expect_err("duplicate append-log seq must be rejected");

    let db_error = duplicate
        .as_database_error()
        .expect("primary-key violation is a database error");
    assert_eq!(
        db_error.code().as_deref(),
        Some("23505"),
        "duplicate seq must surface a unique_violation"
    );
    assert_eq!(
        db_error.constraint(),
        Some("entries_pkey"),
        "the rejecting constraint is the append-log primary key"
    );
}

/// Appending against an absent conversation is reported, not silently ignored:
/// the `FOR UPDATE` head lock finds no row and the allocator refuses to invent
/// a seq.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn append_reports_missing_conversation() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let received_at = clock_now(&pool).await;

    let mut orphan = AppendEntry {
        conversation_id: Uuid::new_v4(),
        entry_id: Uuid::new_v4(),
        entry_kind: APPLICATION_ENTRY_KIND.to_owned(),
        accepted_payload_bytes: vec![1_u8; 8],
        accepted_payload_sha256: Sha256::digest([1_u8; 8]).to_vec(),
        signed_request_bytes: vec![2_u8; 8],
        request_digest: Sha256::digest([3_u8; 8]).to_vec(),
        signature: vec![4_u8; 64],
        server_fields_bytes: vec![5_u8; 1],
        outer_entry_fingerprint: vec![6_u8; 32],
        actor_did: random_plc_did(),
        actor_device_id: Uuid::new_v4(),
        actor_key_id: sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
            .bind(vec![2_u8; 32])
            .fetch_one(&pool)
            .await
            .expect("derive orphan key id"),
        actor_auth_generation: 1,
        generation: Some(0),
        state_version: Some(0),
        transition_id: None,
        message_id: Some(Uuid::new_v4()),
        received_at,
    };
    orphan.received_at = received_at;

    let mut tx = pool.begin().await.expect("begin orphan probe");
    let error = append_entry(&mut tx, &orphan)
        .await
        .expect_err("append against an absent conversation must fail");
    assert!(
        matches!(error, DeliveryRepositoryError::ConversationMissing),
        "absent conversation is reported as ConversationMissing, got {error:?}"
    );
}
