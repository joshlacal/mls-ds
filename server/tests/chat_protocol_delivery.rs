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
//! repository harnesses — this test `include!`s it directly. Live cases run
//! under the standard whole-suite gate: they hard-fail (panic in
//! `setup_chat_protocol_db`) without `TEST_DATABASE_URL` rather than skipping.
//! Run with:
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_delivery -- --test-threads=1

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

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::Barrier;
use uuid::Uuid;

use repository::delivery::{
    append_entry, append_event, claim_outbox_batch, enqueue_outbox, insert_entry_recipients,
    insert_event_recipients, mark_outbox_delivered, resolve_application_send, AppendEntry,
    ApplicationSend, ApplicationSendDisposition, ApplicationSendOutcome, DeliveryRepositoryError,
    EntryEntitlementKind, EntryRecipient, EventEntitlementKind, EventKind, EventRecipient,
    NewEvent, OutboxWorkKind,
};

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

/// The production `ApplicationSend` mirrors the test `CoherentSend` field-for-field.
fn to_application_send(send: CoherentSend) -> ApplicationSend {
    ApplicationSend {
        entry: send.entry,
        signing_transcript_bytes: send.signing_transcript_bytes,
        outcome_bytes: send.outcome_bytes,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Arm 6 (message send — accepted): `resolve_application_send(Accept)` appends one
/// `applicationEntry` at the self-allocated seq (past the genesis, so 2) + an
/// `accepted` `message_sends` row bound to it, and advances only `next_entry_seq`.
/// An EXACT replay returns the ORIGINAL seq with no new entry; the same message id
/// under DIFFERENT signed bytes conflicts.
#[tokio::test]
async fn application_send_accepts_appends_entry_and_is_idempotent() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let received_at = clock_now(&pool).await;
    let send = to_application_send(coherent_application_send(&fixture, received_at, 0x21));
    let message_id = send
        .entry
        .message_id
        .expect("application send carries a message id");

    let mut tx = pool.begin().await.expect("begin accept");
    let outcome = resolve_application_send(&mut tx, &send, ApplicationSendDisposition::Accept)
        .await
        .expect("accepted send resolves");
    tx.commit()
        .await
        .expect("accept COMMIT past deferred mapping");
    assert_eq!(outcome, ApplicationSendOutcome::Accepted { seq: 2 });
    assert_eq!(next_entry_seq(&pool, fixture.conversation_id).await, 3);

    // The applicationEntry at seq 2 carries the message id.
    let (kind, mid): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT entry_kind,message_id FROM chat.entries WHERE conversation_id=$1 AND seq=2",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&pool)
    .await
    .expect("application entry");
    assert_eq!(kind, APPLICATION_ENTRY_KIND);
    assert_eq!(mid, Some(message_id));
    // The accepted message_sends row is bound to that seq with the mirrored envelope.
    let (status, accepted_seq, digest): (String, Option<i64>, Vec<u8>) = sqlx::query_as(
        "SELECT status,accepted_entry_seq,request_digest FROM chat.message_sends WHERE conversation_id=$1 AND message_id=$2",
    )
    .bind(fixture.conversation_id)
    .bind(message_id)
    .fetch_one(&pool)
    .await
    .expect("message_sends row");
    assert_eq!((status.as_str(), accepted_seq), ("accepted", Some(2)));
    assert_eq!(digest, send.entry.request_digest);

    // Exact replay -> the ORIGINAL seq, no new entry, counter unchanged.
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = resolve_application_send(&mut tx2, &send, ApplicationSendDisposition::Accept)
        .await
        .expect("replay resolves");
    tx2.commit().await.expect("replay COMMIT");
    assert_eq!(replay, ApplicationSendOutcome::Accepted { seq: 2 });
    assert_eq!(next_entry_seq(&pool, fixture.conversation_id).await, 3);
    assert_eq!(
        committed_entry_seqs(&pool, fixture.conversation_id).await,
        vec![1, 2]
    );

    // Same message id, DIFFERENT signed content -> MessageSendConflict, zero residue.
    let mut conflicting = send.clone();
    conflicting.entry.request_digest = Sha256::digest([0xFE_u8; 8]).to_vec();
    let mut tx3 = pool.begin().await.expect("begin conflict");
    let conflict =
        resolve_application_send(&mut tx3, &conflicting, ApplicationSendDisposition::Accept).await;
    assert!(
        matches!(conflict, Err(DeliveryRepositoryError::MessageSendConflict)),
        "a reused message id with different bytes must conflict, got {conflict:?}"
    );
    tx3.rollback().await.expect("rollback conflict");
    assert_eq!(next_entry_seq(&pool, fixture.conversation_id).await, 3);
}

/// Arm 6 (message send — stale tombstone): `resolve_application_send(Stale)` records
/// a durable `stale` `message_sends` row with NO entry / NO seq (the explicitly-
/// committed rejection path — it COMMITS even though the business is a refusal), and
/// leaves `next_entry_seq` untouched. A later `Accept`-intent replay can NEVER
/// succeed — it returns the stored `Stale` outcome and appends nothing.
#[tokio::test]
async fn application_send_stale_tombstones_without_entry_and_never_succeeds() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let received_at = clock_now(&pool).await;
    let send = to_application_send(coherent_application_send(&fixture, received_at, 0x31));
    let message_id = send
        .entry
        .message_id
        .expect("application send carries a message id");

    let mut tx = pool.begin().await.expect("begin stale");
    let outcome = resolve_application_send(&mut tx, &send, ApplicationSendDisposition::Stale)
        .await
        .expect("stale send resolves");
    tx.commit()
        .await
        .expect("stale COMMIT past deferred mapping");
    assert_eq!(outcome, ApplicationSendOutcome::Stale);
    // Counter untouched (no entry appended).
    assert_eq!(next_entry_seq(&pool, fixture.conversation_id).await, 2);
    let (status, accepted_seq): (String, Option<i64>) = sqlx::query_as(
        "SELECT status,accepted_entry_seq FROM chat.message_sends WHERE conversation_id=$1 AND message_id=$2",
    )
    .bind(fixture.conversation_id)
    .bind(message_id)
    .fetch_one(&pool)
    .await
    .expect("stale message_sends row");
    assert_eq!((status.as_str(), accepted_seq), ("stale", None));
    let entry_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.entries WHERE conversation_id=$1 AND message_id=$2",
    )
    .bind(fixture.conversation_id)
    .bind(message_id)
    .fetch_one(&pool)
    .await
    .expect("no application entry for a stale send");
    assert_eq!(entry_count, 0);

    // An Accept-intent replay of a stale send stays Stale — it can never succeed.
    let mut tx2 = pool.begin().await.expect("begin stale replay");
    let replay = resolve_application_send(&mut tx2, &send, ApplicationSendDisposition::Accept)
        .await
        .expect("stale replay resolves");
    tx2.commit().await.expect("stale replay COMMIT");
    assert_eq!(replay, ApplicationSendOutcome::Stale);
    assert_eq!(next_entry_seq(&pool, fixture.conversation_id).await, 2);
    let entry_count_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.entries WHERE conversation_id=$1 AND message_id=$2",
    )
    .bind(fixture.conversation_id)
    .bind(message_id)
    .fetch_one(&pool)
    .await
    .expect("still no entry after the accept replay");
    assert_eq!(entry_count_after, 0);
}

/// K sequential appends in one transaction allocate unique, gap-free seqs that
/// start at the conversation's current `next_entry_seq` (2, past the genesis)
/// and leave the append counter and committed log contiguous.
#[tokio::test]
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

// ===========================================================================
// Audience / event / outbox write primitives (Task E1)
//
// The append-log allocator above materializes `chat.entries`. The primitives
// below materialize the *frozen* control-entry audience, the global event log,
// the event audience, and the durable outbox work the transition executor
// (later tasks) composes on top of a single caller-owned transaction. Each
// primitive is exercised against the sealed production schema: the immediate
// table constraints (kind CHECKs, PKs, FKs) and — where a whole coherent
// transaction is required — the deferred audience/mapping triggers.
// ===========================================================================

/// The clean-chat schema pins a *singleton* `chat.protocol_instances` row that
/// every `chat.events` / `chat.event_retention` row references. The test
/// database is never truncated between runs, so seed it idempotently and return
/// the one instance id all events must bind.
async fn ensure_protocol_instance(pool: &PgPool) -> Uuid {
    let created_at = clock_now(pool).await;
    sqlx::query(
        "INSERT INTO chat.protocol_instances(protocol_instance_id, cursor_key_id, created_at) \
         VALUES ($1, $2, $3) ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(URL_SAFE_NO_PAD.encode([0x41_u8; 32]))
    .bind(created_at)
    .execute(pool)
    .await
    .expect("ensure singleton protocol instance");
    sqlx::query_scalar("SELECT protocol_instance_id FROM chat.protocol_instances")
        .fetch_one(pool)
        .await
        .expect("read singleton protocol instance id")
}

/// Seed one additional active device under an existing principal. Audience rows
/// FK only `chat.devices` (never `chat.device_keys`), so a bare device row is
/// all the frozen-recipient primitives require. Each device carries a unique
/// active `dpop_jkt` to satisfy `devices_active_dpop_jkt_uq`.
async fn seed_extra_device(pool: &PgPool, user_did: &str) -> Uuid {
    let device_id = Uuid::new_v4();
    let created_at = clock_now(pool).await;
    let mut jkt_material = Uuid::new_v4().as_bytes().to_vec();
    jkt_material.extend_from_slice(Uuid::new_v4().as_bytes());
    let dpop_jkt = URL_SAFE_NO_PAD.encode(&jkt_material[..32]);
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'audience-device','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(&dpop_jkt)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert extra audience device");
    device_id
}

/// Canonical audience order is `(user-DID UTF-8 bytes, device UUID raw bytes)`.
fn sorted_by_raw_bytes(mut devices: Vec<Uuid>) -> Vec<Uuid> {
    devices.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    devices
}

async fn entry_recipient_rows(
    pool: &PgPool,
    conversation_id: Uuid,
    seq: i64,
) -> Vec<(String, Uuid, String)> {
    sqlx::query_as(
        "SELECT user_did, device_id, entitlement_kind FROM chat.entry_recipients \
         WHERE conversation_id = $1 AND seq = $2 ORDER BY user_did, device_id",
    )
    .bind(conversation_id)
    .bind(seq)
    .fetch_all(pool)
    .await
    .expect("read frozen entry recipients")
}

async fn event_kind_at(pool: &PgPool, position: i64) -> String {
    sqlx::query_scalar("SELECT event_kind FROM chat.events WHERE event_position = $1")
        .bind(position)
        .fetch_one(pool)
        .await
        .expect("read event kind")
}

async fn event_created_at(pool: &PgPool, position: i64) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT created_at FROM chat.events WHERE event_position = $1")
        .bind(position)
        .fetch_one(pool)
        .await
        .expect("read event created_at")
}

async fn event_payload_sha256(pool: &PgPool, position: i64) -> Vec<u8> {
    sqlx::query_scalar("SELECT payload_sha256 FROM chat.events WHERE event_position = $1")
        .bind(position)
        .fetch_one(pool)
        .await
        .expect("read event payload hash")
}

async fn outbox_row(
    pool: &PgPool,
    outbox_id: Uuid,
) -> (String, Option<Uuid>, Option<DateTime<Utc>>) {
    sqlx::query_as("SELECT status, lease_owner, delivered_at FROM chat.outbox WHERE outbox_id = $1")
        .bind(outbox_id)
        .fetch_one(pool)
        .await
        .expect("read outbox work row")
}

/// Neutralise every pre-existing `chat.outbox` row before a test that asserts
/// over a *global*, unscoped `claim_outbox_batch` scan, by parking it under a
/// sentinel lease that expires far in the future (so it is not claimable during
/// this test).
///
/// `claim_outbox_batch` claims in global `event_position` order with no per-test
/// scoping — this is by design and its production code is review-approved. The
/// clean-chat test database is never truncated between runs, so this suite's own
/// committed work accumulates as claimable residue: the enqueue-uniqueness test
/// commits two `pending` rows, and every claim test commits `leased` rows whose
/// lease then expires relative to a later run's clock, becoming reclaimable.
/// Because residue carries *lower* `event_position` values than a fresh run's
/// rows, `ORDER BY event_position LIMIT n` claims the residue first and inflates
/// (or entirely displaces) the current test's expected result — e.g.
/// `reclaims_only_expired` observed `first.len() == 10` (its `LIMIT 10`) instead
/// of `1` on the second run.
///
/// Outbox rows are immutable (a `BEFORE DELETE` trigger forbids removing them),
/// so residue is *parked*, not deleted. The `pending -> leased` and
/// `leased -> leased` transitions this UPDATE performs are exactly the ones the
/// reviewed `claim_outbox_batch` / reclaim path performs and that the
/// `outbox_lifecycle_monotonic` trigger permits; only the mutable
/// `status`/`lease_owner`/`lease_expires_at` columns are touched (`lease_owner`
/// is a fresh v4 UUID, as the `outbox_lease_owner_check` requires). Every
/// non-terminal residue row lands under a lease dated years ahead, so the test's
/// subsequent claim (sampled at `now`) sees only its own freshly enqueued work.
/// Terminal (`delivered`/`failed`) rows are already non-claimable and left as-is.
async fn drain_outbox(pool: &PgPool) {
    let now = clock_now(pool).await;
    let parked_until = now + chrono::Duration::days(3650);
    sqlx::query(
        r#"
        UPDATE chat.outbox
           SET status = 'leased',
               lease_owner = $1,
               lease_expires_at = $2
         WHERE status IN ('pending', 'leased')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(parked_until)
    .execute(pool)
    .await
    .expect("park residual claimable outbox work before a global-claim test");
}

// ---------------------------------------------------------------------------
// entry_recipients
// ---------------------------------------------------------------------------

/// A control audience for the genesis creation entry freezes one immutable row
/// per exact device, in canonical `(DID,device)` order, and commits cleanly:
/// the deferred `entry_recipients_mapping_deferred` guard is satisfied because
/// seq 1 is a non-application control entry.
#[tokio::test]
async fn entry_recipients_control_arm_freezes_and_commits() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let extra_a = seed_extra_device(&pool, &fixture.actor_did).await;
    let extra_b = seed_extra_device(&pool, &fixture.actor_did).await;

    let devices = sorted_by_raw_bytes(vec![fixture.actor_device_id, extra_a, extra_b]);
    let recipients: Vec<EntryRecipient> = devices
        .iter()
        .map(|device| EntryRecipient {
            user_did: fixture.actor_did.clone(),
            device_id: *device,
            entitlement_kind: EntryEntitlementKind::Control,
        })
        .collect();

    let mut tx = pool.begin().await.expect("begin control audience freeze");
    insert_entry_recipients(&mut tx, fixture.conversation_id, 1, &recipients)
        .await
        .expect("freeze control audience for the genesis entry");
    tx.commit().await.expect("commit control audience freeze");

    let rows = entry_recipient_rows(&pool, fixture.conversation_id, 1).await;
    assert_eq!(rows.len(), 3, "one frozen row per exact device");
    assert!(
        rows.iter()
            .all(|(did, _, kind)| did == &fixture.actor_did && kind == "control"),
        "every frozen row is a control-arm row for the actor principal: {rows:?}"
    );
    let mut stored: Vec<Uuid> = rows.iter().map(|(_, device, _)| *device).collect();
    stored.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    assert_eq!(stored, devices, "all three exact devices are frozen");
}

/// A control entry with no audience is a caller bug: the primitive refuses an
/// empty recipient list rather than writing zero rows.
#[tokio::test]
async fn entry_recipients_reject_empty_audience() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let fixture = seed_fixture(&pool).await;

    let mut tx = pool.begin().await.expect("begin empty audience probe");
    let error = insert_entry_recipients(&mut tx, fixture.conversation_id, 1, &[])
        .await
        .expect_err("empty control audience must be rejected");
    assert!(
        matches!(error, DeliveryRepositoryError::EmptyRecipients),
        "empty audience is reported as EmptyRecipients, got {error:?}"
    );
}

/// The primitive enforces canonical `(DID,device)` input order and rejects both
/// out-of-order and duplicate tuples rather than silently sorting/deduping.
#[tokio::test]
async fn entry_recipients_reject_noncanonical_or_duplicate_input() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let fixture = seed_fixture(&pool).await;
    let extra = seed_extra_device(&pool, &fixture.actor_did).await;

    let ordered = sorted_by_raw_bytes(vec![fixture.actor_device_id, extra]);
    let (low, high) = (ordered[0], ordered[1]);
    let row = |device: Uuid| EntryRecipient {
        user_did: fixture.actor_did.clone(),
        device_id: device,
        entitlement_kind: EntryEntitlementKind::Control,
    };

    let mut tx = pool.begin().await.expect("begin ordering probe");
    let reversed =
        insert_entry_recipients(&mut tx, fixture.conversation_id, 1, &[row(high), row(low)])
            .await
            .expect_err("descending audience input must be rejected");
    assert!(
        matches!(reversed, DeliveryRepositoryError::NonCanonicalRecipients),
        "out-of-order input is reported as NonCanonicalRecipients, got {reversed:?}"
    );

    let duplicate =
        insert_entry_recipients(&mut tx, fixture.conversation_id, 1, &[row(low), row(low)])
            .await
            .expect_err("duplicate audience input must be rejected");
    assert!(
        matches!(duplicate, DeliveryRepositoryError::NonCanonicalRecipients),
        "duplicate input is reported as NonCanonicalRecipients, got {duplicate:?}"
    );
}

/// The `(conversation,seq,DID,device)` primary key rejects a second frozen row
/// for the same exact device at the same entry — audience rows are immutable.
#[tokio::test]
async fn entry_recipients_duplicate_pk_rejected() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let fixture = seed_fixture(&pool).await;

    let recipient = EntryRecipient {
        user_did: fixture.actor_did.clone(),
        device_id: fixture.actor_device_id,
        entitlement_kind: EntryEntitlementKind::Control,
    };

    let mut tx = pool.begin().await.expect("begin duplicate-pk probe");
    insert_entry_recipients(
        &mut tx,
        fixture.conversation_id,
        1,
        std::slice::from_ref(&recipient),
    )
    .await
    .expect("first frozen row is accepted");
    let error = insert_entry_recipients(
        &mut tx,
        fixture.conversation_id,
        1,
        std::slice::from_ref(&recipient),
    )
    .await
    .expect_err("a second row for the same exact device must be rejected");
    let db_error = match &error {
        DeliveryRepositoryError::Database(db) => db.as_database_error().expect("database error"),
        other => panic!("duplicate audience must surface a database error, got {other:?}"),
    };
    assert_eq!(
        db_error.code().as_deref(),
        Some("23505"),
        "duplicate audience is a unique_violation"
    );
    assert_eq!(
        db_error.constraint(),
        Some("entry_recipients_pkey"),
        "the rejecting constraint is the audience primary key"
    );
}

/// Frozen rows require both the addressed entry and the exact device to exist:
/// the two immediate foreign keys reject an audience row aimed at a
/// non-existent seq or a non-existent device.
#[tokio::test]
async fn entry_recipients_reject_missing_entry_or_device_fk() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let fixture = seed_fixture(&pool).await;

    // Missing device: a real seq (genesis entry 1) but a device absent from
    // chat.devices trips entry_recipients_device_fk.
    let mut tx = pool.begin().await.expect("begin missing-device probe");
    let missing_device = insert_entry_recipients(
        &mut tx,
        fixture.conversation_id,
        1,
        &[EntryRecipient {
            user_did: fixture.actor_did.clone(),
            device_id: Uuid::new_v4(),
            entitlement_kind: EntryEntitlementKind::Control,
        }],
    )
    .await
    .expect_err("audience for an unknown device must be rejected");
    let device_error = match &missing_device {
        DeliveryRepositoryError::Database(db) => db.as_database_error().expect("database error"),
        other => panic!("missing device must surface a database error, got {other:?}"),
    };
    assert_eq!(
        device_error.code().as_deref(),
        Some("23503"),
        "missing device is a foreign_key_violation"
    );
    assert_eq!(
        device_error.constraint(),
        Some("entry_recipients_device_fk")
    );
    drop(tx);

    // Missing entry: a real device but a seq with no committed entry trips
    // entry_recipients_entry_fk.
    let mut tx = pool.begin().await.expect("begin missing-entry probe");
    let missing_entry = insert_entry_recipients(
        &mut tx,
        fixture.conversation_id,
        9_999,
        &[EntryRecipient {
            user_did: fixture.actor_did.clone(),
            device_id: fixture.actor_device_id,
            entitlement_kind: EntryEntitlementKind::Control,
        }],
    )
    .await
    .expect_err("audience for an absent entry seq must be rejected");
    let entry_error = match &missing_entry {
        DeliveryRepositoryError::Database(db) => db.as_database_error().expect("database error"),
        other => panic!("missing entry must surface a database error, got {other:?}"),
    };
    assert_eq!(
        entry_error.code().as_deref(),
        Some("23503"),
        "missing entry is a foreign_key_violation"
    );
    assert_eq!(entry_error.constraint(), Some("entry_recipients_entry_fk"));
}

/// The `intervalClose` and `scheduleTerminal` arms are written by this primitive
/// (immediate table constraints pass) but their COMMIT coherence is enforced by
/// the deferred `entry_recipients_mapping_deferred` guard, which the transition
/// executor satisfies by composing the closed application interval / terminal
/// proof in the same transaction. Isolated here — with no interval/proof — the
/// insert is accepted while the commit is rejected, proving both the primitive
/// and the schema guard.
#[tokio::test]
async fn entry_recipients_interval_kinds_written_but_guarded_at_commit() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let fixture = seed_fixture(&pool).await;
    let interval_device = seed_extra_device(&pool, &fixture.actor_did).await;
    let terminal_device = seed_extra_device(&pool, &fixture.actor_did).await;

    for (device, kind) in [
        (interval_device, EntryEntitlementKind::IntervalClose),
        (terminal_device, EntryEntitlementKind::ScheduleTerminal),
    ] {
        let mut tx = pool.begin().await.expect("begin interval-kind probe");
        insert_entry_recipients(
            &mut tx,
            fixture.conversation_id,
            1,
            &[EntryRecipient {
                user_did: fixture.actor_did.clone(),
                device_id: device,
                entitlement_kind: kind,
            }],
        )
        .await
        .unwrap_or_else(|error| {
            panic!("{kind:?} row must pass immediate constraints, got {error:?}")
        });

        let commit = tx
            .commit()
            .await
            .expect_err("an un-scaffolded interval-bound audience row must be rejected at commit");
        let db_error = commit
            .as_database_error()
            .expect("deferred mapping guard raises a database error");
        assert_eq!(
            db_error.code().as_deref(),
            Some("23514"),
            "the deferred audience-mapping guard rejects {kind:?} with a check_violation"
        );
    }
}

// ---------------------------------------------------------------------------
// events
// ---------------------------------------------------------------------------

fn new_event(instance: Uuid, kind: EventKind, created_at: DateTime<Utc>, salt: u8) -> NewEvent {
    NewEvent {
        event_id: Uuid::new_v4(),
        event_kind: kind,
        payload_bytes: vec![salt; 8],
        created_at,
        protocol_instance_id: instance,
    }
}

/// The DB-allocated `event_position` identity is strictly increasing across
/// sequential appends (gaps are allowed, order is not).
#[tokio::test]
async fn append_event_allocates_strictly_increasing_positions() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let instance = ensure_protocol_instance(&pool).await;
    let created_at = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin event batch");
    let mut positions = Vec::new();
    for salt in [1_u8, 2, 3, 4] {
        let event = new_event(instance, EventKind::MessageAvailable, created_at, salt);
        positions.push(append_event(&mut tx, &event).await.expect("append event"));
    }
    tx.commit().await.expect("commit event batch");

    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "event positions must be strictly increasing: {positions:?}"
    );
}

/// Each of the ten closed `event_kind` values round-trips through the primitive,
/// and the caller-supplied `created_at` is stored verbatim (never `now()`).
#[tokio::test]
async fn append_event_roundtrips_every_kind_and_caller_timestamp() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let instance = ensure_protocol_instance(&pool).await;
    // A caller-authored instant firmly in the past: if the primitive used
    // now() the stored value would not match.
    let authored_at = "2020-01-02T03:04:05.678Z"
        .parse::<DateTime<Utc>>()
        .expect("parse caller-authored instant");

    let kinds = [
        (EventKind::ConversationChanged, "conversationChanged"),
        (EventKind::ConversationClosed, "conversationClosed"),
        (EventKind::MessageAvailable, "messageAvailable"),
        (EventKind::WelcomeAvailable, "welcomeAvailable"),
        (EventKind::WelcomeDisposition, "welcomeDisposition"),
        (EventKind::ResetRequested, "resetRequested"),
        (EventKind::LeafRecovery, "leafRecovery"),
        (EventKind::LeaveRequest, "leaveRequest"),
        (EventKind::AccessEnded, "accessEnded"),
        (EventKind::Watermark, "watermark"),
    ];

    for (salt, (kind, expected)) in kinds.into_iter().enumerate() {
        let mut tx = pool.begin().await.expect("begin single-kind append");
        let event = new_event(instance, kind, authored_at, salt as u8);
        let position = append_event(&mut tx, &event)
            .await
            .expect("append typed event");
        tx.commit().await.expect("commit single-kind append");

        assert_eq!(
            event_kind_at(&pool, position).await,
            expected,
            "kind {kind:?} round-trips"
        );
        assert_eq!(
            event_created_at(&pool, position).await,
            authored_at,
            "created_at is the caller-supplied instant for {kind:?}"
        );
    }
}

/// The API computes `payload_sha256` from the same bytes it stores, so a hash
/// mismatch is impossible through the primitive; the DB CHECK independently
/// rejects a hand-rolled row whose stored hash does not match its payload.
#[tokio::test]
async fn append_event_hash_is_api_computed_and_db_enforced() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let instance = ensure_protocol_instance(&pool).await;
    let created_at = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin hashed append");
    let event = new_event(instance, EventKind::MessageAvailable, created_at, 7);
    let position = append_event(&mut tx, &event)
        .await
        .expect("append hashed event");
    tx.commit().await.expect("commit hashed append");
    assert_eq!(
        event_payload_sha256(&pool, position).await,
        Sha256::digest(&event.payload_bytes).to_vec(),
        "the stored hash is the API-computed digest of the payload"
    );

    // A direct insert with a deliberately wrong hash must be refused by the DB.
    let mut tx = pool.begin().await.expect("begin bad-hash probe");
    let bad = sqlx::query(
        "INSERT INTO chat.events(event_id,event_kind,payload_bytes,payload_sha256,created_at,protocol_instance_id) \
         VALUES($1,'messageAvailable',$2,$3,$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(vec![9_u8; 8])
    .bind(vec![0_u8; 32])
    .bind(created_at)
    .bind(instance)
    .execute(&mut *tx)
    .await
    .expect_err("a mismatched payload hash must be rejected by the DB CHECK");
    assert_eq!(
        bad.as_database_error()
            .and_then(|db| db.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("23514"),
        "the payload-hash CHECK rejects a mismatched digest"
    );
}

// ---------------------------------------------------------------------------
// event_recipients
// ---------------------------------------------------------------------------

fn event_recipient(did: &str, device: Uuid, predecessor: Option<i64>) -> EventRecipient {
    EventRecipient {
        user_did: did.to_owned(),
        device_id: device,
        entitlement_kind: EventEntitlementKind::Participant,
        audience_predecessor_position: predecessor,
    }
}

/// A device's audience rows chain across events via
/// `audience_predecessor_position`: the first row is `NULL`, each later row
/// points at the same device's immediately preceding event_position. A valid
/// chain commits.
#[tokio::test]
async fn event_recipients_valid_predecessor_chain_commits() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let fixture = seed_fixture(&pool).await;
    let instance = ensure_protocol_instance(&pool).await;
    let created_at = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin chain build");
    let first = append_event(
        &mut tx,
        &new_event(instance, EventKind::MessageAvailable, created_at, 1),
    )
    .await
    .expect("append first event");
    insert_event_recipients(
        &mut tx,
        first,
        &[event_recipient(
            &fixture.actor_did,
            fixture.actor_device_id,
            None,
        )],
    )
    .await
    .expect("freeze first audience row (chain head)");

    let second = append_event(
        &mut tx,
        &new_event(instance, EventKind::MessageAvailable, created_at, 2),
    )
    .await
    .expect("append second event");
    insert_event_recipients(
        &mut tx,
        second,
        &[event_recipient(
            &fixture.actor_did,
            fixture.actor_device_id,
            Some(first),
        )],
    )
    .await
    .expect("freeze second audience row chained to the first");
    tx.commit()
        .await
        .expect("a valid same-device chain commits");

    let predecessor: Option<i64> = sqlx::query_scalar(
        "SELECT audience_predecessor_position FROM chat.event_recipients \
         WHERE event_position = $1 AND user_did = $2 AND device_id = $3",
    )
    .bind(second)
    .bind(&fixture.actor_did)
    .bind(fixture.actor_device_id)
    .fetch_one(&pool)
    .await
    .expect("read chained predecessor");
    assert_eq!(
        predecessor,
        Some(first),
        "the second row chains to the first event position"
    );
}

/// A predecessor that names a *different* device's event_position has no
/// matching `event_recipients(user_did,device_id,event_position)` row, so the
/// deferred self-referential foreign key rejects the chain at commit.
#[tokio::test]
async fn event_recipients_cross_device_predecessor_rejected_at_commit() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let fixture = seed_fixture(&pool).await;
    let other_device = seed_extra_device(&pool, &fixture.actor_did).await;
    let instance = ensure_protocol_instance(&pool).await;
    let created_at = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin cross-device chain");
    let first = append_event(
        &mut tx,
        &new_event(instance, EventKind::MessageAvailable, created_at, 1),
    )
    .await
    .expect("append first event");
    insert_event_recipients(
        &mut tx,
        first,
        &[event_recipient(
            &fixture.actor_did,
            fixture.actor_device_id,
            None,
        )],
    )
    .await
    .expect("freeze the actor device's head row");

    let second = append_event(
        &mut tx,
        &new_event(instance, EventKind::MessageAvailable, created_at, 2),
    )
    .await
    .expect("append second event");
    // `other_device` points its predecessor at the actor device's position.
    insert_event_recipients(
        &mut tx,
        second,
        &[event_recipient(
            &fixture.actor_did,
            other_device,
            Some(first),
        )],
    )
    .await
    .expect("insert is accepted; the mis-chain is caught at commit");

    let commit = tx
        .commit()
        .await
        .expect_err("a cross-device predecessor must be rejected at commit");
    let db_error = commit
        .as_database_error()
        .expect("deferred chain guard raises a database error");
    assert!(
        matches!(db_error.code().as_deref(), Some("23503") | Some("23514")),
        "cross-device predecessor fails the deferred FK / chain guard, got {:?}",
        db_error.code()
    );
}

/// The `audience_predecessor_position < event_position` CHECK is immediate: a
/// predecessor at or beyond the row's own position is refused at insert.
#[tokio::test]
async fn event_recipients_non_earlier_predecessor_rejected() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let fixture = seed_fixture(&pool).await;
    let instance = ensure_protocol_instance(&pool).await;
    let created_at = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin self-predecessor probe");
    let position = append_event(
        &mut tx,
        &new_event(instance, EventKind::MessageAvailable, created_at, 1),
    )
    .await
    .expect("append event");
    let error = insert_event_recipients(
        &mut tx,
        position,
        &[event_recipient(
            &fixture.actor_did,
            fixture.actor_device_id,
            Some(position),
        )],
    )
    .await
    .expect_err("a predecessor equal to the row position must be rejected");
    let db_error = match &error {
        DeliveryRepositoryError::Database(db) => db.as_database_error().expect("database error"),
        other => panic!("non-earlier predecessor must surface a database error, got {other:?}"),
    };
    assert_eq!(
        db_error.code().as_deref(),
        Some("23514"),
        "predecessor >= position fails the immediate CHECK"
    );
}

/// The `(event_position,user_did,device_id)` primary key rejects a second
/// audience row for the same exact device at the same event.
#[tokio::test]
async fn event_recipients_duplicate_pk_rejected() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let fixture = seed_fixture(&pool).await;
    let instance = ensure_protocol_instance(&pool).await;
    let created_at = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin duplicate audience probe");
    let position = append_event(
        &mut tx,
        &new_event(instance, EventKind::MessageAvailable, created_at, 1),
    )
    .await
    .expect("append event");
    insert_event_recipients(
        &mut tx,
        position,
        &[event_recipient(
            &fixture.actor_did,
            fixture.actor_device_id,
            None,
        )],
    )
    .await
    .expect("first audience row accepted");
    let error = insert_event_recipients(
        &mut tx,
        position,
        &[event_recipient(
            &fixture.actor_did,
            fixture.actor_device_id,
            None,
        )],
    )
    .await
    .expect_err("a second row for the same exact device is rejected");
    let db_error = match &error {
        DeliveryRepositoryError::Database(db) => db.as_database_error().expect("database error"),
        other => panic!("duplicate audience must surface a database error, got {other:?}"),
    };
    assert_eq!(
        db_error.code().as_deref(),
        Some("23505"),
        "duplicate audience is a unique_violation"
    );
    assert_eq!(db_error.constraint(), Some("event_recipients_pkey"));
}

// ---------------------------------------------------------------------------
// outbox
// ---------------------------------------------------------------------------

/// Enqueue one durable work row per `(event_position, work_kind)`. The
/// `outbox_event_work_uq` uniqueness prevents a double enqueue for the same
/// work kind, while a different work kind for the same event is allowed.
#[tokio::test]
async fn enqueue_outbox_enforces_event_work_uniqueness() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let instance = ensure_protocol_instance(&pool).await;
    let now = clock_now(&pool).await;

    // Commit the event and its first stream work so both the duplicate probe
    // and the distinct-kind enqueue observe a durable event + outbox row.
    let mut tx = pool.begin().await.expect("begin enqueue");
    let position = append_event(
        &mut tx,
        &new_event(instance, EventKind::MessageAvailable, now, 1),
    )
    .await
    .expect("append event");
    enqueue_outbox(
        &mut tx,
        Uuid::new_v4(),
        position,
        OutboxWorkKind::Stream,
        now,
    )
    .await
    .expect("first stream work enqueued");
    tx.commit().await.expect("commit event + first stream work");

    // A second stream row for the same event violates the work-kind uniqueness.
    let mut tx = pool.begin().await.expect("begin duplicate enqueue probe");
    let duplicate = enqueue_outbox(
        &mut tx,
        Uuid::new_v4(),
        position,
        OutboxWorkKind::Stream,
        now,
    )
    .await
    .expect_err("a second stream row for the same event is rejected");
    let db_error = match &duplicate {
        DeliveryRepositoryError::Database(db) => db.as_database_error().expect("database error"),
        other => panic!("double enqueue must surface a database error, got {other:?}"),
    };
    assert_eq!(
        db_error.code().as_deref(),
        Some("23505"),
        "double enqueue is a unique_violation"
    );
    assert_eq!(db_error.constraint(), Some("outbox_event_work_uq"));
    drop(tx);

    // A distinct work kind for the same event position is legitimate.
    let mut tx = pool.begin().await.expect("begin distinct-kind enqueue");
    enqueue_outbox(
        &mut tx,
        Uuid::new_v4(),
        position,
        OutboxWorkKind::Notification,
        now,
    )
    .await
    .expect("notification work for the same event is allowed");
    tx.commit().await.expect("commit distinct-kind enqueue");
}

/// SECURITY-CRITICAL: two workers claiming the queue concurrently (two
/// connections, a shared barrier) partition the pending rows via
/// `FOR UPDATE SKIP LOCKED` and never claim the same row twice.
#[tokio::test]
async fn claim_outbox_batch_two_claimers_never_double_claim() {
    let pool = common::chat_protocol::setup_chat_protocol_db(6).await;
    // Remove prior-run residue so the two claimers partition exactly this test's
    // freshly enqueued rows (the assertions below are exact over that set).
    drain_outbox(&pool).await;
    let instance = ensure_protocol_instance(&pool).await;
    let base = clock_now(&pool).await;

    const WORK_COUNT: usize = 6;
    let mut enqueue_tx = pool.begin().await.expect("begin enqueue batch");
    let mut outbox_ids = Vec::new();
    for salt in 0..WORK_COUNT {
        let position = append_event(
            &mut enqueue_tx,
            &new_event(instance, EventKind::MessageAvailable, base, salt as u8),
        )
        .await
        .expect("append event for outbox row");
        let outbox_id = Uuid::new_v4();
        enqueue_outbox(
            &mut enqueue_tx,
            outbox_id,
            position,
            OutboxWorkKind::Stream,
            base,
        )
        .await
        .expect("enqueue pending stream work");
        outbox_ids.push(outbox_id);
    }
    enqueue_tx.commit().await.expect("commit enqueue batch");

    let lease_expires_at = base + chrono::Duration::seconds(300);
    let barrier = Arc::new(Barrier::new(2));

    let claim = |owner: Uuid| {
        let pool = pool.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            let mut tx = pool.begin().await.expect("begin claimer tx");
            barrier.wait().await;
            let claimed =
                claim_outbox_batch(&mut tx, owner, base, lease_expires_at, WORK_COUNT as i64)
                    .await
                    .expect("claim outbox batch");
            tx.commit().await.expect("commit claimer tx");
            claimed
                .into_iter()
                .map(|work| work.outbox_id)
                .collect::<Vec<_>>()
        })
    };

    let claimer_a = claim(Uuid::new_v4());
    let claimer_b = claim(Uuid::new_v4());
    let claimed_a = claimer_a.await.expect("join claimer a");
    let claimed_b = claimer_b.await.expect("join claimer b");

    let set_a: HashSet<Uuid> = claimed_a.iter().copied().collect();
    let set_b: HashSet<Uuid> = claimed_b.iter().copied().collect();
    assert_eq!(
        set_a.len(),
        claimed_a.len(),
        "claimer a returns no internal duplicates"
    );
    assert_eq!(
        set_b.len(),
        claimed_b.len(),
        "claimer b returns no internal duplicates"
    );
    assert!(
        set_a.is_disjoint(&set_b),
        "no outbox row is claimed by both workers"
    );
    assert_eq!(
        claimed_a.len() + claimed_b.len(),
        WORK_COUNT,
        "the two workers together claim every pending row exactly once"
    );
    let mut union = set_a;
    union.extend(set_b);
    assert_eq!(
        union,
        outbox_ids.iter().copied().collect::<HashSet<Uuid>>(),
        "the claimed union is exactly the enqueued set"
    );
}

/// A lease that has expired relative to the caller's `now` is reclaimable by a
/// fresh worker; a still-valid lease is not.
#[tokio::test]
async fn claim_outbox_batch_reclaims_only_expired_leases() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    // Remove prior-run residue so the global claim scans only this test's row
    // (asserted `first.len() == 1`, and the reclaim counts, are exact).
    drain_outbox(&pool).await;
    let instance = ensure_protocol_instance(&pool).await;
    let base = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin enqueue");
    let position = append_event(
        &mut tx,
        &new_event(instance, EventKind::MessageAvailable, base, 1),
    )
    .await
    .expect("append event");
    let outbox_id = Uuid::new_v4();
    enqueue_outbox(&mut tx, outbox_id, position, OutboxWorkKind::Stream, base)
        .await
        .expect("enqueue pending work");
    tx.commit().await.expect("commit enqueue");

    // First worker takes a short lease.
    let owner_a = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("begin first claim");
    let first = claim_outbox_batch(
        &mut tx,
        owner_a,
        base,
        base + chrono::Duration::seconds(100),
        10,
    )
    .await
    .expect("first claim");
    tx.commit().await.expect("commit first claim");
    assert_eq!(first.len(), 1, "the pending row is claimed once");

    // A second worker before the lease expires reclaims nothing.
    let mut tx = pool.begin().await.expect("begin early reclaim");
    let early = claim_outbox_batch(
        &mut tx,
        Uuid::new_v4(),
        base + chrono::Duration::seconds(50),
        base + chrono::Duration::seconds(400),
        10,
    )
    .await
    .expect("early reclaim attempt");
    tx.commit().await.expect("commit early reclaim");
    assert!(early.is_empty(), "a still-valid lease is not reclaimable");

    // After the lease expires the row is reclaimed by a new owner.
    let owner_b = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("begin expired reclaim");
    let reclaimed = claim_outbox_batch(
        &mut tx,
        owner_b,
        base + chrono::Duration::seconds(200),
        base + chrono::Duration::seconds(600),
        10,
    )
    .await
    .expect("expired reclaim");
    tx.commit().await.expect("commit expired reclaim");
    assert_eq!(reclaimed.len(), 1, "the expired lease is reclaimed");

    let (status, lease_owner, _) = outbox_row(&pool, outbox_id).await;
    assert_eq!(status, "leased", "the reclaimed row remains leased");
    assert_eq!(
        lease_owner,
        Some(owner_b),
        "the reclaim installs the new owner"
    );
}

/// Marking work delivered is an owner-scoped CAS: only the exact current lease
/// owner can terminalize the row. A stale or non-owner caller updates zero rows
/// and is reported as an error, leaving the row untouched.
#[tokio::test]
async fn mark_outbox_delivered_requires_exact_lease_owner() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    // Remove prior-run residue so the claim (LIMIT 10) leases this test's single
    // row rather than displacing it with older claimable residue.
    drain_outbox(&pool).await;
    let instance = ensure_protocol_instance(&pool).await;
    let base = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin enqueue");
    let position = append_event(
        &mut tx,
        &new_event(instance, EventKind::MessageAvailable, base, 1),
    )
    .await
    .expect("append event");
    let outbox_id = Uuid::new_v4();
    enqueue_outbox(&mut tx, outbox_id, position, OutboxWorkKind::Stream, base)
        .await
        .expect("enqueue pending work");
    tx.commit().await.expect("commit enqueue");

    let owner = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("begin claim");
    claim_outbox_batch(
        &mut tx,
        owner,
        base,
        base + chrono::Duration::seconds(100),
        10,
    )
    .await
    .expect("claim the row");
    tx.commit().await.expect("commit claim");

    // A non-owner cannot terminalize the lease.
    let mut tx = pool.begin().await.expect("begin wrong-owner mark");
    let wrong = mark_outbox_delivered(
        &mut tx,
        outbox_id,
        Uuid::new_v4(),
        base + chrono::Duration::seconds(10),
    )
    .await
    .expect_err("a non-owner mark must be rejected");
    assert!(
        matches!(wrong, DeliveryRepositoryError::OutboxLeaseMismatch),
        "a stale/non-owner mark is reported as OutboxLeaseMismatch, got {wrong:?}"
    );
    tx.commit().await.expect("commit wrong-owner mark (no-op)");
    let (status, _, _) = outbox_row(&pool, outbox_id).await;
    assert_eq!(
        status, "leased",
        "the row is untouched after a rejected mark"
    );

    // The exact owner terminalizes the row exactly once.
    let mut tx = pool.begin().await.expect("begin owner mark");
    mark_outbox_delivered(
        &mut tx,
        outbox_id,
        owner,
        base + chrono::Duration::seconds(20),
    )
    .await
    .expect("the exact lease owner delivers the row");
    tx.commit().await.expect("commit owner mark");
    let (status, _, delivered_at) = outbox_row(&pool, outbox_id).await;
    assert_eq!(status, "delivered", "the row is delivered");
    assert!(delivered_at.is_some(), "delivered_at is stamped");

    // A repeat mark on an already-delivered row updates nothing and is an error.
    let mut tx = pool.begin().await.expect("begin repeat mark");
    let repeat = mark_outbox_delivered(
        &mut tx,
        outbox_id,
        owner,
        base + chrono::Duration::seconds(30),
    )
    .await
    .expect_err("a repeat mark on a terminal row must be rejected");
    assert!(
        matches!(repeat, DeliveryRepositoryError::OutboxLeaseMismatch),
        "a repeat mark is reported as OutboxLeaseMismatch, got {repeat:?}"
    );
    drop(tx);
}
