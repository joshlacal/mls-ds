//! Live-PostgreSQL concurrency race suite over the clean-chat protocol's
//! production serialization points (`chat_protocol::repository::delivery`).
//!
//! Ported in-crate from `server/tests/chat_protocol_concurrency.rs`: the module
//! and the functions it asserts on are `pub(crate)`, so an integration crate
//! could only reach them by `include!`-ing `delivery.rs` into a synthetic
//! `repository` module, which then failed to compile because that synthetic
//! module has none of `delivery.rs`'s real siblings. Running inside the library
//! crate keeps the real module graph.
//!
//! Every scenario runs TWO real transactions against the same committed prior
//! state CONCURRENTLY (two pool connections synchronized by a `tokio::sync::Barrier`)
//! and asserts the result is equivalent to exactly ONE legal lock-ordered
//! serialization: for a compare-and-set race exactly one writer commits and the
//! loser leaves ZERO business residue; for the append-log allocator concurrent
//! writers get UNIQUE, CONTIGUOUS seqs; for the outbox two workers never
//! double-claim.
//!
//! Live cases run under the standard whole-suite gate: they hard-fail (panic in
//! `setup_chat_protocol_db`) without `TEST_DATABASE_URL` rather than skipping.

#![allow(dead_code)]

use super::delivery::{
    append_event, claim_outbox_batch, enqueue_outbox, mark_outbox_delivered,
    resolve_application_send, AppendEntry, ApplicationSend, ApplicationSendDisposition,
    ApplicationSendOutcome, DeliveryRepositoryError, EventKind, NewEvent, OutboxWorkKind,
    APPLICATION_ENTRY_KIND,
};

use std::collections::HashSet;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Barrier;
use uuid::Uuid;

/// Reserved per-run database prefix owned by this module.
const CONCURRENCY_DB_PREFIX: &str = "chat_concurrency_";

/// Mint a private, fully migrated clean-protocol database for one test case.
///
/// The fixed shared target (`setup_chat_protocol_db`) is validation-only and
/// refuses to run against the polluted shared installation, so each case owns a
/// disposable clone of the *same* reviewed 14-migration schema. The returned
/// guard must stay bound for the whole test — it reaps the database on the
/// normal path and during panic unwind.
async fn concurrency_db(
    max_connections: u32,
) -> (PgPool, crate::common::fresh_db::DisposableDatabase) {
    crate::common::fresh_db::fresh_clean_protocol_db(CONCURRENCY_DB_PREFIX, max_connections).await
}

// ---------------------------------------------------------------------------
// Harness (adapted from tests/chat_protocol_delivery.rs + the executor seeders).
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

async fn next_entry_seq(pool: &PgPool, conversation_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1")
        .bind(conversation_id)
        .fetch_one(pool)
        .await
        .expect("read append counter")
}

async fn committed_entry_seqs(pool: &PgPool, conversation_id: Uuid) -> Vec<i64> {
    sqlx::query_scalar("SELECT seq FROM chat.entries WHERE conversation_id=$1 ORDER BY seq")
        .bind(conversation_id)
        .fetch_all(pool)
        .await
        .expect("read committed entry seqs")
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
         VALUES($1,$2,'race-actor','active',$3,1,chat.protocol_capabilities(),$4,$4)",
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

/// Seed a coherent committed GROUP conversation (genesis creation entry at seq 1,
/// `next_entry_seq` 2) the append-log allocator can extend.
async fn seed_base(pool: &PgPool) -> BaseConversation {
    let (actor_did, actor_device_id, actor_key_id) = seed_actor(pool).await;
    // Re-derive the public key the device-key row stored (needed for the creation graph).
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

async fn seed_protocol_instance(pool: &PgPool) -> Uuid {
    let cursor_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(vec![0x51_u8; 32])
        .fetch_one(pool)
        .await
        .expect("derive cursor key");
    sqlx::query(
        "INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) \
         VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(&cursor_key)
    .execute(pool)
    .await
    .expect("seed protocol instance");
    sqlx::query_scalar("SELECT protocol_instance_id FROM chat.protocol_instances")
        .fetch_one(pool)
        .await
        .expect("read protocol instance id")
}

fn coherent_application_send(base: &BaseConversation, salt: u8) -> ApplicationSend {
    let payload = vec![salt; 8];
    let signing_transcript = vec![salt ^ 0x5a; 8];
    let request_digest = Sha256::digest(&signing_transcript).to_vec();
    let entry = AppendEntry {
        conversation_id: base.conversation_id,
        entry_id: Uuid::new_v4(),
        entry_kind: APPLICATION_ENTRY_KIND.to_owned(),
        accepted_payload_bytes: payload.clone(),
        accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
        signed_request_bytes: vec![salt ^ 0x33; 8],
        request_digest,
        signature: vec![salt; 64],
        server_fields_bytes: vec![salt; 1],
        outer_entry_fingerprint: vec![salt; 32],
        actor_did: base.actor_did.clone(),
        actor_device_id: base.actor_device_id,
        actor_key_id: base.actor_key_id.clone(),
        actor_auth_generation: 1,
        generation: Some(0),
        state_version: Some(0),
        transition_id: None,
        message_id: Some(Uuid::new_v4()),
        received_at: Utc::now(),
    };
    ApplicationSend {
        entry,
        signing_transcript_bytes: vec![salt ^ 0x5a; 8],
        outcome_bytes: vec![salt ^ 0x0f; 8],
        epoch: 0,
        send_counter: 1,
    }
}

// ===========================================================================
// Sub-boundary 1 — single-row CAS race: exactly one commit, loser zero residue.
// ===========================================================================

/// Two terminal authorities contend for ONE leased outbox row: two workers each
/// try to mark the same row `delivered` under the SAME lease. Exactly one CAS
/// commits (`leased -> delivered`); the other matches no leased row and is the
/// typed `OutboxLeaseMismatch`, rolling back with zero residue. This is the
/// single-row CAS that serializes two terminal authorities on one row — the exact
/// mechanism the executor's multi-row terminal races (device revoke vs mutation,
/// reservation expiry vs fulfillment) reduce to at their contended row; those
/// full multi-row races are proven at the executor level in
/// `tests/chat_protocol_executor.rs`, not claimed here.
#[tokio::test]
async fn two_terminal_authorities_on_one_work_row_serialize_to_one_winner() {
    let (pool, _database) = concurrency_db(4).await;
    let protocol_instance_id = seed_protocol_instance(&pool).await;
    let now = clock_now(&pool).await;

    // Seed one outbox row and claim it under a single lease owner (committed).
    let mut tx = pool.begin().await.expect("begin seed");
    let position = append_event(
        &mut tx,
        &NewEvent {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::MessageAvailable,
            payload_bytes: vec![0x01_u8; 8],
            created_at: now,
            protocol_instance_id,
        },
    )
    .await
    .expect("append event");
    let outbox_id = Uuid::new_v4();
    enqueue_outbox(&mut tx, outbox_id, position, OutboxWorkKind::Stream, now)
        .await
        .expect("enqueue");
    // Lease THIS row to one owner deterministically (the shared test DB carries
    // leftover due rows from other cases, so a `claim_outbox_batch` limit could
    // grab any of them; we contend on this exact row).
    let lease_owner = Uuid::new_v4();
    sqlx::query(
        "UPDATE chat.outbox SET status='leased', lease_owner=$2, lease_expires_at=$3 WHERE outbox_id=$1",
    )
    .bind(outbox_id)
    .bind(lease_owner)
    .bind(now + Duration::minutes(1))
    .execute(&mut *tx)
    .await
    .expect("lease the seeded row");
    tx.commit().await.expect("commit seed + lease");

    let barrier = Arc::new(Barrier::new(2));
    let run = |barrier: Arc<Barrier>, pool: PgPool, delivered_at: DateTime<Utc>| async move {
        let mut tx = pool.begin().await.expect("begin racer");
        barrier.wait().await;
        let result = mark_outbox_delivered(&mut tx, outbox_id, lease_owner, delivered_at).await;
        match &result {
            Ok(()) => tx.commit().await.expect("winner commits"),
            Err(_) => tx.rollback().await.expect("loser rolls back"),
        }
        result
    };
    let (a, b) = tokio::join!(
        run(barrier.clone(), pool.clone(), now),
        run(barrier.clone(), pool.clone(), now),
    );

    let winners = [&a, &b].iter().filter(|r| r.is_ok()).count();
    let conflicts = [&a, &b]
        .iter()
        .filter(|r| matches!(r, Err(DeliveryRepositoryError::OutboxLeaseMismatch)))
        .count();
    assert_eq!(winners, 1, "exactly one terminal authority commits");
    assert_eq!(conflicts, 1, "the loser is a typed lease mismatch");
    let status: String = sqlx::query_scalar("SELECT status FROM chat.outbox WHERE outbox_id=$1")
        .bind(outbox_id)
        .fetch_one(&pool)
        .await
        .expect("read outbox status");
    assert_eq!(status, "delivered", "the row is terminalized exactly once");
}

// ===========================================================================
// Sub-boundary 2 — append-log allocator + outbox worker concurrency.
// ===========================================================================

/// Concurrent append-log writers get UNIQUE, CONTIGUOUS seqs: two application
/// sends from one conversation head commit at distinct adjacent seqs (2 and 3),
/// never the same seq and never a gap — the head `SELECT ... FOR UPDATE` seq
/// allocator serializes them. `next_entry_seq` ends at 4.
#[tokio::test]
async fn concurrent_application_appends_get_unique_contiguous_seqs() {
    let (pool, _database) = concurrency_db(4).await;
    let base = seed_base(&pool).await;
    // This frozen clean-protocol schema predates the send-order table every
    // first application resolution now advances.
    sqlx::raw_sql(include_str!(
        "../../../migrations/20261107000001_application_send_order.sql"
    ))
    .execute(&pool)
    .await
    .expect("install the send-order table");
    // Racer B signs as another device: one device's racing sends would turn
    // this seq race into a send-order race (`application_send_order`).
    let mut send_b = coherent_application_send(&base, 0x22);
    (
        send_b.entry.actor_did,
        send_b.entry.actor_device_id,
        send_b.entry.actor_key_id,
    ) = seed_actor(&pool).await;

    let barrier = Arc::new(Barrier::new(2));
    let run = |barrier: Arc<Barrier>, pool: PgPool, send: ApplicationSend| async move {
        let mut tx = pool.begin().await.expect("begin send");
        barrier.wait().await;
        let outcome = resolve_application_send(&mut tx, &send, ApplicationSendDisposition::Accept)
            .await
            .expect("send resolves");
        tx.commit().await.expect("send commit");
        outcome
    };
    let (outcome_a, outcome_b) = tokio::join!(
        run(
            barrier.clone(),
            pool.clone(),
            coherent_application_send(&base, 0x21)
        ),
        run(barrier.clone(), pool.clone(), send_b),
    );

    let seq_a = match outcome_a {
        ApplicationSendOutcome::Accepted { seq } => seq,
        other => panic!("send A must be accepted, got {other:?}"),
    };
    let seq_b = match outcome_b {
        ApplicationSendOutcome::Accepted { seq } => seq,
        other => panic!("send B must be accepted, got {other:?}"),
    };
    assert_ne!(seq_a, seq_b, "concurrent appends never share a seq");
    let mut seqs = [seq_a, seq_b];
    seqs.sort_unstable();
    assert_eq!(seqs, [2, 3], "adjacent, contiguous seqs past the genesis");
    assert_eq!(next_entry_seq(&pool, base.conversation_id).await, 4);
    assert_eq!(
        committed_entry_seqs(&pool, base.conversation_id).await,
        vec![1, 2, 3],
        "contiguous append log with no gap"
    );
}

/// Two outbox workers never double-claim: with several due rows, two concurrent
/// `claim_outbox_batch` calls end up with disjoint claim sets. The row lock a
/// claiming UPDATE takes plus its status filter (a row leased by one worker no
/// longer matches the other's `pending`/expired-lease predicate) is what makes the
/// claims disjoint; `FOR UPDATE SKIP LOCKED` only adds liveness — a worker skips a
/// row another already locked instead of blocking on it.
#[tokio::test]
async fn two_outbox_workers_never_double_claim() {
    let (pool, _database) = concurrency_db(4).await;
    let protocol_instance_id = seed_protocol_instance(&pool).await;
    let now = clock_now(&pool).await;

    // Seed six due outbox rows in one committed transaction.
    let mut tx = pool.begin().await.expect("begin seed outbox");
    for index in 0..6_u8 {
        let position = append_event(
            &mut tx,
            &NewEvent {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::MessageAvailable,
                payload_bytes: vec![index; 8],
                created_at: now,
                protocol_instance_id,
            },
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
        .expect("enqueue outbox");
    }
    tx.commit().await.expect("commit outbox seed");

    let lease_until = now + Duration::minutes(1);
    let barrier = Arc::new(Barrier::new(2));
    let run = |barrier: Arc<Barrier>, pool: PgPool| async move {
        let worker = Uuid::new_v4();
        let mut tx = pool.begin().await.expect("begin worker");
        barrier.wait().await;
        let claimed = claim_outbox_batch(&mut tx, worker, now, lease_until, 4)
            .await
            .expect("claim batch");
        tx.commit().await.expect("commit claim");
        claimed
            .into_iter()
            .map(|work| work.outbox_id)
            .collect::<Vec<Uuid>>()
    };
    let (claimed_a, claimed_b) = tokio::join!(
        run(barrier.clone(), pool.clone()),
        run(barrier.clone(), pool.clone())
    );

    let set_a: HashSet<Uuid> = claimed_a.iter().copied().collect();
    let set_b: HashSet<Uuid> = claimed_b.iter().copied().collect();
    assert_eq!(
        set_a.len(),
        claimed_a.len(),
        "worker A never claims a row twice"
    );
    assert_eq!(
        set_b.len(),
        claimed_b.len(),
        "worker B never claims a row twice"
    );
    assert!(
        set_a.is_disjoint(&set_b),
        "no outbox row is claimed by both workers"
    );
}

// ===========================================================================
// Sub-boundary 3 — closeConversation vs acceptConversation of one request.
// ===========================================================================

/// The e2e C20 close-wins arm (`e2e-tests/tests/encrypted_request_c14_c20.rs`)
/// on real PostgreSQL sessions: a `closeConversation` queued on the
/// conversation head before an `acceptConversation` of the same pending
/// request. The close runs through the production router; the accept side is
/// its exact lock prefix (`direct_request_preparation::admit_request`:
/// operation, request budget, then principal/device/key), then its head lock.
/// The close's wipe debits that budget, so the close must hold it before its
/// own identity locks: the accept then queues on the budget and finds the
/// conversation wiped. Taken first at the wipe, after the identity locks the
/// accept waits on, it closes a cycle and PostgreSQL aborts one side (40P01).
#[cfg(all(feature = "test-support", feature = "sim"))]
mod close_racing_accept {
    use std::{sync::Arc, time::Duration};

    use axum::http::StatusCode;
    use serde_json::json;
    use sqlx::{PgPool, Postgres, Transaction};
    use tokio::task::JoinHandle;
    use uuid::Uuid;

    use crate::{
        chat_protocol::{
            repository::prelude::{
                lock_direct_request_identity_scope, lock_direct_request_operation_set,
            },
            test_support::{seed_genuine_pending_direct_request, sign_mutation_json_for_test},
        },
        common::{fresh_db::fresh_fully_migrated_db, http_acceptance as http},
        sim_hooks::{scope_sim_ds, QueuedTaskSpawner, SimDsHooks},
    };

    /// `did`'s device with a service-auth key, declaring no home.
    async fn device(did: &str, device_id: Uuid) -> http::Device {
        let signing = http::random_p256();
        let jwk = http::public_jwk(&signing);
        let device = http::Device {
            did: did.to_owned(),
            device_id,
            jkt: http::jwk_thumbprint(&jwk),
            signing,
            jwk,
        };
        http::cache_device_did(&device).await;
        device
    }

    async fn backend_pid(transaction: &mut Transaction<'_, Postgres>) -> i32 {
        sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut **transaction)
            .await
            .unwrap()
    }

    /// Wait until `sessions` sessions of this database wait on `holder`,
    /// directly or behind one another; `false` once `task` finished instead.
    async fn queued<T>(pool: &PgPool, holder: i32, sessions: i64, task: &JoinHandle<T>) -> bool {
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let waiting: i64 = sqlx::query_scalar(
                    "WITH RECURSIVE w(pid) AS ( \
                         SELECT pid FROM pg_stat_activity \
                          WHERE datname = current_database() AND $1 = ANY(pg_blocking_pids(pid)) \
                         UNION SELECT a.pid FROM pg_stat_activity a \
                          JOIN w ON w.pid = ANY(pg_blocking_pids(a.pid))) \
                     SELECT count(*) FROM w",
                )
                .bind(holder)
                .fetch_one(pool)
                .await
                .unwrap();
                if waiting >= sessions {
                    return true;
                }
                if task.is_finished() {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the session neither queued nor finished")
    }

    #[tokio::test]
    async fn a_close_queued_first_holds_the_request_budget_before_its_identity_locks() {
        let db = fresh_fully_migrated_db(super::CONCURRENCY_DB_PREFIX).await;
        let pool = db.connect(8).await;
        http::ensure_fence(&pool).await;
        let request = seed_genuine_pending_direct_request(&pool)
            .await
            .expect("a genuinely published pending request");
        let router = http::router_for_authenticated_acceptance_with(pool.clone(), |runtime| {
            runtime.with_spawner(Arc::new(QueuedTaskSpawner::new()))
        })
        .await;
        let hooks = Arc::new(SimDsHooks {
            service_did: "did:web:chat.catbird.blue".into(),
            self_endpoint: "https://chat.catbird.blue".into(),
            signing_key_pem: None,
            group_relay_hmac_secret: None,
            http_transport: Arc::new(|_| {
                Box::pin(async { Err("unexpected close network request".into()) })
            }),
            dns_resolver: Arc::new(|_| Err("unexpected close DNS".into())),
            retain_application_ciphertext: false,
        });
        let (sender, sender_device, key_id, seed) = request.sender_identity();
        let (recipient, recipient_device, ..) = request.recipient_identity();
        let closer = device(&sender, sender_device).await;
        // The recipient's document declares no home: the close owes no C33 fan-out.
        device(&recipient, recipient_device).await;
        let prior = request.coordinate().clone();
        let mut retired = prior.clone();
        retired["stateVersion"] = json!(prior["stateVersion"].as_u64().unwrap() + 1);
        retired["lifecycle"] = json!("superseded");
        let transition = Uuid::new_v4();
        let signed = sign_mutation_json_for_test(
            &json!({
                "$type": "blue.catbird.chat.defs#conversationCloseBody",
                "signatureDomain": "CATBIRD-CHAT-CLOSE\u{0}",
                "transitionId": transition,
                "idempotencyKey": transition,
                "actorDid": sender,
                "actorDeviceId": sender_device,
                "keyId": key_id,
                "authGeneration": 1,
                "conversationKind": "direct",
                "prior": prior,
                "retired": retired,
                "signedAt": chrono::Utc::now()
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            }),
            &ed25519_dalek::SigningKey::from_bytes(&seed),
        )
        .unwrap();
        let body = serde_json::to_vec(&json!({ "signedRequest": signed })).unwrap();

        // The e2e barrier: a third session holds the head both transactions lock.
        let mut barrier = pool.begin().await.unwrap();
        let barrier_pid = backend_pid(&mut barrier).await;
        sqlx::query("SELECT 1 FROM chat.conversations WHERE conversation_id = $1 FOR UPDATE")
            .bind(request.conversation_id)
            .execute(&mut *barrier)
            .await
            .unwrap();
        let close = tokio::spawn(scope_sim_ds(hooks, async move {
            let close =
                http::unsigned_json_request(&closer, "blue.catbird.chat.closeConversation", body);
            http::send(router, close).await
        }));
        if !queued(&pool, barrier_pid, 1, &close).await {
            panic!(
                "the close finished without queuing on the head: {:?}",
                close.await
            );
        }
        let (pid_sender, pid_receiver) = tokio::sync::oneshot::channel();
        let accept = tokio::spawn({
            let (pool, request_id, conversation_id) =
                (pool.clone(), request.request_id, request.conversation_id);
            let accounts = [recipient.clone(), sender.clone()];
            async move {
                let mut transaction = pool.begin().await?;
                let _ = pid_sender.send(backend_pid(&mut transaction).await);
                lock_direct_request_operation_set(&mut transaction, request_id, &[Uuid::new_v4()])
                    .await?;
                lock_direct_request_identity_scope(&mut transaction, &accounts).await?;
                let head: Option<String> = sqlx::query_scalar(
                    "SELECT lifecycle FROM chat.conversations WHERE conversation_id = $1 FOR UPDATE",
                )
                .bind(conversation_id)
                .fetch_optional(&mut *transaction)
                .await?;
                transaction.rollback().await?;
                Ok::<_, sqlx::Error>(head)
            }
        });
        let accept_pid = pid_receiver.await.unwrap();
        if !queued(&pool, barrier_pid, 2, &accept).await {
            panic!("the accept finished without queuing: {:?}", accept.await);
        }
        let accept_waits_in: String =
            sqlx::query_scalar("SELECT query FROM pg_stat_activity WHERE pid = $1")
                .bind(accept_pid)
                .fetch_one(&pool)
                .await
                .unwrap();
        barrier.rollback().await.unwrap();
        let (status, reply) = close.await.unwrap();
        let accepted = accept.await.unwrap();
        assert!(
            status == StatusCode::OK
                && accept_waits_in.contains("chat.direct_request_budget")
                && matches!(accepted, Ok(None)),
            "a close queued before an accept must hold the request budget before its identity \
             locks: close={status} {reply}; the accept waited in `{accept_waits_in}`, then saw \
             head={accepted:?}"
        );
    }
}

/// An `acceptConversation` whose admission loses a lock wait (here the global
/// request budget a request operation holds, under `lock_timeout`) failed in
/// storage, not authentication: it must surface as the endpoint's storage
/// failure (`DirectAcceptanceError::Database` → `ChatFailure::storage`), never as
/// the terminal `InvalidSignature` (401) a client would stop retrying on.
#[cfg(all(feature = "test-support", feature = "sim"))]
mod accept_admission_contention {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::Signer as _;
    use serde_json::json;
    use uuid::Uuid;

    use crate::{
        auth::VerifiedServicePrincipal,
        chat_protocol::{
            direct_request_transcript::{direct_request_signing_bytes, DirectRequestKind},
            relationship_policy::{
                fixed_production_relationship_policy_config, RelationshipAuthority,
            },
            repository::{
                acceptance::{accept_direct_request, DirectAcceptanceError},
                direct_request_receipts::DirectRequestReceiptSigner,
            },
            test_support::{seed_genuine_pending_direct_request, DeterministicTestTransport},
        },
        common::fresh_db::fresh_fully_migrated_db,
    };

    fn pem(key: &p256::ecdsa::SigningKey) -> String {
        use p256::pkcs8::EncodePrivateKey as _;
        p256::SecretKey::from_slice(&key.to_bytes())
            .unwrap()
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn an_accept_admission_lock_timeout_is_a_storage_failure_not_invalid_signature() {
        let db = fresh_fully_migrated_db(super::CONCURRENCY_DB_PREFIX).await;
        let pool = db.connect(4).await;
        let request = seed_genuine_pending_direct_request(&pool)
            .await
            .expect("a genuinely published pending request");
        let (recipient, device, key_id, seed) = request.recipient_identity();
        // The recipient's exact signed acceptance of the published head.
        let (generation, version, group_id, epoch, context_hash, tag): (
            i64,
            i64,
            Vec<u8>,
            i64,
            Vec<u8>,
            Vec<u8>,
        ) = sqlx::query_as(
            "SELECT c.current_generation, c.current_state_version, s.group_id, s.epoch, \
                    s.group_context_hash, s.confirmation_tag \
               FROM chat.conversations c JOIN chat.generation_states s \
                 ON s.conversation_id = c.conversation_id AND s.generation = c.current_generation \
                AND s.state_version = c.current_state_version \
              WHERE c.conversation_id = $1",
        )
        .bind(request.conversation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let (invitation, inviter, inviter_device): (Uuid, String, Uuid) = sqlx::query_as(
            "SELECT invitation_transition_id, created_by_did, created_by_device_id \
               FROM chat.participants \
              WHERE conversation_id = $1 AND user_did = $2 AND current_membership",
        )
        .bind(request.conversation_id)
        .bind(&recipient)
        .fetch_one(&pool)
        .await
        .unwrap();
        let prior = json!({
            "conversationId": request.conversation_id,
            "generation": generation,
            "stateVersion": version,
            "groupId": STANDARD.encode(group_id),
            "epoch": epoch,
            "groupContextHash": STANDARD.encode(context_hash),
            "confirmationTag": STANDARD.encode(tag),
            "lifecycle": "active",
        });
        let mut next = prior.clone();
        next["stateVersion"] = json!(version + 1);
        let transition = Uuid::new_v4();
        let now = chrono::Utc::now();
        let body = json!({
            "$type": "blue.catbird.chat.defs#directRequestAcceptanceBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPT\u{0}",
            "protocolVersion": "2",
            "actorDid": recipient,
            "actorDeviceId": device,
            "keyId": key_id,
            "authGeneration": 1,
            "transitionId": transition,
            "requestId": request.request_id,
            "prior": prior,
            "next": next,
            "invitationProvenance": {
                "invitationTransitionId": invitation,
                "invitedByDid": inviter,
                "invitedByDeviceId": inviter_device,
            },
            "idempotencyKey": transition,
            "signedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });
        let message = direct_request_signing_bytes(
            DirectRequestKind::Accept,
            &serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        let signature = ed25519_dalek::SigningKey::from_bytes(&seed).sign(&message);
        let raw = serde_json::to_vec(&json!({
            "body": body,
            "signature": STANDARD.encode(signature.to_bytes()),
        }))
        .unwrap();
        let principal = VerifiedServicePrincipal::for_federated_s2s(
            &recipient,
            "blue.catbird.chat.acceptConversation",
        );
        let receipt_key = p256::ecdsa::SigningKey::from_slice(&[21; 32]).unwrap();
        let service_key = p256::ecdsa::SigningKey::from_slice(&[22; 32]).unwrap();
        let document = crate::identity::did_doc::build_direct_request_receipt_did_document(
            "did:web:chat.catbird.blue",
            receipt_key.verifying_key(),
        );
        let signer = DirectRequestReceiptSigner::configured(
            &pem(&receipt_key),
            &pem(&service_key),
            &serde_json::to_string(&document).unwrap(),
        )
        .unwrap();
        let policy = RelationshipAuthority::new(
            fixed_production_relationship_policy_config().unwrap(),
            DeterministicTestTransport,
        );

        // Another request operation holds the global request budget.
        let mut holder = pool.begin().await.unwrap();
        sqlx::query("SELECT singleton FROM chat.direct_request_budget WHERE singleton FOR UPDATE")
            .execute(&mut *holder)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL lock_timeout = '200ms'")
            .execute(&mut *tx)
            .await
            .unwrap();
        let outcome = accept_direct_request(&mut tx, &principal, &raw, &signer, &policy, now).await;
        tx.rollback().await.unwrap();
        holder.rollback().await.unwrap();
        assert!(
            matches!(
                &outcome,
                Err(DirectAcceptanceError::Database(sqlx::Error::Database(error)))
                    if error.code().as_deref() == Some("55P03")
            ),
            "a lock timeout in accept admission is a storage failure: {outcome:?}"
        );
    }
}
