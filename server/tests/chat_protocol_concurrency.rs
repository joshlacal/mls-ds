//! Live-PostgreSQL concurrency race suite over the clean-chat protocol's
//! production serialization points (`chat_protocol::repository::{transition,delivery}`).
//!
//! Every scenario runs TWO real transactions against the same committed prior
//! state CONCURRENTLY (two pool connections synchronized by a `tokio::sync::Barrier`,
//! the pattern from the E1 outbox no-double-claim and head-CAS conflict tests) and
//! asserts the result is equivalent to exactly ONE legal lock-ordered
//! serialization: for a compare-and-set race exactly one writer commits and the
//! loser leaves ZERO business residue (its conditional write matched no row and its
//! transaction rolled back); for the append-log allocator concurrent writers get
//! UNIQUE, CONTIGUOUS seqs; for the outbox two workers never double-claim. There is
//! no impossible interleaving and no unproven terminal state.
//!
//! Because each write is a conditional operation keyed on the exact prior state (a
//! CAS `WHERE status = expected`, the head `SELECT ... FOR UPDATE` seq allocator,
//! or `FOR UPDATE SKIP LOCKED`), the outcome is timing-independent: even when the
//! writes do not physically overlap, the second writer re-evaluates against the
//! winner's committed row.
//!
//! Scope note: the coordinate-advancing executor edges (creation / policy / commit
//! / close / reset) compose a full successor generation-state + entry graph guarded
//! by deferred cross-table triggers; racing those faithfully requires the executor
//! plan harness (`tests/chat_protocol_executor.rs`) and is tracked as remainder in
//! the E3 report. This suite proves the same one-legal-serialization property at
//! the underlying single-row serialization authorities the executor composes.
//!
//! The production repository modules are gated `#[cfg(not(test))]`, so — mirroring
//! the sibling repository harnesses — this test `include!`s them directly. Live
//! cases run under the standard whole-suite gate: they hard-fail (panic in
//! `setup_chat_protocol_db`) without `TEST_DATABASE_URL` rather than skipping:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_concurrency -- --test-threads=1

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

use std::collections::HashSet;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Barrier;
use uuid::Uuid;

use repository::delivery::{
    append_event, claim_outbox_batch, enqueue_outbox, mark_outbox_delivered,
    resolve_application_send, AppendEntry, ApplicationSend, ApplicationSendDisposition,
    ApplicationSendOutcome, DeliveryRepositoryError, EventKind, NewEvent, OutboxWorkKind,
    APPLICATION_ENTRY_KIND,
};

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
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
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
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let base = seed_base(&pool).await;

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
        run(
            barrier.clone(),
            pool.clone(),
            coherent_application_send(&base, 0x22)
        ),
    );

    let seq_a = match outcome_a {
        ApplicationSendOutcome::Accepted { seq } => seq,
        ApplicationSendOutcome::Stale => panic!("send A must be accepted"),
    };
    let seq_b = match outcome_b {
        ApplicationSendOutcome::Accepted { seq } => seq,
        ApplicationSendOutcome::Stale => panic!("send B must be accepted"),
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
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
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
