//! Integration tests for Task 5: Clean Federation Durable Outbox-to-Retry Composition.
//!
//! Mandatory DB coverage:
//! 1. Chokepoint typed source job creation (message send / commit fanout)
//! 2. Generic reset audit payload federation stopped
//! 3. Atomic handoff source -> OutboundQueue (same stable ID/method/payload/convo) and source marked done
//! 4. Replay before capacity checks (idempotent duplicate handoff without capacity failure)
//! 5. Post-crash reclaim of expired in_flight leases
//! 6. Claim fencing with claim_token and concurrent worker safety
//! 7. Peer policy recheck immediately before send (revocation after enqueue fails closed)
//! 8. Peer unavailable retry with exponential backoff and terminal dead state
//! 9. Missing receipt on clean federation endpoint retries (never marked delivered)
//! 10. Mismatched receipt fields / possible forgery retries (never marked delivered)
//! 11. Malicious / forged receipt signature marks dead immediately (never delivered, no resend)
//! 12. Verified receipt DB persistence failure retries (never marked delivered)
//! 13. Valid signed receipt marks delivered and records delivery receipt in DB
//! 14. Receiver dedupe and at-least-once safety

#![allow(dead_code)]
#![recursion_limit = "256"]
mod common;

use std::sync::Arc;

use base64::Engine as _;
use catbird_atproto::generated::blue_catbird::chat::ConversationCoordinates;
use catbird_server::auth::{
    cache_test_did_document, AuthMiddleware, DidDocument, PublicKeyJwk, VerificationMethod,
};
use catbird_server::chat_protocol::test_support::repository::{
    build_federated_commit_envelope, derive_submit_commit_delivery_id,
    enqueue_clean_federation_message_jobs, enqueue_federated_welcome_job, AppendEntry,
};
use catbird_server::federation::ack::AckSigner;
use catbird_server::federation::envelope::{
    sign_receipt, ValidatedEntryLocator, DELIVER_MESSAGE_NSID, DELIVER_WELCOME_NSID,
    SUBMIT_COMMIT_NSID,
};
use catbird_server::federation::outbound::OutboundClient;
use catbird_server::federation::queue::OutboundQueue;
use catbird_server::federation::resolver::{DsResolver, ValidatedRemoteDestination};
use catbird_server::identity::service_did_base;
use catbird_server::workers::federation_outbox::{
    claim_due_rows, handoff_to_outbound_queue, FederationOutboxRow,
};
use chrono::Utc;
use common::fresh_db::fresh_legacy_pool;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

const DB_PREFIX: &str = "chat_fedoutbox_";
const LOCAL_SERVICE_DID: &str = "did:web:chat.catbird.blue";

async fn ensure_federation_peers_table(pool: &PgPool) {
    std::env::set_var("SERVICE_DID", LOCAL_SERVICE_DID);
    std::env::set_var(
        "CHAT_NEST_AUDIENCE",
        "did:web:chat.catbird.blue#atproto_mls",
    );
    std::env::set_var("FEDERATION_MODE", "allowlist");

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS federation_peers (
            ds_did TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'pending',
            trust_score INTEGER NOT NULL DEFAULT 0,
            max_requests_per_minute INTEGER DEFAULT 100,
            rejected_request_count BIGINT NOT NULL DEFAULT 0,
            invalid_token_count BIGINT NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT federation_peers_status_check CHECK (status IN ('pending', 'allow', 'suspend', 'block'))
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("create federation_peers table in disposable db");

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ds_endpoints (
            did TEXT PRIMARY KEY,
            endpoint TEXT NOT NULL,
            fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .expect("create ds_endpoints table in disposable db");
}

fn test_signer(did: &str) -> (AckSigner, p256::ecdsa::VerifyingKey, SigningKey) {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = *signing_key.verifying_key();
    let signer = AckSigner::new(signing_key.clone(), did.to_string());
    (signer, verifying_key, signing_key)
}

async fn cache_peer_did_doc(
    auth: &AuthMiddleware,
    peer_did: &str,
    verifying_key: &p256::ecdsa::VerifyingKey,
) {
    let encoded_point = verifying_key.to_encoded_point(false);
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded_point.x().unwrap());
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded_point.y().unwrap());
    let key_id = format!("{peer_did}#atproto_mls");

    let doc = DidDocument {
        id: peer_did.to_string(),
        verification_method: vec![VerificationMethod {
            id: key_id,
            key_type: "JsonWebKey".to_string(),
            controller: peer_did.to_string(),
            public_key_multibase: None,
            public_key_jwk: Some(PublicKeyJwk {
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x,
                y: Some(y),
            }),
        }],
        service: None,
    };
    auth.cache_did_document(doc.clone()).await;
    cache_test_did_document(doc).await;
}
async fn seed_genesis_conversation_for_test(
    pool: &PgPool,
    conversation_id: Uuid,
    entry_id: Uuid,
    source_locator: &ValidatedEntryLocator,
) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx)
        .await
        .unwrap();

    let actor_did = "did:plc:creatoraaaaaaaaaaaaaaaaa";
    let actor_device = Uuid::new_v4();
    let creation_transition_id = Uuid::new_v4();
    let snapshot = b"snapshot".to_vec();
    let tree_summary = b"tree".to_vec();
    let group_id = [1u8; 32];
    let group_context_hash = [2u8; 32];
    let confirmation_tag = [3u8; 32];
    let group_info = b"group_info".to_vec();

    sqlx::query("INSERT INTO chat.principals (user_did, created_at) VALUES ($1, NOW()) ON CONFLICT (user_did) DO NOTHING")
        .bind(actor_did)
        .execute(&mut *tx)
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, auth_generation, capabilities, status, created_at, updated_at) \
         VALUES ($1, $2, 'Test Device', 1, chat.protocol_capabilities(), 'active', NOW(), NOW()) ON CONFLICT (user_did, device_id) DO NOTHING",
    )
    .bind(actor_did)
    .bind(actor_device)
    .execute(&mut *tx)
    .await
    .unwrap();

    let actor_key_bytes = [3u8; 32];
    let actor_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&actor_key_bytes[..])
        .fetch_one(&mut *tx)
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO chat.device_keys (user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at) \
         VALUES ($1, $2, $3, $4, 1, NOW()) ON CONFLICT (user_did, device_id, key_id) DO NOTHING",
    )
    .bind(actor_did)
    .bind(actor_device)
    .bind(&actor_key_id)
    .bind(&actor_key_bytes[..])
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.conversations (
            conversation_id, kind, lifecycle, current_generation, current_state_version,
            next_entry_seq, created_at, is_remote, sequencer_ds, sequencer_term
         ) VALUES ($1, 'group', 'active', 0, 0, 2, NOW(), FALSE, NULL, 1)",
    )
    .bind(conversation_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.generations (
            conversation_id, generation, group_id, lifecycle, genesis_group_info_bytes,
            genesis_group_info_sha256, current_state_version, activated_seq, activated_at
         ) VALUES ($1, 0, $2, 'active', $3, $4, 0, 1, NOW())",
    )
    .bind(conversation_id)
    .bind(&group_id[..])
    .bind(&group_info[..])
    .bind(Sha256::digest(&group_info).to_vec())
    .execute(&mut *tx)
    .await
    .unwrap();

    let metadata_snapshot_id = Uuid::new_v4();
    let ciphertext = vec![0u8; 16];
    let ciphertext_sha = Sha256::digest(&ciphertext).to_vec();

    sqlx::query(
        "INSERT INTO chat.metadata_snapshots(metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,producing_transition_id,origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,author_auth_generation,author_origin_seq,author_role,author_device_status,created_at) VALUES($1,$2,0,0,$3,0,$4,$5,$6,$6,1,$7,$8,$9,16,$10,$11,$12,$13,1,1,'admin','active',NOW())"
    )
    .bind(metadata_snapshot_id)
    .bind(conversation_id)
    .bind(&group_id[..])
    .bind(&group_context_hash[..])
    .bind(&confirmation_tag[..])
    .bind(creation_transition_id)
    .bind(&[1u8; 12][..])
    .bind(&ciphertext)
    .bind(&ciphertext_sha)
    .bind(actor_did)
    .bind(actor_device)
    .bind(&actor_key_id)
    .bind(&actor_key_bytes[..])
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.transitions (
            transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, actor_role, actor_device_status, signed_request_bytes,
            unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature,
            prior_generation, prior_state_version,
            next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at
         ) VALUES ($1, $2, 'creation', $3, $4, $5, 1, 'admin', 'active', $6, $6, $6, $7, $8, NULL, NULL, 0, 0, $9, 1, NOW())",
    )
    .bind(creation_transition_id)
    .bind(conversation_id)
    .bind(actor_did)
    .bind(actor_device)
    .bind(&actor_key_id)
    .bind(b"{}".as_slice())
    .bind(Sha256::digest(b"{}").to_vec())
    .bind(&[2u8; 64][..])
    .bind(metadata_snapshot_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"INSERT INTO chat.generation_states(
            conversation_id, generation, state_version, group_id, epoch,
            group_context_hash, confirmation_tag, lifecycle, state_kind,
            producing_transition_id, public_snapshot_bytes, snapshot_sha256,
            tree_summary_bytes, tree_summary_sha256, leaf_count, created_at
        ) VALUES ($1, 0, 0, $2, 0, $3, $4, 'active', 'creation', $5, $6, $7, $8, $9, 1, NOW())"#,
    )
    .bind(conversation_id)
    .bind(&group_id[..])
    .bind(&group_context_hash[..])
    .bind(&confirmation_tag[..])
    .bind(creation_transition_id)
    .bind(&snapshot)
    .bind(Sha256::digest(&snapshot).to_vec())
    .bind(&tree_summary)
    .bind(Sha256::digest(&tree_summary).to_vec())
    .execute(&mut *tx)
    .await
    .unwrap();

    let payload_bytes = b"{}".as_slice();

    sqlx::query(
        "INSERT INTO chat.entries (
            conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at
        ) VALUES (
            $1, 1, $2, 'blue.catbird.chat.defs#creationEntry', $3, $4,
            $5, $6, $7, $8, $9,
            $10, $11, $12, 1, 0, 0, $13, NOW()
        )",
    )
    .bind(conversation_id)
    .bind(entry_id)
    .bind(payload_bytes)
    .bind(&source_locator.accepted_payload_sha256[..])
    .bind(payload_bytes)
    .bind(Sha256::digest(payload_bytes).to_vec())
    .bind(&[2u8; 64][..])
    .bind(b"{}".as_slice())
    .bind(&source_locator.outer_entry_fingerprint[..])
    .bind(actor_did)
    .bind(actor_device)
    .bind(&actor_key_id)
    .bind(creation_transition_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    let participant_period_id = Uuid::new_v4();
    let leaf_period_id = Uuid::new_v4();
    let basic_credential = format!("{actor_did}#{actor_device}").into_bytes();

    sqlx::query(
        "INSERT INTO chat.participants(participant_period_id,conversation_id,user_did,status,role,role_transition_id,role_changed_at,created_by_did,created_by_device_id,current_membership,created_at) VALUES($1,$2,$3,'active','admin',$4,NOW(),$3,$5,true,NOW())"
    )
    .bind(participant_period_id)
    .bind(conversation_id)
    .bind(actor_did)
    .bind(creation_transition_id)
    .bind(actor_device)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.member_devices(leaf_period_id,participant_period_id,conversation_id,generation,user_did,device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,leaf_auth_generation,origin,joined_state_version,joined_transition_id,joined_seq,active,created_at) VALUES($1,$2,$3,0,$4,$5,0,$6,$7,$8,1,'genesis',0,$9,1,true,NOW())"
    )
    .bind(leaf_period_id)
    .bind(participant_period_id)
    .bind(conversation_id)
    .bind(actor_did)
    .bind(actor_device)
    .bind(&basic_credential)
    .bind(&actor_key_bytes[..])
    .bind(&actor_key_id)
    .bind(creation_transition_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        r#"INSERT INTO chat.application_intervals(
            membership_interval_id, conversation_id, generation, recipient_did, recipient_device_id,
            start_seq, opening_kind, opening_transition_id, opening_outer_entry_fingerprint,
            opening_state_version, opening_group_id, opening_epoch, opening_group_context_hash,
            opening_confirmation_tag, opening_leaf_period_id, created_at
        ) VALUES ($1, $2, 0, $3, $4, 1, 'creation', $1, $5, 0, $6, 0, $7, $8, $9, NOW())"#,
    )
    .bind(creation_transition_id)
    .bind(conversation_id)
    .bind(actor_did)
    .bind(actor_device)
    .bind(&source_locator.outer_entry_fingerprint[..])
    .bind(&group_id[..])
    .bind(&group_context_hash[..])
    .bind(&confirmation_tag[..])
    .bind(leaf_period_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    tx.commit().await.unwrap();
}

#[tokio::test]
async fn test_chokepoint_message_send_creates_typed_outbox_job() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let convo_id = Uuid::new_v4();
    let remote_ds = "did:web:remote.ds.example.com";
    let remote_user = "did:plc:remoteaaaaaaaaaaaaaaaaaa";
    let creator_user = "did:plc:creatoraaaaaaaaaaaaaaaaa";
    let mut tx = pool.begin().await.unwrap();

    // 1. Provision conversation and remote participant inside transaction
    sqlx::query(
        "INSERT INTO chat.conversations (
            conversation_id, kind, lifecycle, current_generation, current_state_version,
            next_entry_seq, created_at, is_remote, sequencer_ds, sequencer_term
         ) VALUES ($1, 'group', 'active', 0, 0, 2, NOW(), FALSE, NULL, 1)",
    )
    .bind(convo_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    let pid = Uuid::new_v4();
    let tid = Uuid::new_v4();
    let creator_device = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) \
         VALUES ($1, NOW()), ($2, NOW())",
    )
    .bind(creator_user)
    .bind(remote_user)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, auth_generation, capabilities, status, created_at, updated_at) \
         VALUES ($1, $2, 'Test Device', 1, chat.protocol_capabilities(), 'active', NOW(), NOW())",
    )
    .bind(creator_user)
    .bind(creator_device)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.participants (
            participant_period_id, conversation_id, user_did, status, role,
            role_transition_id, role_changed_at, created_by_did, created_by_device_id,
            current_membership, created_at, ds_did
         ) VALUES (
            $1, $2, $3, 'active', 'admin',
            $4, NOW(), $5, $6,
            TRUE, NOW(), $7
         )",
    )
    .bind(pid)
    .bind(convo_id)
    .bind(remote_user)
    .bind(tid)
    .bind(creator_user)
    .bind(creator_device)
    .bind(remote_ds)
    .execute(&mut *tx)
    .await
    .unwrap();

    let entry = AppendEntry {
        conversation_id: convo_id,
        entry_id: Uuid::new_v4(),
        entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
        accepted_payload_bytes: b"{\"test\":\"payload\"}".to_vec(),
        accepted_payload_sha256: Sha256::digest(b"{\"test\":\"payload\"}").to_vec(),
        signed_request_bytes: b"{\"test\":\"signed_request\"}".to_vec(),
        request_digest: vec![1u8; 32],
        signature: vec![2u8; 64],
        server_fields_bytes: vec![],
        outer_entry_fingerprint: vec![3u8; 32],
        actor_did: "did:plc:sender456".to_string(),
        actor_device_id: Uuid::new_v4(),
        actor_key_id: "key-1".to_string(),
        actor_auth_generation: 1,
        generation: Some(0),
        state_version: Some(0),
        transition_id: None,
        message_id: Some(Uuid::new_v4()),
        received_at: Utc::now(),
    };

    let count = enqueue_clean_federation_message_jobs(&mut tx, convo_id, &entry, 1, 1)
        .await
        .unwrap();
    assert_eq!(count, 1);

    // Verify outbox row exists with correct fields within tx
    let row = sqlx::query(
        "SELECT id, conversation_id, target_service_did, method, payload, payload_sha256, status \
         FROM federation_outbox WHERE conversation_id = $1",
    )
    .bind(convo_id.to_string())
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    let method: String = row.get("method");
    let target_ds: String = row.get("target_service_did");
    let status: String = row.get("status");
    let payload_sha256: Vec<u8> = row.get("payload_sha256");

    assert_eq!(method, DELIVER_MESSAGE_NSID);
    assert_eq!(target_ds, remote_ds);
    assert_eq!(status, "pending");
    assert_eq!(payload_sha256.len(), 32);

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn test_outbox_worker_atomic_handoff_and_done() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let convo_id = Uuid::new_v4();
    let job_id = Uuid::new_v4().to_string();
    let target_ds = "did:web:target.ds.com";
    let payload = b"{\"mock\":\"envelope\"}".to_vec();
    let payload_sha256 = Sha256::digest(&payload).to_vec();
    // Allowlist the peer
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, trust_score, max_requests_per_minute) \
         VALUES ($1, 'allow', 100, 100) \
         ON CONFLICT (ds_did) DO UPDATE SET status = 'allow'",
    )
    .bind(target_ds)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO federation_outbox (
            id, conversation_id, target_service_did, method, payload, payload_sha256,
            envelope_version, status, next_attempt_at, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, 1, 'pending', NOW(), NOW(), NOW())",
    )
    .bind(&job_id)
    .bind(convo_id.to_string())
    .bind(target_ds)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(&payload)
    .bind(&payload_sha256)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Worker claims due rows
    let claimed = claim_due_rows(&pool, 10).await.unwrap();
    assert_eq!(claimed.len(), 1);
    let row = &claimed[0];
    assert_eq!(row.id, job_id);
    assert!(row.claim_token.is_some());

    // 3. Perform atomic handoff
    handoff_to_outbound_queue(&pool, row).await.unwrap();

    // 4. Verify federation_outbox is marked done
    let outbox_status: String =
        sqlx::query_scalar("SELECT status FROM federation_outbox WHERE id = $1")
            .bind(&job_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(outbox_status, "done");

    // 5. Verify outbound_queue has identical row with same stable ID
    let queue_row = sqlx::query(
        "SELECT id, target_ds_did, method, payload, convo_id, status FROM outbound_queue WHERE id = $1",
    )
    .bind(&job_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let q_id: String = queue_row.get("id");
    let q_target: String = queue_row.get("target_ds_did");
    let q_method: String = queue_row.get("method");
    let q_payload: Vec<u8> = queue_row.get("payload");
    let q_convo: String = queue_row.get("convo_id");
    let q_status: String = queue_row.get("status");

    assert_eq!(q_id, job_id);
    assert_eq!(q_target, target_ds);
    assert_eq!(q_method, DELIVER_MESSAGE_NSID);
    assert_eq!(q_payload, payload);
    assert_eq!(q_convo, convo_id.to_string());
    assert_eq!(q_status, "pending");
}

#[tokio::test]
async fn test_outbox_worker_replay_succeeds_over_cap_and_new_insert_rejected() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    std::env::set_var("FEDERATION_OUTBOUND_QUEUE_PER_PEER_PENDING_CAP", "1");
    std::env::set_var("FEDERATION_OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP", "1");

    let convo_id = Uuid::new_v4().to_string();
    let existing_job_id = Uuid::new_v4().to_string();
    let new_job_id = Uuid::new_v4().to_string();
    let target_ds = "did:web:target.ds.com";
    let payload = b"{\"mock\":\"envelope\"}".to_vec();

    // Allowlist the peer
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, trust_score, max_requests_per_minute) \
         VALUES ($1, 'allow', 100, 100) \
         ON CONFLICT (ds_did) DO UPDATE SET status = 'allow'",
    )
    .bind(target_ds)
    .execute(&pool)
    .await
    .unwrap();

    // 1. Pre-insert 1 pending item into outbound_queue (reaching the cap of 1)
    sqlx::query(
        "INSERT INTO outbound_queue (
            id, target_ds_did, target_endpoint, method, payload, convo_id, status, created_at
         ) VALUES ($1, $2, '', $3, $4, $5, 'pending', NOW())",
    )
    .bind(&existing_job_id)
    .bind(target_ds)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(&payload)
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Insert two rows in federation_outbox: one new, one replay of existing
    sqlx::query(
        "INSERT INTO federation_outbox (
            id, conversation_id, target_service_did, method, payload, status, next_attempt_at, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, 'in_flight', NOW(), NOW(), NOW()),
                  ($6, $2, $3, $4, $5, 'in_flight', NOW(), NOW(), NOW())",
    )
    .bind(&new_job_id)
    .bind(&convo_id)
    .bind(target_ds)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(&payload)
    .bind(&existing_job_id)
    .execute(&pool)
    .await
    .unwrap();

    let new_row = FederationOutboxRow {
        id: new_job_id.clone(),
        conversation_id: convo_id.clone(),
        delivery_event_id: None,
        target_service_did: target_ds.to_string(),
        method: DELIVER_MESSAGE_NSID.to_string(),
        payload: payload.clone(),
        payload_sha256: None,
        envelope_version: 1,
        attempts: 0,
        created_at: Utc::now(),
        claim_token: None,
    };

    let existing_row = FederationOutboxRow {
        id: existing_job_id.clone(),
        conversation_id: convo_id.clone(),
        delivery_event_id: None,
        target_service_did: target_ds.to_string(),
        method: DELIVER_MESSAGE_NSID.to_string(),
        payload: payload.clone(),
        payload_sha256: None,
        envelope_version: 1,
        attempts: 0,
        created_at: Utc::now(),
        claim_token: None,
    };

    // 3. New insert must be REJECTED because queue is at/over pending cap
    let new_insert_res = handoff_to_outbound_queue(&pool, &new_row).await;
    assert!(
        new_insert_res.is_err(),
        "New insert when queue is at cap must fail with capacity rejection"
    );

    let new_outbox_status: String =
        sqlx::query_scalar("SELECT status FROM federation_outbox WHERE id = $1")
            .bind(&new_job_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        new_outbox_status, "in_flight",
        "Failed new insert must not mark outbox done"
    );

    // 4. Replay handoff must SUCCEED over cap, skip duplicate insertion, and mark source done
    handoff_to_outbound_queue(&pool, &existing_row)
        .await
        .unwrap();

    let existing_outbox_status: String =
        sqlx::query_scalar("SELECT status FROM federation_outbox WHERE id = $1")
            .bind(&existing_job_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        existing_outbox_status, "done",
        "Replay must succeed over cap and mark source done"
    );

    // Reset env vars
    std::env::remove_var("FEDERATION_OUTBOUND_QUEUE_PER_PEER_PENDING_CAP");
    std::env::remove_var("FEDERATION_OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP");
}

#[tokio::test]
async fn test_outbox_and_queue_dead_rows_purged() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let convo_id = Uuid::new_v4().to_string();
    let old_outbox_dead_id = Uuid::new_v4().to_string();
    let fresh_outbox_dead_id = Uuid::new_v4().to_string();
    let old_queue_dead_id = Uuid::new_v4().to_string();
    let fresh_queue_dead_id = Uuid::new_v4().to_string();
    let target_ds = "did:web:target.ds.com";
    let payload = b"{\"mock\":\"envelope\"}".to_vec();

    // 1. Insert dead rows in federation_outbox: 8 days old vs 1 hour old
    sqlx::query(
        "INSERT INTO federation_outbox (
            id, conversation_id, target_service_did, method, payload, status, next_attempt_at, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, 'dead', NOW(), NOW() - INTERVAL '8 days', NOW() - INTERVAL '8 days'),
                  ($6, $2, $3, $4, $5, 'dead', NOW(), NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour')",
    )
    .bind(&old_outbox_dead_id)
    .bind(&convo_id)
    .bind(target_ds)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(&payload)
    .bind(&fresh_outbox_dead_id)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Insert dead rows in outbound_queue: 8 days old vs 1 hour old
    sqlx::query(
        "INSERT INTO outbound_queue (
            id, target_ds_did, target_endpoint, method, payload, convo_id, status, created_at
         ) VALUES ($1, $2, '', $3, $4, $5, 'dead', NOW() - INTERVAL '8 days'),
                  ($6, $2, '', $3, $4, $5, 'dead', NOW() - INTERVAL '1 hour')",
    )
    .bind(&old_queue_dead_id)
    .bind(target_ds)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(&payload)
    .bind(&convo_id)
    .bind(&fresh_queue_dead_id)
    .execute(&pool)
    .await
    .unwrap();

    // 3. Run dead row cleanup with 7 day max_age
    let seven_days = std::time::Duration::from_secs(7 * 86_400);
    let outbox_purged =
        catbird_server::workers::cleanup_dead_rows(&pool, "federation_outbox", seven_days)
            .await
            .unwrap();
    assert_eq!(outbox_purged, 1, "Must purge exactly 1 old dead outbox row");

    let queue = OutboundQueue::new(
        pool.clone(),
        AuthMiddleware::new(),
        Arc::new(DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            LOCAL_SERVICE_DID.to_string(),
            "https://chat.catbird.blue".to_string(),
            None,
            3600,
        )),
    );
    let queue_purged = queue.cleanup_dead(seven_days).await.unwrap();
    assert_eq!(queue_purged, 1, "Must purge exactly 1 old dead queue row");

    // 4. Verify old dead rows are gone, fresh dead rows remain
    let old_outbox_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM federation_outbox WHERE id = $1)")
            .bind(&old_outbox_dead_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!old_outbox_exists, "Old dead outbox row must be deleted");

    let fresh_outbox_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM federation_outbox WHERE id = $1)")
            .bind(&fresh_outbox_dead_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        fresh_outbox_exists,
        "Fresh dead outbox row must be retained"
    );

    let old_queue_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbound_queue WHERE id = $1)")
            .bind(&old_queue_dead_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!old_queue_exists, "Old dead queue row must be deleted");

    let fresh_queue_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbound_queue WHERE id = $1)")
            .bind(&fresh_queue_dead_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(fresh_queue_exists, "Fresh dead queue row must be retained");
}

#[tokio::test]
async fn test_outbound_queue_claim_fencing_and_concurrent_workers() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let queue = OutboundQueue::new(
        pool.clone(),
        AuthMiddleware::new(),
        Arc::new(DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )),
    );

    let item_id = Uuid::new_v4().to_string();
    let target_ds = "did:web:target.ds.com";
    let convo_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO outbound_queue (
            id, target_ds_did, target_endpoint, method, payload, convo_id, status, next_retry_at
         ) VALUES ($1, $2, '', $3, $4, $5, 'pending', NOW() - INTERVAL '1 second')",
    )
    .bind(&item_id)
    .bind(target_ds)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(b"{}".as_slice())
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();

    // 1. Worker 1 claims item
    let claimed_1 = queue.claim_due_batch(10).await.unwrap();
    assert_eq!(claimed_1.len(), 1);
    let token_1 = claimed_1[0].claim_token.unwrap();

    // 2. Simulate lease expiration and reclaim
    sqlx::query(
        "UPDATE outbound_queue SET claim_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(&item_id)
    .execute(&pool)
    .await
    .unwrap();

    let reclaimed = queue.reclaim_stuck_in_flight().await.unwrap();
    assert_eq!(reclaimed, 1);

    // 3. Worker 2 claims item with a new token
    let claimed_2 = queue.claim_due_batch(10).await.unwrap();
    assert_eq!(claimed_2.len(), 1);
    let token_2 = claimed_2[0].claim_token.unwrap();
    assert_ne!(token_1, token_2);

    // 4. Worker 1 tries to mark delivered with stale token_1 -> Fails fenced update!
    let w1_success = queue.mark_delivered(&item_id, Some(token_1)).await.unwrap();
    assert!(
        !w1_success,
        "Fenced update with stale token must affect 0 rows"
    );

    // Verify still in_flight (held by worker 2)
    let status_after_w1: String =
        sqlx::query_scalar("SELECT status FROM outbound_queue WHERE id = $1")
            .bind(&item_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status_after_w1, "in_flight");

    // 5. Worker 2 marks delivered with valid token_2 -> Succeeds!
    let w2_success = queue.mark_delivered(&item_id, Some(token_2)).await.unwrap();
    assert!(w2_success, "Fenced update with active token must succeed");

    let status_after_w2: String =
        sqlx::query_scalar("SELECT status FROM outbound_queue WHERE id = $1")
            .bind(&item_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status_after_w2, "delivered");
}

#[tokio::test]
async fn test_outbound_queue_policy_revoked_after_enqueue_fails_closed() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let peer_did = format!("did:web:blocked-{}.example.com", Uuid::new_v4().as_simple());

    // 1. Initial allowlist
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, trust_score, created_at, updated_at) \
         VALUES ($1, 'allow', 100, NOW(), NOW())",
    )
    .bind(&peer_did)
    .execute(&pool)
    .await
    .unwrap();

    let queue = OutboundQueue::new(
        pool.clone(),
        AuthMiddleware::new(),
        Arc::new(DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )),
    );

    let item_id = Uuid::new_v4().to_string();
    let convo_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO outbound_queue (
            id, target_ds_did, target_endpoint, method, payload, convo_id, status, next_retry_at
         ) VALUES ($1, $2, 'https://blocked.example.com', $3, $4, $5, 'pending', NOW() - INTERVAL '1 second')",
    )
    .bind(&item_id)
    .bind(&peer_did)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(b"{}".as_slice())
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Revoke / block policy after enqueue
    sqlx::query("UPDATE federation_peers SET status = 'block' WHERE ds_did = $1")
        .bind(&peer_did)
        .execute(&pool)
        .await
        .unwrap();

    let claimed = queue.claim_due_batch(10).await.unwrap();
    assert_eq!(claimed.len(), 1);

    let outbound = OutboundClient::new(1, 1);
    let auth_sign = Arc::new(|_t: &str, _m: &str| Ok("test-token".to_string()));

    // 3. Process item -> must fail closed on peer policy check
    queue
        .process_item(&claimed[0], &outbound, auth_sign.as_ref())
        .await;

    let (status, last_error): (String, Option<String>) =
        sqlx::query_as("SELECT status, last_error FROM outbound_queue WHERE id = $1")
            .bind(&item_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(status, "failed");
    assert!(last_error.unwrap().contains("Peer policy denied"));
}

#[tokio::test]
async fn test_outbound_queue_malicious_receipt_signature_marks_dead_immediately_mock() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let peer_did = format!("did:web:peer-{}.example.com", Uuid::new_v4().as_simple());
    let (_signer, verifying_key, _sk) = test_signer(&peer_did);
    let auth_mw = AuthMiddleware::new();
    cache_peer_did_doc(&auth_mw, &peer_did, &verifying_key).await;
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, trust_score, created_at, updated_at) \
         VALUES ($1, 'allow', 100, NOW(), NOW())",
    )
    .bind(&peer_did)
    .execute(&pool)
    .await
    .unwrap();

    let item_id = Uuid::new_v4().to_string();
    let convo_id = Uuid::new_v4().to_string();
    let delivery_id = Uuid::parse_str(&item_id).unwrap();
    let conversation_id = Uuid::parse_str(&convo_id).unwrap();

    let source_locator = ValidatedEntryLocator {
        entry_id: Uuid::new_v4(),
        seq: 1,
        accepted_payload_sha256: [1u8; 32],
        outer_entry_fingerprint: [2u8; 32],
    };

    // Create a receipt with forged signature (from another random key)
    let (_, _other_vk, other_sk) = test_signer(&peer_did);
    let fake_signer = AckSigner::new(other_sk, peer_did.clone());

    let forged_receipt = sign_receipt(
        &fake_signer,
        DELIVER_MESSAGE_NSID,
        delivery_id,
        conversation_id,
        &service_did_base(),
        &peer_did,
        &service_did_base(),
        1,
        [42u8; 32],
        [99u8; 32],
        source_locator,
        Utc::now(),
    )
    .unwrap();

    let envelope_json = serde_json::json!({
        "header": {
            "protocolVersion": "1",
            "deliveryId": item_id,
            "conversationId": convo_id,
            "senderDsDid": service_did_base(),
            "receiverDsDid": peer_did,
            "sequencerDid": service_did_base(),
            "sequencerTerm": 1,
            "payloadSha256": base64::engine::general_purpose::STANDARD.encode([42u8; 32]),
        },
        "recipientDid": "did:plc:ragtjsm2j2vknwk6zpkrhgah",
        "entryLocator": {
            "entryId": Uuid::new_v4().to_string(),
            "seq": 1,
            "acceptedPayloadSha256": base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
            "outerEntryFingerprint": base64::engine::general_purpose::STANDARD.encode([2u8; 32]),
        },
        "entryBytes": "",
        "signedRequestBytes": ""
    });

    let payload = serde_json::to_vec(&envelope_json).unwrap();

    let raw_http_response = serde_json::json!({
        "accepted": true,
        "receipt": forged_receipt,
    });
    let raw_http_bytes = serde_json::to_vec(&raw_http_response).unwrap();

    let resp_body_bytes = raw_http_bytes.clone();
    let app = axum::Router::new().fallback(axum::routing::post(move |_: axum::body::Bytes| {
        let b = resp_body_bytes.clone();
        async move {
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(b))
                .unwrap()
        }
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resolver = Arc::new(
        DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )
        .with_destination_resolver_hook(Arc::new(move |_endpoint| {
            let port = local_addr.port();
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
                    host: "127.0.0.1".to_string(),
                    addrs: vec![local_addr],
                })
            }))
        })),
    );

    let queue = OutboundQueue::new(pool.clone(), auth_mw, resolver);

    sqlx::query(
        "INSERT INTO outbound_queue (
            id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, max_retries, next_retry_at
         ) VALUES ($1, $2, '', $3, $4, $5, 'pending', 0, 5, NOW() - INTERVAL '1 second')",
    )
    .bind(&item_id)
    .bind(&peer_did)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(&payload)
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();

    let claimed = queue.claim_due_batch(10).await.unwrap();
    assert_eq!(claimed.len(), 1);

    let outbound = OutboundClient::new(2, 2);
    let auth_sign = Arc::new(|_t: &str, _m: &str| Ok("test-token".to_string()));

    // Process item with mock returning forged signature receipt
    queue
        .process_item(&claimed[0], &outbound, auth_sign.as_ref())
        .await;

    // Verify item is marked 'dead' immediately (hostile forged signature, no resend/retry)
    let (status, last_error, claim_token): (String, Option<String>, Option<Uuid>) =
        sqlx::query_as("SELECT status, last_error, claim_token FROM outbound_queue WHERE id = $1")
            .bind(&item_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(status, "dead");
    assert!(
        claim_token.is_none(),
        "Claim token must be cleared on dead transition"
    );
    let err_str = last_error.expect("last_error must be recorded");
    assert!(
        err_str.contains("Receipt signature verification FAILED — invalid signature"),
        "Unexpected error: {err_str}"
    );

    // Verify chat.federation_delivery_receipts has NO row
    let receipt_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.federation_delivery_receipts WHERE delivery_id = $1",
    )
    .bind(delivery_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        receipt_count, 0,
        "No receipt stored on signature verification failure"
    );

    // Verify queue does not claim or retry dead item
    let re_claimed = queue.claim_due_batch(10).await.unwrap();
    assert_eq!(
        re_claimed.len(),
        0,
        "Dead items must not be claimed for retry"
    );
}

#[tokio::test]
async fn test_outbound_queue_receipt_db_persistence_failure_retries_and_never_marked_delivered() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let peer_did = format!("did:web:peer-{}.example.com", Uuid::new_v4().as_simple());
    let (signer, verifying_key, _sk) = test_signer(&peer_did);
    let auth_mw = AuthMiddleware::new();
    cache_peer_did_doc(&auth_mw, &peer_did, &verifying_key).await;
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, trust_score, created_at, updated_at) \
         VALUES ($1, 'allow', 100, NOW(), NOW())",
    )
    .bind(&peer_did)
    .execute(&pool)
    .await
    .unwrap();

    let item_id = Uuid::new_v4().to_string();
    let convo_id = Uuid::new_v4().to_string();
    let delivery_id = Uuid::parse_str(&item_id).unwrap();
    let conversation_id = Uuid::parse_str(&convo_id).unwrap();

    let entry_id = Uuid::new_v4();
    let source_locator = ValidatedEntryLocator {
        entry_id,
        seq: 1,
        accepted_payload_sha256: Sha256::digest(b"{}").into(),
        outer_entry_fingerprint: [2u8; 32],
    };
    seed_genesis_conversation_for_test(&pool, conversation_id, entry_id, &source_locator).await;

    let msg = catbird_atproto::generated::blue_catbird::mlsDS::deliver_message::DeliverMessage::<
        jacquard_common::DefaultStr,
    > {
        header: catbird_atproto::generated::blue_catbird::mlsDS::EnvelopeHeaderV1 {
            protocol_version: jacquard_common::deps::smol_str::SmolStr::from("1"),
            delivery_id: jacquard_common::deps::smol_str::SmolStr::from(item_id.clone()),
            conversation_id: jacquard_common::deps::smol_str::SmolStr::from(convo_id.clone()),
            sender_ds_did: jacquard_common::types::string::Did::new_owned(service_did_base())
                .unwrap(),
            receiver_ds_did: jacquard_common::types::string::Did::new_owned(peer_did.clone())
                .unwrap(),
            sequencer_did: jacquard_common::types::string::Did::new_owned(service_did_base())
                .unwrap(),
            sequencer_term: 1,
            payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[42u8; 32]),
            extra_data: None,
        },
        recipient_did: jacquard_common::types::string::Did::new_owned(
            "did:plc:ragtjsm2j2vknwk6zpkrhgah".to_string(),
        )
        .unwrap(),
        entry_locator: catbird_atproto::generated::blue_catbird::mlsDS::EntryLocatorV1 {
            entry_id: jacquard_common::deps::smol_str::SmolStr::from(
                source_locator.entry_id.to_string(),
            ),
            seq: source_locator.seq as i64,
            accepted_payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                &source_locator.accepted_payload_sha256,
            ),
            outer_entry_fingerprint: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                &source_locator.outer_entry_fingerprint,
            ),
            extra_data: None,
        },
        entry_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(b"sample-entry-bytes"),
        signed_request_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(
            b"sample-signed-request-bytes",
        ),
        extra_data: None,
    };
    let payload = serde_json::to_vec(&msg).unwrap();
    let expected_envelope_digest =
        catbird_server::federation::queue::recompute_envelope_digest_from_payload(
            DELIVER_MESSAGE_NSID,
            &payload,
        )
        .unwrap();

    let valid_receipt = sign_receipt(
        &signer,
        DELIVER_MESSAGE_NSID,
        delivery_id,
        conversation_id,
        &service_did_base(),
        &peer_did,
        &service_did_base(),
        1,
        expected_envelope_digest,
        Sha256::digest(b"{\"accepted\":true}").into(),
        source_locator,
        Utc::now(),
    )
    .unwrap();

    let raw_http_response = serde_json::json!({
        "accepted": true,
        "receipt": valid_receipt,
    });
    let raw_http_bytes = serde_json::to_vec(&raw_http_response).unwrap();

    let resp_body_bytes = raw_http_bytes.clone();
    let app = axum::Router::new().fallback(axum::routing::post(move |_: axum::body::Bytes| {
        let b = resp_body_bytes.clone();
        async move {
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(b))
                .unwrap()
        }
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resolver = Arc::new(
        DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )
        .with_destination_resolver_hook(Arc::new(move |_endpoint| {
            let port = local_addr.port();
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
                    host: "127.0.0.1".to_string(),
                    addrs: vec![local_addr],
                })
            }))
        })),
    );

    let queue = OutboundQueue::new(pool.clone(), auth_mw, resolver);

    sqlx::query(
        "INSERT INTO outbound_queue (
            id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, max_retries, next_retry_at
         ) VALUES ($1, $2, '', $3, $4, $5, 'pending', 0, 5, NOW() - INTERVAL '1 second')",
    )
    .bind(&item_id)
    .bind(&peer_did)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(&payload)
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();

    // Inject DB persistence failure on receipt table insert using separate statements
    sqlx::query(
        "CREATE OR REPLACE FUNCTION test_fail_receipt_insert() RETURNS trigger AS $$ \
         BEGIN \
             RAISE EXCEPTION 'injected DB failure on receipt insert'; \
         END; \
         $$ LANGUAGE plpgsql;",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TRIGGER inject_receipt_insert_failure \
         BEFORE INSERT ON chat.federation_delivery_receipts \
         FOR EACH ROW EXECUTE FUNCTION test_fail_receipt_insert();",
    )
    .execute(&pool)
    .await
    .unwrap();

    let claimed = queue.claim_due_batch(10).await.unwrap();
    assert_eq!(claimed.len(), 1);

    let outbound = OutboundClient::new(2, 2);
    let auth_sign = Arc::new(|_t: &str, _m: &str| Ok("test-token".to_string()));

    // Process item -> receipt is valid, but DB insert fails
    queue
        .process_item(&claimed[0], &outbound, auth_sign.as_ref())
        .await;

    // 1. Verify item is in 'pending' status for retry, and NOT 'delivered'
    let (status, retry_count, last_error, claim_token): (
        String,
        i32,
        Option<String>,
        Option<Uuid>,
    ) = sqlx::query_as(
        "SELECT status, retry_count, last_error, claim_token FROM outbound_queue WHERE id = $1",
    )
    .bind(&item_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_ne!(
        status, "delivered",
        "Must NEVER mark delivered when receipt DB persistence fails"
    );
    assert_eq!(
        status, "pending",
        "Must retry (pending) on DB persistence failure"
    );
    assert_eq!(retry_count, 1, "Retry count must be incremented");
    assert!(
        claim_token.is_none(),
        "Claim token must be cleared on retry scheduling"
    );
    let err_str = last_error.expect("last_error must be recorded");
    assert!(
        err_str.contains("Receipt DB persistence failure")
            && err_str.contains("injected DB failure on receipt insert"),
        "last_error must record DB persistence failure: {err_str}"
    );

    // 2. Verify no receipt row was persisted
    let receipt_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.federation_delivery_receipts WHERE delivery_id = $1",
    )
    .bind(delivery_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        receipt_count, 0,
        "No receipt stored on DB persistence failure"
    );
}

#[tokio::test]
async fn test_outbound_queue_valid_signed_receipt_marks_delivered_and_stores_response_bytes() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let peer_did = format!("did:web:peer-{}.example.com", Uuid::new_v4().as_simple());
    let (signer, verifying_key, _sk) = test_signer(&peer_did);
    let auth_mw = AuthMiddleware::new();
    cache_peer_did_doc(&auth_mw, &peer_did, &verifying_key).await;
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, trust_score, created_at, updated_at) \
         VALUES ($1, 'allow', 100, NOW(), NOW())",
    )
    .bind(&peer_did)
    .execute(&pool)
    .await
    .unwrap();

    let item_id = Uuid::new_v4().to_string();
    let convo_id = Uuid::new_v4().to_string();
    let delivery_id = Uuid::parse_str(&item_id).unwrap();
    let conversation_id = Uuid::parse_str(&convo_id).unwrap();

    let entry_id = Uuid::new_v4();
    let source_locator = ValidatedEntryLocator {
        entry_id,
        seq: 1,
        accepted_payload_sha256: Sha256::digest(b"{}").into(),
        outer_entry_fingerprint: [2u8; 32],
    };
    seed_genesis_conversation_for_test(&pool, conversation_id, entry_id, &source_locator).await;

    let msg = catbird_atproto::generated::blue_catbird::mlsDS::deliver_message::DeliverMessage::<
        jacquard_common::DefaultStr,
    > {
        header: catbird_atproto::generated::blue_catbird::mlsDS::EnvelopeHeaderV1 {
            protocol_version: jacquard_common::deps::smol_str::SmolStr::from("1"),
            delivery_id: jacquard_common::deps::smol_str::SmolStr::from(item_id.clone()),
            conversation_id: jacquard_common::deps::smol_str::SmolStr::from(convo_id.clone()),
            sender_ds_did: jacquard_common::types::string::Did::new_owned(service_did_base())
                .unwrap(),
            receiver_ds_did: jacquard_common::types::string::Did::new_owned(peer_did.clone())
                .unwrap(),
            sequencer_did: jacquard_common::types::string::Did::new_owned(service_did_base())
                .unwrap(),
            sequencer_term: 1,
            payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[42u8; 32]),
            extra_data: None,
        },
        recipient_did: jacquard_common::types::string::Did::new_owned(
            "did:plc:ragtjsm2j2vknwk6zpkrhgah".to_string(),
        )
        .unwrap(),
        entry_locator: catbird_atproto::generated::blue_catbird::mlsDS::EntryLocatorV1 {
            entry_id: jacquard_common::deps::smol_str::SmolStr::from(
                source_locator.entry_id.to_string(),
            ),
            seq: source_locator.seq as i64,
            accepted_payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                &source_locator.accepted_payload_sha256,
            ),
            outer_entry_fingerprint: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                &source_locator.outer_entry_fingerprint,
            ),
            extra_data: None,
        },
        entry_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(b"sample-entry-bytes"),
        signed_request_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(
            b"sample-signed-request-bytes",
        ),
        extra_data: None,
    };
    let payload = serde_json::to_vec(&msg).unwrap();
    let expected_envelope_digest =
        catbird_server::federation::queue::recompute_envelope_digest_from_payload(
            DELIVER_MESSAGE_NSID,
            &payload,
        )
        .unwrap();

    let valid_receipt = sign_receipt(
        &signer,
        DELIVER_MESSAGE_NSID,
        delivery_id,
        conversation_id,
        &service_did_base(),
        &peer_did,
        &service_did_base(),
        1,
        expected_envelope_digest,
        Sha256::digest(b"{\"accepted\":true}").into(),
        source_locator,
        Utc::now(),
    )
    .unwrap();

    // Start a mock axum server that responds with valid receipt and specific custom response bytes
    let raw_http_response = serde_json::json!({
        "accepted": true,
        "receipt": valid_receipt,
        "customTestProof": "unique-response-bytes-12345"
    });
    let raw_http_bytes = serde_json::to_vec(&raw_http_response).unwrap();
    let expected_response_sha256: [u8; 32] = Sha256::digest(&raw_http_bytes).into();

    let resp_body_bytes = raw_http_bytes.clone();
    let app = axum::Router::new().fallback(axum::routing::post(move |_: axum::body::Bytes| {
        let b = resp_body_bytes.clone();
        async move {
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(b))
                .unwrap()
        }
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resolver = Arc::new(
        DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )
        .with_destination_resolver_hook(Arc::new(move |_endpoint| {
            let port = local_addr.port();
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
                    host: "127.0.0.1".to_string(),
                    addrs: vec![local_addr],
                })
            }))
        })),
    );

    let queue = OutboundQueue::new(pool.clone(), auth_mw, resolver);

    sqlx::query(
        "INSERT INTO outbound_queue (
            id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, max_retries, next_retry_at
         ) VALUES ($1, $2, '', $3, $4, $5, 'pending', 0, 5, NOW() - INTERVAL '1 second')",
    )
    .bind(&item_id)
    .bind(&peer_did)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(&payload)
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();
    let claimed = queue.claim_due_batch(10).await.unwrap();
    assert_eq!(claimed.len(), 1);

    let outbound = OutboundClient::new(2, 2);
    let auth_sign = Arc::new(|_t: &str, _m: &str| Ok("test-token".to_string()));

    // Process item -> makes outbound call, verifies receipt, stores receipt with actual HTTP response bytes
    queue
        .process_item(&claimed[0], &outbound, auth_sign.as_ref())
        .await;

    // 1. Verify outbound_queue item marked delivered
    let (status, _last_error): (String, Option<String>) =
        sqlx::query_as("SELECT status, last_error FROM outbound_queue WHERE id = $1")
            .bind(&item_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "delivered");
    // 2. Verify chat.federation_delivery_receipts stored the ACTUAL HTTP response bytes and SHA256
    let row = sqlx::query(
        "SELECT response_bytes, response_sha256, result_sha256 FROM chat.federation_delivery_receipts WHERE delivery_id = $1",
    )
    .bind(delivery_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let stored_response_bytes: Vec<u8> = row.get("response_bytes");
    let stored_response_sha256: Vec<u8> = row.get("response_sha256");
    let stored_result_sha256: Vec<u8> = row.get("result_sha256");

    assert_eq!(stored_response_bytes, raw_http_bytes);
    assert_eq!(stored_response_sha256.as_slice(), &expected_response_sha256);
    // result_sha256 is distinct from response_sha256 (not result_sha256 stored twice!)
    assert_ne!(stored_response_bytes, stored_result_sha256);
}

#[tokio::test]
async fn test_outbound_queue_cryptographically_valid_field_mismatched_receipt_is_permanent_hostile_dead(
) {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let peer_did = format!("did:web:peer-{}.example.com", Uuid::new_v4().as_simple());
    let (signer, _verifying_key, _sk) = test_signer(&peer_did);
    let auth_mw = AuthMiddleware::new();
    cache_peer_did_doc(&auth_mw, &peer_did, &_verifying_key).await;
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, trust_score, created_at, updated_at) \
         VALUES ($1, 'allow', 100, NOW(), NOW())",
    )
    .bind(&peer_did)
    .execute(&pool)
    .await
    .unwrap();

    let item_id = Uuid::new_v4().to_string();
    let convo_id = Uuid::new_v4().to_string();
    let delivery_id = Uuid::parse_str(&item_id).unwrap();
    // Generate a DIFFERENT conversation ID for the receipt to cause a field mismatch on a cryptographically valid receipt
    let mismatched_convo_id = Uuid::new_v4();

    let source_locator = ValidatedEntryLocator {
        entry_id: Uuid::new_v4(),
        seq: 1,
        accepted_payload_sha256: [1u8; 32],
        outer_entry_fingerprint: [2u8; 32],
    };

    // Validly signed receipt by peer_did, but for the WRONG conversation ID (hostile / spoofed ACK)
    let mismatched_receipt = sign_receipt(
        &signer,
        DELIVER_MESSAGE_NSID,
        delivery_id,
        mismatched_convo_id,
        &service_did_base(),
        &peer_did,
        &service_did_base(),
        1,
        [42u8; 32],
        [99u8; 32],
        source_locator,
        Utc::now(),
    )
    .unwrap();

    let raw_http_response = serde_json::json!({
        "accepted": true,
        "receipt": mismatched_receipt,
    });
    let raw_http_bytes = serde_json::to_vec(&raw_http_response).unwrap();

    let resp_body_bytes = raw_http_bytes.clone();
    let app = axum::Router::new().fallback(axum::routing::post(move |_: axum::body::Bytes| {
        let b = resp_body_bytes.clone();
        async move {
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(b))
                .unwrap()
        }
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resolver = Arc::new(
        DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )
        .with_destination_resolver_hook(Arc::new(move |_endpoint| {
            let port = local_addr.port();
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
                    host: "127.0.0.1".to_string(),
                    addrs: vec![local_addr],
                })
            }))
        })),
    );

    let queue = OutboundQueue::new(pool.clone(), auth_mw, resolver);

    let envelope_json = serde_json::json!({
        "header": {
            "protocolVersion": "1",
            "deliveryId": item_id,
            "conversationId": convo_id,
            "senderDsDid": service_did_base(),
            "receiverDsDid": peer_did,
            "sequencerDid": service_did_base(),
            "sequencerTerm": 1,
            "payloadSha256": base64::engine::general_purpose::STANDARD.encode([42u8; 32]),
        },
        "recipientDid": "did:plc:ragtjsm2j2vknwk6zpkrhgah",
        "entryLocator": {
            "entryId": Uuid::new_v4().to_string(),
            "seq": 1,
            "acceptedPayloadSha256": base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
            "outerEntryFingerprint": base64::engine::general_purpose::STANDARD.encode([2u8; 32]),
        },
        "entryBytes": "",
        "signedRequestBytes": ""
    });
    let payload = serde_json::to_vec(&envelope_json).unwrap();

    sqlx::query(
        "INSERT INTO outbound_queue (
            id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, max_retries, next_retry_at
         ) VALUES ($1, $2, '', $3, $4, $5, 'pending', 0, 5, NOW() - INTERVAL '1 second')",
    )
    .bind(&item_id)
    .bind(&peer_did)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(&payload)
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();

    let claimed = queue.claim_due_batch(10).await.unwrap();
    assert_eq!(claimed.len(), 1);

    let outbound = OutboundClient::new(2, 2);
    let auth_sign = Arc::new(|_t: &str, _m: &str| Ok("test-token".to_string()));

    // Process item -> field mismatch on cryptographically valid receipt must be marked DEAD immediately (no retry!)
    queue
        .process_item(&claimed[0], &outbound, auth_sign.as_ref())
        .await;

    let (status, last_error): (String, Option<String>) =
        sqlx::query_as("SELECT status, last_error FROM outbound_queue WHERE id = $1")
            .bind(&item_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(
        status, "dead",
        "Cryptographically valid but field-mismatched receipt is permanent hostile -> MUST be marked dead immediately (no resend)"
    );
    assert!(last_error
        .unwrap_or_default()
        .contains("Receipt conversationId mismatch"));
}

#[tokio::test]
async fn test_state_machine_creation_does_not_enqueue_synthetic_deliver_message() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let convo_id = Uuid::new_v4();
    let remote_ds = "did:web:remote.ds.example.com";
    let remote_user = "did:plc:remoteaaaaaaaaaaaaaaaaaa";
    let creator_user = "did:plc:creatoraaaaaaaaaaaaaaaaa";

    // Seed conversation with remote participant
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx)
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO chat.conversations (
            conversation_id, kind, lifecycle, current_generation, current_state_version,
            next_entry_seq, created_at, is_remote, sequencer_ds, sequencer_term
         ) VALUES ($1, 'group', 'active', 0, 0, 1, NOW(), FALSE, NULL, 1)",
    )
    .bind(convo_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) \
         VALUES ($1, NOW()), ($2, NOW())",
    )
    .bind(creator_user)
    .bind(remote_user)
    .execute(&mut *tx)
    .await
    .unwrap();

    let creator_device = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, auth_generation, capabilities, status, created_at, updated_at) \
         VALUES ($1, $2, 'Test Device', 1, chat.protocol_capabilities(), 'active', NOW(), NOW())",
    )
    .bind(creator_user)
    .bind(creator_device)
    .execute(&mut *tx)
    .await
    .unwrap();

    let pid = Uuid::new_v4();
    let tid = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO chat.participants (
            participant_period_id, conversation_id, user_did, status, role,
            role_transition_id, role_changed_at, created_by_did, created_by_device_id,
            current_membership, created_at, ds_did
         ) VALUES (
            $1, $2, $3, 'active', 'admin',
            $4, NOW(), $5, $6,
            TRUE, NOW(), $7
         )",
    )
    .bind(pid)
    .bind(convo_id)
    .bind(remote_user)
    .bind(tid)
    .bind(creator_user)
    .bind(creator_device)
    .bind(remote_ds)
    .execute(&mut *tx)
    .await
    .unwrap();
    let group_id = [1u8; 32];
    let group_info = b"group_info".to_vec();
    let genesis_group_context_hash = [2u8; 32];
    let genesis_confirmation_tag = [3u8; 32];
    let genesis_snapshot = b"snapshot".to_vec();
    let genesis_tree_summary = b"tree".to_vec();
    let genesis_tree_summary_sha = Sha256::digest(&genesis_tree_summary).to_vec();

    sqlx::query(
        "INSERT INTO chat.generations (
            conversation_id, generation, group_id, lifecycle, genesis_group_info_bytes,
            genesis_group_info_sha256, current_state_version, activated_seq, activated_at
         ) VALUES ($1, 0, $2, 'active', $3, $4, 0, 1, NOW())",
    )
    .bind(convo_id)
    .bind(&group_id[..])
    .bind(&group_info[..])
    .bind(Sha256::digest(&group_info).to_vec())
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.generation_states (
            conversation_id, generation, state_version, group_id, epoch,
            group_context_hash, confirmation_tag, lifecycle, state_kind,
            producing_transition_id, public_snapshot_bytes, snapshot_sha256,
            tree_summary_bytes, tree_summary_sha256, leaf_count, created_at
        ) VALUES (
            $1, 0, 0, $2, 0,
            $3, $4, 'active', 'creation',
            $5, $6, $7,
            $8, $9, 1, NOW()
        )
        "#,
    )
    .bind(convo_id)
    .bind(&group_id[..])
    .bind(&genesis_group_context_hash[..])
    .bind(&genesis_confirmation_tag[..])
    .bind(tid)
    .bind(&genesis_snapshot)
    .bind(Sha256::digest(&genesis_snapshot).to_vec())
    .bind(&genesis_tree_summary)
    .bind(&genesis_tree_summary_sha[..])
    .execute(&mut *tx)
    .await
    .unwrap();

    let outbox_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM federation_outbox WHERE conversation_id = $1")
            .bind(convo_id.to_string())
            .fetch_one(&mut *tx)
            .await
            .unwrap();

    assert_eq!(
        outbox_count, 0,
        "Creation/policy/metadata must NOT enqueue deliverMessage jobs into federation_outbox"
    );

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn test_notification_outbox_reclaim_does_not_reference_claim_columns() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;

    let convo_id = Uuid::new_v4().to_string();
    let stuck_id = Uuid::new_v4().to_string();
    let fresh_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO conversations (id, creator_did, group_id, created_at, updated_at) VALUES ($1, 'did:plc:ragtjsm2j2vknwk6zpkrhgah', 'group-1', NOW(), NOW()) ON CONFLICT DO NOTHING",
    )
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO delivery_events (id, conversation_id, seq, event_type, sender_did, idempotency_key, payload_json) VALUES ('evt-1', $1, 1, 'message', 'did:plc:ragtjsm2j2vknwk6zpkrhgah', 'idem-1', '{}'), ('evt-2', $1, 2, 'message', 'did:plc:ragtjsm2j2vknwk6zpkrhgah', 'idem-2', '{}') ON CONFLICT DO NOTHING",
    )
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();

    // Row 1: in_flight and updated 10 minutes ago (stuck)
    sqlx::query(
        "INSERT INTO notification_outbox (
            id, conversation_id, delivery_event_id, recipient_did, kind,
            status, next_attempt_at, updated_at, created_at
         ) VALUES ($1, $2, 'evt-1', 'did:plc:alice234567abcdefghijkl', 'sse', 'in_flight', NOW(), NOW() - INTERVAL '10 minutes', NOW() - INTERVAL '10 minutes')",
    )
    .bind(&stuck_id)
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();

    // Row 2: in_flight and updated just now (fresh)
    sqlx::query(
        "INSERT INTO notification_outbox (
            id, conversation_id, delivery_event_id, recipient_did, kind,
            status, next_attempt_at, updated_at, created_at
         ) VALUES ($1, $2, 'evt-2', 'did:plc:bob2345678abcdefghijklm', 'sse', 'in_flight', NOW(), NOW(), NOW())",
    )
    .bind(&fresh_id)
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();

    // Reclaim stuck rows - must succeed without referencing non-existent claim_token / claim_expires_at columns
    let reclaimed = catbird_server::workers::reclaim_stuck_in_flight(&pool, "notification_outbox")
        .await
        .unwrap();
    assert_eq!(
        reclaimed, 1,
        "Exactly one stuck in_flight row should be reclaimed"
    );

    let status_stuck: String =
        sqlx::query_scalar("SELECT status FROM notification_outbox WHERE id = $1")
            .bind(&stuck_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status_stuck, "pending", "Stuck row must revert to pending");

    let status_fresh: String =
        sqlx::query_scalar("SELECT status FROM notification_outbox WHERE id = $1")
            .bind(&fresh_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status_fresh, "in_flight", "Fresh row must remain in_flight");
}

#[tokio::test]
async fn test_recovery_fulfillment_remote_welcome_creates_typed_outbox_job_and_rollback() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let convo_id = Uuid::new_v4();
    let remote_ds = "did:web:remote.ds.example.com";
    let remote_user = "did:plc:remoterecipient234567abc";
    let creator_user = "did:plc:creatoruser234567abcdefg";
    let remote_device = Uuid::new_v4();
    let creator_device = Uuid::new_v4();
    let welcome_id = Uuid::new_v4();
    let recovery_request_id = Uuid::new_v4();
    let key_package_ref = [0x55u8; 32];
    let welcome_bytes = b"encrypted-welcome-payload-for-remote-device";
    let welcome_sha256: [u8; 32] = Sha256::digest(welcome_bytes).into();
    let public_snapshot_sha256 = [0x66u8; 32];
    let tree_summary_sha256 = [0x77u8; 32];

    let mut tx = pool.begin().await.unwrap();

    // Provision conversation and remote participant
    sqlx::query(
        "INSERT INTO chat.conversations (
            conversation_id, kind, lifecycle, current_generation, current_state_version,
            next_entry_seq, created_at, is_remote, sequencer_ds, sequencer_term
         ) VALUES ($1, 'group', 'active', 1, 1, 3, NOW(), FALSE, NULL, 2)",
    )
    .bind(convo_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) \
         VALUES ($1, NOW()), ($2, NOW())",
    )
    .bind(creator_user)
    .bind(remote_user)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, auth_generation, capabilities, status, created_at, updated_at) \
         VALUES ($1, $2, 'Remote Device', 1, chat.protocol_capabilities(), 'active', NOW(), NOW()),
                ($3, $4, 'Creator Device', 1, chat.protocol_capabilities(), 'active', NOW(), NOW())",
    )
    .bind(remote_user)
    .bind(remote_device)
    .bind(creator_user)
    .bind(creator_device)
    .execute(&mut *tx)
    .await
    .unwrap();

    let pid = Uuid::new_v4();
    let tid = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO chat.participants (
            participant_period_id, conversation_id, user_did, status, role,
            role_transition_id, role_changed_at, created_by_did, created_by_device_id,
            current_membership, created_at, ds_did
         ) VALUES (
            $1, $2, $3, 'active', 'admin',
            $4, NOW(), $5, $6,
            TRUE, NOW(), $7
         )",
    )
    .bind(pid)
    .bind(convo_id)
    .bind(remote_user)
    .bind(tid)
    .bind(creator_user)
    .bind(creator_device)
    .bind(remote_ds)
    .execute(&mut *tx)
    .await
    .unwrap();

    let entry = AppendEntry {
        conversation_id: convo_id,
        entry_id: Uuid::new_v4(),
        entry_kind: "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry".to_string(),
        accepted_payload_bytes: b"{\"type\":\"leafRecoveryFulfillmentEntry\"}".to_vec(),
        accepted_payload_sha256: Sha256::digest(b"{\"type\":\"leafRecoveryFulfillmentEntry\"}")
            .to_vec(),
        signed_request_bytes: b"{\"type\":\"signed_fulfillment_request\"}".to_vec(),
        request_digest: vec![0x11u8; 32],
        signature: vec![0x22u8; 64],
        server_fields_bytes: vec![],
        outer_entry_fingerprint: vec![0x33u8; 32],
        actor_did: creator_user.to_string(),
        actor_device_id: creator_device,
        actor_key_id: "key-creator-1".to_string(),
        actor_auth_generation: 1,
        generation: Some(1),
        state_version: Some(1),
        transition_id: Some(tid),
        message_id: None,
        received_at: Utc::now(),
    };

    let coordinates = ConversationCoordinates {
        conversation_id: jacquard_common::deps::smol_str::SmolStr::from(
            convo_id.hyphenated().to_string(),
        ),
        generation: 1,
        state_version: 1,
        epoch: 1,
        group_id: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x44u8; 32]),
        group_context_hash: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x55u8; 32]),
        confirmation_tag: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x66u8; 32]),
        lifecycle: jacquard_common::deps::smol_str::SmolStr::from("active"),
        extra_data: None,
    };

    // Enqueue federated welcome job within the exact transaction
    let job_delivery_id = enqueue_federated_welcome_job(
        &mut tx,
        convo_id,
        remote_ds,
        remote_user,
        remote_device,
        welcome_id,
        recovery_request_id,
        &key_package_ref,
        welcome_bytes,
        &welcome_sha256,
        &entry,
        2,
        coordinates,
        &public_snapshot_sha256,
        &tree_summary_sha256,
        2,
    )
    .await
    .unwrap();

    // Verify outbox row exists in tx
    let row = sqlx::query(
        "SELECT id, conversation_id, target_service_did, method, payload, payload_sha256, status \
         FROM federation_outbox WHERE id = $1",
    )
    .bind(job_delivery_id.to_string())
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    let method: String = row.get("method");
    let target_ds: String = row.get("target_service_did");
    let status: String = row.get("status");
    let payload_sha: Vec<u8> = row.get("payload_sha256");

    assert_eq!(method, DELIVER_WELCOME_NSID);
    assert_eq!(target_ds, remote_ds);
    assert_eq!(status, "pending");
    assert_eq!(payload_sha.len(), 32);

    // Rollback transaction - proves atomic creation with transaction rollback
    tx.rollback().await.unwrap();

    let count_after_rollback: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM federation_outbox WHERE conversation_id = $1")
            .bind(convo_id.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(
        count_after_rollback, 0,
        "Rollback must leave no federation_outbox job behind"
    );
}

#[tokio::test]
async fn test_recovery_fulfillment_absent_participant_fails_hard_and_rolls_back() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let convo_id = Uuid::new_v4();
    let remote_ds = "did:web:remote.ds.example.com";
    let absent_user = "did:plc:absentuser234567abcdefg";
    let creator_user = "did:plc:creatoruser234567abcdefg";
    let remote_device = Uuid::new_v4();
    let creator_device = Uuid::new_v4();
    let welcome_id = Uuid::new_v4();
    let recovery_request_id = Uuid::new_v4();
    let key_package_ref = [0x55u8; 32];
    let welcome_bytes = b"encrypted-welcome-payload-for-remote-device";
    let welcome_sha256: [u8; 32] = Sha256::digest(welcome_bytes).into();
    let public_snapshot_sha256 = [0x66u8; 32];
    let tree_summary_sha256 = [0x77u8; 32];

    let mut tx = pool.begin().await.unwrap();

    // Provision conversation and creator, but deliberately do NOT add absent_user to participants
    sqlx::query(
        "INSERT INTO chat.conversations (
            conversation_id, kind, lifecycle, current_generation, current_state_version,
            next_entry_seq, created_at, is_remote, sequencer_ds, sequencer_term
         ) VALUES ($1, 'group', 'active', 1, 1, 3, NOW(), FALSE, NULL, 2)",
    )
    .bind(convo_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) \
         VALUES ($1, NOW())",
    )
    .bind(creator_user)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, auth_generation, capabilities, status, created_at, updated_at) \
         VALUES ($1, $2, 'Creator Device', 1, chat.protocol_capabilities(), 'active', NOW(), NOW())",
    )
    .bind(creator_user)
    .bind(creator_device)
    .execute(&mut *tx)
    .await
    .unwrap();

    let entry = AppendEntry {
        conversation_id: convo_id,
        entry_id: Uuid::new_v4(),
        entry_kind: "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry".to_string(),
        accepted_payload_bytes: b"{\"type\":\"leafRecoveryFulfillmentEntry\"}".to_vec(),
        accepted_payload_sha256: Sha256::digest(b"{\"type\":\"leafRecoveryFulfillmentEntry\"}")
            .to_vec(),
        signed_request_bytes: b"{\"type\":\"signed_fulfillment_request\"}".to_vec(),
        request_digest: vec![0x11u8; 32],
        signature: vec![0x22u8; 64],
        server_fields_bytes: vec![],
        outer_entry_fingerprint: vec![0x33u8; 32],
        actor_did: creator_user.to_string(),
        actor_device_id: creator_device,
        actor_key_id: "key-creator-1".to_string(),
        actor_auth_generation: 1,
        generation: Some(1),
        state_version: Some(1),
        transition_id: Some(Uuid::new_v4()),
        message_id: None,
        received_at: Utc::now(),
    };

    let coordinates = ConversationCoordinates {
        conversation_id: jacquard_common::deps::smol_str::SmolStr::from(
            convo_id.hyphenated().to_string(),
        ),
        generation: 1,
        state_version: 1,
        epoch: 1,
        group_id: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x44u8; 32]),
        group_context_hash: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x55u8; 32]),
        confirmation_tag: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x66u8; 32]),
        lifecycle: jacquard_common::deps::smol_str::SmolStr::from("active"),
        extra_data: None,
    };

    // Attempting to enqueue welcome for absent participant must fail with hard error
    let res = enqueue_federated_welcome_job(
        &mut tx,
        convo_id,
        remote_ds,
        absent_user,
        remote_device,
        welcome_id,
        recovery_request_id,
        &key_package_ref,
        welcome_bytes,
        &welcome_sha256,
        &entry,
        2,
        coordinates,
        &public_snapshot_sha256,
        &tree_summary_sha256,
        2,
    )
    .await;

    assert!(
        res.is_err(),
        "Absent participant must fail with MailboxNotProvisioned/hard error"
    );

    // Rollback transaction
    tx.rollback().await.unwrap();

    let outbox_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM federation_outbox WHERE conversation_id = $1")
            .bind(convo_id.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        outbox_count, 0,
        "Failed welcome emission must leave no federation_outbox job"
    );
}
#[tokio::test]
async fn test_recovery_fulfillment_local_participant_skips_outbox_job() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let convo_id = Uuid::new_v4();
    let local_user = "did:plc:localrecip234567abcdefgh";
    let creator_user = "did:plc:creatoruser234567abcdefg";
    let local_device = Uuid::new_v4();
    let creator_device = Uuid::new_v4();

    let mut tx = pool.begin().await.unwrap();

    // Provision conversation and local participant (ds_did IS NULL)
    sqlx::query(
        "INSERT INTO chat.conversations (
            conversation_id, kind, lifecycle, current_generation, current_state_version,
            next_entry_seq, created_at, is_remote, sequencer_ds, sequencer_term
         ) VALUES ($1, 'group', 'active', 1, 1, 3, NOW(), FALSE, NULL, 2)",
    )
    .bind(convo_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) \
         VALUES ($1, NOW()), ($2, NOW())",
    )
    .bind(creator_user)
    .bind(local_user)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, auth_generation, capabilities, status, created_at, updated_at) \
         VALUES ($1, $2, 'Local Device', 1, chat.protocol_capabilities(), 'active', NOW(), NOW()),
                ($3, $4, 'Creator Device', 1, chat.protocol_capabilities(), 'active', NOW(), NOW())",
    )
    .bind(local_user)
    .bind(local_device)
    .bind(creator_user)
    .bind(creator_device)
    .execute(&mut *tx)
    .await
    .unwrap();

    let pid = Uuid::new_v4();
    let tid = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO chat.participants (
            participant_period_id, conversation_id, user_did, status, role,
            role_transition_id, role_changed_at, created_by_did, created_by_device_id,
            current_membership, created_at, ds_did
         ) VALUES (
            $1, $2, $3, 'active', 'admin',
            $4, NOW(), $5, $6,
            TRUE, NOW(), NULL
         )",
    )
    .bind(pid)
    .bind(convo_id)
    .bind(local_user)
    .bind(tid)
    .bind(creator_user)
    .bind(creator_device)
    .execute(&mut *tx)
    .await
    .unwrap();

    // Verify participant ds_did query in executor: local participant (NULL ds_did) is local
    let participant_row: Option<Option<String>> = sqlx::query_scalar(
        "SELECT ds_did FROM chat.participants \
         WHERE conversation_id = $1 AND user_did = $2 \
           AND current_membership = TRUE AND status IN ('pending', 'active')",
    )
    .bind(convo_id)
    .bind(local_user)
    .fetch_optional(&mut *tx)
    .await
    .unwrap();

    assert!(participant_row.is_some(), "Participant must exist");
    assert_eq!(
        participant_row.unwrap(),
        None,
        "Local participant has NULL ds_did"
    );

    tx.rollback().await.unwrap();
    let outbox_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM federation_outbox WHERE conversation_id = $1")
            .bind(convo_id.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        outbox_count, 0,
        "Local participant emission must not create federation_outbox job"
    );
}

#[tokio::test]
async fn test_outbound_queue_worker_periodic_cleanup_dead_and_old_wiring() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let target_ds = "did:web:remote.ds.example.com";
    let convo_id = Uuid::new_v4().to_string();
    let dead_item_id = format!("queue-item-dead-{}", Uuid::new_v4().simple());
    let delivered_item_id = format!("queue-item-deliv-{}", Uuid::new_v4().simple());
    let pending_item_id = format!("queue-item-pend-{}", Uuid::new_v4().simple());
    let payload = b"{\"test\":\"periodic_cleanup\"}".to_vec();

    // 1. Insert:
    //    - dead item created in the past (will be purged by cleanup_dead)
    //    - delivered item created in the past (will be purged by cleanup_old)
    //    - pending item (must be preserved)
    sqlx::query(
        "INSERT INTO outbound_queue (
            id, target_ds_did, target_endpoint, method, payload, convo_id, status, created_at
         ) VALUES ($1, $2, '', $3, $4, $5, 'dead', NOW() - INTERVAL '2 hours'),
                  ($6, $2, '', $3, $4, $5, 'delivered', NOW() - INTERVAL '2 hours'),
                  ($7, $2, '', $3, $4, $5, 'pending', NOW())",
    )
    .bind(&dead_item_id)
    .bind(target_ds)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(&payload)
    .bind(&convo_id)
    .bind(&delivered_item_id)
    .bind(&pending_item_id)
    .execute(&pool)
    .await
    .unwrap();

    let queue = Arc::new(OutboundQueue::new(
        pool.clone(),
        AuthMiddleware::new(),
        Arc::new(DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            LOCAL_SERVICE_DID.to_string(),
            "https://chat.catbird.blue".to_string(),
            None,
            3600,
        )),
    ));

    let outbound = Arc::new(OutboundClient::new(5, 5));
    let auth_sign: Arc<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync> =
        Arc::new(|_, _| Ok("dummy-token".to_string()));
    let shutdown = tokio_util::sync::CancellationToken::new();

    // 2. Launch worker with short poll (50ms) and short cleanup interval (50ms)
    //    and retention = 0s / 0 hours so older-than-now rows are purged
    let queue_worker = queue.clone();
    let outbound_worker = outbound.clone();
    let auth_sign_worker = auth_sign.clone();
    let shutdown_worker = shutdown.clone();

    let worker_handle = tokio::spawn(async move {
        queue_worker
            .run_worker_with_intervals(
                outbound_worker,
                auth_sign_worker,
                std::time::Duration::from_millis(20),
                std::time::Duration::from_millis(20),
                std::time::Duration::from_secs(3600), // 1 hour max age
                1,                                    // 1 hour max age
                shutdown_worker,
            )
            .await;
    });

    // Wait for at least a couple ticks of cleanup
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Signal shutdown and await worker completion
    shutdown.cancel();
    worker_handle.await.unwrap();

    // 3. Verify dead and delivered rows were purged periodically by the worker, but pending remains
    let dead_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbound_queue WHERE id = $1)")
            .bind(&dead_item_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !dead_exists,
        "Old dead row must be purged by worker periodic cleanup_dead"
    );

    let delivered_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbound_queue WHERE id = $1)")
            .bind(&delivered_item_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !delivered_exists,
        "Old delivered row must be purged by worker periodic cleanup_old"
    );

    let pending_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbound_queue WHERE id = $1)")
            .bind(&pending_item_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(pending_exists, "Pending row must be preserved");
}

#[tokio::test]
async fn test_recovery_fulfillment_pending_remote_welcome_creates_typed_outbox_job() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let convo_id = Uuid::new_v4();
    let remote_ds = "did:web:remote.ds.example.com";
    let pending_remote_user = "did:plc:pendingrecip234567abcdef";
    let creator_user = "did:plc:creatoruser234567abcdefg";
    let remote_device = Uuid::new_v4();
    let creator_device = Uuid::new_v4();
    let welcome_id = Uuid::new_v4();
    let recovery_request_id = Uuid::new_v4();
    let key_package_ref = [0x77u8; 32];
    let welcome_bytes = b"encrypted-welcome-payload-for-pending-remote-device";
    let welcome_sha256: [u8; 32] = Sha256::digest(welcome_bytes).into();
    let public_snapshot_sha256 = [0x88u8; 32];
    let tree_summary_sha256 = [0x99u8; 32];

    let mut tx = pool.begin().await.unwrap();

    // 1. Provision conversation
    sqlx::query(
        "INSERT INTO chat.conversations (
            conversation_id, kind, lifecycle, current_generation, current_state_version,
            next_entry_seq, created_at, is_remote, sequencer_ds, sequencer_term
         ) VALUES ($1, 'group', 'active', 1, 1, 3, NOW(), FALSE, NULL, 2)",
    )
    .bind(convo_id)
    .execute(&mut *tx)
    .await
    .unwrap();

    // 2. Provision principals and devices
    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, NOW()), ($2, NOW())",
    )
    .bind(creator_user)
    .bind(pending_remote_user)
    .execute(&mut *tx)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, auth_generation, capabilities, status, created_at, updated_at) \
         VALUES ($1, $2, 'Creator Device', 1, chat.protocol_capabilities(), 'active', NOW(), NOW()), \
                ($3, $4, 'Remote Device', 1, chat.protocol_capabilities(), 'active', NOW(), NOW())",
    )
    .bind(creator_user)
    .bind(creator_device)
    .bind(pending_remote_user)
    .bind(remote_device)
    .execute(&mut *tx)
    .await
    .unwrap();

    // 3. Provision participant in 'pending' status for the remote user
    let pid_creator = Uuid::new_v4();
    let pid_remote = Uuid::new_v4();
    let tid = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO chat.participants (
            participant_period_id, conversation_id, user_did, status, role,
            role_transition_id, role_changed_at, created_by_did, created_by_device_id,
            invitation_transition_id, invitation_entry_id, invited_at,
            current_membership, created_at, ds_did
         ) VALUES (
            $1, $2, $3, 'active', 'admin',
            $4, NOW(), $3, $5,
            NULL, NULL, NULL,
            TRUE, NOW(), NULL
         ), (
            $6, $2, $7, 'pending', 'member',
            $4, NOW(), $3, $5,
            $4, $4, NOW(),
            TRUE, NOW(), $8
         )",
    )
    .bind(pid_creator)
    .bind(convo_id)
    .bind(creator_user)
    .bind(tid)
    .bind(creator_device)
    .bind(pid_remote)
    .bind(pending_remote_user)
    .bind(remote_ds)
    .execute(&mut *tx)
    .await
    .unwrap();

    let entry = AppendEntry {
        conversation_id: convo_id,
        entry_id: Uuid::new_v4(),
        entry_kind: "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry".to_string(),
        accepted_payload_bytes: b"{\"type\":\"leafRecoveryFulfillmentEntry\"}".to_vec(),
        accepted_payload_sha256: Sha256::digest(b"{\"type\":\"leafRecoveryFulfillmentEntry\"}")
            .to_vec(),
        signed_request_bytes: b"{\"type\":\"signed_fulfillment_request\"}".to_vec(),
        request_digest: vec![0x11u8; 32],
        signature: vec![0x22u8; 64],
        server_fields_bytes: vec![],
        outer_entry_fingerprint: vec![0x33u8; 32],
        actor_did: creator_user.to_string(),
        actor_device_id: creator_device,
        actor_key_id: "key-creator-1".to_string(),
        actor_auth_generation: 1,
        generation: Some(1),
        state_version: Some(1),
        transition_id: Some(Uuid::new_v4()),
        message_id: None,
        received_at: Utc::now(),
    };

    let coordinates = ConversationCoordinates {
        conversation_id: jacquard_common::deps::smol_str::SmolStr::from(
            convo_id.hyphenated().to_string(),
        ),
        generation: 1,
        state_version: 1,
        epoch: 1,
        group_id: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x44u8; 32]),
        group_context_hash: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x55u8; 32]),
        confirmation_tag: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x66u8; 32]),
        lifecycle: jacquard_common::deps::smol_str::SmolStr::from("active"),
        extra_data: None,
    };

    // 4. Calling enqueue_federated_welcome_job for pending remote participant MUST succeed and emit outbox job
    let delivery_id = enqueue_federated_welcome_job(
        &mut tx,
        convo_id,
        remote_ds,
        pending_remote_user,
        remote_device,
        welcome_id,
        recovery_request_id,
        &key_package_ref,
        welcome_bytes,
        &welcome_sha256,
        &entry,
        2,
        coordinates,
        &public_snapshot_sha256,
        &tree_summary_sha256,
        2,
    )
    .await
    .expect("pending remote participant must emit welcome job without aborting");

    // 5. Verify the emitted job in federation_outbox within the transaction
    let row: (String, String, String, i32) = sqlx::query_as(
        "SELECT method, target_service_did, status, envelope_version \
         FROM federation_outbox \
         WHERE id = $1",
    )
    .bind(delivery_id.to_string())
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    assert_eq!(row.0, DELIVER_WELCOME_NSID);
    assert_eq!(row.1, remote_ds);
    assert_eq!(row.2, "pending");
    assert_eq!(row.3, 1);

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn test_submit_commit_valid_receipt_marks_delivered_end_to_end_mock() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let peer_did = format!(
        "did:web:sequencer-{}.example.com",
        Uuid::new_v4().as_simple()
    );
    let (signer, _verifying_key, _sk) = test_signer(&peer_did);
    let auth_mw = AuthMiddleware::new();
    cache_peer_did_doc(&auth_mw, &peer_did, &_verifying_key).await;
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, trust_score, created_at, updated_at) \
         VALUES ($1, 'allow', 100, NOW(), NOW())",
    )
    .bind(&peer_did)
    .execute(&pool)
    .await
    .unwrap();

    let item_id = Uuid::new_v4().to_string();
    let convo_id = Uuid::new_v4().to_string();
    let delivery_id = Uuid::parse_str(&item_id).unwrap();
    let conversation_id = Uuid::parse_str(&convo_id).unwrap();

    let entry_id = Uuid::new_v4();
    let source_locator = ValidatedEntryLocator {
        entry_id,
        seq: 1,
        accepted_payload_sha256: Sha256::digest(b"{}").into(),
        outer_entry_fingerprint: [0x66u8; 32],
    };
    seed_genesis_conversation_for_test(&pool, conversation_id, entry_id, &source_locator).await;
    let msg = catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::SubmitCommit::<
        jacquard_common::DefaultStr,
    > {
        header: catbird_atproto::generated::blue_catbird::mlsDS::EnvelopeHeaderV1 {
            protocol_version: jacquard_common::deps::smol_str::SmolStr::from("1"),
            delivery_id: jacquard_common::deps::smol_str::SmolStr::from(item_id.clone()),
            conversation_id: jacquard_common::deps::smol_str::SmolStr::from(convo_id.clone()),
            sender_ds_did: jacquard_common::types::string::Did::new_owned(service_did_base())
                .unwrap(),
            receiver_ds_did: jacquard_common::types::string::Did::new_owned(peer_did.clone())
                .unwrap(),
            sequencer_did: jacquard_common::types::string::Did::new_owned(peer_did.clone())
                .unwrap(),
            sequencer_term: 1,
            payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[42u8; 32]),
            extra_data: None,
        },
        signed_request_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(
            b"signed-commit-request-bytes",
        ),
        extra_data: None,
    };
    let payload = serde_json::to_vec(&msg).unwrap();
    let expected_envelope_digest =
        catbird_server::federation::queue::recompute_envelope_digest_from_payload(
            SUBMIT_COMMIT_NSID,
            &payload,
        )
        .unwrap();

    let b64_32 = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
    let b64_48 = base64::engine::general_purpose::STANDARD.encode([1u8; 48]);
    let b64_12 = base64::engine::general_purpose::STANDARD.encode([1u8; 12]);
    let b64_64 = base64::engine::general_purpose::STANDARD.encode([1u8; 64]);
    let b16 = serde_json::to_string(&vec![1u8; 16]).unwrap();
    let b32_arr = serde_json::to_string(&vec![1u8; 32]).unwrap();

    let entry_id_str = Uuid::new_v4().to_string();
    let st_expected_json = format!(
        r#"{{
        "coordinates": {{
            "confirmationTag": {{"$bytes": "{b64_32}"}},
            "conversationId": "{convo_id}",
            "epoch": 1,
            "generation": 0,
            "groupContextHash": {{"$bytes": "{b64_32}"}},
            "groupId": {{"$bytes": "{b64_32}"}},
            "lifecycle": "active",
            "stateVersion": 1
        }},
        "entry": {{
            "$type": "blue.catbird.chat.defs#commitEntry",
            "conversationId": "{convo_id}",
            "entryId": "{entry_id_str}",
            "receivedAt": "2026-08-25T12:00:00Z",
            "seq": 1,
            "signedRequest": {{
                "body": {{
                    "$type": "blue.catbird.chat.defs#commitTransitionBody",
                    "signatureDomain": "CATBIRD-CHAT-COMMIT\u0000",
                    "transitionId": "{entry_id_str}",
                    "idempotencyKey": "{entry_id_str}",
                    "actorDid": "did:plc:alice",
                    "actorDeviceId": "{entry_id_str}",
                    "keyId": "k-1",
                    "authGeneration": 1,
                    "signedAt": "2026-08-25T12:00:00Z",
                    "conversationId": "{convo_id}",
                    "prior": {{
                        "conversationId": "{convo_id}",
                        "generation": 0,
                        "stateVersion": 0,
                        "groupId": {{"$bytes": "{b64_32}"}},
                        "epoch": 0,
                        "groupContextHash": {{"$bytes": "{b64_32}"}},
                        "confirmationTag": {{"$bytes": "{b64_32}"}},
                        "lifecycle": "active"
                    }},
                    "next": {{
                        "conversationId": "{convo_id}",
                        "generation": 0,
                        "stateVersion": 1,
                        "groupId": {{"$bytes": "{b64_32}"}},
                        "epoch": 1,
                        "groupContextHash": {{"$bytes": "{b64_32}"}},
                        "confirmationTag": {{"$bytes": "{b64_32}"}},
                        "lifecycle": "active"
                    }},
                    "aad": {{
                        "protocolVersion": "1",
                        "conversationId": {b16},
                        "generation": 0,
                        "transitionId": {b16},
                        "prior": {{
                            "conversationId": {b16},
                            "generation": 0,
                            "stateVersion": 0,
                            "groupId": {{"$bytes": "{b64_32}"}},
                            "epoch": 0,
                            "groupContextHash": {{"$bytes": "{b64_32}"}},
                            "confirmationTag": {{"$bytes": "{b64_32}"}},
                            "lifecycle": "active"
                        }}
                    }},
                    "manifest": {{
                        "participantChanges": [],
                        "leafChanges": []
                    }},
                    "commit": {{
                        "framing": "mlsMessage",
                        "contentType": "publicMessageCommit",
                        "bytes": {{"$bytes": "{b64_48}"}},
                        "sha256": {b32_arr}
                    }},
                    "metadataSnapshot": {{
                        "coordinate": {{
                            "conversationId": {b16},
                            "generation": 0,
                            "groupId": {{"$bytes": "{b64_32}"}},
                            "epoch": 1,
                            "groupContextHash": {{"$bytes": "{b64_32}"}},
                            "confirmationTag": {{"$bytes": "{b64_32}"}}
                        }},
                        "originTransitionId": "{entry_id_str}",
                        "metadataVersion": 1,
                        "nonce": {{"$bytes": "{b64_12}"}},
                        "ciphertext": {{"$bytes": "{b64_48}"}},
                        "ciphertextSha256": {b32_arr},
                        "ciphertextSize": 48,
                        "authorProof": {{
                            "authorDid": "did:plc:alice",
                            "authorDeviceId": "{entry_id_str}",
                            "authorKeyId": "k-1",
                            "signaturePublicKey": {{"$bytes": "{b64_32}"}},
                            "authGenerationAtOrigin": 1,
                            "originTransitionId": "{entry_id_str}",
                            "originSeq": 1,
                            "roleAtOrigin": "admin",
                            "deviceStatusAtOrigin": "active"
                        }}
                    }}
                }},
                "signature": {{"$bytes": "{b64_64}"}}
            }}
        }},
        "welcomes": []
    }}"#
    );
    let st_dto: catbird_atproto::generated::blue_catbird::chat::submit_transition::SubmitTransitionOutput =
        serde_json::from_str(&st_expected_json).unwrap();
    let canonical_result_bytes = serde_json::to_vec(&st_dto).unwrap();
    let expected_result_sha256: [u8; 32] = Sha256::digest(&canonical_result_bytes).into();

    let valid_receipt = sign_receipt(
        &signer,
        SUBMIT_COMMIT_NSID,
        delivery_id,
        conversation_id,
        &service_did_base(),
        &peer_did,
        &peer_did,
        1,
        expected_envelope_digest,
        expected_result_sha256,
        source_locator,
        Utc::now(),
    )
    .unwrap();

    let raw_http_response_str = format!(
        r#"{{
        "commitEntry": {{
            "conversationId": "{convo_id}",
            "entryId": "{entry_id_str}",
            "receivedAt": "2026-08-25T12:00:00Z",
            "seq": 1,
            "signedRequest": {{
                "body": {{
                    "$type": "blue.catbird.chat.defs#commitTransitionBody",
                    "signatureDomain": "CATBIRD-CHAT-COMMIT\u0000",
                    "transitionId": "{entry_id_str}",
                    "idempotencyKey": "{entry_id_str}",
                    "actorDid": "did:plc:alice",
                    "actorDeviceId": "{entry_id_str}",
                    "keyId": "k-1",
                    "authGeneration": 1,
                    "signedAt": "2026-08-25T12:00:00Z",
                    "conversationId": "{convo_id}",
                    "prior": {{
                        "conversationId": "{convo_id}",
                        "generation": 0,
                        "stateVersion": 0,
                        "groupId": {{"$bytes": "{b64_32}"}},
                        "epoch": 0,
                        "groupContextHash": {{"$bytes": "{b64_32}"}},
                        "confirmationTag": {{"$bytes": "{b64_32}"}},
                        "lifecycle": "active"
                    }},
                    "next": {{
                        "conversationId": "{convo_id}",
                        "generation": 0,
                        "stateVersion": 1,
                        "groupId": {{"$bytes": "{b64_32}"}},
                        "epoch": 1,
                        "groupContextHash": {{"$bytes": "{b64_32}"}},
                        "confirmationTag": {{"$bytes": "{b64_32}"}},
                        "lifecycle": "active"
                    }},
                    "aad": {{
                        "protocolVersion": "1",
                        "conversationId": {b16},
                        "generation": 0,
                        "transitionId": {b16},
                        "prior": {{
                            "conversationId": {b16},
                            "generation": 0,
                            "stateVersion": 0,
                            "groupId": {{"$bytes": "{b64_32}"}},
                            "epoch": 0,
                            "groupContextHash": {{"$bytes": "{b64_32}"}},
                            "confirmationTag": {{"$bytes": "{b64_32}"}},
                            "lifecycle": "active"
                        }}
                    }},
                    "manifest": {{
                        "participantChanges": [],
                        "leafChanges": []
                    }},
                    "commit": {{
                        "framing": "mlsMessage",
                        "contentType": "publicMessageCommit",
                        "bytes": {{"$bytes": "{b64_48}"}},
                        "sha256": {b32_arr}
                    }},
                    "metadataSnapshot": {{
                        "coordinate": {{
                            "conversationId": {b16},
                            "generation": 0,
                            "groupId": {{"$bytes": "{b64_32}"}},
                            "epoch": 1,
                            "groupContextHash": {{"$bytes": "{b64_32}"}},
                            "confirmationTag": {{"$bytes": "{b64_32}"}}
                        }},
                        "originTransitionId": "{entry_id_str}",
                        "metadataVersion": 1,
                        "nonce": {{"$bytes": "{b64_12}"}},
                        "ciphertext": {{"$bytes": "{b64_48}"}},
                        "ciphertextSha256": {b32_arr},
                        "ciphertextSize": 48,
                        "authorProof": {{
                            "authorDid": "did:plc:alice",
                            "authorDeviceId": "{entry_id_str}",
                            "authorKeyId": "k-1",
                            "signaturePublicKey": {{"$bytes": "{b64_32}"}},
                            "authGenerationAtOrigin": 1,
                            "originTransitionId": "{entry_id_str}",
                            "originSeq": 1,
                            "roleAtOrigin": "admin",
                            "deviceStatusAtOrigin": "active"
                        }}
                    }}
                }},
                "signature": {{"$bytes": "{b64_64}"}}
            }}
        }},
        "coordinates": {{
            "confirmationTag": {{"$bytes": "{b64_32}"}},
            "conversationId": "{convo_id}",
            "epoch": 1,
            "generation": 0,
            "groupContextHash": {{"$bytes": "{b64_32}"}},
            "groupId": {{"$bytes": "{b64_32}"}},
            "lifecycle": "active",
            "stateVersion": 1
        }},
        "receipt": {},
        "welcomes": []
    }}"#,
        serde_json::to_string(&valid_receipt).unwrap()
    );
    let raw_http_bytes = raw_http_response_str.into_bytes();
    let resp_body_bytes = raw_http_bytes.clone();
    let app = axum::Router::new().fallback(axum::routing::post(move |_: axum::body::Bytes| {
        let b = resp_body_bytes.clone();
        async move {
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(b))
                .unwrap()
        }
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resolver = Arc::new(
        DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )
        .with_destination_resolver_hook(Arc::new(move |_endpoint| {
            let port = local_addr.port();
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
                    host: "127.0.0.1".to_string(),
                    addrs: vec![local_addr],
                })
            }))
        })),
    );

    let queue = OutboundQueue::new(pool.clone(), auth_mw, resolver);

    sqlx::query(
        "INSERT INTO outbound_queue (
            id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, max_retries, next_retry_at
         ) VALUES ($1, $2, '', $3, $4, $5, 'pending', 0, 5, NOW() - INTERVAL '1 second')",
    )
    .bind(&item_id)
    .bind(&peer_did)
    .bind(SUBMIT_COMMIT_NSID)
    .bind(&payload)
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();

    let claimed = queue.claim_due_batch(10).await.unwrap();
    assert_eq!(claimed.len(), 1);

    let outbound = OutboundClient::new(2, 2);
    let auth_sign = Arc::new(|_t: &str, _m: &str| Ok("test-token".to_string()));

    queue
        .process_item(&claimed[0], &outbound, auth_sign.as_ref())
        .await;

    // Verify submitCommit was marked delivered because receipt was present & valid
    let (status, last_error): (String, Option<String>) =
        sqlx::query_as("SELECT status, last_error FROM outbound_queue WHERE id = $1")
            .bind(&item_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        status, "delivered",
        "submitCommit with valid receipt must be marked delivered: {last_error:?}"
    );
}

#[tokio::test]
async fn test_outbox_record_failure_with_stale_claim_token_does_not_mutate_reclaimed_or_done_row() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;

    let row_id = Uuid::new_v4().to_string();
    let token_a = Uuid::new_v4();
    let now = Utc::now();

    // 1. Seed an in_flight row with claim_token = token_a
    sqlx::query(
        "INSERT INTO federation_outbox (
            id, conversation_id, target_service_did, method, payload, status,
            claim_token, claim_expires_at, attempts, created_at, updated_at
         ) VALUES ($1, $2, 'did:web:peer.test', 'blue.catbird.mlsDS.deliverMessage', $3, 'in_flight', $4, NOW() - INTERVAL '1 second', 0, $5, $5)",
    )
    .bind(&row_id)
    .bind(Uuid::new_v4().to_string())
    .bind(b"payload-bytes".to_vec())
    .bind(token_a)
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Reclaim the expired in_flight row -> flips back to 'pending' with claim_token = NULL
    let reclaimed = catbird_server::workers::reclaim_stuck_in_flight(&pool, "federation_outbox")
        .await
        .unwrap();
    assert_eq!(reclaimed, 1);

    // 3. Stale worker holding token_a attempts to record failure -> MUST NOT mutate the reclaimed pending row!
    let res = catbird_server::workers::record_failure(
        &pool,
        "federation_outbox",
        &row_id,
        Some(token_a),
        0,
        now,
        "stale-worker-error",
    )
    .await
    .unwrap();
    assert_eq!(res, "stale", "Stale worker call must return 'stale'");

    // 4. Verify the row on disk is still 'pending' with attempts = 0 and last_error is NULL
    let (status, attempts, last_error): (String, i32, Option<String>) =
        sqlx::query_as("SELECT status, attempts, last_error FROM federation_outbox WHERE id = $1")
            .bind(&row_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(status, "pending");
    assert_eq!(attempts, 0);
    assert!(
        last_error.is_none(),
        "Stale worker must not write last_error to reclaimed row"
    );

    // 5. Now mark the row as 'done'
    sqlx::query("UPDATE federation_outbox SET status = 'done' WHERE id = $1")
        .bind(&row_id)
        .execute(&pool)
        .await
        .unwrap();

    // 6. Another stale worker call on the 'done' row -> MUST NOT mutate the 'done' row!
    let res_done = catbird_server::workers::record_failure(
        &pool,
        "federation_outbox",
        &row_id,
        Some(token_a),
        1,
        now,
        "stale-worker-error-2",
    )
    .await
    .unwrap();
    assert_eq!(res_done, "stale");

    let status_after: String =
        sqlx::query_scalar("SELECT status FROM federation_outbox WHERE id = $1")
            .bind(&row_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status_after, "done", "Done row must remain done");
}

#[tokio::test]
async fn test_recomputed_envelope_digest_mismatch_marks_dead_immediately() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let peer_did = format!("did:web:peer-{}.example.com", Uuid::new_v4().as_simple());
    let (signer, _verifying_key, _sk) = test_signer(&peer_did);
    let auth_mw = AuthMiddleware::new();
    cache_peer_did_doc(&auth_mw, &peer_did, &_verifying_key).await;
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, trust_score, created_at, updated_at) \
         VALUES ($1, 'allow', 100, NOW(), NOW())",
    )
    .bind(&peer_did)
    .execute(&pool)
    .await
    .unwrap();

    let item_id = Uuid::new_v4().to_string();
    let convo_id = Uuid::new_v4().to_string();
    let delivery_id = Uuid::parse_str(&item_id).unwrap();
    let conversation_id = Uuid::parse_str(&convo_id).unwrap();

    let source_locator = ValidatedEntryLocator {
        entry_id: Uuid::new_v4(),
        seq: 1,
        accepted_payload_sha256: [1u8; 32],
        outer_entry_fingerprint: [2u8; 32],
    };

    let msg = catbird_atproto::generated::blue_catbird::mlsDS::deliver_message::DeliverMessage::<
        jacquard_common::DefaultStr,
    > {
        header: catbird_atproto::generated::blue_catbird::mlsDS::EnvelopeHeaderV1 {
            protocol_version: jacquard_common::deps::smol_str::SmolStr::from("1"),
            delivery_id: jacquard_common::deps::smol_str::SmolStr::from(item_id.clone()),
            conversation_id: jacquard_common::deps::smol_str::SmolStr::from(convo_id.clone()),
            sender_ds_did: jacquard_common::types::string::Did::new_owned(service_did_base())
                .unwrap(),
            receiver_ds_did: jacquard_common::types::string::Did::new_owned(peer_did.clone())
                .unwrap(),
            sequencer_did: jacquard_common::types::string::Did::new_owned(service_did_base())
                .unwrap(),
            sequencer_term: 1,
            payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[42u8; 32]),
            extra_data: None,
        },
        recipient_did: jacquard_common::types::string::Did::new_owned(
            "did:plc:ragtjsm2j2vknwk6zpkrhgah".to_string(),
        )
        .unwrap(),
        entry_locator: catbird_atproto::generated::blue_catbird::mlsDS::EntryLocatorV1 {
            entry_id: jacquard_common::deps::smol_str::SmolStr::from(
                source_locator.entry_id.to_string(),
            ),
            seq: source_locator.seq as i64,
            accepted_payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                &source_locator.accepted_payload_sha256,
            ),
            outer_entry_fingerprint: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                &source_locator.outer_entry_fingerprint,
            ),
            extra_data: None,
        },
        entry_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(b"sample-entry-bytes"),
        signed_request_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(
            b"sample-signed-request-bytes",
        ),
        extra_data: None,
    };
    let payload = serde_json::to_vec(&msg).unwrap();

    // Sign a receipt with a FORGED / MISMATCHED envelope_sha256
    let forged_envelope_digest = [0xEEu8; 32];
    let forged_receipt = sign_receipt(
        &signer,
        DELIVER_MESSAGE_NSID,
        delivery_id,
        conversation_id,
        &service_did_base(),
        &peer_did,
        &service_did_base(),
        1,
        forged_envelope_digest,
        [99u8; 32],
        source_locator,
        Utc::now(),
    )
    .unwrap();

    let raw_http_response = serde_json::json!({
        "accepted": true,
        "receipt": forged_receipt,
    });
    let raw_http_bytes = serde_json::to_vec(&raw_http_response).unwrap();

    let resp_body_bytes = raw_http_bytes.clone();
    let app = axum::Router::new().fallback(axum::routing::post(move |_: axum::body::Bytes| {
        let b = resp_body_bytes.clone();
        async move {
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(b))
                .unwrap()
        }
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resolver = Arc::new(
        DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )
        .with_destination_resolver_hook(Arc::new(move |_endpoint| {
            let port = local_addr.port();
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
                    host: "127.0.0.1".to_string(),
                    addrs: vec![local_addr],
                })
            }))
        })),
    );

    let queue = OutboundQueue::new(pool.clone(), auth_mw, resolver);

    sqlx::query(
        "INSERT INTO outbound_queue (
            id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, max_retries, next_retry_at
         ) VALUES ($1, $2, '', $3, $4, $5, 'pending', 0, 5, NOW() - INTERVAL '1 second')",
    )
    .bind(&item_id)
    .bind(&peer_did)
    .bind(DELIVER_MESSAGE_NSID)
    .bind(&payload)
    .bind(&convo_id)
    .execute(&pool)
    .await
    .unwrap();

    let claimed = queue.claim_due_batch(10).await.unwrap();
    assert_eq!(claimed.len(), 1);

    let outbound = OutboundClient::new(2, 2);
    let auth_sign = Arc::new(|_t: &str, _m: &str| Ok("test-token".to_string()));

    queue
        .process_item(&claimed[0], &outbound, auth_sign.as_ref())
        .await;

    // Envelope digest mismatch must immediately transition to 'dead' without retry
    let (status, last_error): (String, Option<String>) =
        sqlx::query_as("SELECT status, last_error FROM outbound_queue WHERE id = $1")
            .bind(&item_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(status, "dead");
    assert!(last_error.unwrap().contains("envelope_sha256 mismatch"));
}

#[tokio::test]
async fn test_store_federation_receipt_db_conflict_exact_compares_digest_and_bytes() {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;

    let peer_did = "did:web:peer.example.com";
    let (signer, _vk, _sk) = test_signer(peer_did);

    let delivery_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();

    let entry_id = Uuid::new_v4();
    let source_locator = ValidatedEntryLocator {
        entry_id,
        seq: 1,
        accepted_payload_sha256: Sha256::digest(b"{}").into(),
        outer_entry_fingerprint: [2u8; 32],
    };
    seed_genesis_conversation_for_test(&pool, conversation_id, entry_id, &source_locator).await;

    let receipt = sign_receipt(
        &signer,
        DELIVER_MESSAGE_NSID,
        delivery_id,
        conversation_id,
        &service_did_base(),
        peer_did,
        &service_did_base(),
        1,
        [0x11u8; 32],
        [0x22u8; 32],
        source_locator.clone(),
        Utc::now(),
    )
    .unwrap();

    let response_bytes = b"{\"accepted\":true,\"test\":123}".to_vec();

    // 1. Initial insert succeeds
    catbird_server::federation::queue::store_federation_receipt(&pool, &receipt, &response_bytes)
        .await
        .expect("initial store must succeed");

    // 2. Identical replay succeeds
    catbird_server::federation::queue::store_federation_receipt(&pool, &receipt, &response_bytes)
        .await
        .expect("identical replay must succeed without error");

    // 3. Conflicting response bytes must fail with Protocol error, not silently do nothing
    let conflicting_response_bytes = b"{\"accepted\":true,\"test\":999}".to_vec();
    let err = catbird_server::federation::queue::store_federation_receipt(
        &pool,
        &receipt,
        &conflicting_response_bytes,
    )
    .await
    .expect_err("conflicting response bytes must error");

    assert!(err.to_string().contains("Receipt conflict"));

    // 4. Conflicting envelope digest in receipt must fail with Protocol error
    let mut conflicting_receipt = receipt.clone();
    conflicting_receipt.envelope_sha256 =
        jacquard_common::deps::bytes::Bytes::copy_from_slice(&[0x99u8; 32]);
    let err_envelope = catbird_server::federation::queue::store_federation_receipt(
        &pool,
        &conflicting_receipt,
        &response_bytes,
    )
    .await
    .expect_err("conflicting envelope digest must error");

    assert!(err_envelope.to_string().contains("Receipt conflict"));
}
async fn assert_wrong_result_sha256_marks_queue_item_dead(
    method: &str,
    item_id: &str,
    convo_id: &str,
    peer_did: &str,
    verifying_key: &p256::ecdsa::VerifyingKey,
    payload: Vec<u8>,
    raw_http_bytes: Vec<u8>,
) {
    let (pool, _guard) = fresh_legacy_pool(DB_PREFIX, 4, 1).await;
    ensure_federation_peers_table(&pool).await;

    let delivery_id = Uuid::parse_str(item_id).unwrap();
    let auth_mw = AuthMiddleware::new();
    cache_peer_did_doc(&auth_mw, peer_did, verifying_key).await;
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, trust_score, created_at, updated_at)          VALUES ($1, 'allow', 100, NOW(), NOW())",
    )
    .bind(peer_did)
    .execute(&pool)
    .await
    .unwrap();

    let resp_body_bytes = raw_http_bytes.clone();
    let app = axum::Router::new().fallback(axum::routing::post(move |_: axum::body::Bytes| {
        let b = resp_body_bytes.clone();
        async move {
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(b))
                .unwrap()
        }
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resolver = Arc::new(
        DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        )
        .with_destination_resolver_hook(Arc::new(move |_endpoint| {
            let port = local_addr.port();
            Some(Box::pin(async move {
                Ok(ValidatedRemoteDestination {
                    url: url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
                    host: "127.0.0.1".to_string(),
                    addrs: vec![local_addr],
                })
            }))
        })),
    );

    let queue = OutboundQueue::new(pool.clone(), auth_mw, resolver);

    sqlx::query(
        "INSERT INTO outbound_queue (
            id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, max_retries, next_retry_at
         ) VALUES ($1, $2, '', $3, $4, $5, 'pending', 0, 5, NOW() - INTERVAL '1 second')",
    )
    .bind(item_id)
    .bind(peer_did)
    .bind(method)
    .bind(&payload)
    .bind(convo_id)
    .execute(&pool)
    .await
    .unwrap();

    let claimed = queue.claim_due_batch(10).await.unwrap();
    assert_eq!(claimed.len(), 1);

    let outbound = OutboundClient::new(2, 2);
    let auth_sign = Arc::new(|_t: &str, _m: &str| Ok("test-token".to_string()));

    queue
        .process_item(&claimed[0], &outbound, auth_sign.as_ref())
        .await;

    let (status, last_error): (String, Option<String>) =
        sqlx::query_as("SELECT status, last_error FROM outbound_queue WHERE id = $1")
            .bind(item_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(
        status, "dead",
        "{method} with wrong result_sha256 must mark dead immediately"
    );
    let err_str = last_error.unwrap_or_default();
    assert!(
        err_str.contains("result_sha256 mismatch"),
        "expected result_sha256 mismatch, got: {err_str}"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.federation_delivery_receipts WHERE delivery_id = $1",
    )
    .bind(delivery_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        count, 0,
        "No receipt must be persisted for hostile wrong result hash on {method}"
    );
}

#[tokio::test]
async fn test_outbound_queue_valid_signed_receipt_wrong_result_sha256_deliver_welcome_is_permanent_dead(
) {
    std::env::set_var("SERVICE_DID", LOCAL_SERVICE_DID);
    let item_id = Uuid::new_v4().to_string();
    let convo_id = Uuid::new_v4().to_string();
    let delivery_id = Uuid::parse_str(&item_id).unwrap();
    let convo_uuid = Uuid::parse_str(&convo_id).unwrap();
    let peer_did = format!(
        "did:web:peer-welcome-{}.example.com",
        Uuid::new_v4().as_simple()
    );
    let (signer, verifying_key, _) = test_signer(&peer_did);

    let source_locator = ValidatedEntryLocator {
        entry_id: Uuid::new_v4(),
        seq: 1,
        accepted_payload_sha256: [1u8; 32],
        outer_entry_fingerprint: [2u8; 32],
    };

    let msg = catbird_atproto::generated::blue_catbird::mlsDS::deliver_welcome::DeliverWelcome::<
        jacquard_common::DefaultStr,
    > {
        header: catbird_atproto::generated::blue_catbird::mlsDS::EnvelopeHeaderV1 {
            protocol_version: "1".into(),
            delivery_id: delivery_id.to_string().into(),
            conversation_id: convo_id.clone().into(),
            sender_ds_did: service_did_base().into(),
            receiver_ds_did: peer_did.clone().into(),
            sequencer_did: service_did_base().into(),
            sequencer_term: 1,
            payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[42u8; 32]),
            extra_data: None,
        },
        recipient_did: jacquard_common::types::string::Did::new_owned(
            "did:plc:ragtjsm2j2vknwk6zpkrhgah".to_string(),
        )
        .unwrap(),
        recipient_device_id: Uuid::new_v4().to_string().into(),
        recovery_request_id: Uuid::new_v4().to_string().into(),
        coordinates: catbird_atproto::generated::blue_catbird::chat::ConversationCoordinates {
            conversation_id: convo_id.clone().into(),
            epoch: 1,
            generation: 0,
            state_version: 1,
            lifecycle: "active".into(),
            group_id: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[1u8; 32]),
            group_context_hash: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[2u8; 32]),
            confirmation_tag: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[3u8; 32]),
            extra_data: None,
        },
        welcome_id: Uuid::new_v4().to_string().into(),
        welcome_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(b"welcome"),
        welcome_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&Sha256::digest(
            b"welcome",
        )),
        key_package_ref: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[11u8; 32]),
        tree_summary_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[12u8; 32]),
        public_snapshot_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[13u8; 32]),
        entry_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(b"sample-entry-bytes"),
        signed_request_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(
            b"sample-signed-request-bytes",
        ),
        entry_locator: catbird_atproto::generated::blue_catbird::mlsDS::EntryLocatorV1 {
            entry_id: jacquard_common::deps::smol_str::SmolStr::from(
                source_locator.entry_id.to_string(),
            ),
            seq: source_locator.seq as i64,
            accepted_payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                &source_locator.accepted_payload_sha256,
            ),
            outer_entry_fingerprint: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                &source_locator.outer_entry_fingerprint,
            ),
            extra_data: None,
        },
        extra_data: None,
    };
    let payload = serde_json::to_vec(&msg).unwrap();
    let envelope_digest =
        catbird_server::federation::queue::recompute_envelope_digest_from_payload(
            DELIVER_WELCOME_NSID,
            &payload,
        )
        .unwrap();

    let wrong_result_sha256 = [0xeeu8; 32];
    let wrong_receipt = sign_receipt(
        &signer,
        DELIVER_WELCOME_NSID,
        delivery_id,
        convo_uuid,
        &service_did_base(),
        &peer_did,
        &service_did_base(),
        1,
        envelope_digest,
        wrong_result_sha256,
        source_locator,
        Utc::now(),
    )
    .unwrap();

    let raw_http_response = serde_json::json!({
        "accepted": true,
        "receipt": wrong_receipt,
    });
    let raw_http_bytes = serde_json::to_vec(&raw_http_response).unwrap();

    assert_wrong_result_sha256_marks_queue_item_dead(
        DELIVER_WELCOME_NSID,
        &item_id,
        &convo_id,
        &peer_did,
        &verifying_key,
        payload,
        raw_http_bytes,
    )
    .await;
}

#[tokio::test]
async fn test_outbound_queue_valid_signed_receipt_wrong_result_sha256_deliver_message_is_permanent_dead(
) {
    std::env::set_var("SERVICE_DID", LOCAL_SERVICE_DID);
    let item_id = Uuid::new_v4().to_string();
    let convo_id = Uuid::new_v4().to_string();
    let delivery_id = Uuid::parse_str(&item_id).unwrap();
    let convo_uuid = Uuid::parse_str(&convo_id).unwrap();
    let peer_did = format!(
        "did:web:peer-msg-{}.example.com",
        Uuid::new_v4().as_simple()
    );
    let (signer, verifying_key, _) = test_signer(&peer_did);

    let source_locator = ValidatedEntryLocator {
        entry_id: Uuid::new_v4(),
        seq: 1,
        accepted_payload_sha256: [1u8; 32],
        outer_entry_fingerprint: [2u8; 32],
    };

    let msg = catbird_atproto::generated::blue_catbird::mlsDS::deliver_message::DeliverMessage::<
        jacquard_common::DefaultStr,
    > {
        header: catbird_atproto::generated::blue_catbird::mlsDS::EnvelopeHeaderV1 {
            protocol_version: "1".into(),
            delivery_id: delivery_id.to_string().into(),
            conversation_id: convo_id.clone().into(),
            sender_ds_did: service_did_base().into(),
            receiver_ds_did: peer_did.clone().into(),
            sequencer_did: service_did_base().into(),
            sequencer_term: 1,
            payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[42u8; 32]),
            extra_data: None,
        },
        recipient_did: jacquard_common::types::string::Did::new_owned(
            "did:plc:ragtjsm2j2vknwk6zpkrhgah".to_string(),
        )
        .unwrap(),
        entry_locator: catbird_atproto::generated::blue_catbird::mlsDS::EntryLocatorV1 {
            entry_id: jacquard_common::deps::smol_str::SmolStr::from(
                source_locator.entry_id.to_string(),
            ),
            seq: source_locator.seq as i64,
            accepted_payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                &source_locator.accepted_payload_sha256,
            ),
            outer_entry_fingerprint: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                &source_locator.outer_entry_fingerprint,
            ),
            extra_data: None,
        },
        entry_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(b"sample-entry-bytes"),
        signed_request_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(
            b"sample-signed-request-bytes",
        ),
        extra_data: None,
    };
    let payload = serde_json::to_vec(&msg).unwrap();
    let envelope_digest =
        catbird_server::federation::queue::recompute_envelope_digest_from_payload(
            DELIVER_MESSAGE_NSID,
            &payload,
        )
        .unwrap();

    let wrong_result_sha256 = [0xeeu8; 32];
    let wrong_receipt = sign_receipt(
        &signer,
        DELIVER_MESSAGE_NSID,
        delivery_id,
        convo_uuid,
        &service_did_base(),
        &peer_did,
        &service_did_base(),
        1,
        envelope_digest,
        wrong_result_sha256,
        source_locator,
        Utc::now(),
    )
    .unwrap();

    let raw_http_response = serde_json::json!({
        "accepted": true,
        "receipt": wrong_receipt,
    });
    let raw_http_bytes = serde_json::to_vec(&raw_http_response).unwrap();

    assert_wrong_result_sha256_marks_queue_item_dead(
        DELIVER_MESSAGE_NSID,
        &item_id,
        &convo_id,
        &peer_did,
        &verifying_key,
        payload,
        raw_http_bytes,
    )
    .await;
}

#[tokio::test]
async fn test_outbound_queue_valid_signed_receipt_wrong_result_sha256_submit_commit_is_permanent_dead(
) {
    std::env::set_var("SERVICE_DID", LOCAL_SERVICE_DID);
    let item_id = Uuid::new_v4().to_string();
    let convo_id = Uuid::new_v4().to_string();
    let delivery_id = Uuid::parse_str(&item_id).unwrap();
    let convo_uuid = Uuid::parse_str(&convo_id).unwrap();
    let peer_did = format!(
        "did:web:peer-commit-{}.example.com",
        Uuid::new_v4().as_simple()
    );
    let (signer, verifying_key, _) = test_signer(&peer_did);

    let source_locator = ValidatedEntryLocator {
        entry_id: Uuid::new_v4(),
        seq: 1,
        accepted_payload_sha256: [1u8; 32],
        outer_entry_fingerprint: [2u8; 32],
    };

    let msg = catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::SubmitCommit::<
        jacquard_common::DefaultStr,
    > {
        header: catbird_atproto::generated::blue_catbird::mlsDS::EnvelopeHeaderV1 {
            protocol_version: "1".into(),
            delivery_id: delivery_id.to_string().into(),
            conversation_id: convo_id.clone().into(),
            sender_ds_did: service_did_base().into(),
            receiver_ds_did: peer_did.clone().into(),
            sequencer_did: peer_did.clone().into(),
            sequencer_term: 1,
            payload_sha256: jacquard_common::deps::bytes::Bytes::copy_from_slice(&[42u8; 32]),
            extra_data: None,
        },
        signed_request_bytes: jacquard_common::deps::bytes::Bytes::copy_from_slice(
            b"fake-signed-request",
        ),
        extra_data: None,
    };
    let payload = serde_json::to_vec(&msg).unwrap();
    let envelope_digest =
        catbird_server::federation::queue::recompute_envelope_digest_from_payload(
            SUBMIT_COMMIT_NSID,
            &payload,
        )
        .unwrap();

    let wrong_result_sha256 = [0xeeu8; 32];
    let wrong_receipt = sign_receipt(
        &signer,
        SUBMIT_COMMIT_NSID,
        delivery_id,
        convo_uuid,
        &service_did_base(),
        &peer_did,
        &peer_did,
        1,
        envelope_digest,
        wrong_result_sha256,
        source_locator,
        Utc::now(),
    )
    .unwrap();

    let b64_32 = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
    let b64_48 = base64::engine::general_purpose::STANDARD.encode([1u8; 48]);
    let b64_12 = base64::engine::general_purpose::STANDARD.encode([1u8; 12]);
    let b64_64 = base64::engine::general_purpose::STANDARD.encode([1u8; 64]);
    let b16 = serde_json::to_string(&vec![1u8; 16]).unwrap();
    let b32_arr = serde_json::to_string(&vec![1u8; 32]).unwrap();

    let json_str = format!(
        r#"{{"commitEntry":{{"conversationId":"{convo_id}","entryId":"{item_id}","receivedAt":"2026-08-25T12:00:00Z","seq":1,"signedRequest":{{"body":{{"$type":"blue.catbird.chat.defs#commitTransitionBody","signatureDomain":"CATBIRD-CHAT-COMMIT\u0000","transitionId":"{item_id}","idempotencyKey":"{item_id}","actorDid":"did:plc:alice","actorDeviceId":"{item_id}","keyId":"k-1","authGeneration":1,"signedAt":"2026-08-25T12:00:00Z","conversationId":"{convo_id}","prior":{{"conversationId":"{convo_id}","generation":0,"stateVersion":0,"groupId":{{"$bytes":"{b64_32}"}},"epoch":0,"groupContextHash":{{"$bytes":"{b64_32}"}},"confirmationTag":{{"$bytes":"{b64_32}"}},"lifecycle":"active"}},"next":{{"conversationId":"{convo_id}","generation":0,"stateVersion":1,"groupId":{{"$bytes":"{b64_32}"}},"epoch":1,"groupContextHash":{{"$bytes":"{b64_32}"}},"confirmationTag":{{"$bytes":"{b64_32}"}},"lifecycle":"active"}},"aad":{{"protocolVersion":"1","conversationId":{b16},"generation":0,"transitionId":{b16},"prior":{{"conversationId":{b16},"generation":0,"stateVersion":0,"groupId":{{"$bytes":"{b64_32}"}},"epoch":0,"groupContextHash":{{"$bytes":"{b64_32}"}},"confirmationTag":{{"$bytes":"{b64_32}"}},"lifecycle":"active"}}}},"manifest":{{"participantChanges":[],"leafChanges":[]}},"commit":{{"framing":"mlsMessage","contentType":"publicMessageCommit","bytes":{{"$bytes":"{b64_48}"}},"sha256":{b32_arr}}},"metadataSnapshot":{{"coordinate":{{"conversationId":{b16},"generation":0,"groupId":{{"$bytes":"{b64_32}"}},"epoch":1,"groupContextHash":{{"$bytes":"{b64_32}"}},"confirmationTag":{{"$bytes":"{b64_32}"}}}},"originTransitionId":"{item_id}","metadataVersion":1,"nonce":{{"$bytes":"{b64_12}"}},"ciphertext":{{"$bytes":"{b64_48}"}},"ciphertextSha256":{b32_arr},"ciphertextSize":48,"authorProof":{{"authorDid":"did:plc:alice","authorDeviceId":"{item_id}","authorKeyId":"k-1","signaturePublicKey":{{"$bytes":"{b64_32}"}},"authGenerationAtOrigin":1,"originTransitionId":"{item_id}","originSeq":1,"roleAtOrigin":"admin","deviceStatusAtOrigin":"active"}}}}}},"signature":{{"$bytes":"{b64_64}"}}}}}},"coordinates":{{"confirmationTag":{{"$bytes":"{b64_32}"}},"conversationId":"{convo_id}","epoch":1,"generation":0,"groupContextHash":{{"$bytes":"{b64_32}"}},"groupId":{{"$bytes":"{b64_32}"}},"lifecycle":"active","stateVersion":1}},"receipt":{},"welcomes":[]}}"#,
        serde_json::to_string(&wrong_receipt).unwrap()
    );
    let raw_http_bytes = json_str.into_bytes();

    assert_wrong_result_sha256_marks_queue_item_dead(
        SUBMIT_COMMIT_NSID,
        &item_id,
        &convo_id,
        &peer_did,
        &verifying_key,
        payload,
        raw_http_bytes,
    )
    .await;
}
