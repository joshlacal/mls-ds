//! Subscription-ticket mint + one-use consume tests (Task 2, Slice 4c).
//!
//! Unlike the Welcome chain, an inventory session and its ticket bind only to a
//! device — no roster/Welcome coherence — so the full mint/consume path is
//! exercised against the live schema here. A session is seeded COMPLETE in all
//! three shared domains with zero materialized items: the materialization
//! trigger accepts a complete-with-zero domain when `count = 0` and the domain
//! hash equals `SHA256("")`, so no item rows are needed.
//!
//! Run with:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_ticket -- --include-ignored --test-threads=1

#![allow(dead_code)]

mod common;

mod repository {
    pub(crate) mod ticket {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/ticket.rs"
        ));
    }
}

#[test]
fn ticket_repository_uses_only_g7_hash_and_sealed_columns() {
    let source = include_str!("../src/chat_protocol/repository/ticket.rs");
    assert!(!source.contains(concat!("snapshot_event_cursor_", "bytes")));
    assert!(!source.contains(concat!("event_cursor_", "bytes")));
    for required in [
        "token_hash = $1",
        "snapshot_event_cursor_sha256 = $1",
        "event_cursor_sha256",
        "protocol_instance_id",
        "cursor_key_id",
        "snapshot_retained_floor",
        "chat.event_cursor_receipts",
        "cursor_nonce",
        "cursor_ciphertext",
        "FOR UPDATE\"#",
        "device.device_id = ticket.device_id",
    ] {
        assert!(
            source.contains(required),
            "missing G7 repository fragment: {required}"
        );
    }
}

#[test]
fn g7_event_receipts_are_immutable_and_single_use_by_hash() {
    let migration = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/20260729000001_chat_g7_inventory_entitlement.sql"
    ))
    .expect("read G7 migration");
    assert!(migration.contains("cursor_hash BYTEA PRIMARY KEY"));
    assert!(migration.contains("CREATE TRIGGER event_cursor_receipts_immutable"));
    assert!(migration.contains("cursor_nonce BYTEA NOT NULL"));
    assert!(migration.contains("cursor_ciphertext BYTEA NOT NULL"));
}

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Barrier;
use tokio::time::{sleep, Duration as TokioDuration};
use uuid::Uuid;

use repository::ticket::{
    consume_subscription_ticket, mint_subscription_ticket, ticket_hash, MintSubscriptionTicket,
    TicketRepositoryError, SUBSCRIBE_EVENTS_PATH,
};

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

fn fresh_blob() -> Vec<u8> {
    let mut b = Uuid::new_v4().as_bytes().to_vec();
    b.extend_from_slice(Uuid::new_v4().as_bytes());
    b
}

struct DeviceFixture {
    did: String,
    device_id: Uuid,
    jkt: String,
    auth_generation: i64,
}

/// Seed an active device whose `dpop_jkt` is a valid 43-char base64url string.
async fn seed_device(pool: &PgPool, at: DateTime<Utc>) -> DeviceFixture {
    let did = random_plc_did();
    let device_id = Uuid::new_v4();
    let jkt: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(fresh_blob())
        .fetch_one(pool)
        .await
        .expect("derive jkt");
    let public_key = fresh_blob();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&public_key)
        .fetch_one(pool)
        .await
        .expect("derive key id");

    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(&did)
        .bind(at)
        .execute(pool)
        .await
        .expect("insert principal");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'ticket-device','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(&did)
    .bind(device_id)
    .bind(&jkt)
    .bind(at)
    .execute(pool)
    .await
    .expect("insert device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(&did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&public_key)
    .bind(at)
    .execute(pool)
    .await
    .expect("insert device key");

    DeviceFixture {
        did,
        device_id,
        jkt,
        auth_generation: 1,
    }
}

struct SessionFixture {
    inventory_session_id: Uuid,
    snapshot_event_position: i64,
    capability: String,
    capability_hash: Vec<u8>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Seed one inventory session. When `complete` is true all three shared domains
/// are marked complete with zero materialized items (count 0, hash SHA256("")).
async fn seed_session(
    pool: &PgPool,
    device: &DeviceFixture,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    complete: bool,
) -> SessionFixture {
    let inventory_session_id = Uuid::new_v4();
    let capability_bytes = fresh_blob();
    let capability = URL_SAFE_NO_PAD.encode(&capability_bytes);
    let capability_hash = Sha256::digest(&capability_bytes).to_vec();
    let empty_hash = Sha256::digest([]).to_vec();
    let snapshot_event_position: i64 = 42;

    // Completion evidence is all-or-nothing per domain; a complete-with-zero
    // domain carries count 0 and the empty-string SHA-256.
    let (conv_count, conv_hash, wel_count, wel_hash, rec_count, rec_hash): (
        Option<i64>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<Vec<u8>>,
    ) = if complete {
        (
            Some(0),
            Some(empty_hash.clone()),
            Some(0),
            Some(empty_hash.clone()),
            Some(0),
            Some(empty_hash.clone()),
        )
    } else {
        (None, None, None, None, None, None)
    };

    let (protocol_instance_id, cursor_key_id, retained_floor): (Uuid, String, i64) =
        sqlx::query_as(
            "SELECT protocol_instance_id, cursor_key_id, retained_floor FROM chat.protocol_instances JOIN chat.event_retention USING (protocol_instance_id) WHERE singleton = TRUE",
        )
        .fetch_one(pool)
        .await
        .expect("read protocol fence");
    sqlx::query(
        r#"
        INSERT INTO chat.inventory_sessions(
            inventory_session_id, token_hash, user_did, device_id, jkt, auth_generation,
            snapshot_event_position, snapshot_event_cursor_sha256, created_at, expires_at,
            protocol_instance_id, cursor_key_id, cursor_format_version, snapshot_retained_floor,
            snapshot_event_cursor_nonce, snapshot_event_cursor_ciphertext,
            conversations_complete, welcomes_complete, recovery_complete,
            conversation_item_count, conversation_items_sha256,
            welcome_item_count, welcome_items_sha256,
            recovery_item_count, recovery_items_sha256,
            conversation_payload_bytes, welcome_payload_bytes, recovery_payload_bytes,
            conversations_consumed, welcomes_consumed, recovery_consumed,
            conversations_consumed_at, welcomes_consumed_at, recovery_consumed_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,$13,$14,$15,$16,$16,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31)
        "#,
    )
    .bind(inventory_session_id)
    .bind(&capability_hash)
    .bind(&device.did)
    .bind(device.device_id)
    .bind(&device.jkt)
    .bind(device.auth_generation)
    .bind(snapshot_event_position)
    .bind(&capability_hash)
    .bind(created_at)
    .bind(expires_at)
    .bind(protocol_instance_id)
    .bind(&cursor_key_id)
    .bind(retained_floor)
    .bind([7u8; 12].as_slice())
    .bind([9u8; 32].as_slice())
    .bind(complete)
    .bind(conv_count)
    .bind(conv_hash)
    .bind(wel_count)
    .bind(wel_hash)
    .bind(rec_count)
    .bind(rec_hash)
    .bind(if complete { Some(0_i64) } else { None })
    .bind(if complete { Some(0_i64) } else { None })
    .bind(if complete { Some(0_i64) } else { None })
    .bind(complete)
    .bind(complete)
    .bind(complete)
    .bind(if complete { Some(created_at) } else { None })
    .bind(if complete { Some(created_at) } else { None })
    .bind(if complete { Some(created_at) } else { None })
    .execute(pool)
    .await
    .expect("insert inventory session");

    SessionFixture {
        inventory_session_id,
        snapshot_event_position,
        capability,
        capability_hash,
        created_at,
        expires_at,
    }
}

fn mint_request(
    device: &DeviceFixture,
    session: &SessionFixture,
    opaque_ticket: &[u8],
    capability: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> MintSubscriptionTicket {
    MintSubscriptionTicket {
        ticket_hash: ticket_hash(opaque_ticket).to_vec(),
        user_did: device.did.clone(),
        device_id: device.device_id,
        jkt: device.jkt.clone(),
        auth_generation: device.auth_generation,
        inventory_session_id: session.capability.clone(),
        event_cursor: capability,
        subscription_path: SUBSCRIBE_EVENTS_PATH.to_owned(),
        created_at,
        expires_at,
    }
}

#[tokio::test]
async fn mint_binds_the_session_fence_and_ticket_is_consumable_once() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let now = clock_now(&pool).await;
    let device = seed_device(&pool, now - Duration::seconds(200)).await;
    let session = seed_session(
        &pool,
        &device,
        now - Duration::seconds(10),
        now + Duration::minutes(10),
        true,
    )
    .await;

    let opaque = fresh_blob();
    let request = mint_request(
        &device,
        &session,
        &opaque,
        session.capability.clone(),
        now,
        now + Duration::seconds(60),
    );

    let mut tx = pool.begin().await.expect("begin mint");
    let minted = mint_subscription_ticket(&mut tx, &request)
        .await
        .expect("mint succeeds on a complete session with a byte-equal cursor");
    tx.commit()
        .await
        .expect("mint COMMIT past deferred binding");
    assert_eq!(minted.event_position, session.snapshot_event_position);
    assert_eq!(
        minted.event_cursor_hash.as_slice(),
        session.capability_hash.as_slice()
    );

    // Consume once — succeeds and returns the continuation fence.
    let mut c1 = pool.begin().await.expect("begin consume 1");
    let consumed = consume_subscription_ticket(
        &mut c1,
        &ticket_hash(&opaque),
        &session.capability,
        SUBSCRIBE_EVENTS_PATH,
        clock_now(&pool).await,
    )
    .await
    .expect("first consume wins");
    assert_eq!(consumed.event_position, session.snapshot_event_position);
    assert_eq!(consumed.inventory_session_id, session.inventory_session_id);
    c1.commit().await.expect("commit consume 1");

    // Consume again — one-use, so the second attempt loses.
    let mut c2 = pool.begin().await.expect("begin consume 2");
    let again = consume_subscription_ticket(
        &mut c2,
        &ticket_hash(&opaque),
        &session.capability,
        SUBSCRIBE_EVENTS_PATH,
        clock_now(&pool).await,
    )
    .await;
    assert!(
        matches!(again, Err(TicketRepositoryError::TicketAlreadyConsumed)),
        "a second consume of a one-use ticket must lose, got {again:?}"
    );
    c2.rollback().await.expect("rollback consume 2");
}

#[tokio::test]
async fn mint_rejects_incomplete_session() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let now = clock_now(&pool).await;
    let device = seed_device(&pool, now - Duration::seconds(200)).await;
    let session = seed_session(
        &pool,
        &device,
        now - Duration::seconds(10),
        now + Duration::minutes(10),
        false,
    )
    .await;

    let opaque = fresh_blob();
    let request = mint_request(
        &device,
        &session,
        &opaque,
        session.capability.clone(),
        now,
        now + Duration::seconds(60),
    );
    let mut tx = pool.begin().await.expect("begin mint");
    let result = mint_subscription_ticket(&mut tx, &request).await;
    assert!(
        matches!(result, Err(TicketRepositoryError::SessionIncomplete)),
        "mint must reject an incomplete session, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn mint_rejects_cursor_that_does_not_match_the_session() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let now = clock_now(&pool).await;
    let device = seed_device(&pool, now - Duration::seconds(200)).await;
    let session = seed_session(
        &pool,
        &device,
        now - Duration::seconds(10),
        now + Duration::minutes(10),
        true,
    )
    .await;

    let opaque = fresh_blob();
    let request = mint_request(
        &device,
        &session,
        &opaque,
        URL_SAFE_NO_PAD.encode([8u8; 32]),
        now,
        now + Duration::seconds(60),
    );
    let mut tx = pool.begin().await.expect("begin mint");
    let result = mint_subscription_ticket(&mut tx, &request).await;
    assert!(
        matches!(result, Err(TicketRepositoryError::CapabilityMismatch)),
        "mint must reject a cursor that is not byte-equal to the session, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn consume_rejects_an_expired_ticket() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let now = clock_now(&pool).await;
    let device = seed_device(&pool, now - Duration::seconds(400)).await;
    // A session window entirely in the past so the ticket can be minted expired.
    let session = seed_session(
        &pool,
        &device,
        now - Duration::seconds(300),
        now - Duration::seconds(70),
        true,
    )
    .await;

    let opaque = fresh_blob();
    let request = mint_request(
        &device,
        &session,
        &opaque,
        session.capability.clone(),
        now - Duration::seconds(130),
        now - Duration::seconds(70),
    );
    let mut tx = pool.begin().await.expect("begin mint");
    mint_subscription_ticket(&mut tx, &request)
        .await
        .expect("mint an already-expired-window ticket");
    tx.commit().await.expect("commit expired-window ticket");

    let mut c = pool.begin().await.expect("begin consume");
    let result = consume_subscription_ticket(
        &mut c,
        &ticket_hash(&opaque),
        &session.capability,
        SUBSCRIBE_EVENTS_PATH,
        now,
    )
    .await;
    assert!(
        matches!(result, Err(TicketRepositoryError::TicketExpired)),
        "consume must reject an expired ticket, got {result:?}"
    );
    c.rollback().await.expect("rollback");
}

#[tokio::test]
async fn concurrent_consumes_never_double_claim() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let now = clock_now(&pool).await;
    let device = seed_device(&pool, now - Duration::seconds(200)).await;
    let session = seed_session(
        &pool,
        &device,
        now - Duration::seconds(10),
        now + Duration::minutes(10),
        true,
    )
    .await;

    let opaque = fresh_blob();
    let request = mint_request(
        &device,
        &session,
        &opaque,
        session.capability.clone(),
        now,
        now + Duration::seconds(60),
    );
    let mut tx = pool.begin().await.expect("begin mint");
    mint_subscription_ticket(&mut tx, &request)
        .await
        .expect("mint");
    tx.commit().await.expect("commit mint");

    // Two workers race to consume the one ticket; exactly one wins.
    let barrier = Arc::new(Barrier::new(2));
    let hash = ticket_hash(&opaque);
    let cursor = session.capability.clone();
    let mut handles = Vec::new();
    for _ in 0..2 {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        let hash = hash.to_vec();
        let cursor = cursor.clone();
        handles.push(tokio::spawn(async move {
            let observed = clock_now(&pool).await;
            barrier.wait().await;
            let mut tx = pool.begin().await.expect("begin racing consume");
            let outcome = consume_subscription_ticket(
                &mut tx,
                &hash,
                &cursor,
                SUBSCRIBE_EVENTS_PATH,
                observed,
            )
            .await;
            if outcome.is_ok() {
                tx.commit().await.expect("commit winning consume");
            } else {
                tx.rollback().await.expect("rollback losing consume");
            }
            outcome.is_ok()
        }));
    }

    let mut wins = 0;
    for handle in handles {
        if handle.await.expect("join racing consume") {
            wins += 1;
        }
    }
    assert_eq!(
        wins, 1,
        "exactly one racing consume may claim the one-use ticket"
    );
}

#[tokio::test]
async fn consume_serializes_with_exact_device_revocation() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let now = clock_now(&pool).await;
    let device = seed_device(&pool, now - Duration::seconds(200)).await;
    let session = seed_session(
        &pool,
        &device,
        now - Duration::seconds(10),
        now + Duration::minutes(10),
        true,
    )
    .await;
    let opaque = fresh_blob();
    let request = mint_request(
        &device,
        &session,
        &opaque,
        session.capability.clone(),
        now,
        now + Duration::seconds(60),
    );
    let mut mint = pool.begin().await.expect("begin mint");
    mint_subscription_ticket(&mut mint, &request)
        .await
        .expect("mint");
    mint.commit().await.expect("commit mint");

    // Hold the exact device row while the consume transaction queues behind
    // it. Once revocation commits, the consume CAS must lose rather than
    // claiming a ticket under stale device authority.
    let mut revoke = pool.begin().await.expect("begin revocation");
    sqlx::query(
        "SELECT device_id FROM chat.devices WHERE user_did = $1 AND device_id = $2 FOR UPDATE",
    )
    .bind(&device.did)
    .bind(device.device_id)
    .fetch_one(&mut *revoke)
    .await
    .expect("lock exact device");

    let consume_pool = pool.clone();
    let consume_session = session;
    let consume_opaque = opaque.clone();
    let consume = tokio::spawn(async move {
        let mut transaction = consume_pool.begin().await.expect("begin consume");
        let result = consume_subscription_ticket(
            &mut transaction,
            &ticket_hash(&consume_opaque),
            &consume_session.capability,
            SUBSCRIBE_EVENTS_PATH,
            now,
        )
        .await;
        if result.is_ok() {
            transaction.commit().await.expect("commit consume");
        } else {
            transaction.rollback().await.expect("rollback consume");
        }
        result
    });
    sleep(TokioDuration::from_millis(25)).await;
    sqlx::query(
        "UPDATE chat.devices SET status = 'revoked', revoked_at = $3 WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&device.did)
    .bind(device.device_id)
    .bind(now + Duration::seconds(1))
    .execute(&mut *revoke)
    .await
    .expect("revoke locked device");
    revoke.commit().await.expect("commit revocation");

    let result = consume.await.expect("join consume");
    assert!(matches!(
        result,
        Err(TicketRepositoryError::DeviceBindingMismatch)
    ));
}
