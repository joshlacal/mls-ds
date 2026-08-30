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

pub use catbird_server::{auth, crypto, federation, handlers, identity, sqlx_jacquard, util};

#[path = "common/chat_protocol_harness.rs"]
mod chat_protocol;

mod repository {
    pub(crate) use crate::chat_protocol::repository::*;
}
mod cursor {
    pub(crate) use crate::chat_protocol::cursor::*;
}
use chat_protocol::cursor::{CursorSealer, SealerBinding, SecureRandom, SecureRandomError};
use zeroize::Zeroizing;

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
use chrono::{DateTime, Duration, Timelike, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Barrier;
use tokio::time::{sleep, Duration as TokioDuration};
use tower_util::ServiceExt;
use uuid::Uuid;

use repository::ticket::{
    consume_subscription_ticket, insert_event_cursor_receipt, mint_subscription_ticket,
    revalidate_consumed_ticket, ticket_hash, MintSubscriptionTicket, NewEventCursorReceipt,
    TicketRepositoryError, SUBSCRIBE_EVENTS_PATH,
};

struct FixtureRandom(u8);

impl SecureRandom for FixtureRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SecureRandomError> {
        out.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
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

const INVENTORY_MATERIALIZATION_ENCODING_VERSION: u8 = 2;

fn derive_inventory_session_uuid(
    user_did: &str,
    device_id: Uuid,
    jkt: Option<&str>,
    auth_generation: u64,
) -> Uuid {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-INVENTORY-SESSION-IDENTITY\0");
    digest.update([INVENTORY_MATERIALIZATION_ENCODING_VERSION]);
    digest.update((user_did.len() as u64).to_be_bytes());
    digest.update(user_did.as_bytes());
    digest.update(device_id.as_bytes());
    let jkt_str = jkt.unwrap_or_default();
    digest.update((jkt_str.len() as u64).to_be_bytes());
    digest.update(jkt_str.as_bytes());
    digest.update(auth_generation.to_be_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&bytes[..16]);
    uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40;
    uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80;
    Uuid::from_bytes(uuid_bytes)
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
    let inventory_session_id = derive_inventory_session_uuid(
        &device.did,
        device.device_id,
        Some(device.jkt.as_str()),
        device.auth_generation as u64,
    );
    let capability_bytes = fresh_blob();
    let capability = URL_SAFE_NO_PAD.encode(&capability_bytes);
    let capability_hash = Sha256::digest(&capability_bytes).to_vec();
    let empty_hash = Sha256::digest([]).to_vec();
    let device_created_at: DateTime<Utc> = sqlx::query_scalar(
        "SELECT created_at FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&device.did)
    .bind(device.device_id)
    .fetch_one(pool)
    .await
    .expect("read session device creation timestamp");
    let device_session_floor = if device_created_at.timestamp_subsec_nanos() == 0 {
        device_created_at
    } else {
        device_created_at + Duration::seconds(1)
            - Duration::nanoseconds(i64::from(device_created_at.timestamp_subsec_nanos()))
    };
    // Sealed inventory-session bindings use whole-second timestamps, matching
    // the production `unix_seconds` validation. The session must also be no
    // earlier than the device row for the deferred identity trigger.
    let mut created_at = created_at
        .with_nanosecond(0)
        .expect("normalize session creation timestamp");
    if created_at < device_session_floor {
        created_at = device_session_floor;
    }
    let expires_at = expires_at
        .with_nanosecond(0)
        .expect("normalize session expiry timestamp");

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
    let snapshot_event_position: i64 =
        sqlx::query_scalar("SELECT coalesce(max(event_position), 0)::bigint FROM chat.events")
            .fetch_one(pool)
            .await
            .expect("read event head for sealed session");
    let key_id: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&cursor_key_id)
        .expect("decode cursor key id")
        .try_into()
        .expect("cursor key id is 32 bytes");
    let sealer = CursorSealer::new(key_id, Zeroizing::new([0xA5_u8; 32]))
        .expect("construct HTTP acceptance cursor sealer");
    let binding = SealerBinding::for_event_cursor_receipt(
        inventory_session_id,
        device.did.as_bytes(),
        device.device_id,
        device.jkt.as_bytes(),
        u64::try_from(device.auth_generation).expect("generation fits u64"),
        protocol_instance_id,
        cursor_key_id.as_bytes(),
        u64::try_from(snapshot_event_position).expect("event position fits u64"),
        None,
        u64::try_from(retained_floor).expect("retained floor fits u64"),
        u64::try_from(created_at.timestamp()).expect("creation timestamp fits u64"),
        u64::try_from(expires_at.timestamp()).expect("expiry timestamp fits u64"),
    )
    .expect("bind sealed session capability");
    let sealed = sealer
        .seal_successor(
            capability_bytes.as_slice(),
            &binding,
            &mut FixtureRandom(0x33),
        )
        .expect("seal session capability");
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
    .bind(&sealed.nonce)
    .bind(&sealed.ciphertext)
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
        jkt: Some(device.jkt.clone()),
        auth_generation: device.auth_generation,
        inventory_session_id: session.capability.clone(),
        event_cursor: capability,
        subscription_path: SUBSCRIBE_EVENTS_PATH.to_owned(),
        created_at,
        // The durable session uses canonical whole-second expiry; clamp the
        // test request to that row fence when callers supply a fractional
        // timestamp at the same second.
        expires_at: expires_at.min(session.expires_at),
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
async fn retention_floor_cannot_advance_beneath_a_live_ticket_session() {
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
        .expect("mint before floor advance");
    mint.commit().await.expect("commit ticket");

    let advance = sqlx::query(
        "UPDATE chat.event_retention SET retained_floor=$1,updated_at=clock_timestamp()",
    )
    .bind(session.snapshot_event_position + 1)
    .execute(&pool)
    .await;
    let error = advance.expect_err("live session FK must pin the retained floor");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database| database.code().map(|code| code.into_owned())),
        Some("23503".to_owned())
    );
}

#[tokio::test]
async fn snapshot_cursor_receipt_is_persisted_with_exact_session_authority() {
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
    let (protocol_instance_id, cursor_key_id, retained_floor): (Uuid, String, i64) =
        sqlx::query_as(
            "SELECT protocol_instance_id,cursor_key_id,retained_floor FROM chat.protocol_instances JOIN chat.event_retention USING(protocol_instance_id) WHERE singleton=TRUE",
        )
        .fetch_one(&pool)
        .await
        .expect("load protocol fence");
    let cursor_hash: [u8; 32] = session
        .capability_hash
        .clone()
        .try_into()
        .expect("fixture capability hash");
    let mut transaction = pool.begin().await.expect("begin receipt");
    insert_event_cursor_receipt(
        &mut transaction,
        &NewEventCursorReceipt {
            cursor_hash,
            inventory_session_id: session.inventory_session_id,
            user_did: device.did.clone(),
            device_id: device.device_id,
            jkt: Some(device.jkt.clone()),
            auth_generation: device.auth_generation,
            protocol_instance_id,
            cursor_key_id,
            event_position: session.snapshot_event_position,
            predecessor_cursor_hash: None,
            retained_floor_at_issue: retained_floor,
            cursor_nonce: [7; 12],
            cursor_ciphertext: vec![9; 32],
            canonical_envelope_sha256: None,
            created_at: session.created_at,
            expires_at: session.expires_at,
        },
    )
    .await
    .expect("persist the initial receipt through the production primitive");
    transaction.commit().await.expect("commit initial receipt");

    let stored: (i64, Option<Vec<u8>>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT event_position,predecessor_cursor_hash,canonical_envelope_sha256 FROM chat.event_cursor_receipts WHERE cursor_hash=$1",
    )
    .bind(cursor_hash.as_slice())
    .fetch_one(&pool)
    .await
    .expect("read initial receipt");
    assert_eq!(stored.0, session.snapshot_event_position);
    assert!(stored.1.is_none() && stored.2.is_none());
}

#[tokio::test]
async fn idle_subscription_revalidation_stops_after_exact_device_revocation() {
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
        .expect("mint idle-stream ticket");
    mint.commit().await.expect("commit ticket");
    let mut consume = pool.begin().await.expect("begin consume");
    let authority = consume_subscription_ticket(
        &mut consume,
        &ticket_hash(&opaque),
        &session.capability,
        SUBSCRIBE_EVENTS_PATH,
        clock_now(&pool).await,
    )
    .await
    .expect("consume ticket before revocation");
    consume.commit().await.expect("commit consume");

    sqlx::query(
        "UPDATE chat.devices SET status='revoked',revoked_at=$3 WHERE user_did=$1 AND device_id=$2",
    )
    .bind(&device.did)
    .bind(device.device_id)
    .bind(clock_now(&pool).await)
    .execute(&pool)
    .await
    .expect("revoke exact device without appending a durable event");

    let mut live = pool.begin().await.expect("begin idle revalidation");
    let result = revalidate_consumed_ticket(
        &mut live,
        &authority,
        authority.event_position,
        clock_now(&pool).await,
    )
    .await;
    assert!(matches!(
        result,
        Err(TicketRepositoryError::DeviceBindingMismatch)
    ));
    live.rollback().await.expect("rollback rejected live pass");
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

use common::http_acceptance as http;

#[tokio::test]
async fn http_subscription_ticket_mints_once_consumes_once_and_denies_foreign_device() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    http::ensure_fence(&pool).await;
    let owner = http::seed_device(&pool).await;
    let foreign = http::seed_device(&pool).await;
    let requested_at = clock_now(&pool).await;
    let owner_fixture = DeviceFixture {
        did: owner.did.clone(),
        device_id: owner.device_id,
        jkt: owner.jkt.clone(),
        auth_generation: 1,
    };
    let session = seed_session(
        &pool,
        &owner_fixture,
        requested_at,
        requested_at + Duration::minutes(10),
        true,
    )
    .await;
    while clock_now(&pool).await < session.created_at {
        sleep(TokioDuration::from_millis(10)).await;
    }
    let now = clock_now(&pool).await;
    let opaque = fresh_blob();

    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    let body = serde_json::to_vec(&serde_json::json!({
        "actorDeviceId": owner.device_id.hyphenated().to_string(),
        "inventorySessionId": session.capability.clone(),
        "eventCursor": session.capability.clone(),
    }))
    .expect("ticket body");

    let (owner_status, owner_response) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &owner,
            "blue.catbird.chat.getSubscriptionTicket",
            body.clone(),
        ),
    )
    .await;
    assert_eq!(owner_status, axum::http::StatusCode::OK);
    assert_eq!(
        owner_response["endpoint"],
        "wss://chat.example.net/xrpc/blue.catbird.chat.subscribeEvents"
    );
    assert_eq!(owner_response["ticket"].as_str().map(str::len), Some(43));
    let (foreign_status, foreign_response) = http::send(
        router.clone(),
        http::unsigned_json_request(&foreign, "blue.catbird.chat.getSubscriptionTicket", body),
    )
    .await;
    assert_eq!(foreign_status, axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(foreign_response["error"], "DeviceNotRegistered");
    assert!(foreign_response.get("ticket").is_none());
    let ticket_str = owner_response["ticket"]
        .as_str()
        .expect("minted ticket string");
    let opaque_bytes = URL_SAFE_NO_PAD
        .decode(ticket_str.as_bytes())
        .expect("decode ticket");
    let opaque_hash = ticket_hash(&opaque_bytes);
    let subscribe_query = format!("?ticket={ticket_str}&cursor={}", session.capability);
    let first = router
        .clone()
        .oneshot(http::websocket_request(
            "blue.catbird.chat.subscribeEvents",
            &subscribe_query,
        ))
        .await
        .expect("first subscribe response");
    assert_eq!(
        first.status(),
        axum::http::StatusCode::UPGRADE_REQUIRED,
        "in-process HTTP harness has no hyper upgrade state; authorization is exercised below"
    );
    let mut consume = pool.begin().await.expect("begin first ticket consume");
    consume_subscription_ticket(
        &mut consume,
        &opaque_hash,
        &session.capability,
        SUBSCRIBE_EVENTS_PATH,
        clock_now(&pool).await,
    )
    .await
    .expect("first real ticket consume succeeds");
    consume.commit().await.expect("commit first ticket consume");

    let mut replay = pool.begin().await.expect("begin replay ticket consume");
    let replayed = consume_subscription_ticket(
        &mut replay,
        &opaque_hash,
        &session.capability,
        SUBSCRIBE_EVENTS_PATH,
        clock_now(&pool).await,
    )
    .await;
    assert!(
        matches!(replayed, Err(TicketRepositoryError::TicketAlreadyConsumed)),
        "a replayed real ticket must fail closed: {replayed:?}"
    );
    replay.rollback().await.expect("rollback replay consume");
}
