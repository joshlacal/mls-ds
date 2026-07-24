//! Live-PostgreSQL tests for the bounded `getDevices` directory read
//! (Task 2, Slice 4b inventory extension).
//!
//! `getDevices` is fenceless: it binds only to the requested DIDs, so it is
//! exercised end-to-end here. The inventory session CREATE/materialize half and
//! the separate `getOwnDevices` device fence are NOT covered here — see the
//! Slice 4b report for their remainder (their populated paths depend on an
//! executor-seeded coherent graph).
//!
//! Run with:
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_inventory -- --include-ignored --test-threads=1

#![allow(dead_code)]

mod common;

#[path = "../src/chat_protocol/model.rs"]
mod model;
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

// Full production-module prelude (mirrors `chat_protocol_executor.rs`) so the
// shared `common::executor_seed` fulfillment-graph builders compile here and can
// seed a coherent conversation + membership graph for the populated CREATE test.
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

#[path = "common/executor_seed.rs"]
mod executor_seed;

mod repository {
    pub(crate) mod inventory {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/inventory.rs"
        ));
    }
    pub(crate) mod ticket {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/ticket.rs"
        ));
    }
}

mod cursor {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/chat_protocol/cursor.rs"
    ));
}

use chrono::{DateTime, Duration, TimeZone, Utc};
use cursor::CursorCodec;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

use repository::inventory::{
    create_device_inventory_session, create_inventory_session, get_devices,
    ConversationInventoryItem, CreateDeviceInventorySessionRequest, CreateInventorySessionRequest,
    DeviceInventorySubject, EventTerminalHint, IntervalSummaryTerminalHint,
    InventoryRepositoryError, InventorySummaryTerminalHint, TombstoneTerminalHint,
    MAX_GET_DEVICES_DIDS,
};
use repository::ticket::{
    consume_subscription_ticket, mint_subscription_ticket, ticket_hash, MintSubscriptionTicket,
    SUBSCRIBE_EVENTS_PATH,
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

async fn fresh_jkt(pool: &PgPool) -> String {
    let mut blob = Uuid::new_v4().as_bytes().to_vec();
    blob.extend_from_slice(Uuid::new_v4().as_bytes());
    sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(blob)
        .fetch_one(pool)
        .await
        .expect("derive jkt")
}

async fn seed_principal(pool: &PgPool, did: &str, at: DateTime<Utc>) {
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(did)
    .bind(at)
    .execute(pool)
    .await
    .expect("insert principal");
}

async fn seed_active_device(pool: &PgPool, did: &str, at: DateTime<Utc>) -> Uuid {
    let device_id = Uuid::new_v4();
    let jkt = fresh_jkt(pool).await;
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'dev-active','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(did)
    .bind(device_id)
    .bind(&jkt)
    .bind(at)
    .execute(pool)
    .await
    .expect("insert active device");
    device_id
}

fn fresh_blob() -> Vec<u8> {
    let mut b = Uuid::new_v4().as_bytes().to_vec();
    b.extend_from_slice(Uuid::new_v4().as_bytes());
    b
}

/// Seed a coherent REVOKED device (self-revocation) for `did`: an active device
/// with its single device key, then the full revocation graph the deferred
/// `assert_device_revocation_mapping` trigger requires — a `revokeDevice`
/// idempotency receipt, the `device_revocations` row, and the target device/key
/// terminalization. `get_devices` must exclude the result (status `<> 'active'`
/// / `revoked_at IS NOT NULL`).
async fn seed_revoked_device(pool: &PgPool, did: &str, created_at: DateTime<Utc>) -> Uuid {
    let device_id = Uuid::new_v4();
    let jkt = fresh_jkt(pool).await;
    let public_key = fresh_blob();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&public_key)
        .fetch_one(pool)
        .await
        .expect("derive key id");

    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'dev-revoked','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(did)
    .bind(device_id)
    .bind(&jkt)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert active device to revoke");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&public_key)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert device key");

    // Self-revocation: the actor is the same device/key as the target. The
    // revocation is accepted strictly after creation so every `created_at <=
    // accepted_at` binding holds.
    let accepted_at = created_at + Duration::seconds(30);
    let revocation_id = Uuid::new_v4();
    let accepted_request_bytes = fresh_blob();
    let signing_transcript_bytes = fresh_blob();
    let request_digest: [u8; 32] = Sha256::digest(&signing_transcript_bytes).into();
    let signature = [3_u8; 64];
    let response = br#"{"revoked":true}"#;
    let response_sha256: [u8; 32] = Sha256::digest(response).into();

    let mut tx = pool.begin().await.expect("begin revocation");
    sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records (
            principal_did, endpoint_nsid, operation_id, request_digest,
            accepted_request_bytes, signing_transcript_bytes, signature,
            completed_status, response_bytes, response_sha256,
            historical_jkt, completed_at
        ) VALUES ($1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,200,$7,$8,$9,$10)
        "#,
    )
    .bind(did)
    .bind(revocation_id)
    .bind(request_digest.as_slice())
    .bind(&accepted_request_bytes)
    .bind(&signing_transcript_bytes)
    .bind(signature.as_slice())
    .bind(response.as_slice())
    .bind(response_sha256.as_slice())
    .bind(&jkt)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert revokeDevice receipt");
    sqlx::query(
        r#"
        INSERT INTO chat.device_revocations (
            revocation_id, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, target_did, target_device_id,
            target_auth_generation, accepted_request_bytes,
            signing_transcript_bytes, request_digest, signature,
            signed_at, accepted_at
        ) VALUES ($1,$2,$3,$4,1,$2,$3,1,$5,$6,$7,$8,$9,$9)
        "#,
    )
    .bind(revocation_id)
    .bind(did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&accepted_request_bytes)
    .bind(&signing_transcript_bytes)
    .bind(request_digest.as_slice())
    .bind(signature.as_slice())
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert device revocation");
    sqlx::query(
        "UPDATE chat.devices SET status='revoked', updated_at=$3, revoked_at=$3, revocation_id=$4 \
         WHERE user_did=$1 AND device_id=$2",
    )
    .bind(did)
    .bind(device_id)
    .bind(accepted_at)
    .bind(revocation_id)
    .execute(&mut *tx)
    .await
    .expect("revoke target device");
    sqlx::query(
        "UPDATE chat.device_keys SET revoked_at=$3, revocation_id=$4 WHERE user_did=$1 AND device_id=$2",
    )
    .bind(did)
    .bind(device_id)
    .bind(accepted_at)
    .bind(revocation_id)
    .execute(&mut *tx)
    .await
    .expect("revoke target device key");
    tx.commit().await.expect("commit revocation");

    device_id
}

#[tokio::test]
#[ignore = "requires the dedicated clean-chat PostgreSQL database"]
async fn get_devices_rejects_zero_or_too_many_dids() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;

    let mut tx = pool.begin().await.expect("begin");
    let empty = get_devices(&mut tx, &[]).await;
    assert!(
        matches!(empty, Err(InventoryRepositoryError::RequestTooBroad)),
        "zero DIDs must be rejected, got {empty:?}"
    );

    let too_many: Vec<String> = (0..=MAX_GET_DEVICES_DIDS)
        .map(|_| random_plc_did())
        .collect();
    let over = get_devices(&mut tx, &too_many).await;
    assert!(
        matches!(over, Err(InventoryRepositoryError::RequestTooBroad)),
        "more than {MAX_GET_DEVICES_DIDS} DIDs must be rejected, got {over:?}"
    );
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
#[ignore = "requires the dedicated clean-chat PostgreSQL database"]
async fn get_devices_returns_active_devices_scoped_to_requested_dids() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let now = clock_now(&pool).await;

    let did_a = random_plc_did();
    let did_b = random_plc_did();
    let did_c = random_plc_did();
    seed_principal(&pool, &did_a, now).await;
    seed_principal(&pool, &did_b, now).await;
    seed_principal(&pool, &did_c, now).await;

    let a1 = seed_active_device(&pool, &did_a, now).await;
    let a2 = seed_active_device(&pool, &did_a, now).await;
    let b1 = seed_active_device(&pool, &did_b, now).await;
    let c1 = seed_active_device(&pool, &did_c, now).await;

    let mut tx = pool.begin().await.expect("begin");
    let devices = get_devices(&mut tx, &[did_a.clone(), did_b.clone()])
        .await
        .expect("get_devices executes");
    tx.rollback().await.expect("rollback");

    let returned: std::collections::HashSet<Uuid> = devices.iter().map(|d| d.device_id).collect();
    assert!(
        returned.contains(&a1) && returned.contains(&a2),
        "both of A's active devices"
    );
    assert!(returned.contains(&b1), "B's active device");
    assert!(
        !returned.contains(&c1),
        "a device of a DID that was not requested must be excluded"
    );
    // Every returned row is active and belongs to a requested DID.
    for d in &devices {
        assert_eq!(d.status, "active");
        assert!(d.user_did == did_a || d.user_did == did_b);
    }
    assert_eq!(
        devices.len(),
        3,
        "exactly the three active in-scope devices"
    );
}

#[tokio::test]
#[ignore = "requires the dedicated clean-chat PostgreSQL database"]
async fn get_devices_excludes_revoked_devices() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let now = clock_now(&pool).await;

    let did = random_plc_did();
    seed_principal(&pool, &did, now).await;
    let active = seed_active_device(&pool, &did, now).await;
    let revoked = seed_revoked_device(&pool, &did, now).await;

    let mut tx = pool.begin().await.expect("begin");
    let devices = get_devices(&mut tx, &[did.clone()])
        .await
        .expect("get_devices executes");
    tx.rollback().await.expect("rollback");

    let returned: std::collections::HashSet<Uuid> = devices.iter().map(|d| d.device_id).collect();
    assert!(returned.contains(&active), "the active device is returned");
    assert!(
        !returned.contains(&revoked),
        "a revoked device must be excluded by the status/revoked_at predicate"
    );
    for d in &devices {
        assert_eq!(d.status, "active", "every returned device is active");
        assert_eq!(d.user_did, did);
    }
}

// NOTE (r12 minor #3, closed as not-a-gap): this test cannot isolate WHICH of the
// two `get_devices` predicates (`status = 'active'` vs `revoked_at IS NULL`)
// excludes the revoked device, because the two are DDL-coupled and cannot diverge.
// `devices_revocation_shape_check` (`20260722000001…:326-328`) enforces exactly
// `(status = 'active' AND revoked_at IS NULL AND revocation_id IS NULL)
//  OR (status = 'revoked' AND revoked_at IS NOT NULL ...)`, so a row with
// `status = 'revoked'` and `revoked_at IS NULL` (or the converse) is unseedable.
// Predicate isolation is therefore not a coverage gap here — the redundancy is
// DDL-guaranteed, and behavioral exclusion (proved above) is the only observable
// property.

// ===========================================================================
// Inventory-session CREATE + materialize (the first-getConversations half).
// ===========================================================================

fn whole_second(dt: DateTime<Utc>) -> DateTime<Utc> {
    Utc.timestamp_opt(dt.timestamp(), 0)
        .single()
        .expect("whole-second instant")
}

struct SessionDevice {
    did: String,
    device_id: Uuid,
    jkt: String,
}

/// Seed an active device WITH its single device key (the CREATE path joins
/// `device_keys`), returning the identity fields the create request binds.
async fn seed_device_with_key(pool: &PgPool, at: DateTime<Utc>) -> SessionDevice {
    let did = random_plc_did();
    let device_id = Uuid::new_v4();
    let jkt = fresh_jkt(pool).await;
    let public_key = fresh_blob();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&public_key)
        .fetch_one(pool)
        .await
        .expect("derive key id");
    seed_principal(pool, &did, at).await;
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'dev-session','active',$3,1,chat.protocol_capabilities(),$4,$4)",
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
    SessionDevice {
        did,
        device_id,
        jkt,
    }
}

/// Ensure the protocol singleton + retention floor exist (a concurrent suite may
/// have seeded them already) and return a `CursorCodec` bound to the singleton's
/// exact `protocol_instance_id` + `cursor_key_id`. The codec secret is arbitrary
/// but consistent within the codec, so cursors it issues verify against it.
async fn ensure_fence(pool: &PgPool) -> CursorCodec {
    let cursor_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(vec![0x51u8; 32])
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
    let (protocol_instance_id, cursor_key_id): (Uuid, String) = sqlx::query_as(
        "SELECT protocol_instance_id, cursor_key_id FROM chat.protocol_instances WHERE singleton = TRUE",
    )
    .fetch_one(pool)
    .await
    .expect("read protocol instance");
    sqlx::query(
        "INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) \
         VALUES($1,0,clock_timestamp()) ON CONFLICT DO NOTHING",
    )
    .bind(protocol_instance_id)
    .execute(pool)
    .await
    .expect("seed retention floor");
    CursorCodec::new(
        protocol_instance_id,
        &cursor_key_id,
        Zeroizing::new([0xC7u8; 32]),
    )
    .expect("codec bound to the DB protocol singleton")
}

fn empty_sha256() -> Vec<u8> {
    Sha256::digest([]).to_vec()
}

#[tokio::test]
#[ignore = "requires the dedicated clean-chat PostgreSQL database"]
async fn first_get_conversations_creates_one_session_and_fence() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let codec = ensure_fence(&pool).await;
    let now = whole_second(clock_now(&pool).await);
    let device = seed_device_with_key(&pool, now - Duration::seconds(120)).await;
    let session_id = Uuid::new_v4();

    let mut tx = pool.begin().await.expect("begin create");
    let created = create_inventory_session(
        &mut tx,
        &codec,
        CreateInventorySessionRequest {
            inventory_session_id: session_id,
            user_did: &device.did,
            device_id: device.device_id,
            jkt: &device.jkt,
            auth_generation: 1,
            created_at: now,
            expires_at: now + Duration::minutes(10),
            conversations: vec![],
            welcomes: vec![],
            recovery: vec![],
        },
    )
    .await
    .expect("create an empty-device inventory session");
    tx.commit()
        .await
        .expect("commit past the deferred materialization + identity triggers");

    assert_eq!(created.inventory_session_id, session_id);
    assert_eq!(created.conversation_item_count, 0);
    assert_eq!(created.welcome_item_count, 0);
    assert_eq!(created.recovery_item_count, 0);

    // Exactly one retained session row, with the captured fence and the
    // complete-with-zero shape (count 0, hash SHA256("")) every domain.
    let row: (
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        bool,
        bool,
        bool,
        Option<i64>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<Vec<u8>>,
    ) = sqlx::query_as(
        "SELECT token_hash, snapshot_event_position, snapshot_event_cursor_bytes, \
                snapshot_event_cursor_sha256, conversations_complete, welcomes_complete, \
                recovery_complete, conversation_item_count, conversation_items_sha256, \
                welcome_item_count, welcome_items_sha256, recovery_item_count, recovery_items_sha256 \
           FROM chat.inventory_sessions WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("the created session row is retained");

    assert_eq!(
        row.1 as u64, created.snapshot_event_position,
        "the stored fence position matches the receipt"
    );
    assert_eq!(
        row.2, created.snapshot_event_cursor_bytes,
        "the stored snapshot cursor bytes match the receipt (byte-identical fence)"
    );
    assert_eq!(
        row.3,
        Sha256::digest(&created.snapshot_event_cursor_bytes).to_vec(),
        "the stored cursor sha256 is the digest of the cursor bytes"
    );
    assert!(row.4 && row.5 && row.6, "every domain is complete");
    assert_eq!(row.7, Some(0));
    assert_eq!(row.8, Some(empty_sha256()));
    assert_eq!(row.9, Some(0));
    assert_eq!(row.10, Some(empty_sha256()));
    assert_eq!(row.11, Some(0));
    assert_eq!(row.12, Some(empty_sha256()));

    // The token hash the CREATE stored is the binding hash of the opaque token it
    // returned — the two agree, so the client's session id round-trips.
    let token_hash: Vec<u8> =
        cursor::opaque_binding_hash(created.inventory_session_token.as_bytes())
            .expect("token within the opaque bound")
            .to_vec();
    assert_eq!(
        row.0, token_hash,
        "durable token_hash == hash(returned token)"
    );
}

#[tokio::test]
#[ignore = "requires the dedicated clean-chat PostgreSQL database"]
async fn create_then_mint_subscription_ticket_closes_the_loop() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let codec = ensure_fence(&pool).await;
    let now = whole_second(clock_now(&pool).await);
    let device = seed_device_with_key(&pool, now - Duration::seconds(120)).await;
    let session_id = Uuid::new_v4();

    let mut tx = pool.begin().await.expect("begin create");
    let created = create_inventory_session(
        &mut tx,
        &codec,
        CreateInventorySessionRequest {
            inventory_session_id: session_id,
            user_did: &device.did,
            device_id: device.device_id,
            jkt: &device.jkt,
            auth_generation: 1,
            created_at: now,
            expires_at: now + Duration::minutes(10),
            conversations: vec![],
            welcomes: vec![],
            recovery: vec![],
        },
    )
    .await
    .expect("create session");
    tx.commit().await.expect("commit create");

    // A ticket mints against the session THIS code created: it is complete in all
    // three domains and the presented cursor byte-equals the session snapshot
    // cursor, so the deferred ticket-binding trigger accepts it at commit.
    let opaque = fresh_blob();
    let mint = MintSubscriptionTicket {
        ticket_hash: ticket_hash(&opaque).to_vec(),
        user_did: device.did.clone(),
        device_id: device.device_id,
        jkt: device.jkt.clone(),
        auth_generation: 1,
        inventory_session_id: session_id,
        event_cursor_bytes: created.snapshot_event_cursor_bytes.clone(),
        subscription_path: SUBSCRIBE_EVENTS_PATH.to_owned(),
        created_at: now,
        expires_at: now + Duration::seconds(60),
    };
    let mut tx = pool.begin().await.expect("begin mint");
    let minted = mint_subscription_ticket(&mut tx, &mint)
        .await
        .expect("mint a ticket from a session created by create_inventory_session");
    tx.commit()
        .await
        .expect("commit mint past deferred binding");
    assert_eq!(
        minted.event_position as u64,
        created.snapshot_event_position
    );
    assert_eq!(
        minted.event_cursor_bytes,
        created.snapshot_event_cursor_bytes
    );

    // And the minted ticket consumes exactly once against the same fence.
    let mut tx = pool.begin().await.expect("begin consume");
    let consumed = consume_subscription_ticket(
        &mut tx,
        &ticket_hash(&opaque),
        &created.snapshot_event_cursor_bytes,
        SUBSCRIBE_EVENTS_PATH,
        whole_second(clock_now(&pool).await),
    )
    .await
    .expect("consume the minted ticket once");
    tx.commit().await.expect("commit consume");
    assert_eq!(consumed.inventory_session_id, session_id);
}

#[tokio::test]
#[ignore = "requires the dedicated clean-chat PostgreSQL database"]
async fn get_own_devices_uses_separate_device_fence() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let now = whole_second(clock_now(&pool).await);
    // The requester device (with its key) plus a sibling device of the SAME
    // principal — both are subjects of the own-device snapshot.
    let requester = seed_device_with_key(&pool, now - Duration::seconds(120)).await;
    let sibling = seed_active_device(&pool, &requester.did, now - Duration::seconds(90)).await;
    let session_id = Uuid::new_v4();

    let mut tx = pool.begin().await.expect("begin create");
    let created = create_device_inventory_session(
        &mut tx,
        CreateDeviceInventorySessionRequest {
            device_inventory_session_id: session_id,
            user_did: &requester.did,
            device_id: requester.device_id,
            jkt: &requester.jkt,
            auth_generation: 1,
            fence_revision: 0,
            created_at: now,
            expires_at: now + Duration::minutes(10),
            subjects: vec![
                DeviceInventorySubject {
                    subject_device_id: requester.device_id,
                    payload_bytes: b"own-device-self".to_vec(),
                },
                DeviceInventorySubject {
                    subject_device_id: sibling,
                    payload_bytes: b"own-device-sibling".to_vec(),
                },
            ],
        },
    )
    .await
    .expect("create the separate own-device fence");
    tx.commit()
        .await
        .expect("commit past device_inventory materialization + principal triggers");

    assert_eq!(created.item_count, 2);

    // Materialized into the SEPARATE device fence tables, not the shared session.
    let subjects: Vec<(i64, Uuid)> = sqlx::query_as(
        "SELECT ordinal, subject_device_id FROM chat.device_inventory_items \
           WHERE device_inventory_session_id = $1 ORDER BY ordinal",
    )
    .bind(session_id)
    .fetch_all(&pool)
    .await
    .expect("read materialized own-device items");
    assert_eq!(subjects.len(), 2);
    assert_eq!(subjects[0], (0, requester.device_id));
    assert_eq!(subjects[1], (1, sibling));

    let (complete, count): (bool, Option<i64>) = sqlx::query_as(
        "SELECT complete, item_count FROM chat.device_inventory_sessions \
           WHERE device_inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("read device fence row");
    assert!(complete);
    assert_eq!(count, Some(2));

    // The id is NOT a shared inventory session — the two fences never collide.
    let shared: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.inventory_sessions WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("count shared sessions");
    assert_eq!(
        shared, 0,
        "getOwnDevices never writes the shared session fence"
    );
}

#[test]
fn terminal_seq_hints_carry_no_fingerprint() {
    // The DTOs expose a `terminal_seq` (wake/navigation) and nothing else that
    // could authorize a close: constructing each proves the field exists and is
    // the only seq carried.
    let tombstone = TombstoneTerminalHint {
        conversation_id: Uuid::new_v4(),
        terminal_seq: 7,
    };
    let event = EventTerminalHint {
        conversation_id: Uuid::new_v4(),
        terminal_seq: 7,
    };
    let inventory = InventorySummaryTerminalHint {
        conversation_id: Uuid::new_v4(),
        terminal_seq: 7,
    };
    let interval = IntervalSummaryTerminalHint {
        conversation_id: Uuid::new_v4(),
        terminal_seq: 7,
    };
    assert_eq!(tombstone.terminal_seq, 7);
    assert_eq!(event.terminal_seq, 7);
    assert_eq!(inventory.terminal_seq, 7);
    assert_eq!(interval.terminal_seq, 7);

    // No hint DTO carries an outer-entry fingerprint (a hint must never duplicate
    // one, nor authorize a close/schedule-terminalize). Assert structurally over
    // the hint DTO block in the production source.
    let source = include_str!("../src/chat_protocol/repository/inventory.rs");
    let hint_block = source
        .split_once("terminalSeq wake/navigation hint DTOs")
        .expect("hint DTO section exists")
        .1;
    for hint in [
        "pub(crate) struct TombstoneTerminalHint",
        "pub(crate) struct EventTerminalHint",
        "pub(crate) struct InventorySummaryTerminalHint",
        "pub(crate) struct IntervalSummaryTerminalHint",
    ] {
        let body = hint_block
            .split_once(hint)
            .expect("hint struct present")
            .1
            .split_once("\n}")
            .expect("hint struct body closed")
            .0;
        assert!(body.contains("terminal_seq"), "{hint} exposes terminal_seq");
        assert!(
            !body.contains("fingerprint"),
            "{hint} must NOT carry an outer-entry fingerprint"
        );
    }
}

// NOTE (r12 correction): the populated conversation-domain materialization case
// (remainder #8) IS raw-seedable in a single transaction — the earlier claim that
// `conversations_current_state_fk` is an IMMEDIATE circular FK was wrong. That FK
// on `(conversation_id, current_generation, current_state_version)` into
// `generation_states` is `DEFERRABLE INITIALLY DEFERRED`
// (`20260722000001…:922-926`); it exists precisely to break the
// conversations⇄generations⇄generation_states cycle. The two immediate legs
// (`generations_conversation_fk`, `generation_states_generation_fk`) are satisfied
// by insert order (conversation → generation → generation_states), and the
// deferred leg resolves at COMMIT. Raw seeding is therefore possible, only
// laborious to assemble coherently. The populated conversation/welcome/recovery
// materialization path is exercised beside the executor harness via the shared
// `common::executor_seed` fulfillment graph (Seal A), which produces a coherent
// conversation + generation graph directly. The empty-domain and ticket-loop
// cases above prove the CREATE transaction (fence capture, token derivation,
// ordinal/digest/completion, and the deferred materialization + identity
// triggers) end-to-end.

// ===========================================================================
// Populated conversation-domain selection + bijection (Seal B), driven by the
// shared `common::executor_seed` fulfillment graph on a fresh per-run DB. The
// committed creation makes alice a CURRENT member of exactly the seeded
// conversation, so the repository's membership selection returns exactly it.
// ===========================================================================

/// The repository OWNS the conversation set: it selects the conversations the
/// device is a current member of (active `member_devices`) under the fence and
/// binds the caller's payloads by exact bijection. A member conversation with no
/// supplied payload, and a payload for a non-member conversation, both reject; the
/// exact member set materializes with a repository-assigned ordinal.
#[tokio::test]
#[ignore = "requires the dedicated clean-chat PostgreSQL database"]
async fn create_selects_and_bijection_binds_the_member_conversation() {
    let (pool, _guard) = executor_seed::setup().await;
    let scenario = executor_seed::run_fulfillment_scenario(&pool).await;
    let codec = ensure_fence(&pool).await;
    // `create_inventory_session` requires a whole-second `created_at` (the cursor
    // codec rejects sub-second instants). Alice's member device was seeded mid-way
    // through this same wall-clock second and `chat.devices` is immutable, so use
    // the START of the NEXT whole second: it is >= the device's `created_at` (the
    // deferred identity trigger's requirement) and still a whole second.
    let now = whole_second(clock_now(&pool).await) + Duration::seconds(1);

    // Alice (creator/admin) is a current member of exactly the seeded conversation;
    // her device was seeded active with dpop_jkt == its key id.
    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let alice_jkt = scenario.fixture.alice_key_id.clone();
    let conversation_id = scenario.conversation_id;

    let base = |conversations: Vec<ConversationInventoryItem>| CreateInventorySessionRequest {
        inventory_session_id: Uuid::new_v4(),
        user_did: &alice_did,
        device_id: alice_device,
        jkt: &alice_jkt,
        auth_generation: 1,
        created_at: now,
        expires_at: now + Duration::minutes(10),
        conversations,
        welcomes: vec![],
        recovery: vec![],
    };

    // (a) Supplying NO conversation payload for a member conversation → reject.
    {
        let mut tx = pool.begin().await.expect("begin reject-empty");
        let err = create_inventory_session(&mut tx, &codec, base(vec![]))
            .await
            .expect_err("a member conversation with no supplied payload must reject");
        assert_eq!(
            err,
            InventoryRepositoryError::InconsistentConversationSelection
        );
        tx.rollback().await.expect("rollback reject-empty");
    }

    // (b) A payload for a conversation the device is NOT a member of → reject.
    {
        let mut tx = pool.begin().await.expect("begin reject-nonmember");
        let err = create_inventory_session(
            &mut tx,
            &codec,
            base(vec![ConversationInventoryItem {
                conversation_id: Uuid::new_v4(),
                payload_bytes: vec![0x01, 0x02, 0x03],
                schedule_terminal: None,
            }]),
        )
        .await
        .expect_err("a payload for a non-member conversation must reject");
        assert_eq!(
            err,
            InventoryRepositoryError::InconsistentConversationSelection
        );
        tx.rollback().await.expect("rollback reject-nonmember");
    }

    // (c) Supplying exactly the member conversation materializes it (count 1),
    //     committing past the deferred materialization + identity triggers.
    {
        let mut tx = pool.begin().await.expect("begin accept");
        let created = create_inventory_session(
            &mut tx,
            &codec,
            base(vec![ConversationInventoryItem {
                conversation_id,
                payload_bytes: vec![0xAB; 16],
                schedule_terminal: None,
            }]),
        )
        .await
        .expect("the exact member conversation materializes");
        tx.commit()
            .await
            .expect("commit past deferred materialization + identity triggers");
        assert_eq!(created.conversation_item_count, 1);
        assert_eq!(created.welcome_item_count, 0);
        assert_eq!(created.recovery_item_count, 0);
    }
}
