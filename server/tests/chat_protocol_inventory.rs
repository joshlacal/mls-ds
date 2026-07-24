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
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod repository {
    pub(crate) mod inventory {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/inventory.rs"
        ));
    }
}

mod cursor {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/chat_protocol/cursor.rs"
    ));
}

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use repository::inventory::{get_devices, InventoryRepositoryError, MAX_GET_DEVICES_DIDS};

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
