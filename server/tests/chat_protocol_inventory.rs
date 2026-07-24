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

use chrono::{DateTime, Utc};
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
