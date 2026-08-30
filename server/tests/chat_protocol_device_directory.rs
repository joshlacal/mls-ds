//! Live-PostgreSQL tests for the clean-chat read-only device-directory
//! projections (`chat_protocol::repository::device_directory`, Task 4 seal 2b).
//!
//! Proves `read_device_view` returns the full deviceView field set for a device
//! by primary key with the pinned capability JSON, that the live package counts
//! are status-only (available/reserved) and exclude consumed/expired/revoked
//! (so a future status addition cannot silently inflate them), that an absent
//! device is `None`, and that `list_own_device_views` returns every device a DID
//! owns (active and revoked) in canonical order.
//!
//! Each case runs inside one transaction with same-tx read-back and is then
//! ROLLED BACK — key packages in terminal states rely on DEFERRABLE INITIALLY
//! DEFERRED FKs that never fire because the transaction never commits. The
//! clean-chat database is never truncated.
//!
//! Run against the dedicated clean-chat database:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_device_directory -- --test-threads=1

#![allow(dead_code)]

mod common;

pub use catbird_server::{auth, crypto, federation, handlers, identity, sqlx_jacquard, util};

#[path = "common/chat_protocol_harness.rs"]
mod chat_protocol;

mod repository {
    pub(crate) use crate::chat_protocol::repository::*;
}

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use repository::device_directory::{list_own_device_views, read_device_view};

fn digest32(seed: &str) -> Vec<u8> {
    Sha256::digest(seed.as_bytes()).to_vec()
}

async fn clock(tx: &mut Transaction<'_, Postgres>) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .expect("sample clock")
}

struct Device {
    did: String,
    device_id: Uuid,
    key_id: String,
    signing_public_key: Vec<u8>,
}

/// Seed one principal (if needed) + device (`status`) + device key inside `tx`.
async fn seed_device(
    tx: &mut Transaction<'_, Postgres>,
    did: &str,
    seed: &str,
    status: &str,
    seed_principal: bool,
) -> Device {
    let now = clock(tx).await;
    let device_id = Uuid::new_v4();
    let signing_public_key = digest32(&format!("{seed}-sig"));
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&signing_public_key));
    let dpop_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(format!("{seed}-jkt").as_bytes()));

    if seed_principal {
        sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
            .bind(did)
            .bind(now)
            .execute(&mut **tx)
            .await
            .expect("seed principal");
    }
    if status == "revoked" {
        // A revoked device row requires its revocation-shape columns; the FK to
        // chat.device_revocations is DEFERRABLE INITIALLY DEFERRED and never
        // fires (tx rolled back).
        sqlx::query(
            r#"
            INSERT INTO chat.devices(
                user_did, device_id, device_name, status, dpop_jkt, auth_generation,
                capabilities, created_at, updated_at, revoked_at, revocation_id
            ) VALUES($1,$2,'device','revoked',$3,1,chat.protocol_capabilities(),$4,$4,$4,$5)
            "#,
        )
        .bind(did)
        .bind(device_id)
        .bind(&dpop_jkt)
        .bind(now)
        .bind(Uuid::new_v4())
        .execute(&mut **tx)
        .await
        .expect("seed revoked device");
    } else {
        sqlx::query(
            r#"
            INSERT INTO chat.devices(
                user_did, device_id, device_name, status, dpop_jkt, auth_generation,
                capabilities, created_at, updated_at
            ) VALUES($1,$2,'device','active',$3,1,chat.protocol_capabilities(),$4,$4)
            "#,
        )
        .bind(did)
        .bind(device_id)
        .bind(&dpop_jkt)
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("seed active device");
    }
    sqlx::query(
        r#"
        INSERT INTO chat.device_keys(
            user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at
        ) VALUES($1,$2,$3,$4,1,$5)
        "#,
    )
    .bind(did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&signing_public_key)
    .bind(now)
    .execute(&mut **tx)
    .await
    .expect("seed device key");

    Device {
        did: did.to_owned(),
        device_id,
        key_id,
        signing_public_key,
    }
}

/// Seed one key package in an explicit `status` with the terminal-shape columns
/// the DDL CHECK requires for that status.
async fn seed_kp(tx: &mut Transaction<'_, Postgres>, device: &Device, seed: &str, status: &str) {
    let now = clock(tx).await;
    let not_before = now - Duration::seconds(60);
    let not_after = now + Duration::seconds(3600);
    let (terminal_transition_id, terminal_revocation_id, terminal_at): (
        Option<Uuid>,
        Option<Uuid>,
        Option<DateTime<Utc>>,
    ) = match status {
        "available" | "reserved" => (None, None, None),
        "consumed" => (Some(Uuid::new_v4()), None, Some(now)),
        "expired" => (None, None, Some(not_after)),
        "revoked" => (None, Some(Uuid::new_v4()), Some(now)),
        other => panic!("unexpected status {other}"),
    };
    let wrapper = digest32(&format!("{seed}-wrap"));
    sqlx::query(
        r#"
        INSERT INTO chat.key_packages(
            key_package_ref, wrapper_bytes, wrapper_sha256, init_key, owner_did,
            owner_device_id, owner_key_id, owner_auth_generation, not_before, not_after,
            status, terminal_transition_id, terminal_revocation_id, terminal_at, created_at
        ) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10,$11,$12,$13,$14)
        "#,
    )
    .bind(digest32(&format!("{seed}-ref")))
    .bind(&wrapper)
    .bind(Sha256::digest(&wrapper).to_vec())
    .bind(digest32(&format!("{seed}-init")))
    .bind(&device.did)
    .bind(device.device_id)
    .bind(&device.key_id)
    .bind(not_before)
    .bind(not_after)
    .bind(status)
    .bind(terminal_transition_id)
    .bind(terminal_revocation_id)
    .bind(terminal_at)
    .bind(now)
    .execute(&mut **tx)
    .await
    .unwrap_or_else(|e| panic!("seed {status} key package: {e}"));
}

#[tokio::test]
async fn read_device_view_returns_fields_and_status_only_counts() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let mut tx = pool.begin().await.expect("begin");
    let device = seed_device(
        &mut tx,
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        "dv",
        "active",
        true,
    )
    .await;
    // One key package in EVERY status; only available + reserved are live.
    for status in ["available", "reserved", "consumed", "expired", "revoked"] {
        seed_kp(&mut tx, &device, &format!("dv-{status}"), status).await;
    }

    let view = read_device_view(&mut tx, &device.did, device.device_id)
        .await
        .expect("read ok")
        .expect("device present");

    assert_eq!(view.device_id, device.device_id);
    assert_eq!(view.key_id, device.key_id);
    assert_eq!(view.signing_public_key, device.signing_public_key);
    assert_eq!(view.status, "active");
    assert_eq!(view.auth_generation, 1);
    assert_eq!(
        view.available_package_count, 1,
        "only status='available' counts"
    );
    assert_eq!(
        view.reserved_package_count, 1,
        "only status='reserved' counts; consumed/expired/revoked excluded"
    );
    // capabilities is the pinned profile; the handler decodes it into the DTO.
    let capabilities: serde_json::Value =
        serde_json::from_str(&view.capabilities_json).expect("capabilities is valid JSON");
    assert_eq!(capabilities["mlsVersion"], "1.0");
    assert_eq!(
        capabilities["cipherSuite"],
        "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
    );
    assert!(capabilities.get("protocolVersion").is_some());
}

#[tokio::test]
async fn read_device_view_absent_device_is_none() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let mut tx = pool.begin().await.expect("begin");
    let view = read_device_view(&mut tx, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", Uuid::new_v4())
        .await
        .expect("read ok");
    assert!(view.is_none());
}

#[tokio::test]
async fn list_own_device_views_returns_active_and_revoked_in_order() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let mut tx = pool.begin().await.expect("begin");
    let did = "did:plc:cccccccccccccccccccccccc";
    let first = seed_device(&mut tx, did, "own-a", "active", true).await;
    let second = seed_device(&mut tx, did, "own-b", "revoked", false).await;

    let views = list_own_device_views(&mut tx, did).await.expect("list ok");
    assert_eq!(
        views.len(),
        2,
        "both own devices returned (active + revoked)"
    );
    // Canonical order is (created_at, device_id); `first` was created first.
    assert_eq!(views[0].device_id, first.device_id);
    assert_eq!(views[0].status, "active");
    assert_eq!(views[1].device_id, second.device_id);
    assert_eq!(views[1].status, "revoked");
    for view in &views {
        assert_eq!(view.available_package_count, 0);
        assert_eq!(view.reserved_package_count, 0);
    }
}
