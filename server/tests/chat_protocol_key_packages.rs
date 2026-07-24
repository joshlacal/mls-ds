//! Live-PostgreSQL tests for the clean-chat key-package persistence sink
//! (`chat_protocol::repository::key_packages::publish_key_packages`, ruling
//! OQ-9).
//!
//! These prove the sink writes faithful `available` rows, honors every DDL
//! invariant it is responsible for (owner FK, `init_key` uniqueness, primary-key
//! uniqueness, the lifetime CHECK), refuses a revoked owner and a batch that
//! would breach the per-device live-inventory limit, and that "bad status" is
//! unreachable because the writer only ever emits `'available'`.
//!
//! Isolation boundary: the production repository module is gated
//! `#[cfg(not(test))]`-free but reached from the executor; mirroring the sibling
//! repository harnesses, this test `include!`s the module directly. It is
//! self-contained (only `chrono`/`sha2`/`sqlx`/`uuid`), so no other production
//! module is included. Every case runs inside one transaction with same-tx
//! read-back and is then ROLLED BACK (the clean-chat database is never
//! truncated), so nothing is committed.
//!
//! Run against the dedicated clean-chat database:
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_key_packages -- --test-threads=1

#![allow(dead_code)]

mod common;

mod repository {
    pub(crate) mod key_packages {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/key_packages.rs"
        ));
    }
}

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use repository::key_packages::{
    publish_key_packages, KeyPackageOwner, KeyPackageRepositoryError, NewKeyPackage,
};

fn digest32(seed: &str) -> Vec<u8> {
    Sha256::digest(seed.as_bytes()).to_vec()
}

fn base64url_sha256(seed: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(seed.as_bytes()))
}

struct Owner {
    did: String,
    device_id: Uuid,
    key_id: String,
}

/// Seed one active principal + device + device key inside `tx`.
async fn seed_owner(tx: &mut Transaction<'_, Postgres>, did: &str, seed: &str) -> Owner {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .expect("sample clock");
    let device_id = Uuid::new_v4();
    let signing_public_key = digest32(&format!("{seed}-sig"));
    // The DDL binds key_id = chat.ed25519_key_id(signing_public_key) =
    // base64url(sha256(signing_public_key)) with padding stripped.
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&signing_public_key));
    let dpop_jkt = base64url_sha256(&format!("{seed}-jkt"));

    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(did)
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("seed principal");
    sqlx::query(
        r#"
        INSERT INTO chat.devices(
            user_did, device_id, device_name, status, dpop_jkt,
            auth_generation, capabilities, created_at, updated_at
        ) VALUES($1,$2,'device','active',$3,1,chat.protocol_capabilities(),$4,$4)
        "#,
    )
    .bind(did)
    .bind(device_id)
    .bind(&dpop_jkt)
    .bind(now)
    .execute(&mut **tx)
    .await
    .expect("seed device");
    sqlx::query(
        r#"
        INSERT INTO chat.device_keys(
            user_did, device_id, key_id, signing_public_key,
            enrollment_auth_generation, created_at
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

    Owner {
        did: did.to_owned(),
        device_id,
        key_id,
    }
}

async fn clock(tx: &mut Transaction<'_, Postgres>) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .expect("sample clock")
}

/// A distinct, DDL-valid publishable package derived from `seed`.
fn package(seed: &str, now: DateTime<Utc>) -> (Vec<u8>, Vec<u8>, Vec<u8>, u64, u64) {
    let key_package_ref = digest32(&format!("{seed}-ref"));
    let wrapper_bytes = digest32(&format!("{seed}-wrap"));
    let init_key = digest32(&format!("{seed}-init"));
    let not_before = (now - Duration::seconds(60)).timestamp() as u64;
    let not_after = (now + Duration::seconds(3600)).timestamp() as u64;
    (
        key_package_ref,
        wrapper_bytes,
        init_key,
        not_before,
        not_after,
    )
}

#[tokio::test]
async fn happy_batch_persists_available_rows_with_faithful_columns() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = seed_owner(&mut tx, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "happy").await;
    let now = clock(&mut tx).await;

    let raw: Vec<_> = (0..3)
        .map(|i| package(&format!("happy-{i}"), now))
        .collect();
    let packages: Vec<NewKeyPackage> = raw
        .iter()
        .map(|(r, w, k, nb, na)| NewKeyPackage {
            key_package_ref: r,
            wrapper_bytes: w,
            init_key: k,
            not_before_unix: *nb,
            not_after_unix: *na,
        })
        .collect();
    let owner_ref = KeyPackageOwner {
        user_did: &owner.did,
        device_id: owner.device_id,
        key_id: &owner.key_id,
        auth_generation: 1,
    };

    let inserted = publish_key_packages(&mut tx, &owner_ref, &packages, now)
        .await
        .expect("happy batch publishes");
    assert_eq!(inserted, 3);

    for (r, w, _k, _nb, _na) in &raw {
        let row: (String, String, Vec<u8>, i64) = sqlx::query_as(
            "SELECT owner_did, status, wrapper_sha256, owner_auth_generation \
             FROM chat.key_packages WHERE key_package_ref = $1",
        )
        .bind(r)
        .fetch_one(&mut *tx)
        .await
        .expect("row present");
        assert_eq!(row.0, owner.did);
        assert_eq!(row.1, "available", "writer only ever emits 'available'");
        assert_eq!(
            row.2,
            Sha256::digest(w).to_vec(),
            "wrapper_sha256 = digest(wrapper)"
        );
        assert_eq!(row.3, 1);
    }
    // Rolled back on drop.
}

#[tokio::test]
async fn duplicate_key_package_ref_is_rejected() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = seed_owner(&mut tx, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", "dupref").await;
    let now = clock(&mut tx).await;
    let (r, w, k, nb, na) = package("dupref", now);
    let (_r2, w2, k2, _nb2, _na2) = package("dupref-other", now);
    // Two packages sharing the same key_package_ref but distinct init keys.
    let packages = vec![
        NewKeyPackage {
            key_package_ref: &r,
            wrapper_bytes: &w,
            init_key: &k,
            not_before_unix: nb,
            not_after_unix: na,
        },
        NewKeyPackage {
            key_package_ref: &r,
            wrapper_bytes: &w2,
            init_key: &k2,
            not_before_unix: nb,
            not_after_unix: na,
        },
    ];
    let owner_ref = KeyPackageOwner {
        user_did: &owner.did,
        device_id: owner.device_id,
        key_id: &owner.key_id,
        auth_generation: 1,
    };
    let error = publish_key_packages(&mut tx, &owner_ref, &packages, now)
        .await
        .expect_err("duplicate ref rejected");
    assert!(matches!(
        error,
        KeyPackageRepositoryError::DuplicateKeyPackage
    ));
}

#[tokio::test]
async fn duplicate_init_key_is_rejected() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = seed_owner(&mut tx, "did:plc:cccccccccccccccccccccccc", "dupinit").await;
    let now = clock(&mut tx).await;
    let (r, w, k, nb, na) = package("dupinit", now);
    let (r2, w2, _k2, _nb2, _na2) = package("dupinit-other", now);
    // Distinct refs, shared init_key.
    let packages = vec![
        NewKeyPackage {
            key_package_ref: &r,
            wrapper_bytes: &w,
            init_key: &k,
            not_before_unix: nb,
            not_after_unix: na,
        },
        NewKeyPackage {
            key_package_ref: &r2,
            wrapper_bytes: &w2,
            init_key: &k,
            not_before_unix: nb,
            not_after_unix: na,
        },
    ];
    let owner_ref = KeyPackageOwner {
        user_did: &owner.did,
        device_id: owner.device_id,
        key_id: &owner.key_id,
        auth_generation: 1,
    };
    let error = publish_key_packages(&mut tx, &owner_ref, &packages, now)
        .await
        .expect_err("duplicate init key rejected");
    assert!(matches!(
        error,
        KeyPackageRepositoryError::DuplicateKeyPackage
    ));
}

#[tokio::test]
async fn revoked_owner_is_rejected_before_any_write() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = seed_owner(&mut tx, "did:plc:dddddddddddddddddddddddd", "revoked").await;
    let now = clock(&mut tx).await;
    // Revoke the owning key (a full devices status='revoked' row additionally
    // requires the DDL revocation-shape columns; a revoked key alone is enough
    // to exercise the sink's revoked-owner guard).
    sqlx::query("UPDATE chat.device_keys SET revoked_at=$4 WHERE user_did=$1 AND device_id=$2 AND key_id=$3")
        .bind(&owner.did)
        .bind(owner.device_id)
        .bind(&owner.key_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .expect("revoke key");

    let (r, w, k, nb, na) = package("revoked", now);
    let packages = vec![NewKeyPackage {
        key_package_ref: &r,
        wrapper_bytes: &w,
        init_key: &k,
        not_before_unix: nb,
        not_after_unix: na,
    }];
    let owner_ref = KeyPackageOwner {
        user_did: &owner.did,
        device_id: owner.device_id,
        key_id: &owner.key_id,
        auth_generation: 1,
    };
    let error = publish_key_packages(&mut tx, &owner_ref, &packages, now)
        .await
        .expect_err("revoked owner rejected");
    assert!(matches!(error, KeyPackageRepositoryError::OwnerRevoked));

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.key_packages WHERE owner_did=$1 AND owner_device_id=$2",
    )
    .bind(&owner.did)
    .bind(owner.device_id)
    .fetch_one(&mut *tx)
    .await
    .expect("count");
    assert_eq!(count, 0, "no rows written for a revoked owner");
}

#[tokio::test]
async fn missing_owner_key_is_rejected() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let mut tx = pool.begin().await.expect("begin");
    let now = clock(&mut tx).await;
    let (r, w, k, nb, na) = package("missing", now);
    let packages = vec![NewKeyPackage {
        key_package_ref: &r,
        wrapper_bytes: &w,
        init_key: &k,
        not_before_unix: nb,
        not_after_unix: na,
    }];
    // No principal/device/device_key seeded.
    let owner_ref = KeyPackageOwner {
        user_did: "did:plc:eeeeeeeeeeeeeeeeeeeeeeee",
        device_id: Uuid::new_v4(),
        key_id: &base64url_sha256("missing-key"),
        auth_generation: 1,
    };
    let error = publish_key_packages(&mut tx, &owner_ref, &packages, now)
        .await
        .expect_err("missing owner key rejected");
    assert!(matches!(error, KeyPackageRepositoryError::OwnerKeyMissing));
}

#[tokio::test]
async fn out_of_range_lifetime_hits_the_ddl_check() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = seed_owner(&mut tx, "did:plc:ffffffffffffffffffffffff", "lifetime").await;
    let now = clock(&mut tx).await;
    let r = digest32("lifetime-ref");
    let w = digest32("lifetime-wrap");
    let k = digest32("lifetime-init");
    // not_after only 100s after created_at violates the >= 600s lifetime CHECK.
    let nb = (now - Duration::seconds(60)).timestamp() as u64;
    let na = (now + Duration::seconds(100)).timestamp() as u64;
    let packages = vec![NewKeyPackage {
        key_package_ref: &r,
        wrapper_bytes: &w,
        init_key: &k,
        not_before_unix: nb,
        not_after_unix: na,
    }];
    let owner_ref = KeyPackageOwner {
        user_did: &owner.did,
        device_id: owner.device_id,
        key_id: &owner.key_id,
        auth_generation: 1,
    };
    let error = publish_key_packages(&mut tx, &owner_ref, &packages, now)
        .await
        .expect_err("short lifetime rejected");
    assert!(matches!(
        error,
        KeyPackageRepositoryError::ConstraintViolation
    ));
}

#[tokio::test]
async fn empty_batch_is_rejected() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = seed_owner(&mut tx, "did:plc:gggggggggggggggggggggggg", "empty").await;
    let now = clock(&mut tx).await;
    let owner_ref = KeyPackageOwner {
        user_did: &owner.did,
        device_id: owner.device_id,
        key_id: &owner.key_id,
        auth_generation: 1,
    };
    let error = publish_key_packages(&mut tx, &owner_ref, &[], now)
        .await
        .expect_err("empty batch rejected");
    assert!(matches!(error, KeyPackageRepositoryError::EmptyBatch));
}

#[tokio::test]
async fn batch_exceeding_live_limit_is_rejected_without_writing() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = seed_owner(&mut tx, "did:plc:hhhhhhhhhhhhhhhhhhhhhhhh", "limit").await;
    let now = clock(&mut tx).await;
    // 1001 distinct packages exceed the 1000 per-device live-inventory limit and
    // are rejected proactively — no rows are written.
    let raw: Vec<_> = (0..1001)
        .map(|i| package(&format!("limit-{i}"), now))
        .collect();
    let packages: Vec<NewKeyPackage> = raw
        .iter()
        .map(|(r, w, k, nb, na)| NewKeyPackage {
            key_package_ref: r,
            wrapper_bytes: w,
            init_key: k,
            not_before_unix: *nb,
            not_after_unix: *na,
        })
        .collect();
    let owner_ref = KeyPackageOwner {
        user_did: &owner.did,
        device_id: owner.device_id,
        key_id: &owner.key_id,
        auth_generation: 1,
    };
    let error = publish_key_packages(&mut tx, &owner_ref, &packages, now)
        .await
        .expect_err("over-limit batch rejected");
    assert!(matches!(
        error,
        KeyPackageRepositoryError::LiveLimitExceeded
    ));

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.key_packages WHERE owner_did=$1 AND owner_device_id=$2",
    )
    .bind(&owner.did)
    .bind(owner.device_id)
    .fetch_one(&mut *tx)
    .await
    .expect("count");
    assert_eq!(count, 0, "no rows written when the batch is rejected");
}
