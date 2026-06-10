//! getKeyPackages authorization coverage for WS-1.1.
//!
//! The handler must not let an arbitrary authenticated DID claim or enumerate
//! another user's key packages. These tests exercise the DB-backed target
//! authorization helper directly so the rule is covered without depending on
//! JWT signing or live PDS block-sync network calls.

use catbird_server::handlers::mls_chat::get_key_packages::authorize_get_key_package_targets;
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::time::Duration as StdDuration;
use uuid::Uuid;

async fn setup_test_db() -> PgPool {
    let db_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://catbird:changeme@localhost:5433/catbird".to_string());

    let config = catbird_server::db::DbConfig {
        database_url: db_url,
        max_connections: 8,
        min_connections: 2,
        acquire_timeout: StdDuration::from_secs(10),
        idle_timeout: StdDuration::from_secs(60),
    };

    catbird_server::db::init_db(config)
        .await
        .expect("Failed to initialize test database")
}

async fn ensure_user(pool: &PgPool, did: &str) {
    sqlx::query(
        "INSERT INTO users (did, created_at, last_seen_at)
         VALUES ($1, NOW(), NOW())
         ON CONFLICT (did) DO NOTHING",
    )
    .bind(did)
    .execute(pool)
    .await
    .expect("ensure_user");
}

async fn cleanup(pool: &PgPool, dids: &[&str], convo_ids: &[&str]) {
    for convo_id in convo_ids {
        let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
            .bind(convo_id)
            .execute(pool)
            .await;
    }
    for did in dids {
        let _ =
            sqlx::query("DELETE FROM chat_requests WHERE sender_did = $1 OR recipient_did = $1")
                .bind(did)
                .execute(pool)
                .await;
        let _ = sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(did)
            .execute(pool)
            .await;
    }
}

async fn seed_conversation_with_members(
    pool: &PgPool,
    convo_id: &str,
    creator_did: &str,
    members: &[(&str, Option<chrono::DateTime<Utc>>)],
) {
    sqlx::query(
        "INSERT INTO conversations (id, creator_did, current_epoch, group_id, created_at, updated_at)
         VALUES ($1, $2, 0, $1, NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(convo_id)
    .bind(creator_did)
    .execute(pool)
    .await
    .expect("insert conversation");

    for (did, left_at) in members {
        let member_did = format!("{did}#device-test");
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, joined_at, left_at)
             VALUES ($1, $2, $3, NOW(), $4)
             ON CONFLICT (convo_id, member_did) DO UPDATE
             SET user_did = EXCLUDED.user_did,
                 left_at = EXCLUDED.left_at",
        )
        .bind(convo_id)
        .bind(member_did)
        .bind(*did)
        .bind(left_at)
        .execute(pool)
        .await
        .expect("insert member");
    }
}

async fn seed_pending_chat_request(pool: &PgPool, sender_did: &str, recipient_did: &str) {
    sqlx::query(
        "INSERT INTO chat_requests
            (id, sender_did, recipient_did, status, created_at, expires_at, updated_at)
         VALUES ($1, $2, $3, 'pending'::chat_request_status, NOW(), $4, NOW())",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(sender_did)
    .bind(recipient_did)
    .bind(Utc::now() + Duration::days(1))
    .execute(pool)
    .await
    .expect("insert pending chat request");
}

#[tokio::test]
async fn non_member_without_pending_relationship_gets_no_authorized_targets() {
    let pool = setup_test_db().await;
    let run_id = Uuid::new_v4();
    let caller = format!("did:plc:ws1-caller-{run_id}");
    let target = format!("did:plc:ws1-target-{run_id}");
    ensure_user(&pool, &caller).await;
    ensure_user(&pool, &target).await;

    let authorized = authorize_get_key_package_targets(&pool, &caller, &[target.as_str()])
        .await
        .expect("authz query");

    assert!(authorized.is_empty());

    cleanup(&pool, &[caller.as_str(), target.as_str()], &[]).await;
}

#[tokio::test]
async fn shared_conversation_authorizes_target() {
    let pool = setup_test_db().await;
    let run_id = Uuid::new_v4();
    let caller = format!("did:plc:ws1-caller-{run_id}");
    let target = format!("did:plc:ws1-target-{run_id}");
    let convo_id = format!("ws1-shared-{run_id}");
    ensure_user(&pool, &caller).await;
    ensure_user(&pool, &target).await;
    seed_conversation_with_members(
        &pool,
        &convo_id,
        &caller,
        &[(caller.as_str(), None), (target.as_str(), None)],
    )
    .await;

    let authorized = authorize_get_key_package_targets(&pool, &caller, &[target.as_str()])
        .await
        .expect("authz query");

    assert_eq!(authorized, vec![target.clone()]);

    cleanup(
        &pool,
        &[caller.as_str(), target.as_str()],
        &[convo_id.as_str()],
    )
    .await;
}

#[tokio::test]
async fn pending_chat_request_authorizes_target() {
    let pool = setup_test_db().await;
    let run_id = Uuid::new_v4();
    let caller = format!("did:plc:ws1-caller-{run_id}");
    let target = format!("did:plc:ws1-target-{run_id}");
    ensure_user(&pool, &caller).await;
    ensure_user(&pool, &target).await;
    seed_pending_chat_request(&pool, &caller, &target).await;

    let authorized = authorize_get_key_package_targets(&pool, &caller, &[target.as_str()])
        .await
        .expect("authz query");

    assert_eq!(authorized, vec![target.clone()]);

    cleanup(&pool, &[caller.as_str(), target.as_str()], &[]).await;
}

#[tokio::test]
async fn self_target_is_authorized() {
    let pool = setup_test_db().await;
    let caller = format!("did:plc:ws1-caller-{}", Uuid::new_v4());
    ensure_user(&pool, &caller).await;

    let authorized = authorize_get_key_package_targets(&pool, &caller, &[caller.as_str()])
        .await
        .expect("authz query");

    assert_eq!(authorized, vec![caller.clone()]);

    cleanup(&pool, &[caller.as_str()], &[]).await;
}

#[tokio::test]
async fn left_membership_does_not_authorize_target() {
    let pool = setup_test_db().await;
    let run_id = Uuid::new_v4();
    let caller = format!("did:plc:ws1-caller-{run_id}");
    let target = format!("did:plc:ws1-target-{run_id}");
    let convo_id = format!("ws1-left-{run_id}");
    ensure_user(&pool, &caller).await;
    ensure_user(&pool, &target).await;
    seed_conversation_with_members(
        &pool,
        &convo_id,
        &caller,
        &[(caller.as_str(), None), (target.as_str(), Some(Utc::now()))],
    )
    .await;

    let authorized = authorize_get_key_package_targets(&pool, &caller, &[target.as_str()])
        .await
        .expect("authz query");

    assert!(authorized.is_empty());

    cleanup(
        &pool,
        &[caller.as_str(), target.as_str()],
        &[convo_id.as_str()],
    )
    .await;
}
