//! getKeyPackages authorization coverage for WS-1.1.
//!
//! The handler must not let an arbitrary authenticated DID claim or enumerate
//! another user's key packages. These tests exercise the DB-backed target
//! authorization helper directly so the rule is covered without depending on
//! JWT signing or live PDS block-sync network calls.

use catbird_server::handlers::mls_chat::{
    get_key_package_status::authorize_get_key_package_status_target,
    get_key_packages::{
        apply_key_package_target_authz, authorize_get_key_package_targets,
        max_first_contact_targets_from_value, GateKeyPackagesMode,
    },
};
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

async fn seed_targeted_invite(pool: &PgPool, creator_did: &str, target_did: &str) -> String {
    let convo_id = format!("ws1-invite-{}", Uuid::new_v4());
    seed_conversation_with_members(pool, &convo_id, creator_did, &[(creator_did, None)]).await;

    sqlx::query(
        "INSERT INTO invites
            (id, convo_id, created_by_did, target_did, psk_hash, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), $6)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&convo_id)
    .bind(creator_did)
    .bind(target_did)
    .bind(format!("{:064x}", 1))
    .bind(Utc::now() + Duration::days(1))
    .execute(pool)
    .await
    .expect("insert targeted invite");

    convo_id
}

#[test]
fn key_package_gate_defaults_to_enforce_and_only_log_only_values_disable_strict_mode() {
    assert_eq!(
        GateKeyPackagesMode::from_env_value(None),
        GateKeyPackagesMode::Enforce
    );
    assert_eq!(
        GateKeyPackagesMode::from_env_value(Some("")),
        GateKeyPackagesMode::Enforce
    );
    assert_eq!(
        GateKeyPackagesMode::from_env_value(Some("log_only")),
        GateKeyPackagesMode::LogOnly
    );
    assert_eq!(
        GateKeyPackagesMode::from_env_value(Some("warn")),
        GateKeyPackagesMode::LogOnly
    );
    assert_eq!(
        GateKeyPackagesMode::from_env_value(Some("unexpected")),
        GateKeyPackagesMode::Enforce
    );
    assert_eq!(
        GateKeyPackagesMode::from_env_value(Some("enforce")),
        GateKeyPackagesMode::Enforce
    );
}

#[test]
fn max_first_contact_targets_resolves_env_with_default_fallback() {
    // default when unset / blank / invalid / non-positive
    assert_eq!(max_first_contact_targets_from_value(None), 32);
    assert_eq!(max_first_contact_targets_from_value(Some("")), 32);
    assert_eq!(max_first_contact_targets_from_value(Some("abc")), 32);
    assert_eq!(max_first_contact_targets_from_value(Some("0")), 32);
    assert_eq!(max_first_contact_targets_from_value(Some("-4")), 32);
    // explicit valid overrides, trimmed
    assert_eq!(max_first_contact_targets_from_value(Some("8")), 8);
    assert_eq!(max_first_contact_targets_from_value(Some(" 16 ")), 16);
}

#[test]
fn enforce_allows_single_first_contact_target() {
    let requested = vec!["did:plc:first-contact-target".to_string()];
    let authorized: Vec<String> = Vec::new();

    let log_only =
        apply_key_package_target_authz(&requested, &authorized, GateKeyPackagesMode::LogOnly, 32)
            .expect("log_only must preserve first-contact compatibility");
    assert_eq!(log_only, requested);

    let enforce =
        apply_key_package_target_authz(&requested, &authorized, GateKeyPackagesMode::Enforce, 32)
            .expect("enforce mode must allow a single first-contact key-package fetch");
    assert_eq!(enforce, requested);
}

#[test]
fn enforce_allows_first_contact_batch_within_bound() {
    let requested = vec![
        "did:plc:first-contact-a".to_string(),
        "did:plc:first-contact-b".to_string(),
    ];
    let authorized: Vec<String> = Vec::new();

    let enforce =
        apply_key_package_target_authz(&requested, &authorized, GateKeyPackagesMode::Enforce, 32)
            .expect("a 2-target first-contact group-create batch must be allowed under the bound");
    // Order preserved, full request returned for the key-package fetch.
    assert_eq!(enforce, requested);
}

#[test]
fn enforce_denies_first_contact_batch_over_bound() {
    let requested = vec![
        "did:plc:first-contact-a".to_string(),
        "did:plc:first-contact-b".to_string(),
        "did:plc:first-contact-c".to_string(),
    ];
    let authorized: Vec<String> = Vec::new();

    // bound = 2, three DISTINCT first-contact targets → fail closed
    let enforce =
        apply_key_package_target_authz(&requested, &authorized, GateKeyPackagesMode::Enforce, 2);
    assert_eq!(enforce, Err(axum::http::StatusCode::FORBIDDEN));
}

#[test]
fn enforce_allows_mixed_authorized_and_first_contact() {
    let requested = vec![
        "did:plc:authorized".to_string(),
        "did:plc:unauthorized".to_string(),
    ];
    let authorized = vec!["did:plc:authorized".to_string()];

    // one first-contact (<= bound) alongside an authorized target → allowed
    let enforce =
        apply_key_package_target_authz(&requested, &authorized, GateKeyPackagesMode::Enforce, 32)
            .expect("mixed batch with a single first-contact must be allowed");
    assert_eq!(enforce, requested);
}

#[test]
fn enforce_counts_distinct_first_contacts_for_bound() {
    let authorized: Vec<String> = Vec::new();

    // 3 entries, 1 DISTINCT first-contact, bound = 1 → allowed, returned as-is
    let dup = vec![
        "did:plc:dup".to_string(),
        "did:plc:dup".to_string(),
        "did:plc:dup".to_string(),
    ];
    let allowed =
        apply_key_package_target_authz(&dup, &authorized, GateKeyPackagesMode::Enforce, 1)
            .expect("duplicates of one DID count once against the bound");
    assert_eq!(
        allowed, dup,
        "order and duplicates preserved in returned vec"
    );

    // 2 DISTINCT first-contacts, bound = 1 → denied
    let two = vec!["did:plc:a".to_string(), "did:plc:b".to_string()];
    let denied = apply_key_package_target_authz(&two, &authorized, GateKeyPackagesMode::Enforce, 1);
    assert_eq!(denied, Err(axum::http::StatusCode::FORBIDDEN));
}

#[test]
fn enforce_allows_when_all_targets_authorized() {
    let requested = vec!["did:plc:a".to_string(), "did:plc:b".to_string()];
    let authorized = vec!["did:plc:a".to_string(), "did:plc:b".to_string()];

    // even bound = 0 cannot deny a batch with zero first-contacts
    let enforce =
        apply_key_package_target_authz(&requested, &authorized, GateKeyPackagesMode::Enforce, 0)
            .expect("a fully relationship-authorized batch is always allowed");
    assert_eq!(enforce, requested);
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
async fn targeted_invite_authorizes_target() {
    let pool = setup_test_db().await;
    let run_id = Uuid::new_v4();
    let caller = format!("did:plc:ws1-caller-{run_id}");
    let target = format!("did:plc:ws1-target-{run_id}");
    ensure_user(&pool, &caller).await;
    ensure_user(&pool, &target).await;
    let convo_id = seed_targeted_invite(&pool, &caller, &target).await;

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
async fn status_target_authz_logs_in_log_only_but_denies_count_oracle_in_enforce() {
    let pool = setup_test_db().await;
    let run_id = Uuid::new_v4();
    let caller = format!("did:plc:ws1-caller-{run_id}");
    let target = format!("did:plc:ws1-target-{run_id}");
    ensure_user(&pool, &caller).await;
    ensure_user(&pool, &target).await;

    let log_only = authorize_get_key_package_status_target(
        &pool,
        &caller,
        &target,
        GateKeyPackagesMode::LogOnly,
    )
    .await
    .expect("status authz query");
    assert!(!log_only.authorized);
    assert!(
        log_only.allowed,
        "log_only preserves compatibility but must still surface a WARN in the handler"
    );

    let enforce = authorize_get_key_package_status_target(
        &pool,
        &caller,
        &target,
        GateKeyPackagesMode::Enforce,
    )
    .await
    .expect("status authz query");
    assert!(!enforce.authorized);
    assert!(
        !enforce.allowed,
        "status uses deny-on-any in enforce mode to avoid key-package count oracles"
    );

    cleanup(&pool, &[caller.as_str(), target.as_str()], &[]).await;
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
