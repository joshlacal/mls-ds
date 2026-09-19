use base64::Engine as _;
use sqlx::Acquire as _;
async fn test_lock(tx: &mut Transaction<'_, Postgres>, identity: AttemptIdentity) -> LockedAttempt {
    let operation = super::prelude::lock_direct_request_operation(tx, identity.request_id)
        .await
        .unwrap();
    load_locked_attempt(tx, identity, &operation).await.unwrap()
}
fn test_identity() -> AttemptIdentity {
    AttemptIdentity {
        request_id: Uuid::new_v4(),
        actor_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
        actor_device_id: Uuid::new_v4(),
        actor_key_id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]),
        actor_auth_generation: 1,
        recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        prepare_digest: vec![2; 32],
    }
}
#[tokio::test]
async fn cancellation_of_unknown_fences_delayed_preparation_and_publication() {
    let pool = crate::common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let i = test_identity();
    let now = Utc::now();
    let lock = test_lock(&mut tx, i.clone()).await;
    assert!(lock.row.is_none());
    let result = finish_terminal(
        &mut tx,
        lock,
        TerminalOutcome::Cancelled,
        b"exact-cancellation-receipt",
        None,
        now,
    )
    .await
    .unwrap();
    let lock = test_lock(&mut tx, i.clone()).await;
    let replay = reserve_preparation(
        &mut tx,
        lock,
        &[],
        b"must-not-prepare",
        &[0; 32],
        now + Duration::seconds(1),
    )
    .await
    .unwrap();
    assert_eq!(replay, result);
    let lock = test_lock(&mut tx, i).await;
    let replay = finish_terminal(
        &mut tx,
        lock,
        TerminalOutcome::Published,
        b"must-not-publish",
        Some(&[9; 32]),
        now + Duration::seconds(600),
    )
    .await
    .unwrap();
    assert_eq!(replay, result);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.direct_request_selected_devices")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(count, 0);
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn unknown_read_is_nonterminal_and_different_attempt_digest_conflicts() {
    let pool = crate::common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let i = test_identity();
    let lock = test_lock(&mut tx, i.clone()).await;
    assert!(lock.row.is_none());
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id=$1")
            .bind(i.request_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(count, 0);
    finish_terminal(
        &mut tx,
        lock,
        TerminalOutcome::Cancelled,
        b"cancel",
        None,
        Utc::now(),
    )
    .await
    .unwrap();
    let mut altered = i.clone();
    altered.prepare_digest = vec![3; 32];
    let operation = super::prelude::lock_direct_request_operation(&mut tx, i.request_id)
        .await
        .unwrap();
    assert!(matches!(
        load_locked_attempt(&mut tx, altered, &operation).await,
        Err(DirectRequestStoreError::IdentityConflict)
    ));
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn terminal_tombstone_and_receipt_are_database_immutable() {
    let pool = crate::common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let i = test_identity();
    let lock = test_lock(&mut tx, i.clone()).await;
    finish_terminal(
        &mut tx,
        lock,
        TerminalOutcome::Cancelled,
        b"cancel",
        None,
        Utc::now(),
    )
    .await
    .unwrap();
    let mut sp = tx.begin().await.unwrap();
    assert!(sqlx::query(
        "UPDATE chat.direct_request_attempts SET terminal_response='tampered' WHERE request_id=$1"
    )
    .bind(i.request_id)
    .execute(&mut *sp)
    .await
    .is_err());
    sp.rollback().await.unwrap();
    let mut sp = tx.begin().await.unwrap();
    assert!(
        sqlx::query("DELETE FROM chat.direct_request_attempts WHERE request_id=$1")
            .bind(i.request_id)
            .execute(&mut *sp)
            .await
            .is_err()
    );
    sp.rollback().await.unwrap();
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn published_receipt_replays_after_lease_expiry_and_cancel_cannot_overwrite() {
    let pool = crate::common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let i = test_identity();
    let now = Utc::now();
    let _lock = test_lock(&mut tx, i.clone()).await;
    sqlx::query("INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepare_response,selected_digest,prepared_at,lease_expires_at,created_at) VALUES($1,$2,$3,$4,1,$5,$6,'prepared','prepared',$7,$8,$9,$8)")
        .bind(i.request_id).bind(&i.actor_did).bind(i.actor_device_id).bind(&i.actor_key_id).bind(&i.recipient_did).bind(&i.prepare_digest).bind(vec![4;32]).bind(now).bind(now+Duration::seconds(300)).execute(&mut *tx).await.unwrap();
    let lock = test_lock(&mut tx, i.clone()).await;
    finish_terminal(
        &mut tx,
        lock,
        TerminalOutcome::Published,
        b"published-exact",
        Some(&[8; 32]),
        now,
    )
    .await
    .unwrap();
    let lock = test_lock(&mut tx, i).await;
    let replay = finish_terminal(
        &mut tx,
        lock,
        TerminalOutcome::Cancelled,
        b"cancel",
        None,
        now + Duration::days(30),
    )
    .await
    .unwrap();
    assert_eq!(replay, b"published-exact");
    tx.rollback().await.unwrap();
}
