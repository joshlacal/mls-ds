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
        &lock,
        &[],
        b"must-not-prepare",
        &[0; 32],
        now + Duration::seconds(1),
    )
    .await
    .unwrap();
    assert_eq!(replay, result);
    let lock = test_lock(&mut tx, i).await;
    let replay = finish_terminal_charged(
        &mut tx,
        lock,
        TerminalOutcome::Published,
        b"must-not-publish",
        Some(&[9; 32]),
        now + Duration::seconds(600),
        Some(MAX_BUNDLE_BYTES),
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
        .bind(i.request_id).bind(&i.actor_did).bind(i.actor_device_id).bind(&i.actor_key_id).bind(&i.recipient_did).bind(&i.prepare_digest).bind(vec![4_u8;32]).bind(now).bind(now+Duration::seconds(300)).execute(&mut *tx).await.unwrap();
    let lock = test_lock(&mut tx, i.clone()).await;
    finish_terminal_charged(
        &mut tx,
        lock,
        TerminalOutcome::Published,
        b"published-exact",
        Some(&[8; 32]),
        now,
        Some(MAX_BUNDLE_BYTES),
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

#[tokio::test]
async fn delayed_prepare_waits_for_committed_cancellation_fence() {
    let pool = crate::common::direct_request_database::setup().await;
    let i = test_identity();
    let mut tx = pool.begin().await.unwrap();
    let lock = test_lock(&mut tx, i.clone()).await;
    finish_terminal(
        &mut tx,
        lock,
        TerminalOutcome::Cancelled,
        b"committed-cancel",
        None,
        Utc::now(),
    )
    .await
    .unwrap();
    let pool2 = pool.clone();
    let mut delayed = tokio::spawn(async move {
        let mut late = pool2.begin().await.unwrap();
        let lock = test_lock(&mut late, i).await;
        let replay =
            reserve_preparation(&mut late, &lock, &[], b"late-prepare", &[4; 32], Utc::now())
                .await
                .unwrap();
        late.commit().await.unwrap();
        replay
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut delayed)
            .await
            .is_err(),
        "operation lock must serialize delayed preparation"
    );
    tx.commit().await.unwrap();
    assert_eq!(delayed.await.unwrap(), b"committed-cancel");
    // The committed tombstone is intentionally retained in this dedicated
    // database; tests do not bypass the no-delete history invariant.
}

#[tokio::test]
async fn nullable_receipt_and_snapshot_fields_cannot_bypass_database_checks() {
    let pool = crate::common::direct_request_database::setup().await;
    for status in ["cancelled", "prepared"] {
        let mut tx = pool.begin().await.unwrap();
        let i = test_identity();
        let error=sqlx::query("INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepared_at,selected_digest,lease_expires_at,terminal_at,created_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,CASE WHEN $7='prepared' THEN clock_timestamp() END,CASE WHEN $7='prepared' THEN $6 END,CASE WHEN $7='prepared' THEN clock_timestamp()+INTERVAL '5 seconds' END,CASE WHEN $7='cancelled' THEN clock_timestamp() END,clock_timestamp())")
            .bind(i.request_id).bind(i.actor_did).bind(i.actor_device_id).bind(i.actor_key_id).bind(i.recipient_did).bind(i.prepare_digest).bind(status).execute(&mut *tx).await.expect_err("null receipt or snapshot cannot authenticate state");
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
        tx.rollback().await.unwrap();
    }
}

#[tokio::test]
async fn acceptance_operation_prefix_sorts_all_ids_before_budget_lock() {
    let pool = crate::common::direct_request_database::setup().await;
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let mut tx = pool.begin().await.unwrap();
    super::prelude::lock_direct_request_operation_set(&mut tx, first, &[second])
        .await
        .unwrap();
    let pool2 = pool.clone();
    let mut competing = tokio::spawn(async move {
        let mut tx = pool2.begin().await.unwrap();
        super::prelude::lock_direct_request_operation_set(&mut tx, second, &[first])
            .await
            .unwrap();
        tx.commit().await.unwrap();
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut competing)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), competing)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn publication_compare_exchange_rejects_expiry_after_captured_admission_time() {
    let pool = crate::common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let i = test_identity();
    let now = Utc::now();
    let admitted = now - Duration::seconds(299);
    let _lock = test_lock(&mut tx, i.clone()).await;
    sqlx::query("INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepare_response,selected_digest,prepared_at,lease_expires_at,created_at) VALUES($1,$2,$3,$4,1,$5,$6,'prepared','prepared',$7,$8,$9,$8)")
        .bind(i.request_id).bind(&i.actor_did).bind(i.actor_device_id).bind(&i.actor_key_id).bind(&i.recipient_did).bind(&i.prepare_digest).bind(vec![4_u8;32]).bind(admitted).bind(now-Duration::seconds(1)).execute(&mut *tx).await.unwrap();
    let lock = test_lock(&mut tx, i.clone()).await;
    assert!(matches!(
        finish_terminal_charged(
            &mut tx,
            lock,
            TerminalOutcome::Published,
            b"must-not-publish",
            Some(&[8; 32]),
            admitted,
            Some(MAX_BUNDLE_BYTES),
        )
        .await,
        Err(DirectRequestStoreError::Expired)
    ));
    let status: String =
        sqlx::query_scalar("SELECT status FROM chat.direct_request_attempts WHERE request_id=$1")
            .bind(i.request_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(status, "prepared");
    let lock = test_lock(&mut tx, i).await;
    finish_terminal(
        &mut tx,
        lock,
        TerminalOutcome::Rejected,
        b"expiry-rejection",
        None,
        now,
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn publication_artifact_topup_and_capacity_rejection_are_atomic() {
    let pool = crate::common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let i = test_identity();
    let now = Utc::now();
    let _lock = test_lock(&mut tx, i.clone()).await;
    sqlx::query("INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepare_response,selected_digest,prepared_at,lease_expires_at,reserved_bytes,created_at) VALUES($1,$2,$3,$4,1,$5,$6,'prepared','prepared',$7,$8,$9,$10,$8)")
        .bind(i.request_id).bind(&i.actor_did).bind(i.actor_device_id).bind(&i.actor_key_id).bind(&i.recipient_did).bind(&i.prepare_digest).bind(vec![4_u8;32]).bind(now).bind(now+Duration::seconds(300)).bind(MAX_BUNDLE_BYTES).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE chat.direct_request_budget SET pending_bytes=pending_bytes+$1,retained_bytes=retained_bytes+$1 WHERE singleton")
        .bind(MAX_BUNDLE_BYTES).execute(&mut *tx).await.unwrap();
    let before: (i64, i64) = sqlx::query_as(
        "SELECT pending_bytes,retained_bytes FROM chat.direct_request_budget WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    sqlx::query("SAVEPOINT before_charge")
        .execute(&mut *tx)
        .await
        .unwrap();
    let lock = test_lock(&mut tx, i.clone()).await;
    finish_terminal_charged(
        &mut tx,
        lock,
        TerminalOutcome::Published,
        b"synthetic-large-publication",
        Some(&[8; 32]),
        now,
        Some(MAX_BUNDLE_BYTES * 2),
    )
    .await
    .unwrap();
    let after: (i64, i64) = sqlx::query_as(
        "SELECT pending_bytes,retained_bytes FROM chat.direct_request_budget WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(
        after,
        (before.0 + MAX_BUNDLE_BYTES, before.1 + MAX_BUNDLE_BYTES)
    );
    let charge: i64 = sqlx::query_scalar(
        "SELECT charged_bytes FROM chat.direct_request_retained_charges WHERE request_id=$1",
    )
    .bind(i.request_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(charge, MAX_BUNDLE_BYTES * 2);
    sqlx::query("ROLLBACK TO SAVEPOINT before_charge")
        .execute(&mut *tx)
        .await
        .unwrap();
    let restored: (i64, i64) = sqlx::query_as(
        "SELECT pending_bytes,retained_bytes FROM chat.direct_request_budget WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(restored, before);
    sqlx::query("UPDATE chat.direct_request_budget SET retained_bytes=$1 WHERE singleton")
        .bind(MAX_RETAINED_GLOBAL_BYTES)
        .execute(&mut *tx)
        .await
        .unwrap();
    let lock = test_lock(&mut tx, i.clone()).await;
    assert!(matches!(
        finish_terminal_charged(
            &mut tx,
            lock,
            TerminalOutcome::Published,
            b"no-capacity",
            Some(&[8; 32]),
            now,
            Some(MAX_BUNDLE_BYTES * 2)
        )
        .await,
        Err(DirectRequestStoreError::QuotaExceeded)
    ));
    let unchanged: (i64, i64) = sqlx::query_as(
        "SELECT pending_bytes,retained_bytes FROM chat.direct_request_budget WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(unchanged, (before.0, MAX_RETAINED_GLOBAL_BYTES));
    let lock = test_lock(&mut tx, i.clone()).await;
    finish_terminal(
        &mut tx,
        lock,
        TerminalOutcome::Rejected,
        b"capacity-rejection",
        None,
        now,
    )
    .await
    .unwrap();
    let settled: i64 = sqlx::query_scalar(
        "SELECT charged_bytes FROM chat.direct_request_retained_charges WHERE request_id=$1",
    )
    .bind(i.request_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(settled > 0 && settled < MAX_BUNDLE_BYTES);
    let final_budget: (i64, i64) = sqlx::query_as(
        "SELECT pending_bytes,retained_bytes FROM chat.direct_request_budget WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(
        final_budget,
        (
            before.0 - MAX_BUNDLE_BYTES,
            MAX_RETAINED_GLOBAL_BYTES - MAX_BUNDLE_BYTES + settled
        )
    );
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn retained_history_is_charged_to_each_account_after_pending_ends() {
    let pool = crate::common::direct_request_database::setup().await;
    for recipient_history in [false, true] {
        let mut tx = pool.begin().await.unwrap();
        let i = test_identity();
        let now = Utc::now();
        let lock = test_lock(&mut tx, i.clone()).await;
        let mut prior = test_identity();
        if recipient_history {
            prior.actor_did = i.recipient_did.clone();
            prior.recipient_did = "did:plc:cccccccccccccccccccccccc".into();
        } else {
            prior.actor_did = "did:plc:cccccccccccccccccccccccc".into();
            prior.recipient_did = i.actor_did.clone();
        }
        let charged = retained_account_limit().unwrap() - 4 * 1024 * 1024;
        // Synthetic immutable history isolates accounting from cryptographic
        // validation; this transaction never commits a protocol receipt.
        sqlx::query("INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,terminal_at,terminal_response,terminal_response_sha256,reserved_bytes,created_at) VALUES($1,$2,$3,$4,1,$5,$6,'cancelled',$7,'retained-history',$8,$9,$7)")
            .bind(prior.request_id).bind(&prior.actor_did).bind(prior.actor_device_id).bind(&prior.actor_key_id).bind(&prior.recipient_did).bind(&prior.prepare_digest).bind(now).bind(Sha256::digest(b"retained-history").to_vec()).bind(charged).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO chat.direct_request_retained_charges(request_id,charged_bytes,model_version,recorded_at) VALUES($1,$2,1,$3)")
            .bind(prior.request_id).bind(charged).bind(now).execute(&mut *tx).await.unwrap();
        sqlx::query("UPDATE chat.direct_request_budget SET retained_bytes=retained_bytes+$1 WHERE singleton")
            .bind(charged).execute(&mut *tx).await.unwrap();
        assert!(matches!(
            validate_terminal_charge(&mut tx, &lock, MAX_BUNDLE_BYTES * 2, true).await,
            Err(DirectRequestStoreError::QuotaExceeded)
        ));
        tx.rollback().await.unwrap();
    }
}
