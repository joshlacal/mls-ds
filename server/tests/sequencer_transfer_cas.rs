mod common;

use std::time::Duration;

use catbird_server::federation::{SequencerTransfer, TransferError};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_conversation(pool: &PgPool, convo_id: &str, sequencer_ds: &str, term: i64) {
    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, sequencer_term, sequencer_ds, created_at, updated_at, group_id) \
         VALUES ($1, $2, 7, $3, $2, NOW(), NOW(), $1)",
    )
    .bind(convo_id)
    .bind(sequencer_ds)
    .bind(term)
    .execute(pool)
    .await
    .expect("seed conversation");
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn accept_transfer_rejects_owner_change_between_read_and_update() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = format!("ws1-transfer-cas-{}", Uuid::new_v4());
    let from_ds = format!("did:web:sequencer-from-{}.example", Uuid::new_v4());
    let accepting_ds = format!("did:web:sequencer-accept-{}.example", Uuid::new_v4());
    let concurrent_ds = format!("did:web:sequencer-race-{}.example", Uuid::new_v4());

    seed_conversation(&pool, &convo_id, &from_ds, 5).await;

    let mut tx = pool.begin().await.expect("begin locking tx");
    sqlx::query("UPDATE conversations SET updated_at = updated_at WHERE id = $1")
        .bind(&convo_id)
        .execute(&mut *tx)
        .await
        .expect("lock conversation row");

    let transfer = SequencerTransfer::new(pool.clone(), accepting_ds.clone());
    let task_convo_id = convo_id.clone();
    let task_from_ds = from_ds.clone();
    let accept_task = tokio::spawn(async move {
        transfer
            .accept_transfer(&task_convo_id, &task_from_ds, 6)
            .await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !accept_task.is_finished(),
        "accept_transfer should be blocked behind the row lock before the race is committed"
    );

    sqlx::query(
        "UPDATE conversations \
         SET sequencer_ds = $2, sequencer_term = 6, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(&convo_id)
    .bind(&concurrent_ds)
    .execute(&mut *tx)
    .await
    .expect("commit concurrent owner change");
    tx.commit().await.expect("commit locking tx");

    let result = tokio::time::timeout(Duration::from_secs(5), accept_task)
        .await
        .expect("accept_transfer completed")
        .expect("accept_transfer task joined");

    assert!(
        matches!(result, Err(TransferError::NotCurrentSequencer { .. })),
        "accept_transfer must reject a stale observed owner/term instead of overwriting it: {result:?}"
    );

    let (sequencer_ds, sequencer_term): (Option<String>, i64) =
        sqlx::query_as("SELECT sequencer_ds, sequencer_term FROM conversations WHERE id = $1")
            .bind(&convo_id)
            .fetch_one(&pool)
            .await
            .expect("read final conversation state");
    assert_eq!(sequencer_ds.as_deref(), Some(concurrent_ds.as_str()));
    assert_eq!(sequencer_term, 6);

    common::cleanup(&pool, &convo_id).await;
}

/// N30: `initiate_transfer` must carry the same `(owner, term)` CAS fence as
/// `accept_transfer`. A failover (`assume_sequencer_role`) that lands between
/// the initiating DS's read and its UPDATE must not be silently overwritten.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn initiate_transfer_rejects_owner_change_between_read_and_update() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = format!("ws1-initiate-cas-{}", Uuid::new_v4());
    let initiating_ds = format!("did:web:sequencer-init-{}.example", Uuid::new_v4());
    let new_ds = format!("did:web:sequencer-new-{}.example", Uuid::new_v4());
    let concurrent_ds = format!("did:web:sequencer-race-{}.example", Uuid::new_v4());

    // We are the current sequencer at term 5 and want to hand off to new_ds.
    seed_conversation(&pool, &convo_id, &initiating_ds, 5).await;

    let mut tx = pool.begin().await.expect("begin locking tx");
    sqlx::query("UPDATE conversations SET updated_at = updated_at WHERE id = $1")
        .bind(&convo_id)
        .execute(&mut *tx)
        .await
        .expect("lock conversation row");

    let transfer = SequencerTransfer::new(pool.clone(), initiating_ds.clone());
    let task_convo_id = convo_id.clone();
    let task_new_ds = new_ds.clone();
    let initiate_task = tokio::spawn(async move {
        transfer
            .initiate_transfer(&task_convo_id, &task_new_ds)
            .await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !initiate_task.is_finished(),
        "initiate_transfer should be blocked behind the row lock before the race is committed"
    );

    // Concurrent failover: another DS takes over at term 6 while our UPDATE
    // is blocked on the row lock.
    sqlx::query(
        "UPDATE conversations \
         SET sequencer_ds = $2, sequencer_term = 6, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(&convo_id)
    .bind(&concurrent_ds)
    .execute(&mut *tx)
    .await
    .expect("commit concurrent owner change");
    tx.commit().await.expect("commit locking tx");

    let result = tokio::time::timeout(Duration::from_secs(5), initiate_task)
        .await
        .expect("initiate_transfer completed")
        .expect("initiate_transfer task joined");

    assert!(
        matches!(result, Err(TransferError::NotCurrentSequencer { .. })),
        "initiate_transfer must reject a stale observed owner/term instead of overwriting it: {result:?}"
    );

    let (sequencer_ds, sequencer_term): (Option<String>, i64) =
        sqlx::query_as("SELECT sequencer_ds, sequencer_term FROM conversations WHERE id = $1")
            .bind(&convo_id)
            .fetch_one(&pool)
            .await
            .expect("read final conversation state");
    assert_eq!(
        sequencer_ds.as_deref(),
        Some(concurrent_ds.as_str()),
        "concurrent takeover must win; the fenced initiate_transfer must not clobber it"
    );
    assert_eq!(sequencer_term, 6);

    common::cleanup(&pool, &convo_id).await;
}

/// WS-4 rung 2 (ADR-010 D4): after a sequencer transfer is accepted, the
/// conversation's API projection (`convoView.sequencerDid`) must report the
/// NEW sequencer — not the previous owner and not the local default.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn transferred_conversation_reports_new_sequencer_in_convo_view() {
    use catbird_server::models::Conversation;

    let (pool, _database) = common::setup_test_db().await;
    let convo_id = format!("ws4-rung2-transfer-view-{}", Uuid::new_v4());
    let from_ds = format!("did:web:sequencer-from-{}.example", Uuid::new_v4());
    let accepting_ds = format!("did:web:sequencer-accept-{}.example", Uuid::new_v4());
    let local_ds = "did:web:local-ds.example";

    seed_conversation(&pool, &convo_id, &from_ds, 5).await;

    let transfer = SequencerTransfer::new(pool.clone(), accepting_ds.clone());
    transfer
        .accept_transfer(&convo_id, &from_ds, 6)
        .await
        .expect("accept_transfer succeeds without contention");

    let convo: Conversation = sqlx::query_as(
        "SELECT id, creator_did, current_epoch, created_at, updated_at, cipher_suite, \
                confirmation_tag, sequencer_ds, is_remote, group_id, reset_count \
         FROM conversations WHERE id = $1",
    )
    .bind(&convo_id)
    .fetch_one(&pool)
    .await
    .expect("load transferred conversation");

    let view = convo
        .to_convo_view(vec![], Some(local_ds))
        .expect("to_convo_view");
    assert_eq!(
        view.sequencer_did.as_ref().map(|d| d.as_str()),
        Some(accepting_ds.as_str()),
        "convoView.sequencerDid must report the NEW sequencer after transfer"
    );

    common::cleanup(&pool, &convo_id).await;
}
