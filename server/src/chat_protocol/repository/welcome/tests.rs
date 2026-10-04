use super::welcome::*;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[path = "../../../../tests/common/executor_seed.rs"]
mod executor_seed;

async fn clock_now(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .expect("sample trusted database clock")
}

#[tokio::test]
async fn claim_returns_the_seeded_due_welcome_delivery() {
    let (pool, _guard) = executor_seed::setup().await;
    let scenario = executor_seed::run_fulfillment_scenario(&pool).await;

    // The seeded delivery's `expires_at` is the consumed Add KeyPackage
    // `not_after` (~24h out); observe well past it so the row is due.
    let observed_at = clock_now(&pool).await + chrono::Duration::hours(48);
    let mut tx = pool.begin().await.expect("begin claim");
    let claimed = claim_due_welcome_deliveries(&mut tx, observed_at, 32)
        .await
        .expect("claim executes against the seeded schema");
    assert_eq!(
        claimed.len(),
        1,
        "exactly the one seeded pending delivery is due on the fresh DB"
    );
    let due = &claimed[0];
    assert_eq!(due.welcome_id, scenario.welcome_id);
    assert_eq!(due.conversation_id, scenario.conversation_id);
    assert_eq!(due.recovery_request_id, scenario.recovery_request_id);
    assert_eq!(due.recipient_did, scenario.bob_did);
    assert_eq!(
        due.recipient_device_id,
        Uuid::from_bytes(*scenario.bob_id.device_id())
    );
    assert!(due.expires_at <= observed_at);
    // The fulfillment committed at entry seq 3 / state_version 2 (run_fulfillment
    // scenario proves allocated_seq == 3 and the sv-2 commit gen state).
    assert_eq!(due.transition_seq, 3);
    assert_eq!(due.state_version, 2);
    tx.rollback().await.expect("rollback claim");
}

#[tokio::test]
async fn two_workers_never_double_claim_the_seeded_delivery() {
    let (pool, _guard) = executor_seed::setup().await;
    let _scenario = executor_seed::run_fulfillment_scenario(&pool).await;
    let observed_at = clock_now(&pool).await + chrono::Duration::hours(48);

    // Worker 1 claims + locks the one due delivery, holding its transaction open.
    let mut tx1 = pool.begin().await.expect("begin worker 1");
    let claimed1 = claim_due_welcome_deliveries(&mut tx1, observed_at, 32)
        .await
        .expect("worker 1 claims");
    assert_eq!(
        claimed1.len(),
        1,
        "worker 1 claims and locks the one due delivery"
    );

    // Worker 2, concurrent, must SKIP LOCKED the row worker 1 holds and see none.
    let mut tx2 = pool.begin().await.expect("begin worker 2");
    let claimed2 = claim_due_welcome_deliveries(&mut tx2, observed_at, 32)
        .await
        .expect("worker 2 claims");
    assert!(
        claimed2.is_empty(),
        "worker 2 never double-claims the delivery worker 1 holds"
    );
    tx2.rollback().await.expect("rollback worker 2");
    tx1.rollback().await.expect("rollback worker 1");
}
