//! PostgreSQL contention regression for request-push lease ownership.
//!
//! This test deliberately holds the mapped outbox row lock until the lease
//! expires. The production renewal must sample the database clock after it
//! acquires that lock and reject the stale lease without changing the row.

#![cfg(feature = "test-support")]
#![allow(dead_code)]

#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
}

use chrono::{DateTime, Utc};
use sqlx::{Acquire, PgPool};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct OriginalOutboxState {
    status: String,
    attempt_count: i64,
    next_attempt_at: DateTime<Utc>,
    lease_owner: Option<Uuid>,
    lease_expires_at: Option<DateTime<Utc>>,
    delivered_at: Option<DateTime<Utc>>,
}

async fn restore(
    pool: &PgPool,
    outbox_id: Uuid,
    original: &OriginalOutboxState,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE chat.outbox SET status=$2,attempt_count=$3,next_attempt_at=$4,\
         lease_owner=$5,lease_expires_at=$6,delivered_at=$7 WHERE outbox_id=$1",
    )
    .bind(outbox_id)
    .bind(&original.status)
    .bind(original.attempt_count)
    .bind(original.next_attempt_at)
    .bind(original.lease_owner)
    .bind(original.lease_expires_at)
    .bind(original.delivered_at)
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renewal_rechecks_database_clock_after_waiting_for_row_lock() {
    let pool = common::direct_request_database::setup().await;
    let outbox_id: Uuid = sqlx::query_scalar(
        "SELECT work.outbox_id FROM chat.outbox work \
         JOIN chat.direct_request_push_events mapped ON mapped.outbox_id=work.outbox_id \
         ORDER BY mapped.event_position DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("C01 retained publication must provide one mapped push event");
    let original: OriginalOutboxState = sqlx::query_as(
        "SELECT status,attempt_count,next_attempt_at,lease_owner,lease_expires_at,delivered_at \
         FROM chat.outbox WHERE outbox_id=$1",
    )
    .bind(outbox_id)
    .fetch_one(&pool)
    .await
    .expect("read original outbox state");

    let owner = Uuid::new_v4();
    sqlx::query(
        "UPDATE chat.outbox SET status='leased',attempt_count=0,delivered_at=NULL,\
         lease_owner=$2,lease_expires_at=clock_timestamp()+interval '500 milliseconds' \
         WHERE outbox_id=$1",
    )
    .bind(outbox_id)
    .bind(owner)
    .execute(&pool)
    .await
    .expect("install short test lease");

    let result = async {
        let mut blocker = pool.begin().await?;
        sqlx::query("SELECT outbox_id FROM chat.outbox WHERE outbox_id=$1 FOR UPDATE")
            .bind(outbox_id)
            .fetch_one(&mut *blocker)
            .await?;

        let waiting_pool = pool.clone();
        let waiter = tokio::spawn(async move {
            catbird_server::workers::renew_request_push_lease_for_test(
                &waiting_pool,
                outbox_id,
                owner,
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        blocker.commit().await?;

        let renewal = waiter.await.expect("renewal task joined");
        assert!(renewal.is_err(), "an expired blocked lease was renewed");
        let (status, same_owner, expired): (String, bool, bool) = sqlx::query_as(
            "SELECT status,lease_owner=$2,lease_expires_at<=clock_timestamp() \
             FROM chat.outbox WHERE outbox_id=$1",
        )
        .bind(outbox_id)
        .bind(owner)
        .fetch_one(&pool)
        .await?;
        assert_eq!(status, "leased");
        assert!(same_owner);
        assert!(expired);
        Ok::<(), sqlx::Error>(())
    }
    .await;

    restore(&pool, outbox_id, &original)
        .await
        .expect("restore exact original outbox state");
    result.expect("held-row-lock lease regression");
}
