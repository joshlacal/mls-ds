//! Real PostgreSQL slot/cap invariants. Fixtures intentionally roll back before
//! canonical publication provenance is required; these are not HTTP authority
//! or cryptographic publication tests.
#![allow(dead_code)]
#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
    // main's chat_protocol harness serializes migrations via fresh_db.
    pub mod fresh_db;
}
#[path = "../src/chat_protocol/repository/direct_request_retention.rs"]
mod retention;
use retention::*;
use uuid::Uuid;

#[tokio::test]
async fn decision_reserve_has_one_immutable_bounded_consumption() {
    let pool = common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let request = Uuid::new_v4();
    let reserve = decision_reservation_bytes(1024, 80).unwrap();
    install_lifecycle_reserve(&mut tx, request, reserve, 1)
        .await
        .unwrap();
    assert!(matches!(
        consume_decision(&mut tx, request, Uuid::new_v4(), "accept", reserve + 1).await,
        Err(RetentionError::CapacityUnavailable)
    ));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.direct_request_decision_slots WHERE request_id=$1",
    )
    .bind(request)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(count, 0);
    let original = Uuid::new_v4();
    consume_decision(&mut tx, request, original, "accept", reserve)
        .await
        .unwrap();
    assert!(matches!(
        consume_decision(&mut tx, request, Uuid::new_v4(), "close", 1024).await,
        Err(RetentionError::AlreadyConsumed)
    ));
    let stored:(Uuid,i64)=sqlx::query_as("SELECT operation_id,charged_bytes FROM chat.direct_request_decision_slots WHERE request_id=$1").bind(request).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(stored, (original, reserve as i64));
    sqlx::query("SAVEPOINT immutable_slot")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(sqlx::query(
        "UPDATE chat.direct_request_decision_slots SET charged_bytes=1 WHERE request_id=$1"
    )
    .bind(request)
    .execute(&mut *tx)
    .await
    .is_err());
    sqlx::query("ROLLBACK TO SAVEPOINT immutable_slot")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn welcome_delivery_cannot_acquire_a_second_operation_slot() {
    let pool = common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let request = Uuid::new_v4();
    install_lifecycle_reserve(
        &mut tx,
        request,
        decision_reservation_bytes(0, 2).unwrap(),
        1,
    )
    .await
    .unwrap();
    let device = Uuid::new_v4();
    let original = Uuid::new_v4();
    // References are deferred while constructing the synthetic graph. The
    // unique delivery/operation constraints themselves are immediate.
    sqlx::query("INSERT INTO chat.direct_request_welcome_slots(request_id,recipient_did,recipient_device_id,operation_id,request_digest,charged_bytes) VALUES($1,'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',$2,$3,$4,32768)")
        .bind(request).bind(device).bind(original).bind(vec![1u8;32]).execute(&mut *tx).await.unwrap();
    sqlx::query("SAVEPOINT new_welcome_id")
        .execute(&mut *tx)
        .await
        .unwrap();
    let error=sqlx::query("INSERT INTO chat.direct_request_welcome_slots(request_id,recipient_did,recipient_device_id,operation_id,request_digest,charged_bytes) VALUES($1,'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',$2,$3,$4,32768)")
        .bind(request).bind(device).bind(Uuid::new_v4()).bind(vec![2u8;32]).execute(&mut *tx).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23505")
    );
    sqlx::query("ROLLBACK TO SAVEPOINT new_welcome_id")
        .execute(&mut *tx)
        .await
        .unwrap();
    let rows:Vec<(Uuid,Vec<u8>)>=sqlx::query_as("SELECT operation_id,request_digest FROM chat.direct_request_welcome_slots WHERE request_id=$1").bind(request).fetch_all(&mut *tx).await.unwrap();
    assert_eq!(rows, vec![(original, vec![1u8; 32])]);
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn complete_historical_audience_is_measured_not_truncated() {
    let pool = common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let request = Uuid::new_v4();
    let reserved = decision_reservation_bytes(2048, 4000).unwrap();
    install_lifecycle_reserve(&mut tx, request, reserved, 39)
        .await
        .unwrap();
    let actual = logical_charge(&[b"signed"], 2048, 16 + 3 * 4000).unwrap();
    consume_decision(&mut tx, request, Uuid::new_v4(), "close", actual)
        .await
        .unwrap();
    let charged: i64 = sqlx::query_scalar(
        "SELECT charged_bytes FROM chat.direct_request_decision_slots WHERE request_id=$1",
    )
    .bind(request)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(charged, actual as i64);
    assert!(charged > 100_000_000);
    tx.rollback().await.unwrap();
}
