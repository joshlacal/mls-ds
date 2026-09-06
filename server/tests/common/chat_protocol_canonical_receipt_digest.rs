//! Proof-only child of the existing generation transport fixture module.
//! The exact frozen f451 producer is exercised, not a rewritten approximation.
#![cfg(all(test, feature = "test-support"))]
use super::*;
use crate::chat_protocol::{
    cursor::CursorSealer,
    repository::{subscription, ticket},
};
use sqlx::Row;

#[path = "fixtures/subscription_producer_f451.rs"]
mod legacy_producer;

fn old_event(event: &subscription::VisibleEvent) -> legacy_producer::VisibleEvent {
    legacy_producer::VisibleEvent {
        event_position: event.event_position,
        payload: event.payload.clone(),
        created_at: event.created_at,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_replay_preserves_the_exact_legacy_receipt_and_rejects_changed_inputs() {
    let _serial = SERIAL.lock().await;
    let pool = owned_database().await;
    let (mut group, device) = ready_group(&pool).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    let inventory = inventory_roundtrip(&pool, &router, &device).await;
    let opaque_ticket = mint_existing_ticket(&router, &device, &inventory).await;
    let raw_ticket = URL_SAFE_NO_PAD.decode(opaque_ticket).unwrap();
    let mut tx = pool.begin().await.unwrap();
    let now = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let consumed = ticket::consume_subscription_ticket(
        &mut tx,
        &ticket::ticket_hash(&raw_ticket),
        &inventory.cursor,
        ticket::SUBSCRIBE_EVENTS_PATH,
        now,
    )
    .await
    .expect("actual HTTP-minted one-use ticket consumption");
    subscription::ensure_initial_receipt(&mut tx, &consumed)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&consumed.cursor_key_id)
        .unwrap()
        .try_into()
        .unwrap();
    let sealer = CursorSealer::new(key, zeroize::Zeroizing::new([0xA5; 32])).unwrap();
    send_ready_application(&pool, &router, &device, &mut group).await;
    let mut tx = pool.begin().await.unwrap();
    let through = subscription::replay_high_water(&mut tx, &consumed)
        .await
        .unwrap();
    let events =
        subscription::visible_events(&mut tx, &consumed, consumed.event_position, through, 10)
            .await
            .unwrap();
    assert_eq!(
        events.len(),
        1,
        "one actual signed addressed application event"
    );
    let event = events.into_iter().next().unwrap();
    tx.commit().await.unwrap();

    // An unpublished, rollback-only bad-digest fixture uses a correctly sealed
    // cursor and exact parent/predecessor. No immutable retained row is updated
    // and no trigger is disabled. Only the initially inserted digest is wrong.
    let mut tx = pool.begin().await.unwrap();
    subscription::replay_high_water(&mut tx, &consumed)
        .await
        .unwrap();
    sqlx::query("SAVEPOINT unpublished_digest_probe")
        .execute(&mut *tx)
        .await
        .unwrap();
    let (_, _, probe_hash) = legacy_producer::materialize_envelope(
        &mut tx,
        &consumed,
        old_event(&event),
        &inventory.cursor,
        consumed.event_cursor_hash,
        &sealer,
    )
    .await
    .unwrap();
    let row = sqlx::query("SELECT * FROM chat.event_cursor_receipts WHERE cursor_hash=$1")
        .bind(probe_hash.as_slice())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let invalid = ticket::NewEventCursorReceipt {
        cursor_hash: probe_hash,
        inventory_session_id: consumed.inventory_session_id,
        user_did: consumed.user_did.clone(),
        device_id: consumed.device_id,
        jkt: consumed.jkt.clone(),
        auth_generation: consumed.auth_generation,
        protocol_instance_id: consumed.protocol_instance_id,
        cursor_key_id: consumed.cursor_key_id.clone(),
        event_position: event.event_position,
        predecessor_cursor_hash: Some(consumed.event_cursor_hash),
        retained_floor_at_issue: consumed.snapshot_retained_floor,
        cursor_nonce: row.get::<Vec<u8>, _>("cursor_nonce").try_into().unwrap(),
        cursor_ciphertext: row.get("cursor_ciphertext"),
        canonical_envelope_sha256: Some([0x7B; 32]),
        created_at: row.get("created_at"),
        expires_at: row.get("expires_at"),
    };
    sqlx::query("ROLLBACK TO SAVEPOINT unpublished_digest_probe")
        .execute(&mut *tx)
        .await
        .unwrap();
    ticket::insert_event_cursor_receipt(&mut tx, &invalid)
        .await
        .unwrap();
    assert!(matches!(
        subscription::materialize_envelope(
            &mut tx,
            &consumed,
            event.clone(),
            &inventory.cursor,
            consumed.event_cursor_hash,
            &sealer,
        )
        .await,
        Err(ticket::TicketRepositoryError::InvalidReceipt)
    ));
    tx.rollback().await.unwrap();

    // Commit the exact old producer output under all original constraints.
    let mut tx = pool.begin().await.unwrap();
    subscription::replay_high_water(&mut tx, &consumed)
        .await
        .unwrap();
    let (legacy, cursor, hash) = legacy_producer::materialize_envelope(
        &mut tx,
        &consumed,
        old_event(&event),
        &inventory.cursor,
        consumed.event_cursor_hash,
        &sealer,
    )
    .await
    .unwrap();
    let legacy_json = serde_json::to_value(&legacy).unwrap();
    assert_eq!(legacy_json["createdAt"].as_str().unwrap().len(), 27);
    tx.commit().await.unwrap();
    let before = receipt(&pool, &cursor).await.unwrap();
    let parent_before = row_by_session(&pool, consumed.inventory_session_id)
        .await
        .unwrap();

    let mut tx = pool.begin().await.unwrap();
    subscription::replay_high_water(&mut tx, &consumed)
        .await
        .unwrap();
    let (canonical, replay_cursor, replay_hash) = subscription::materialize_envelope(
        &mut tx,
        &consumed,
        event.clone(),
        &inventory.cursor,
        consumed.event_cursor_hash,
        &sealer,
    )
    .await
    .expect("exact historical producer digest remains readable");
    tx.commit().await.unwrap();
    let canonical_json = serde_json::to_value(&canonical).unwrap();
    let text = canonical_json["createdAt"].as_str().unwrap();
    assert_eq!(text.len(), 24, "canonical .sssZ publication");
    assert!(text.ends_with('Z'));
    assert_eq!(cursor, replay_cursor);
    assert_eq!(hash, replay_hash);
    assert_eq!(canonical_json["payload"], legacy_json["payload"]);
    assert_eq!(
        canonical_json["previousCursor"],
        legacy_json["previousCursor"]
    );
    assert_eq!(
        receipt(&pool, &cursor).await.unwrap(),
        before,
        "all retained receipt bytes unchanged"
    );

    for changed in ["payload", "date", "cursor", "predecessor"] {
        let mut altered = event.clone();
        let mut previous = inventory.cursor.clone();
        let mut predecessor = consumed.event_cursor_hash;
        match changed {
            "payload" => {
                let mut value = serde_json::to_value(&altered.payload).unwrap();
                value["seq"] = json!(value["seq"].as_u64().unwrap() + 1);
                altered.payload = serde_json::from_value(value).unwrap();
            }
            "date" => altered.created_at += Duration::milliseconds(1),
            "cursor" => previous = URL_SAFE_NO_PAD.encode([0x6A; 32]),
            "predecessor" => predecessor = [0x6B; 32],
            _ => unreachable!(),
        }
        let mut tx = pool.begin().await.unwrap();
        subscription::replay_high_water(&mut tx, &consumed)
            .await
            .unwrap();
        assert!(
            matches!(
                subscription::materialize_envelope(
                    &mut tx,
                    &consumed,
                    altered,
                    &previous,
                    predecessor,
                    &sealer,
                )
                .await,
                Err(ticket::TicketRepositoryError::InvalidReceipt)
            ),
            "changed {changed} must reject"
        );
        tx.rollback().await.unwrap();
    }
    assert_eq!(receipt(&pool, &cursor).await.unwrap(), before);
    assert_eq!(
        row_by_session(&pool, consumed.inventory_session_id)
            .await
            .unwrap(),
        parent_before
    );
}
