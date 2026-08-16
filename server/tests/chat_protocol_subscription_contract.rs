//! Static contract gates for the clean subscription route. PostgreSQL behavior
//! is covered by `chat_protocol_ticket`; these assertions prevent accidental
//! regression to the legacy socket/store authority during later refactors.

#[test]
fn durable_subscription_uses_exact_device_global_event_authority() {
    let source = include_str!("../src/chat_protocol/repository/subscription.rs");
    for required in [
        "FROM chat.event_recipients recipient",
        "JOIN chat.events event USING (event_position)",
        "recipient.user_did = $1",
        "recipient.device_id = $2",
        "event.event_position > $4",
        "ORDER BY event.event_position",
        "insert_event_cursor_receipt",
        "predecessor_cursor_hash: Some(previous_cursor_hash)",
        "canonical_envelope_sha256: Some(envelope_hash)",
        "revalidate_consumed_ticket(transaction, ticket, ticket.event_position, observed_at)",
        "revalidate_consumed_ticket(transaction, ticket, after_position, observed_at)",
    ] {
        assert!(
            source.contains(required),
            "missing subscription fence: {required}"
        );
    }
    assert!(!source.contains("event_stream"));
    assert!(!source.contains("subscribeConvoEvents"));
}

#[test]
fn production_ticket_facade_hashes_the_returned_bearer_before_persistence() {
    let source = include_str!("../src/chat_protocol/repository/ticket.rs");
    assert!(source.contains("ticket_hash: ticket_hash(&opaque).to_vec()"));
}

#[test]
fn route_replays_frozen_high_water_before_live_reconciliation() {
    let source = include_str!("../src/handlers/chat/subscribe_events.rs");
    let replay = source.find("replay_through").expect("frozen replay fence");
    let live = source
        .find("Reconcile the replay/live race")
        .expect("live reconciliation");
    assert!(replay < live);
    assert!(source.contains("ensure_initial_receipt"));
    assert!(source.contains("consume_subscription_ticket"));
    assert!(source.contains("StreamEvent::CleanTypingEvent"));
    assert!(!source.contains("handlers::mls_chat"));
}
