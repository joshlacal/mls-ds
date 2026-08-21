const DELIVERY: &str = include_str!("../src/chat_protocol/repository/message_delivery.rs");
const SEND_HANDLER: &str = include_str!("../src/handlers/chat/send_message.rs");
const TYPING_HANDLER: &str = include_str!("../src/handlers/chat/publish_typing.rs");

#[test]
fn send_and_typing_consume_the_sealed_live_traffic_projection() {
    for required in [
        "seal_traffic_fallback_scope",
        "load_fallback_traffic_projection",
        "consume_locked_traffic_projection",
        "RelationshipConsumptionError::PolicyDenied",
        "MessageDeliveryError::BlockedRelationship",
        "RelationshipConsumptionError::InvalidWitness",
        "MessageDeliveryError::RelationshipPolicyUnavailable",
    ] {
        assert!(
            DELIVERY.contains(required),
            "message delivery dropped required traffic authority step: {required}"
        );
    }

    assert_eq!(
        DELIVERY.matches("require_relationship_policy(tx,").count(),
        2,
        "send and typing must both consume the same traffic authority"
    );
    assert!(
        SEND_HANDLER.contains("runtime.relationship_authority().as_ref()"),
        "send handler must supply the fixed production relationship authority"
    );
    assert!(
        TYPING_HANDLER.contains("runtime.relationship_authority().as_ref()"),
        "typing handler must supply the fixed production relationship authority"
    );
}

#[test]
fn message_delivery_does_not_use_unscoped_snapshot_sql() {
    assert!(
        !DELIVERY.contains("relationship_projection_snapshots s"),
        "message delivery must not authorize from an unscoped snapshot existence query"
    );
    assert!(
        !DELIVERY.contains("completed_at >="),
        "freshness belongs to the sealed traffic loader, not ad-hoc send SQL"
    );
}
