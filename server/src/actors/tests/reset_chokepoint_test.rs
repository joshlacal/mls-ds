//! Type-level smoke tests for the Phase 2 §2.2 two-phase reset surface.
//!
//! Real semantic verification of the `request_crypto_session_reset_tx` and
//! `activate_crypto_session_tx` contracts (idempotency, tie-break,
//! legacy-column sync, pending_welcomes binding) defers to #11 acceptance
//! tests against a real Postgres. These tests pin the type surface so
//! refactors that accidentally change the message shape, the
//! `ResetTrigger` enum, or the `ActivationResult` variants surface as
//! compile errors immediately.
//!
//! See `repository_fake_test.rs` for the trait-level idempotency
//! contracts that the chokepoint relies on.

use crate::actors::messages::{
    ConvoMessage, ResetRequest, ResetTrigger, WelcomeEnvelope,
};

#[test]
fn reset_trigger_str_repr_round_trips_all_variants() {
    // The chokepoint persists `trigger` in delivery_events.payload_json
    // via `ResetTrigger::as_str()`. Pinning the repr so a future enum
    // shuffle doesn't silently break audit-log readers.
    assert_eq!(ResetTrigger::Admin.as_str(), "admin");
    assert_eq!(ResetTrigger::QuorumVote.as_str(), "quorum_vote");
    assert_eq!(ResetTrigger::SystemSweep.as_str(), "system_sweep");
    assert_eq!(ResetTrigger::Bootstrap.as_str(), "bootstrap");
}

#[test]
fn reset_request_constructs_with_owned_strings() {
    let r = ResetRequest {
        request_id: "req-1".to_string(),
        conversation_id: "convo-1".to_string(),
        initiator_did: "did:plc:alice".to_string(),
        reason: "manual_admin".to_string(),
    };
    assert_eq!(r.request_id, "req-1");
    assert_eq!(r.conversation_id, "convo-1");
}

#[test]
fn welcome_envelope_recipient_did_is_in_memory_field() {
    // The DB column is `target_did`; this struct uses `recipient_did`.
    // The mapping happens at the SQL boundary in the activate chokepoint.
    // This test pins the field name so a renaming refactor must be
    // accompanied by an audit of the chokepoint INSERT.
    let w = WelcomeEnvelope {
        recipient_did: "did:plc:bob".to_string(),
        recipient_device_id: Some("device-1".to_string()),
        welcome_data: vec![1, 2, 3],
        key_package_hash: Some("hash".to_string()),
    };
    assert_eq!(w.recipient_did, "did:plc:bob");
    assert_eq!(w.recipient_device_id.as_deref(), Some("device-1"));
}

#[tokio::test]
async fn convo_message_request_reset_constructs_with_oneshot() {
    // Pinning the variant shape so renaming a field surfaces here.
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let msg = ConvoMessage::RequestCryptoSessionReset {
        trigger: ResetTrigger::Admin,
        initiator_did: "did:plc:admin".to_string(),
        reason: "spec test".to_string(),
        idempotency_key: "test-key-1".to_string(),
        expected_new_mls_group_id: Some("mls-group-XYZ".to_string()),
        reply: tx,
    };
    // The variant is constructed; pattern-match to verify destructuring.
    match msg {
        ConvoMessage::RequestCryptoSessionReset {
            trigger,
            initiator_did,
            reason,
            idempotency_key,
            expected_new_mls_group_id,
            ..
        } => {
            assert_eq!(trigger, ResetTrigger::Admin);
            assert_eq!(initiator_did, "did:plc:admin");
            assert_eq!(reason, "spec test");
            assert_eq!(idempotency_key, "test-key-1");
            assert_eq!(
                expected_new_mls_group_id.as_deref(),
                Some("mls-group-XYZ")
            );
        }
        _ => panic!("expected RequestCryptoSessionReset"),
    }
}

#[tokio::test]
async fn convo_message_activate_constructs_with_welcomes() {
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let welcomes = vec![WelcomeEnvelope {
        recipient_did: "did:plc:bob".to_string(),
        recipient_device_id: None,
        welcome_data: vec![],
        key_package_hash: None,
    }];
    let msg = ConvoMessage::ActivateCryptoSession {
        reset_request_id: Some("req-1".to_string()),
        trigger: ResetTrigger::Bootstrap,
        new_mls_group_id: "mls-group-X".to_string(),
        new_group_info: Some(vec![0xaa]),
        welcomes,
        initiator_did: "did:plc:bob".to_string(),
        idempotency_key: "act-key-1".to_string(),
        reply: tx,
    };
    match msg {
        ConvoMessage::ActivateCryptoSession {
            reset_request_id,
            trigger,
            new_mls_group_id,
            new_group_info,
            welcomes,
            ..
        } => {
            assert_eq!(reset_request_id.as_deref(), Some("req-1"));
            assert_eq!(trigger, ResetTrigger::Bootstrap);
            assert_eq!(new_mls_group_id, "mls-group-X");
            assert_eq!(new_group_info.as_deref(), Some(&[0xaa][..]));
            assert_eq!(welcomes.len(), 1);
            assert_eq!(welcomes[0].recipient_did, "did:plc:bob");
        }
        _ => panic!("expected ActivateCryptoSession"),
    }
}
