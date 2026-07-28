//! No-database Task 6 proof that Recovery owns first-execution response
//! projection and endpoint-specific replay release.

const RECOVERY: &str = include_str!("../src/chat_protocol/repository/recovery.rs");
const PRELUDE: &str = include_str!("../src/chat_protocol/repository/prelude.rs");
const STATE_MACHINE: &str = include_str!("../src/chat_protocol/state_machine.rs");

fn function_body<'a>(source: &'a str, signature: &str, next_signature: &str) -> &'a str {
    let start = source.find(signature).expect("function signature exists");
    let tail = &source[start..];
    let end = tail
        .find(next_signature)
        .expect("following function signature exists");
    &tail[..end]
}

#[test]
fn fulfillment_is_bound_to_submit_transition_and_never_a_fake_recovery_endpoint() {
    assert!(
        STATE_MACHINE.contains("ValidatedChatNsid::parse(\"blue.catbird.chat.submitTransition\")")
    );
    assert!(!STATE_MACHINE.contains("blue.catbird.chat.fulfillLeafRecovery"));
    assert!(!RECOVERY.contains("blue.catbird.chat.fulfillLeafRecovery"));
}

#[test]
fn first_execution_graph_owns_complete_recovery_response_projection() {
    for required in [
        "pub(crate) struct RecoveryCanonicalResponse",
        "fn leaf_recovery_response_from_rows(",
        "\"recovery\": {",
        "\"reservation\": {",
        "\"keyPackage\": {",
        "fn fulfillment_response_bytes(",
        "\"coordinates\": response_coordinate_from_snapshot(successor)?",
        "\"entry\": entry",
        "\"welcomes\": [{",
        "response: Option<RecoveryCanonicalResponse>",
        "pub(crate) response: Option<RecoveryCanonicalResponse>",
    ] {
        assert!(
            RECOVERY.contains(required),
            "missing response seam: {required}"
        );
    }
}

#[test]
fn replay_bytes_are_released_only_after_recovery_post_state_validation() {
    let facade = function_body(
        RECOVERY,
        "pub(crate) async fn validate_recovery_operation_replay(",
        "async fn prepare_recovery_replay_post_state(",
    );
    let lock = facade
        .find("lock_signed_operation_replay_authority")
        .expect("pre-head replay lock");
    let validate = facade
        .find("prepare_recovery_replay_post_state")
        .expect("Recovery post-state validation");
    let release = facade
        .find("release_signed_operation_replay")
        .expect("opaque completion release");
    assert!(lock < validate && validate < release);
    assert!(facade.contains("SignedOperationReplayPostStateProof::Recovery(proof)"));

    let post_state = function_body(
        RECOVERY,
        "async fn prepare_recovery_replay_post_state(",
        "pub(crate) async fn prepare_recovery_request_authority(",
    );
    for required in [
        "lock_recovery_replay_head_graph(",
        "lock_terminal_rows(",
        "validate_replay_locked_triple(",
        "validate_terminal_linkage(",
        "lock_recovery_fulfillment_replay_graph(",
        "RecoveryReplayPostStateProof::mint(",
    ] {
        assert!(
            post_state.contains(required),
            "missing replay graph lock/validation: {required}"
        );
    }
}

#[test]
fn handler_safe_facade_consumes_first_or_replay_and_never_commits() {
    let facade = function_body(
        RECOVERY,
        "pub(crate) async fn execute_prepared_recovery<T: PublicTransport>(",
        "async fn complete_applied_recovery(",
    );
    for required in [
        "PreparedSignedOperationState::Replay",
        "validate_recovery_operation_replay(",
        "PreparedSignedOperationState::First",
        "prepare_actor_prelude(",
        "discover_recovery_fulfillment_terminal_scope(",
        "prepare_identity_scope_prelude(",
        "prepare_recovery_request_authority(",
        "prepare_recovery_cancellation_authority(",
        "prepare_recovery_fulfillment_authority(",
        "complete_applied_recovery(",
        "complete_classified_recovery(",
    ] {
        assert!(
            facade.contains(required),
            "missing facade stage: {required}"
        );
    }
    assert!(!facade.contains(".commit("));
    assert!(!facade.contains("COMMIT"));
}

#[test]
fn closed_release_binds_status_response_hash_and_nonzero_post_state_digest() {
    for required in [
        "Recovery(recovery::RecoveryReplayPostStateProof)",
        "post_state.expected_status()",
        "post_state.expected_response_sha256()",
        "post_state.post_state_digest() == &[0; 32]",
        "completed.status() != post_state.expected_status()",
        "completed.response_sha256() != post_state.expected_response_sha256()",
    ] {
        assert!(
            PRELUDE.contains(required),
            "missing closed release check: {required}"
        );
    }
    for required in [
        "expected_status: i32",
        "expected_response_sha256: [u8; 32]",
        "pub(in crate::chat_protocol::repository) fn expected_status(&self) -> i32",
        "pub(in crate::chat_protocol::repository) fn expected_response_sha256(&self)",
        "pub(in crate::chat_protocol::repository) fn validates_seal(&self) -> bool",
    ] {
        assert!(
            RECOVERY.contains(required),
            "missing sealed Recovery proof field: {required}"
        );
    }
}
