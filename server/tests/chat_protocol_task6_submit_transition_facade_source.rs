use std::fs;

const FACADE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/chat_protocol/repository/submit_transition.rs"
);

fn facade_source() -> String {
    fs::read_to_string(FACADE_PATH).unwrap_or_else(|error| {
        panic!("Task 6 non-Recovery submitTransition facade is missing: {error}")
    })
}

#[test]
fn task6_submit_transition_facade_owns_the_closed_non_recovery_union() {
    let source = facade_source();

    for required in [
        "SignedMutationKind::CommitTransition",
        "SignedMutationKind::PolicyTransition",
        "SignedMutationKind::MetadataTransition",
        "SignedMutationKind::LeaveCommitFulfillment",
        "PreparedSignedOperation",
        "prepare_identity_scope_prelude",
        "hydrate_locked_conversation_state",
        "hydrate_locked_reserved_recovery_package",
        "build_verified_control_entry",
        "CanonicalControlEntryProducts::mint",
        "plan_commit_entry",
        "plan_policy_without_pending_admission",
        "plan_policy(",
        "plan_metadata_entry",
        "plan_leave_fulfillment_entry",
        "prepare_submit_transition_execution",
        "apply_prepared_submit_transition_execution",
        "complete_operation",
    ] {
        assert!(
            source.contains(required),
            "facade must own `{required}` rather than delegating it to a handler"
        );
    }

    assert!(
        !source.contains("SignedMutationKind::LeafRecoveryFulfillment"),
        "Recovery fulfillment must stay on the sealed Recovery bridge"
    );
    assert!(
        !source.contains(".commit().await"),
        "the caller-owned outer transaction is committed only by the handler"
    );
}

#[test]
fn task6_submit_transition_facade_owns_canonical_output_and_replay_poststate() {
    let source = facade_source();

    for required in [
        "SubmitTransitionCanonicalResponse",
        "SubmitTransitionReplayPostStateProof",
        "\"coordinates\"",
        "\"entry\"",
        "\"welcomes\"",
        "release_signed_operation_replay",
        "post_state_digest",
    ] {
        assert!(
            source.contains(required),
            "facade must bind canonical output/replay component `{required}`"
        );
    }

    for forbidden in [
        "ExecutionContextArtifacts {",
        "ConversationExecutionArtifacts::new",
        "fulfillLeafRecovery",
    ] {
        assert!(
            !source.contains(forbidden),
            "facade must not expose caller-built artifact/legacy seam `{forbidden}`"
        );
    }
}

#[test]
fn task6_submit_transition_facade_derives_complete_welcome_sets_for_first_and_replay() {
    let source = facade_source();

    for required in [
        "canonical_new_pending_welcomes",
        "plan.effects().welcome_changes()",
        "change.before().is_none()",
        "welcome.status() != WelcomeStatus::Pending",
        "left.recipient()",
        "left.key_package_ref()",
        "left.welcome_id()",
        "WHERE wb.transition_id=$1",
        "ORDER BY wd.recipient_did",
        "FOR SHARE OF wb,wd",
        "\"status\": \"pending\"",
        "replay_welcome_json",
    ] {
        assert!(
            source.contains(required),
            "facade must derive and lock the complete deterministic Welcome set via `{required}`"
        );
    }

    assert!(
        !source.contains("\"welcomes\": []"),
        "non-Recovery submitTransition must not blanket-assume an empty Welcome result"
    );
}

#[test]
fn task6_submit_transition_replay_proof_binds_completion_and_exact_rows() {
    let source = facade_source();

    for required in [
        "expected_response_sha256",
        "expected_status",
        "validates_seal",
        "SUBMIT_REPLAY_POST_STATE_DOMAIN",
        "SUBMIT_REPLAY_SEAL_DOMAIN",
        "FROM chat.transitions",
        "FROM chat.entries",
        "FROM chat.generation_states",
        "submit_replay_post_state_digest",
        "bind_optional_i64",
        "bind_optional_uuid",
    ] {
        assert!(
            source.contains(required),
            "replay proof must bind `{required}` before recorded bytes escape"
        );
    }
}

#[test]
fn task6_submit_transition_executor_seam_derives_server_events() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/chat_protocol/repository/execution_context.rs"
    );
    let source = fs::read_to_string(path).expect("execution-context source");

    for required in [
        "canonical_submit_transition_primary_event_payload",
        "submit_transition_authority_matches_plan",
        "prepare_submit_transition_execution",
        "apply_prepared_submit_transition_execution",
        "(SignedMutationKind::CommitTransition, PlanKind::Commit)",
        "(SignedMutationKind::PolicyTransition, PlanKind::Policy)",
        "(SignedMutationKind::MetadataTransition, PlanKind::Metadata)",
        "(SignedMutationKind::LeaveCommitFulfillment, PlanKind::Commit)",
        "primary_event_payload: Some(primary_event_payload)",
        "welcome_disposition_event_payloads: Vec::new()",
    ] {
        assert!(
            source.contains(required),
            "canonical submitTransition executor seam must own `{required}`"
        );
    }
    assert_eq!(
        source
            .matches("submit_transition_authority_matches_plan(plan)")
            .count(),
        2,
        "both preparation and primary-event construction must enforce the exact signed-authority/plan-kind pair",
    );
    assert!(
        !source.contains("PlanKind::Commit | PlanKind::Policy | PlanKind::Metadata"),
        "a grouped plan-kind set would admit cross-paired signed authorities",
    );
}
