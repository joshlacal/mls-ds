//! Source-level capability checks for Task 6 operation-only admission.
//!
//! These checks are intentionally database-free. They guard the visibility
//! boundary that Rust's ordinary behavior tests cannot exercise: generic
//! admission and initial operation arbitration may carry sealed authority, but
//! they may not carry or load completed response material.

fn function_block<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing source boundary: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing source boundary: {end}"))
        .0
}

#[test]
fn generic_signed_admission_and_preparation_are_response_byte_opaque() {
    let auth = include_str!("../src/chat_protocol/repository/auth.rs");
    let admission = function_block(
        auth,
        "pub(crate) struct SignedOperationAdmission",
        "pub(crate) struct ReplenishmentOperationAdmission",
    );
    assert!(admission.contains("pre_replay: PreReplayCryptographicVerification"));
    assert!(admission.contains("canonical: CanonicalSignedMutation"));
    assert!(admission.contains("signing_public_key: Vec<u8>"));
    assert!(admission.contains("receipt: RepositoryAuthorityReceipt"));
    assert!(admission.contains("pub(crate) struct SignedOperationReplayAuthority"));
    assert!(!admission.contains("CompletedIdempotentResponse"));
    assert!(!admission.contains("response_bytes"));

    let authorizer = function_block(
        auth,
        "pub(crate) async fn authorize_signed_operation_only",
        "pub(crate) async fn authorize_replenishment_operation_only",
    );
    assert!(!authorizer.contains("completed_replay("));
    assert!(!authorizer.contains("load_validated_completed_business_replay"));
    assert!(!authorizer.contains("response_bytes"));
    assert!(authorizer.contains("completed_request_material_matches_without_response"));

    let prelude = include_str!("../src/chat_protocol/repository/prelude.rs");
    let prepared = function_block(
        prelude,
        "pub(crate) enum PreparedSignedOperation",
        "pub(crate) struct PreparedBusinessPrelude",
    );
    assert!(prepared.contains("authority: VerifiedChatDeviceRequest"));
    assert!(prepared.contains("authority: auth::SignedOperationReplayAuthority"));
    assert!(prepared.contains("reservation: OperationReservationGuard"));
    assert!(prepared.contains("replay: OperationReplayGuard"));
    assert!(!prepared.contains("CompletedIdempotentResponse"));
    assert!(!prepared.contains("response_bytes"));

    let preparation = function_block(
        prelude,
        "pub(crate) async fn prepare_signed_operation",
        "pub(crate) async fn prepare_enrollment_bootstrap_prelude",
    );
    assert!(!preparation.contains("load_validated_completed_business_replay"));
    assert!(!preparation.contains("CompletedIdempotentResponse"));
    assert!(!preparation.contains("response_bytes"));
}

#[test]
fn completed_replay_uses_signature_authority_without_reapplying_first_execution_age() {
    let source = include_str!("../src/chat_protocol/repository/auth.rs");
    let first = function_block(
        source,
        "pub(super) fn into_first_authority",
        "pub(super) fn into_replay_authority",
    );
    assert!(first.contains("mint_signed_repository_authority"));

    let replay = function_block(
        source,
        "pub(super) fn into_replay_authority",
        "impl SignedOperationReplayAuthority",
    );
    assert!(replay.contains("transcript::verify_signed_mutation"));
    assert!(!replay.contains("mint_signed_repository_authority"));
}

#[test]
fn replay_release_is_two_phase_repository_only_and_binds_endpoint_post_state() {
    let source = include_str!("../src/chat_protocol/repository/prelude.rs");
    let proof = function_block(
        source,
        "pub(in crate::chat_protocol::repository) enum SignedOperationReplayPostStateProof",
        "pub(crate) struct PreparedBusinessPrelude",
    );
    for variant in [
        "ResetRequest(reset::ResetReplayPostStateProof)",
        "ResetActivation(reset::ResetReplayPostStateProof)",
        "DeviceRevocation(revocation::DeviceRevocationReplayPostStateProof)",
        "WelcomeAcknowledgement(welcome_terminal::WelcomeReplayPostStateProof)",
        "WelcomeRejection(welcome_terminal::WelcomeReplayPostStateProof)",
        "Recovery(recovery::RecoveryReplayPostStateProof)",
        "SubmitTransition(submit_transition::SubmitTransitionReplayPostStateProof)",
    ] {
        assert!(
            proof.contains(variant),
            "closed replay proof omitted endpoint variant: {variant}",
        );
    }
    assert!(!proof.contains(" trait SignedOperationReplayPostStateProof"));

    let lock = function_block(
        source,
        "pub(in crate::chat_protocol::repository) async fn lock_signed_operation_replay_authority",
        "pub(in crate::chat_protocol::repository) async fn release_signed_operation_replay",
    );
    assert!(lock.contains("auth::lock_signed_operation_replay_identity"));
    assert!(!lock.contains("load_signed_operation_replay_completion"));
    assert!(!lock.contains("CompletedIdempotentResponse"));

    let release = function_block(
        source,
        "pub(in crate::chat_protocol::repository) async fn release_signed_operation_replay",
        "pub(crate) async fn validate_enrollment_operation_replay",
    );
    for exact_fact in [
        "transaction_id()",
        "operation_id()",
        "principal_did()",
        "endpoint_nsid()",
        "mutation_kind()",
        "request_digest()",
        "accepted_request_sha256()",
        "signature()",
        "post_state_digest()",
        "expected_status()",
        "expected_response_sha256()",
        "validates_seal()",
        "matches_exact(binding)",
    ] {
        assert!(
            release.contains(exact_fact),
            "replay release omitted exact fact: {exact_fact}",
        );
    }
    assert!(release.contains("auth::load_signed_operation_replay_completion"));
    assert!(release.contains("completed.status()"));
    assert!(release.contains("completed.response_sha256()"));
    assert!(release.contains("Sha256::digest(completed.response_bytes())"));
    assert!(!release.contains("auth::lock_signed_operation_replay_identity"));
    assert!(!release.contains("P: SignedOperationReplayPostStateProof"));
}

#[test]
fn handler_context_returns_the_opaque_signed_admission() {
    let source = include_str!("../src/handlers/chat/context.rs");
    let admission = function_block(
        source,
        "pub(crate) async fn admit_signed_operation_only",
        "pub(crate) async fn admit_enrollment_operation_only",
    );
    assert!(admission.contains("Result<SignedOperationAdmission, ChatFailure>"));
    assert!(admission.contains("auth::authorize_signed_operation_only"));
    assert!(!admission.contains("into_admission"));
    assert!(!admission.contains("replay_response"));
}

#[test]
fn non_recovery_submit_transition_verifier_is_closed_to_four_mutation_kinds() {
    let source = include_str!("../src/chat_protocol/repository/prelude.rs");
    let verifier = function_block(
        source,
        "pub(crate) fn verify_submit_transition_operation",
        "fn verify_exact_operation_claim",
    );
    assert!(verifier.contains("\"blue.catbird.chat.submitTransition\""));
    for kind in [
        "SignedMutationKind::CommitTransition",
        "SignedMutationKind::PolicyTransition",
        "SignedMutationKind::MetadataTransition",
        "SignedMutationKind::LeaveCommitFulfillment",
    ] {
        assert!(
            verifier.contains(kind),
            "submitTransition verifier omitted {kind}",
        );
    }
    assert!(!verifier.contains("SignedMutationKind::LeafRecoveryFulfillment"));
    assert!(!verifier.contains("SignedMutationKind::ZeroLeafLeave"));
}

#[test]
fn submit_transition_admission_excludes_zero_leaf_leave() {
    let source = include_str!("../src/chat_protocol/repository/auth.rs");
    let endpoint_kinds = function_block(source, "fn endpoint_accepts_kind", "fn completion_jkts");
    let submit_transition = function_block(
        endpoint_kinds,
        "\"blue.catbird.chat.submitTransition\"",
        "\"blue.catbird.chat.acceptConversation\"",
    );
    assert!(submit_transition.contains("SignedMutationKind::LeafRecoveryFulfillment"));
    assert!(submit_transition.contains("SignedMutationKind::LeaveCommitFulfillment"));
    assert!(!submit_transition.contains("SignedMutationKind::ZeroLeafLeave"));

    let request_leave = function_block(
        endpoint_kinds,
        "\"blue.catbird.chat.requestLeave\"",
        "\"blue.catbird.chat.cancelLeave\"",
    );
    assert!(request_leave.contains("SignedMutationKind::ZeroLeafLeave"));
}
