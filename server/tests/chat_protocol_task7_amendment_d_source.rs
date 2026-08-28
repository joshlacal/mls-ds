//! Amendment D type-state proof: completed active-handler retries arbitrate
//! their immutable operation claim before first-execution body-age authority is
//! minted. Replay capabilities remain endpoint-specific and byte-opaque.

fn block<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing source boundary: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing source boundary: {end}"))
        .0
}

#[test]
fn bootstrap_admissions_defer_first_execution_age_until_after_claim_arbitration() {
    let auth = include_str!("../src/chat_protocol/repository/auth.rs");
    let admissions = block(
        auth,
        "pub(crate) struct EnrollmentOperationAdmission",
        "pub(crate) struct SignedOperationAdmission",
    );
    assert!(admissions.contains("pre_replay: PreReplayCryptographicVerification"));
    assert!(admissions.contains("receipt: RepositoryAuthorityReceipt"));
    assert!(admissions.contains("signing_public_key: Vec<u8>"));
    assert!(!admissions.contains("authority: VerifiedChatDeviceRequest"));

    let enrollment = block(
        auth,
        "impl EnrollmentOperationAdmission",
        "impl RebindOperationAdmission",
    );
    assert!(enrollment.contains("into_first_authority"));
    assert!(enrollment.contains("mint_enrollment_repository_authority"));
    assert!(enrollment.contains("into_replay_authority"));
    assert!(!enrollment.contains("CompletedIdempotentResponse"));

    let rebind = block(
        auth,
        "impl RebindOperationAdmission",
        "impl SignedOperationAdmission",
    );
    assert!(rebind.contains("into_first_authority"));
    assert!(rebind.contains("mint_rebind_repository_authority"));
    assert!(rebind.contains("into_replay_authority"));
    assert!(!rebind.contains("CompletedIdempotentResponse"));
}

#[test]
fn active_handlers_arbitrate_deferred_admission_and_never_render_unvalidated_bytes() {
    let prelude = include_str!("../src/chat_protocol/repository/prelude.rs");
    for preparation in ["prepare_enrollment_operation", "prepare_rebind_operation"] {
        let start = format!("pub(crate) async fn {preparation}");
        let body = prelude
            .split_once(&start)
            .unwrap_or_else(|| panic!("missing {preparation}"))
            .1;
        let body = body
            .split_once("\npub(crate) async fn ")
            .map_or(body, |(body, _)| body);
        assert!(body.contains("operation_claims"));
        assert!(body.contains("into_first_authority"));
        assert!(body.contains("into_replay_authority"));
        assert!(body.contains("validate_"));
        assert!(body.contains("Prepared"));
        assert!(!body.contains("response_bytes"));
    }
    let replenishment = block(
        prelude,
        "pub(crate) async fn prepare_replenishment_operation",
        "pub(crate) async fn prepare_signed_operation",
    );
    assert!(replenishment.contains("prepare_signed_operation"));
    assert!(replenishment.contains("validate_replenishment_operation_replay"));
    assert!(replenishment.contains("PreparedReplenishmentOperation"));
    assert!(!replenishment.contains("response_bytes"));

    for file in [
        "../src/handlers/chat/enroll_device.rs",
        "../src/handlers/chat/replenish_key_packages.rs",
    ] {
        let handler = match file {
            "../src/handlers/chat/enroll_device.rs" => {
                include_str!("../src/handlers/chat/enroll_device.rs")
            }
            _ => include_str!("../src/handlers/chat/replenish_key_packages.rs"),
        };
        assert!(handler.contains("context::replay_response"));
        assert!(!handler.contains("validate_enrollment_operation_replay"));
        assert!(!handler.contains("validate_rebind_operation_replay"));
        assert!(!handler.contains("validate_replenishment_operation_replay"));
    }
}

#[test]
fn replenishment_reuses_generic_deferred_signed_admission() {
    let context = include_str!("../src/handlers/chat/context.rs");
    let admission = block(
        context,
        "pub(crate) async fn admit_replenishment_operation_only",
        "pub(crate) fn json_ok",
    );
    assert!(admission.contains("Result<SignedOperationAdmission, ChatFailure>"));
    assert!(admission.contains("auth::authorize_replenishment_operation_only"));
    assert!(!admission.contains("ReplenishmentOperationAdmission"));
}

#[test]
fn endpoint_preparation_never_exposes_raw_verified_or_replay_authority_to_handlers() {
    let prelude = include_str!("../src/chat_protocol/repository/prelude.rs");
    let endpoint_results = block(
        prelude,
        "pub(crate) enum PreparedEnrollmentOperation",
        "pub(crate) struct OperationReplayGuard",
    );
    assert!(!endpoint_results.contains("VerifiedChatDeviceRequest"));
    assert!(!endpoint_results.contains("OperationReplayGuard"));
    assert!(!endpoint_results.contains("OperationReplayAuthority"));
    assert!(endpoint_results.contains("PreparedEnrollmentBootstrapPrelude"));
    assert!(endpoint_results.contains("PreparedRebindBootstrapPrelude"));
    assert!(endpoint_results.contains("CompletedIdempotentResponse"));

    let signed = block(
        prelude,
        "pub(crate) struct PreparedSignedOperation",
        "pub(in crate::chat_protocol::repository) enum PreparedSignedOperationState",
    );
    assert!(!signed.contains("VerifiedChatDeviceRequest"));
    assert!(!signed.contains("OperationReplayGuard"));
    assert!(!signed.contains("SignedOperationReplayAuthority"));

    for handler in [
        include_str!("../src/handlers/chat/enroll_device.rs"),
        include_str!("../src/handlers/chat/replenish_key_packages.rs"),
    ] {
        assert!(!handler.contains("VerifiedChatDeviceRequest"));
        assert!(!handler.contains("OperationReplayGuard"));
        assert!(!handler.contains("OperationReservationGuard"));
        assert!(!handler.contains("validate_enrollment_operation_replay"));
        assert!(!handler.contains("validate_rebind_operation_replay"));
        assert!(!handler.contains("validate_replenishment_operation_replay"));
    }
}

#[test]
fn exact_replay_locks_and_validates_the_signed_package_effect_manifest() {
    let auth = include_str!("../src/chat_protocol/repository/auth.rs");
    let validator = block(
        auth,
        "async fn lock_and_validate_signed_package_effect_manifest",
        "\n/// Pre-head identity lock",
    );
    for required in [
        "key_package_ref",
        "wrapper_bytes",
        "wrapper_sha256",
        "owner_did",
        "owner_device_id",
        "owner_key_id",
        "owner_auth_generation",
        "signing_public_key",
        "FOR UPDATE",
    ] {
        assert!(
            validator.contains(required),
            "package-effect validator omitted {required}"
        );
    }
    assert!(validator.contains("Sha256::digest"));
    assert!(!validator.contains("availablePackageCount"));
    assert!(!validator.contains("reservedPackageCount"));
    assert!(!validator.contains("status IN"));

    let enrollment = block(
        auth,
        "pub(super) async fn load_validated_completed_enrollment_replay",
        "\n/// Rebind replay release",
    );
    let enrollment_manifest = enrollment
        .find("lock_and_validate_signed_package_effect_manifest")
        .expect("enrollment replay validates its signed package effects");
    let enrollment_bytes = enrollment
        .find("completed_replay")
        .expect("enrollment replay loads completion");
    assert!(enrollment_manifest < enrollment_bytes);

    let replenishment = block(
        auth,
        "pub(super) async fn load_validated_completed_replenishment_replay",
        "\nasync fn lock_and_validate_signed_package_effect_manifest",
    );
    let replenishment_manifest = replenishment
        .find("lock_and_validate_signed_package_effect_manifest")
        .expect("replenishment replay validates its signed package effects");
    let replenishment_bytes = replenishment
        .find("completed_replay")
        .expect("replenishment replay loads completion");
    assert!(replenishment_manifest < replenishment_bytes);
}
