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
    assert!(!admissions.contains("signing_public_key: Vec<u8>"));
    assert!(!admissions.contains("authority: VerifiedChatDeviceRequest"));

    let enrollment = block(
        auth,
        "impl EnrollmentOperationAdmission",
        "impl EnrollmentOperationReplayAuthority",
    );
    assert!(enrollment.contains("into_first_authority"));
    assert!(enrollment.contains("mint_enrollment_repository_authority"));
    assert!(enrollment.contains("into_replay_authority"));
    assert!(!enrollment.contains("CompletedIdempotentResponse"));
}

#[test]
fn active_handlers_arbitrate_deferred_admission_and_never_render_unvalidated_bytes() {
    let prelude = include_str!("../src/chat_protocol/repository/prelude.rs");
    let enrollment = prelude
        .split_once("pub(crate) async fn prepare_enrollment_operation")
        .expect("missing prepare_enrollment_operation")
        .1
        .split_once("\npub(crate) async fn ")
        .map_or_else(
            || panic!("missing function after prepare_enrollment_operation"),
            |(body, _)| body,
        );
    assert!(enrollment.contains("operation_claims"));
    assert!(enrollment.contains("into_first_authority"));
    assert!(enrollment.contains("into_replay_authority"));
    assert!(enrollment.contains("validate_"));
    assert!(enrollment.contains("Prepared"));
    assert!(!enrollment.contains("response_bytes"));
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
    let enrollment_result = block(
        prelude,
        "pub(crate) enum PreparedEnrollmentOperation",
        "pub(crate) enum PreparedReplenishmentOperation",
    );
    assert!(!enrollment_result.contains("VerifiedChatDeviceRequest"));
    assert!(!enrollment_result.contains("OperationReplayGuard"));
    assert!(!enrollment_result.contains("OperationReplayAuthority"));
    assert!(enrollment_result.contains("PreparedEnrollmentBootstrapPrelude"));
    assert!(enrollment_result.contains("CompletedIdempotentResponse"));

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
        "\n/// Replenishment replay release",
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
