//! Database-free production-shape proofs for the Task 6 G6 facade.

fn ordered(source: &str, needles: &[&str]) {
    let mut cursor = 0;
    for needle in needles {
        let offset = source[cursor..]
            .find(needle)
            .unwrap_or_else(|| panic!("missing ordered G6 stage: {needle}"));
        cursor += offset + needle.len();
    }
}

#[test]
fn g6_facade_owns_the_complete_first_execution_order() {
    let source = include_str!("../src/chat_protocol/repository/revocation.rs");
    let first = source
        .split_once("async fn prepare_first_device_revocation")
        .expect("G6 first-execution facade")
        .1
        .split_once("#[derive(sqlx::FromRow)]")
        .expect("G6 replay rows follow first execution")
        .0;

    ordered(
        first,
        &[
            "prepare_g6_identity_scope(",
            "verify_device_revocation_operation(",
            "lock_active_revocation_device_view(",
            "seal_g6_scope_authority(",
            "lock_g6_revocation_prehead_scope(",
            "conversation_ids().to_vec()",
            "hydrate_locked_conversation_state(",
            "seal_fanout(",
            "hydrate_locked_g6_prelude(",
            "locked_global_registration_from_scope_authority(",
            "plan_device_revocation_batch(",
            "into_post_revocation_view(",
            "into_execution_parts()",
        ],
    );
    assert!(
        !first.contains("conversation_ids.is_empty")
            && !first.contains("locked_conversations.is_empty"),
        "the legal empty G6 fanout must not be rejected"
    );
    assert!(
        !first.contains("ExecutionContextArtifacts")
            && !first.contains("ConversationExecutionArtifacts"),
        "handlers/facade cannot inject G6 execution artifacts"
    );
    assert!(
        !first.contains(".commit().await"),
        "G6 facade must not commit the caller-owned transaction"
    );
}

#[test]
fn g6_execution_capsule_has_canonical_artifacts_and_explicit_rollback() {
    let facade = include_str!("../src/chat_protocol/repository/revocation.rs");
    for required in [
        "prepare_canonical_device_revocation_batch_execution",
        "PreparedDeviceRevocationApplication",
        "apply_device_revocation_batch_sequential",
        "self.prepared.rollback().await",
        "requires_outer_abort",
        "complete_operation(",
        "CanonicalDeviceRevocationResponse",
        "&self.response.body",
        "None,",
    ] {
        assert!(
            facade.contains(required),
            "G6 facade omitted linear execution property: {required}"
        );
    }

    let execution = include_str!("../src/chat_protocol/repository/execution_context.rs");
    let canonical = execution
        .split_once("pub(crate) async fn prepare_canonical_device_revocation_batch_execution")
        .expect("canonical G6 executor constructor")
        .1
        .split_once("/// Test compatibility")
        .expect("bounded canonical G6 executor constructor")
        .0;
    assert!(canonical.contains("ExecutionContextArtifacts::default()"));
    assert!(!canonical.contains("artifact_inputs:"));
    assert!(!canonical.contains("accepted_control"));
    assert!(!canonical.contains("primary_event"));
}

#[test]
fn g6_replay_releases_no_bytes_before_exact_poststate_and_response_hash() {
    let source = include_str!("../src/chat_protocol/repository/revocation.rs");
    let dispatch = source
        .split_once("pub(crate) async fn prepare_device_revocation")
        .expect("G6 operation dispatcher")
        .1
        .split_once("async fn prepare_first_device_revocation")
        .expect("bounded G6 operation dispatcher")
        .0;
    assert!(dispatch.contains("lock_signed_operation_replay_authority"));
    assert!(dispatch.contains("prepare_device_revocation_replay"));
    let replay = source
        .split_once("async fn prepare_device_revocation_replay")
        .expect("G6 replay facade")
        .1
        .split_once("/// Real-library compiler witness")
        .expect("bounded G6 replay facade")
        .0;

    ordered(
        replay,
        &[
            "FROM chat.device_revocations",
            "FOR UPDATE",
            "FROM chat.devices device",
            "FOR UPDATE OF device,device_key",
            "CanonicalDeviceRevocationResponse::from_device",
            "post_state_digest",
            "release_signed_operation_replay",
            "response.status()",
        ],
    );
    for exact_terminal_fact in [
        "available_package_count != 0",
        "reserved_package_count != 0",
        "open_recovery_request_count != 0",
        "active_reservation_count != 0",
        "pending_welcome_count != 0",
        "pending_recovery_work_count != 0",
        "invalid_package_terminal_count != 0",
        "invalid_request_terminal_count != 0",
        "invalid_reservation_terminal_count != 0",
        "invalid_recovery_work_terminal_count != 0",
    ] {
        assert!(
            replay.contains(exact_terminal_fact),
            "G6 replay omitted terminal poststate fact: {exact_terminal_fact}"
        );
    }
    let release_at = replay
        .find("release_signed_operation_replay")
        .expect("G6 release call");
    assert!(
        !replay[..release_at].contains("response_bytes()"),
        "stored response bytes must remain opaque until exact G6 validation"
    );
}

#[test]
fn g6_completion_accepts_only_facade_owned_canonical_bytes() {
    let facade = include_str!("../src/chat_protocol/repository/revocation.rs");
    let applied = facade
        .split_once("impl AppliedDeviceRevocationMutation")
        .expect("applied G6 mutation")
        .1
        .split_once("struct ExactRevocationInput")
        .expect("bounded applied G6 mutation")
        .0;

    for required in [
        "CanonicalDeviceRevocationResponse",
        "validates_device(self.material.device())",
        "self.response.status",
        "&self.response.body",
        "CompletedDeviceRevocationMutation",
        "into_response_bytes",
    ] {
        assert!(
            facade.contains(required),
            "G6 completion omitted canonical response boundary: {required}"
        );
    }
    let signature = applied
        .split_once("pub(crate) async fn complete(")
        .expect("G6 completion")
        .1
        .split_once(") -> Result<CompletedDeviceRevocationMutation")
        .expect("bounded G6 completion signature")
        .0;
    assert!(
        !signature.contains("response_bytes") && !signature.contains("&[u8]"),
        "G6 completion must not accept caller-authored response bytes"
    );

    let handler = include_str!("../src/handlers/chat/revoke_device.rs");
    assert!(
        !handler.contains("serde_json::to_vec")
            && handler.contains(".complete(&mut transaction)")
            && handler.contains("into_response_bytes"),
        "revokeDevice handler must transmit only facade-owned completed bytes"
    );
}

#[test]
fn g6_replay_proof_is_sealed_to_canonical_device_output() {
    let source = include_str!("../src/chat_protocol/repository/revocation.rs");
    for required in [
        "pub(in crate::chat_protocol::repository) struct DeviceRevocationReplayPostStateProof",
        "expected_response_sha256",
        "expected_status",
        "post_state_digest",
        "validates_seal",
        "RevokeDeviceOutput::<DefaultStr>",
        "DeviceView",
        "G6_REPLAY_POST_STATE_DOMAIN",
    ] {
        assert!(
            source.contains(required),
            "sealed G6 replay proof omitted {required}"
        );
    }
}

#[test]
fn g6_target_failures_are_closed_semantic_facade_errors() {
    let directory = include_str!("../src/chat_protocol/repository/device_directory.rs");
    for required in [
        "RevocationDeviceViewError::Missing",
        "RevocationDeviceViewError::Revoked",
        "RevocationDeviceViewError::AuthGenerationConflict",
        "RevocationDeviceViewError::Projection",
        "validate_active_revocation_device_view_row",
    ] {
        assert!(
            directory.contains(required),
            "device-view lock omitted semantic classification: {required}"
        );
    }

    let facade = include_str!("../src/chat_protocol/repository/revocation.rs");
    for required in [
        "TargetMissing",
        "TargetRevoked",
        "AuthenticationGenerationConflict",
        "TargetProjection",
        "DeviceViewDatabase",
        "impl From<RevocationDeviceViewError>",
        "LockedG6PreludeError::Prelude(PreludeError::MissingDevice)",
    ] {
        assert!(
            facade.contains(required),
            "G6 facade did not propagate target failure: {required}"
        );
    }
}
