use super::{
    auth, bootstrap_completion_digest, canonical_operation_lock_key, BootstrapCompletionGuard,
    BootstrapCompletionJktShape, CanonicalDeviceIdentity, CanonicalLockScope, OperationArbitration,
    OperationClaimGuard, ReplayCandidate,
};
use super::{OperationClaimBinding, OperationClaimRow};
use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[test]
fn operation_advisory_identity_is_global_not_actor_or_endpoint_scoped() {
    let operation_id = Uuid::parse_str("67a08d9c-46a3-4cb2-aa4a-50f756748f3a").unwrap();

    assert_eq!(
        canonical_operation_lock_key(operation_id),
        "chat-operation-id:67a08d9c-46a3-4cb2-aa4a-50f756748f3a"
    );
}

#[test]
fn canonical_identity_scope_orders_did_bytes_then_uuid_bytes() {
    let low_uuid = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
    let high_uuid = Uuid::parse_str("ffffffff-ffff-4fff-bfff-ffffffffffff").unwrap();

    let scope = CanonicalLockScope::new(
        vec![
            "did:web:principal-only.example.com".to_owned(),
            "did:web:a.example.com".to_owned(),
        ],
        vec![
            CanonicalDeviceIdentity::new("did:web:z.example.com", low_uuid),
            CanonicalDeviceIdentity::new("did:web:a.example.com", high_uuid),
            CanonicalDeviceIdentity::new("did:web:a.example.com", low_uuid),
            CanonicalDeviceIdentity::new("did:web:a.example.com", low_uuid),
        ],
    )
    .unwrap();

    let ordered = scope
        .devices()
        .iter()
        .map(|identity| (identity.did(), identity.device_id()))
        .collect::<Vec<_>>();
    assert_eq!(
        ordered,
        vec![
            ("did:web:a.example.com", low_uuid),
            ("did:web:a.example.com", high_uuid),
            ("did:web:z.example.com", low_uuid),
        ]
    );
    assert_eq!(
        scope.principals(),
        &[
            "did:web:a.example.com".to_owned(),
            "did:web:principal-only.example.com".to_owned(),
            "did:web:z.example.com".to_owned(),
        ]
    );
}

#[test]
fn canonical_identity_scope_rejects_empty_or_non_bare_did() {
    assert!(CanonicalLockScope::new(Vec::new(), Vec::new()).is_err());
    assert!(CanonicalLockScope::new(
        vec!["did:web:a.example.com#fragment".to_owned()],
        Vec::new(),
    )
    .is_err());
    assert!(CanonicalLockScope::new(
        vec!["did:web:a.example.com".to_owned()],
        vec![CanonicalDeviceIdentity::new(
            "did:web:a.example.com#fragment",
            Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap(),
        )],
    )
    .is_err());
}

#[test]
fn canonical_lock_projection_requires_only_the_actor_key() {
    let source = include_str!("../../src/chat_protocol/repository/auth.rs");
    let block = source
        .split_once("pub(super) async fn lock_canonical_business_authority_scope")
        .unwrap()
        .1
        .split_once("/// Repository-slice test seam")
        .unwrap()
        .0;
    assert!(block.contains("key.enrollment_auth_generation"));
    assert!(!block.contains("actor_key.enrollment_auth_generation"));
    assert!(block.contains("operation: &CanonicalOperationReservationGuard"));
    assert!(block.contains("operation.transaction_id != transaction_id"));
    assert!(block
        .contains("authority.repository_receipt().operation_id() != Some(operation.operation_id)"));
    assert!(!block.contains("scope.identities.iter().any"));
    assert!(block.contains("let actor_key = locked_keys"));
    assert!(block.contains("actor_key.revoked_at.is_some()"));
}

#[test]
fn canonical_identity_lock_requires_the_opaque_global_operation_reservation() {
    let auth_source = include_str!("../../src/chat_protocol/repository/auth.rs");
    let permit = auth_source
        .split_once("pub(super) struct CanonicalOperationReservationGuard")
        .unwrap()
        .1
        .split_once("impl CanonicalOperationReservationGuard")
        .unwrap()
        .0;
    assert!(permit.contains("transaction_id: String"));
    assert!(permit.contains("operation_id: Uuid"));
    assert!(!permit.contains("pub(super) transaction_id"));
    assert!(!permit.contains("pub(super) operation_id"));

    let prelude_source = include_str!("../../src/chat_protocol/repository/prelude.rs");
    let arbitration = prelude_source
        .split_once("pub(crate) async fn arbitrate_operation")
        .unwrap()
        .1
        .split_once("pub(crate) async fn prepare_actor_prelude")
        .unwrap()
        .0;
    let global_reservation = arbitration.find("reserve_canonical_operation").unwrap();
    let claim_lookup = arbitration.find("FROM chat.operation_claims").unwrap();
    assert!(global_reservation < claim_lookup);
    assert!(!prelude_source.contains("pg_advisory_xact_lock"));
}

#[test]
fn prepared_scope_authority_has_no_raw_business_guard_escape() {
    let source = include_str!("../../src/chat_protocol/repository/prelude.rs");
    let prepared_boundary = source
        .split_once("pub(crate) struct PreparedBusinessPrelude")
        .unwrap()
        .1
        .split_once("pub(crate) async fn arbitrate_operation")
        .unwrap()
        .0;
    assert!(!prepared_boundary.contains("BusinessAuthorityGuard"));
    assert!(!prepared_boundary.contains("impl Deref"));
    assert!(
        prepared_boundary.contains(") -> (ScopeBoundBusinessAuthority, OperationCompletionGuard)")
    );

    let completion_boundary = source
        .split_once("pub(crate) async fn complete_operation")
        .unwrap()
        .1
        .split_once("fn completion_digest_from_scope_authority")
        .unwrap()
        .0;
    assert!(completion_boundary.contains("scope_authority: ScopeBoundBusinessAuthority"));
    assert!(completion_boundary.contains("scope_authority.receipt_id() != scope_receipt_id"));
    assert!(completion_boundary.contains("scope_authority.scope_digest() != &scope_digest"));
    assert!(completion_boundary
        .contains("completion_digest_from_scope_authority(&scope_authority, &claim.binding)"));
}

#[test]
fn recovery_claim_verifier_is_consuming_and_binds_every_exact_dimension() {
    let source = include_str!("../../src/chat_protocol/repository/prelude.rs");
    let function = source
        .split_once("pub(crate) fn verify_recovery_operation(")
        .expect("missing recovery claim verifier")
        .1
        .split_once("\n    }\n")
        .expect("unterminated recovery claim verifier")
        .0;
    assert!(function.contains("self,"));
    for fact in [
        "operation_id",
        "principal_did",
        "endpoint_nsid",
        "mutation_kind",
        "request_digest",
        "accepted_request_sha256",
        "signature",
        "transaction_id",
    ] {
        assert!(function.contains(fact), "missing exact claim fact: {fact}");
    }
}

#[test]
fn reset_revocation_and_welcome_claim_verifiers_are_consuming_and_exact() {
    let source = include_str!("../../src/chat_protocol/repository/prelude.rs");
    let transcript_source = include_str!("../../src/chat_protocol/transcript.rs");
    for function_name in [
        "verify_reset_operation",
        "verify_device_revocation_operation",
        "verify_welcome_operation",
    ] {
        let function = source
            .split_once(&format!("pub(crate) fn {function_name}("))
            .unwrap_or_else(|| panic!("missing {function_name}"))
            .1
            .split_once("\n    }\n")
            .unwrap_or_else(|| panic!("unterminated {function_name}"))
            .0;
        assert!(
            function.contains("self,"),
            "{function_name} must consume the prepared prelude"
        );
        assert!(
            function.contains("verify_exact_operation_claim"),
            "{function_name} must use the closed exact-claim verifier"
        );
    }

    for exact_mapping in [
        (
            "RequestReset",
            "blue.catbird.chat.requestReset",
            "SignedMutationKind::ResetRequest",
            "\"resetRequestBody\"",
        ),
        (
            "ActivateReset",
            "blue.catbird.chat.activateReset",
            "SignedMutationKind::ResetActivation",
            "\"resetActivationBody\"",
        ),
        (
            "DeviceRevocation",
            "blue.catbird.chat.revokeDevice",
            "SignedMutationKind::DeviceRevocation",
            "\"deviceRevocationBody\"",
        ),
        (
            "AcknowledgeWelcome",
            "blue.catbird.chat.acknowledgeWelcome",
            "SignedMutationKind::WelcomeAcknowledgement",
            "\"welcomeAcknowledgementBody\"",
        ),
        (
            "RejectWelcome",
            "blue.catbird.chat.rejectWelcome",
            "SignedMutationKind::WelcomeRejection",
            "\"welcomeRejectionBody\"",
        ),
    ] {
        for value in [exact_mapping.0, exact_mapping.1, exact_mapping.2] {
            assert!(
                source.contains(value),
                "missing exact operation mapping fact: {value}"
            );
        }
        assert!(
            transcript_source.contains(exact_mapping.3),
            "missing canonical mutation body: {}",
            exact_mapping.3
        );
    }

    let exact = source
        .split_once("fn verify_exact_operation_claim(")
        .expect("missing closed exact operation-claim verifier")
        .1
        .split_once("\n    }\n")
        .expect("unterminated exact operation-claim verifier")
        .0;
    for fact in [
        "operation_id.get_version_num() != 4",
        "operation.transaction_id",
        "authority.transaction_id()",
        "binding.operation_id",
        "binding.principal_did",
        "mutation.actor_did()",
        "binding.endpoint_nsid",
        "binding.mutation_kind",
        "mutation.type_id()",
        "binding.request_digest",
        "mutation.request_digest()",
        "binding.accepted_request_sha256",
        "Sha256::digest(accepted_request_bytes)",
        "binding.signature",
        "mutation.signature()",
    ] {
        assert!(exact.contains(fact), "missing exact claim fact: {fact}");
    }
}

#[test]
fn scope_registration_adapter_borrows_without_raw_guard_escape() {
    let source = include_str!("../../src/chat_protocol/state_machine.rs");
    let adapter = source
        .split_once("pub(crate) fn locked_registration_from_scope_authority(")
        .expect("missing scope-derived registration adapter")
        .1
        .split_once("\n    pub(crate) fn locked_recovery_reservation(")
        .expect("unterminated scope-derived registration adapter")
        .0;

    assert!(adapter.contains("scope: &ScopeBoundBusinessAuthority"));
    assert!(!source.contains(
        "#[cfg(not(test))]\nuse super::repository::prelude::ScopeBoundBusinessAuthority"
    ));
    assert!(!source
        .contains("#[cfg(not(test))]\n    pub(crate) fn locked_registration_from_scope_authority"));
    assert!(!adapter.contains("BusinessAuthorityGuard"));
    assert!(!adapter.contains("locked_registration_from_guard"));
    for fact in [
        "scope.actor_class()",
        "scope.actor_did()",
        "scope.actor_device_id()",
        "actor_dpop_jkt()",
        "actor_auth_generation()",
        "actor_key_id()",
        "actor_signing_public_key()",
        "trusted_instant()",
        ".principals()",
        ".devices()",
        ".keys()",
        "scope.transaction_id()",
    ] {
        assert!(
            adapter.contains(fact),
            "scope adapter omitted locked projection fact: {fact}"
        );
    }
}

#[test]
fn scope_registration_adapter_preserves_scope_digest_across_auth_rebind() {
    let source = include_str!("../../src/chat_protocol/state_machine.rs");
    let adapter = source
        .split_once("pub(crate) fn locked_registration_from_scope_authority(")
        .expect("missing scope-derived registration adapter")
        .1
        .split_once("\n    pub(crate) fn locked_recovery_reservation(")
        .expect("unterminated scope-derived registration adapter")
        .0;
    assert!(adapter.contains("actor_projected_signing_public_key()"));
    assert!(adapter.contains("authority_scope_digest: *scope.scope_digest()"));
    assert!(!adapter.contains("locked_key.enrollment_auth_generation() == actor_auth_generation"));

    let registration = source
        .split_once("pub(crate) struct LockedRegistrationProjection {")
        .expect("missing locked registration projection")
        .1
        .split_once("\n}")
        .expect("unterminated locked registration projection")
        .0;
    assert!(registration.contains("authority_scope_digest: [u8; 32]"));
    assert!(source.contains("pub(crate) fn authority_scope_digest(&self) -> &[u8; 32]"));

    let plan = source
        .split_once("pub(crate) struct DeviceRevocationBatchPersistencePlan {")
        .expect("missing device-revocation batch plan")
        .1
        .split_once("\n}")
        .expect("unterminated device-revocation batch plan")
        .0;
    assert!(plan.contains("authority_scope_digest: [u8; 32]"));
    let constructor = source
        .split_once("Ok(DeviceRevocationBatchPersistencePlan {")
        .expect("missing production device-revocation plan constructor")
        .1
        .split_once("\n        })")
        .expect("unterminated production device-revocation plan constructor")
        .0;
    assert!(constructor
        .contains("authority_scope_digest: *actor_registration.authority_scope_digest()"));
}

#[test]
fn scope_registration_adapter_rejects_post_rebind_key_material_drift() {
    let source = include_str!("../../src/chat_protocol/state_machine.rs");
    let adapter = source
        .split_once("pub(crate) fn locked_registration_from_scope_authority(")
        .expect("missing scope-derived registration adapter")
        .1
        .split_once("\n    pub(crate) fn locked_recovery_reservation(")
        .expect("unterminated scope-derived registration adapter")
        .0;
    assert!(adapter.contains("exact_signing_public_key != actor_signing_public_key"));
    assert!(adapter.contains("exact_key.signing_public_key_sha256()"));
    assert!(adapter.contains("Sha256::digest(registered_mls_signature_key)"));
    assert!(adapter.contains("exact_device.auth_generation() != actor_auth_generation"));
    assert!(adapter.contains("exact_key.revoked_at().is_some()"));
}

#[test]
fn revocation_batch_consumes_scope_derived_registration_not_raw_authority() {
    let source = include_str!("../../src/chat_protocol/state_machine.rs");
    let planner = source
        .split_once("pub(crate) fn plan_device_revocation_batch(")
        .expect("missing device-revocation batch planner")
        .1
        .split_once("\n    }\n")
        .expect("unterminated device-revocation batch planner")
        .0;
    assert!(planner.contains("actor_registration: LockedRegistrationProjection"));
    assert!(planner.contains("actor_registration.authorizes_revocation(&evidence)"));
    assert!(planner.contains("actor_registration.transaction_id()"));
    assert!(planner.contains("actor_registration.trusted_read_at()"));
    assert!(!planner.contains("BusinessAuthorityGuard"));
    assert!(!planner.contains("stored_key_id"));
    assert!(!planner.contains("stored_auth_generation"));
}

#[test]
fn scope_signing_key_lookup_is_exact_and_has_no_broad_raw_key_escape() {
    let prelude_source = include_str!("../../src/chat_protocol/repository/prelude.rs");
    let lookup = prelude_source
        .split_once("pub(crate) fn signing_public_key_for(")
        .expect("missing exact scope signing-key lookup")
        .1
        .split_once("\n    }\n")
        .expect("unterminated exact scope signing-key lookup")
        .0;
    assert!(lookup.contains("self.locked"));
    assert!(lookup.contains(".signing_public_key_for("));
    assert!(!lookup.contains(".keys()"));
    assert!(!lookup.contains("key.signing_public_key()"));

    let auth_source = include_str!("../../src/chat_protocol/repository/auth.rs");
    let key_projection = auth_source
        .split_once("impl LockedCanonicalKeyProjection {")
        .expect("missing locked canonical key projection")
        .1
        .split_once("\n}")
        .expect("unterminated locked canonical key projection")
        .0;
    let opaque_scope = auth_source
        .split_once("impl LockedCanonicalAuthorityScope {")
        .expect("missing locked canonical authority scope")
        .1;
    let opaque_lookup = opaque_scope
        .split_once("pub(super) fn signing_public_key_for(")
        .expect("missing opaque-scope exact signing-key lookup")
        .1
        .split_once("\n    }\n")
        .expect("unterminated opaque-scope exact signing-key lookup")
        .0;
    for dimension in [
        "key.user_did() == did",
        "key.device_id() == device_id",
        "key.key_id() == key_id",
        "key.enrollment_auth_generation() == enrollment_auth_generation",
        "key.signing_public_key()",
    ] {
        assert!(
            opaque_lookup.contains(dimension),
            "opaque signing-key lookup omitted exact tuple dimension: {dimension}"
        );
    }

    assert!(key_projection.contains("fn signing_public_key(&self) -> &[u8]"));
    assert!(!key_projection.contains("pub(super) fn signing_public_key(&self) -> &[u8]"));
    assert!(!key_projection.contains("pub(crate) fn signing_public_key(&self) -> &[u8]"));
    let actor_lookup = opaque_scope
        .split_once("pub(super) fn actor_projected_signing_public_key(")
        .expect("missing actor-restricted projected signing-key lookup")
        .1
        .split_once("\n    }\n")
        .expect("unterminated actor-restricted projected signing-key lookup")
        .0;
    assert!(!actor_lookup.contains("enrollment_auth_generation"));
    assert!(actor_lookup.contains("key.user_did() == self.actor.subject()"));
    assert!(actor_lookup.contains("key.device_id() == self.actor.device_id()"));
    assert!(actor_lookup.contains("key.key_id() == actor_key_id"));
}

#[test]
fn completed_replay_bytes_cross_auth_only_after_post_state_validation() {
    let auth_source = include_str!("../../src/chat_protocol/repository/auth.rs");
    assert!(!auth_source.contains("pub(super) async fn load_completed_business_replay"));
    assert!(!auth_source.contains("pub(super) async fn validate_completed_business_authority"));

    let loader = auth_source
        .split_once("pub(super) async fn load_validated_completed_business_replay")
        .unwrap()
        .1
        .split_once("fn completed_replay_jkt_matches")
        .unwrap()
        .0;
    let raw_load = loader.find("completed_replay(").unwrap();
    let validation = loader
        .find("validate_completed_business_authority(")
        .unwrap();
    let release = loader.find("Ok(response)").unwrap();
    assert!(raw_load < validation && validation < release);

    let prelude_source = include_str!("../../src/chat_protocol/repository/prelude.rs");
    assert!(prelude_source.contains("load_validated_completed_business_replay"));
    assert!(!prelude_source.contains("auth::validate_completed_business_authority"));
}

#[test]
fn signed_self_revocation_replay_validates_terminal_authority_before_release_and_after_race() {
    let source = include_str!("../../src/chat_protocol/repository/auth.rs");
    let arbitration = source
        .split_once("async fn arbitrate_signed")
        .unwrap()
        .1
        .split_once("async fn arbitrate_enrollment")
        .unwrap()
        .0;

    let classify_self = arbitration
        .find("canonical_is_exact_self_target_revocation")
        .unwrap();
    let initial_completed = arbitration
        .find("exact_self_revocation && completed.is_some()")
        .unwrap();
    let first_terminal_validation = arbitration
        .find("validate_completed_self_revocation_material")
        .unwrap();
    let active_lock = arbitration.find("lock_existing_authority").unwrap();
    assert!(classify_self < initial_completed);
    assert!(
        initial_completed < first_terminal_validation && first_terminal_validation < active_lock
    );

    let revoked_race = arbitration
        .find("Err(AuthRepositoryError::DeviceRevoked) if exact_self_revocation")
        .unwrap();
    let reread = arbitration[revoked_race..]
        .find("completed_replay(transaction, pre_replay, material)")
        .unwrap()
        + revoked_race;
    let second_terminal_validation = arbitration[reread..]
        .find("validate_completed_self_revocation_material")
        .unwrap()
        + reread;
    assert!(active_lock < revoked_race);
    assert!(revoked_race < reread && reread < second_terminal_validation);
    assert!(arbitration[second_terminal_validation..]
        .contains("return Err(AuthRepositoryError::CorruptIdempotencyRecord)"));
}

#[test]
fn operation_claim_match_binds_every_immutable_request_dimension() {
    let operation_id = Uuid::parse_str("67a08d9c-46a3-4cb2-aa4a-50f756748f3a").unwrap();
    let accepted = b"exact accepted wrapper";
    let binding = OperationClaimBinding::for_test(
        operation_id,
        "did:web:actor.example.com",
        "blue.catbird.chat.requestReset",
        "blue.catbird.chat.defs#resetRequestBody",
        [7; 32],
        Sha256::digest(accepted).into(),
        [9; 64],
        Utc.timestamp_millis_opt(1_785_252_309_123).unwrap(),
    );
    let exact = OperationClaimRow::for_test(
        operation_id,
        "did:web:actor.example.com",
        "blue.catbird.chat.requestReset",
        "blue.catbird.chat.defs#resetRequestBody",
        [7; 32].to_vec(),
        Sha256::digest(accepted).to_vec(),
        [9; 64].to_vec(),
    );
    assert!(exact.matches(&binding));

    let changed_endpoint = OperationClaimRow::for_test(
        operation_id,
        "did:web:actor.example.com",
        "blue.catbird.chat.revokeDevice",
        "blue.catbird.chat.defs#deviceRevocationBody",
        [7; 32].to_vec(),
        Sha256::digest(accepted).to_vec(),
        [9; 64].to_vec(),
    );
    assert!(!changed_endpoint.matches(&binding));

    let changed_signature = OperationClaimRow::for_test(
        operation_id,
        "did:web:actor.example.com",
        "blue.catbird.chat.requestReset",
        "blue.catbird.chat.defs#resetRequestBody",
        [7; 32].to_vec(),
        Sha256::digest(accepted).to_vec(),
        [8; 64].to_vec(),
    );
    assert!(!changed_signature.matches(&binding));
}

#[test]
fn unvalidated_replay_debug_never_exposes_response_material() {
    let operation_id = Uuid::parse_str("67a08d9c-46a3-4cb2-aa4a-50f756748f3a").unwrap();
    let response_bytes = vec![222, 173, 190, 239, 17, 34, 51, 68];
    let response = auth::CompletedIdempotentResponse::debug_redaction_sentinel_for_test(
        598,
        response_bytes.clone(),
    );
    let candidate = ReplayCandidate {
        transaction_id: "debug-redaction-test-transaction".to_owned(),
        binding: OperationClaimBinding::for_test(
            operation_id,
            "did:web:actor.example.com",
            "blue.catbird.chat.requestReset",
            "blue.catbird.chat.defs#resetRequestBody",
            [7; 32],
            [8; 32],
            [9; 64],
            Utc.timestamp_millis_opt(1_785_252_309_123).unwrap(),
        ),
        response,
    };

    let candidate_debug = format!("{candidate:?}");
    let arbitration_debug = format!("{:?}", OperationArbitration::Replay(candidate));
    assert_eq!(candidate_debug, "ReplayCandidate(<redacted>)");
    assert_eq!(
        arbitration_debug,
        "OperationArbitration::Replay(<redacted>)"
    );
    for rendered in [candidate_debug, arbitration_debug] {
        assert!(!rendered.contains("598"));
        assert!(!rendered.contains(&format!("{response_bytes:?}")));
    }
}

#[test]
fn bootstrap_completion_guard_rejects_foreign_transaction() {
    let (guard, binding, scope_receipt, scope_digest, instant) = enrollment_guard_fixture();
    assert!(guard.matches_test_material(
        "bootstrap-test-tx",
        &binding,
        scope_receipt,
        &scope_digest,
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "new-jkt",
        None,
        None,
        None,
        None,
    ));
    assert!(!guard.matches_test_material(
        "foreign-tx",
        &binding,
        scope_receipt,
        &scope_digest,
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "new-jkt",
        None,
        None,
        None,
        None,
    ));
}

#[test]
fn bootstrap_completion_guard_rejects_digest_mismatch() {
    let (guard, binding, scope_receipt, scope_digest, instant) = enrollment_guard_fixture();
    assert!(!guard.matches_test_material(
        "bootstrap-test-tx",
        &binding,
        Uuid::from_u128(2),
        &scope_digest,
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "new-jkt",
        None,
        None,
        None,
        None,
    ));
    assert!(!guard.matches_test_material(
        "bootstrap-test-tx",
        &binding,
        scope_receipt,
        &[2u8; 32],
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "new-jkt",
        None,
        None,
        None,
        None,
    ));
}

#[test]
fn bootstrap_completion_guard_rejects_claim_and_completion_token_mismatch() {
    let (guard, binding, scope_receipt, scope_digest, instant) = enrollment_guard_fixture();
    let mut changed_binding = OperationClaimBinding::for_test(
        binding.operation_id,
        &binding.principal_did,
        &binding.endpoint_nsid,
        &binding.mutation_kind,
        binding.request_digest,
        binding.accepted_request_sha256,
        [8u8; 64],
        instant,
    );
    assert!(!guard.matches_test_material(
        "bootstrap-test-tx",
        &changed_binding,
        scope_receipt,
        &scope_digest,
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "new-jkt",
        None,
        None,
        None,
        None,
    ));
    changed_binding.operation_id = Uuid::from_u128(9);
    assert!(!guard.matches_test_material(
        "bootstrap-test-tx",
        &changed_binding,
        scope_receipt,
        &scope_digest,
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "new-jkt",
        None,
        None,
        None,
        None,
    ));
}

#[test]
fn rebind_completion_guard_rejects_old_jkt_generation_key_and_signature_drift() {
    let op_id = Uuid::parse_str("67a08d9c-46a3-4cb2-aa4a-50f756748f3a").unwrap();
    let scope_receipt = Uuid::from_u128(2);
    let scope_digest = [3u8; 32];
    let instant = Utc.timestamp_millis_opt(1_785_252_309_123).unwrap();
    let binding = OperationClaimBinding::for_test(
        op_id,
        "did:plc:test",
        "blue.catbird.chat.rebindDeviceAuthentication",
        "deviceAuthenticationRebind",
        [7u8; 32],
        [8u8; 32],
        [9u8; 64],
        instant,
    );
    let guard = BootstrapCompletionGuard {
        operation: OperationClaimGuard {
            transaction_id: "rebind-test-tx".to_owned(),
            binding: OperationClaimBinding::for_test(
                op_id,
                "did:plc:test",
                "blue.catbird.chat.rebindDeviceAuthentication",
                "deviceAuthenticationRebind",
                [7u8; 32],
                [8u8; 32],
                [9u8; 64],
                instant,
            ),
        },
        scope_receipt_id: scope_receipt,
        authority_digest: bootstrap_completion_digest(
            "rebind-test-tx",
            &binding,
            scope_receipt,
            &scope_digest,
            instant,
            "did:plc:test",
            Uuid::from_u128(3),
            "new-jkt",
            Some("old-jkt"),
            Some("key-id"),
            Some(7),
            Some(&[2u8; 32]),
        ),
        scope_digest,
        jkt_shape: BootstrapCompletionJktShape::Rebind {
            historical: "old-jkt".to_owned(),
            current: "new-jkt".to_owned(),
        },
    };
    for (old_jkt, generation, key_id, key_digest) in [
        ("drifted-old-jkt", 7, "key-id", [2u8; 32]),
        ("old-jkt", 8, "key-id", [2u8; 32]),
        ("old-jkt", 7, "other-key", [2u8; 32]),
        ("old-jkt", 7, "key-id", [4u8; 32]),
    ] {
        assert!(!guard.matches_test_material(
            "rebind-test-tx",
            &binding,
            scope_receipt,
            &scope_digest,
            instant,
            "did:plc:test",
            Uuid::from_u128(3),
            "new-jkt",
            Some(old_jkt),
            Some(key_id),
            Some(generation),
            Some(&key_digest),
        ));
    }
}

fn enrollment_guard_fixture() -> (
    BootstrapCompletionGuard,
    OperationClaimBinding,
    Uuid,
    [u8; 32],
    chrono::DateTime<Utc>,
) {
    let operation_id = Uuid::parse_str("67a08d9c-46a3-4cb2-aa4a-50f756748f3a").unwrap();
    let instant = Utc.timestamp_millis_opt(1_785_252_309_123).unwrap();
    let binding = OperationClaimBinding::for_test(
        operation_id,
        "did:plc:test",
        "blue.catbird.chat.enrollDevice",
        "deviceEnrollment",
        [7u8; 32],
        [8u8; 32],
        [9u8; 64],
        instant,
    );
    let scope_receipt = Uuid::from_u128(11);
    let scope_digest = [1u8; 32];
    let authority_digest = bootstrap_completion_digest(
        "bootstrap-test-tx",
        &binding,
        scope_receipt,
        &scope_digest,
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "new-jkt",
        None,
        None,
        None,
        None,
    );
    let guard = BootstrapCompletionGuard {
        operation: OperationClaimGuard {
            transaction_id: "bootstrap-test-tx".to_owned(),
            binding: OperationClaimBinding::for_test(
                operation_id,
                "did:plc:test",
                "blue.catbird.chat.enrollDevice",
                "deviceEnrollment",
                [7u8; 32],
                [8u8; 32],
                [9u8; 64],
                instant,
            ),
        },
        scope_receipt_id: scope_receipt,
        authority_digest,
        scope_digest,
        jkt_shape: BootstrapCompletionJktShape::Enrollment {
            current: "new-jkt".to_owned(),
        },
    };
    (guard, binding, scope_receipt, scope_digest, instant)
}

#[test]
fn bootstrap_completion_digest_is_deterministic() {
    let op_id = Uuid::parse_str("67a08d9c-46a3-4cb2-aa4a-50f756748f3a").unwrap();
    let scope_receipt = Uuid::parse_str("f0000000-0000-4000-a000-000000000001").unwrap();
    let scope_digest = [1u8; 32];
    let instant = Utc.timestamp_millis_opt(1_785_252_309_123).unwrap();
    let binding = OperationClaimBinding::for_test(
        op_id,
        "did:plc:test",
        "blue.catbird.chat.enrollDevice",
        "deviceEnrollment",
        [7u8; 32],
        [8u8; 32],
        [9u8; 64],
        Utc.timestamp_millis_opt(1_785_252_309_123).unwrap(),
    );
    let first = bootstrap_completion_digest(
        "test-tx",
        &binding,
        scope_receipt,
        &scope_digest,
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "new-jkt",
        None,
        None,
        None,
        None,
    );
    let second = bootstrap_completion_digest(
        "test-tx",
        &binding,
        scope_receipt,
        &scope_digest,
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "new-jkt",
        None,
        None,
        None,
        None,
    );
    assert_eq!(
        first, second,
        "deterministic inputs must produce identical digests"
    );
}

#[test]
fn bootstrap_completion_digest_differs_per_jkt_shape() {
    let op_id = Uuid::parse_str("67a08d9c-46a3-4cb2-aa4a-50f756748f3a").unwrap();
    let scope_receipt = Uuid::parse_str("f0000000-0000-4000-a000-000000000001").unwrap();
    let scope_digest = [1u8; 32];
    let instant = Utc.timestamp_millis_opt(1_785_252_309_123).unwrap();
    let binding = OperationClaimBinding::for_test(
        op_id,
        "did:plc:test",
        "blue.catbird.chat.enrollDevice",
        "deviceEnrollment",
        [7u8; 32],
        [8u8; 32],
        [9u8; 64],
        instant,
    );
    // Enrollment: (None, Some(new)), Rebind: (Some(old), Some(new)), Replenishment: (None, None)
    let enrollment = bootstrap_completion_digest(
        "test-tx",
        &binding,
        scope_receipt,
        &scope_digest,
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "new-jkt",
        None,
        None,
        None,
        None,
    );
    let replenishment = bootstrap_completion_digest(
        "test-tx",
        &binding,
        scope_receipt,
        &scope_digest,
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "",
        None,
        None,
        None,
        None,
    );
    let rebind = bootstrap_completion_digest(
        "test-tx",
        &binding,
        scope_receipt,
        &scope_digest,
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "new-jkt",
        Some("old-jkt"),
        Some("key-id"),
        Some(7),
        Some(&[2u8; 32]),
    );
    assert!(
        enrollment != replenishment || enrollment != rebind || replenishment != rebind,
        "each JKT shape must produce a distinct digest"
    );
}

#[test]
fn bootstrap_completion_digest_changes_on_every_input_field() {
    let op_id = Uuid::parse_str("67a08d9c-46a3-4cb2-aa4a-50f756748f3a").unwrap();
    let scope_receipt = Uuid::parse_str("f0000000-0000-4000-a000-000000000001").unwrap();
    let scope_digest = [1u8; 32];
    let instant = Utc.timestamp_millis_opt(1_785_252_309_123).unwrap();
    let binding = OperationClaimBinding::for_test(
        op_id,
        "did:plc:test",
        "blue.catbird.chat.enrollDevice",
        "deviceEnrollment",
        [7u8; 32],
        [8u8; 32],
        [9u8; 64],
        instant,
    );
    let baseline = bootstrap_completion_digest(
        "test-tx",
        &binding,
        scope_receipt,
        &scope_digest,
        instant,
        "did:plc:test",
        Uuid::from_u128(1),
        "new-jkt",
        None,
        None,
        None,
        None,
    );
    let variants: Vec<[u8; 32]> = vec![
        // different operation_id
        bootstrap_completion_digest(
            "test-tx",
            &OperationClaimBinding::for_test(
                Uuid::parse_str("00000000-0000-4000-a000-000000000001").unwrap(),
                "did:plc:test",
                "blue.catbird.chat.enrollDevice",
                "deviceEnrollment",
                [7u8; 32],
                [8u8; 32],
                [9u8; 64],
                instant,
            ),
            scope_receipt,
            &scope_digest,
            instant,
            "did:plc:test",
            Uuid::from_u128(1),
            "new-jkt",
            None,
            None,
            None,
            None,
        ),
        // different transaction id
        bootstrap_completion_digest(
            "other-tx",
            &binding,
            scope_receipt,
            &scope_digest,
            instant,
            "did:plc:test",
            Uuid::from_u128(1),
            "new-jkt",
            None,
            None,
            None,
            None,
        ),
        // different scope_receipt
        bootstrap_completion_digest(
            "test-tx",
            &binding,
            Uuid::from_u128(2),
            &scope_digest,
            instant,
            "did:plc:test",
            Uuid::from_u128(1),
            "new-jkt",
            None,
            None,
            None,
            None,
        ),
        // different scope_digest
        bootstrap_completion_digest(
            "test-tx",
            &binding,
            scope_receipt,
            &[2u8; 32],
            instant,
            "did:plc:test",
            Uuid::from_u128(1),
            "new-jkt",
            None,
            None,
            None,
            None,
        ),
        // different principal
        bootstrap_completion_digest(
            "test-tx",
            &binding,
            scope_receipt,
            &scope_digest,
            instant,
            "did:plc:other",
            Uuid::from_u128(1),
            "new-jkt",
            None,
            None,
            None,
            None,
        ),
        // different device
        bootstrap_completion_digest(
            "test-tx",
            &binding,
            scope_receipt,
            &scope_digest,
            instant,
            "did:plc:test",
            Uuid::from_u128(2),
            "new-jkt",
            None,
            None,
            None,
            None,
        ),
        // different current_jkt
        bootstrap_completion_digest(
            "test-tx",
            &binding,
            scope_receipt,
            &scope_digest,
            instant,
            "did:plc:test",
            Uuid::from_u128(1),
            "other-jkt",
            None,
            None,
            None,
            None,
        ),
    ];
    for (i, variant) in variants.iter().enumerate() {
        assert!(
            baseline != *variant,
            "variant {i} produced the same digest as the baseline"
        );
    }
}

#[test]
fn bootstrap_completion_resource_functions_never_commit() {
    let source = include_str!("../../src/chat_protocol/repository/prelude.rs");
    for function_name in [
        "complete_enrollment_bootstrap_operation",
        "complete_rebind_bootstrap_operation",
        "complete_replenishment_operation",
    ] {
        assert!(source.contains(function_name), "missing {function_name}");
    }
    assert!(
        source.contains("validate_bootstrap_completion"),
        "common completion validator must exist"
    );
    // The functions consume the guard and call validate_bootstrap_completion;
    // no outer commit is performed in any of them.
    assert!(
        source.matches(".commit();").count() <= source.matches("self.").count(),
        "completion functions must not commit the outer transaction"
    );
}
