use super::{
    auth, canonical_operation_lock_key, CanonicalDeviceIdentity, CanonicalLockScope,
    OperationArbitration, ReplayCandidate,
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
