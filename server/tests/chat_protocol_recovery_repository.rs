//! Pure authority and SQL-contract tests for the clean-chat Recovery repository.
//!
//! This target performs no database I/O. It includes the not-yet-wired
//! repository module directly so the authority slice can compile before the
//! later `repository/mod.rs` integration change.

#![allow(dead_code)]

#[path = "../src/chat_protocol/dpop.rs"]
mod dpop;
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod snapshot {
    pub use catbird_server::chat_protocol::snapshot::*;
}

mod repository {
    pub mod auth {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/auth.rs"
        ));
    }
    pub mod prelude {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/prelude.rs"
        ));
    }
    pub mod transition {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/transition.rs"
        ));
    }
    pub mod recovery {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/recovery.rs"
        ));
    }
}

use chrono::{Duration, TimeZone, Utc};
use repository::recovery::{
    cancellation_actor_matches_requester, classify_locked_recovery, persisted_recovery_origin,
    requester_key_liveness_matches, requester_row_liveness_matches, RecoveryLockStage,
    RecoveryPersistedOrigin, RecoveryRowStatus, RecoveryTerminalClassification,
    CANONICAL_RECOVERY_LOCK_ORDER, LOCK_AVAILABLE_RECOVERY_PACKAGE_SQL,
    LOCK_RECOVERY_CONVERSATION_SQL, LOCK_RECOVERY_EXPIRY_DEVICE_SQL, LOCK_RECOVERY_EXPIRY_KEY_SQL,
    LOCK_RECOVERY_EXPIRY_PRINCIPAL_SQL, LOCK_RECOVERY_GENERATION_SQL,
    LOCK_RECOVERY_GENERATION_STATE_SQL, LOCK_RECOVERY_MEMBER_DEVICE_SQL, LOCK_RECOVERY_PACKAGE_SQL,
    LOCK_RECOVERY_REQUEST_SQL, LOCK_RECOVERY_RESERVATION_SQL,
};

fn compact(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn exact_expiry_boundary_is_due_and_retained_expiry_wins_later_rehydration() {
    let expires_at = Utc.timestamp_millis_opt(1_900_000_000_000).unwrap();
    assert_eq!(
        classify_locked_recovery(
            RecoveryRowStatus::Open,
            expires_at - Duration::milliseconds(1),
            expires_at,
        ),
        RecoveryTerminalClassification::OpenLive
    );
    assert_eq!(
        classify_locked_recovery(RecoveryRowStatus::Open, expires_at, expires_at),
        RecoveryTerminalClassification::OpenDue
    );
    assert_eq!(
        classify_locked_recovery(RecoveryRowStatus::Expired, expires_at, expires_at),
        RecoveryTerminalClassification::RetainedExpired
    );
    assert_eq!(
        classify_locked_recovery(
            RecoveryRowStatus::Expired,
            expires_at + Duration::milliseconds(1),
            expires_at,
        ),
        RecoveryTerminalClassification::RetainedExpired
    );
}

#[test]
fn every_terminal_status_rehydrates_as_retained_and_never_as_open() {
    let expires_at = Utc.timestamp_millis_opt(1_900_000_000_000).unwrap();
    for (status, expected) in [
        (
            RecoveryRowStatus::Fulfilled,
            RecoveryTerminalClassification::RetainedFulfilled,
        ),
        (
            RecoveryRowStatus::Cancelled,
            RecoveryTerminalClassification::RetainedCancelled,
        ),
        (
            RecoveryRowStatus::Expired,
            RecoveryTerminalClassification::RetainedExpired,
        ),
        (
            RecoveryRowStatus::Superseded,
            RecoveryTerminalClassification::RetainedSuperseded,
        ),
    ] {
        assert_eq!(
            classify_locked_recovery(status, expires_at, expires_at),
            expected
        );
    }
}

#[test]
fn canonical_lock_order_keeps_identity_prefix_before_graph_and_recovery_rows() {
    assert_eq!(
        CANONICAL_RECOVERY_LOCK_ORDER,
        [
            RecoveryLockStage::GlobalOperation,
            RecoveryLockStage::Principals,
            RecoveryLockStage::Devices,
            RecoveryLockStage::ActorKey,
            RecoveryLockStage::ConversationHead,
            RecoveryLockStage::ConversationGraph,
            RecoveryLockStage::RecoveryRequest,
            RecoveryLockStage::Reservation,
            RecoveryLockStage::KeyPackage,
        ]
    );
}

#[test]
fn head_graph_locks_are_legal_single_table_locks_in_exact_order() {
    let conversation = compact(LOCK_RECOVERY_CONVERSATION_SQL);
    for projection in [
        "c.conversation_id",
        "c.kind",
        "c.lifecycle",
        "c.current_generation",
        "c.current_state_version",
        "c.next_entry_seq",
        "c.created_at",
        "FOR UPDATE OF c",
    ] {
        assert!(
            conversation.contains(projection),
            "missing conversation fact: {projection}"
        );
    }
    assert!(!conversation.contains("JOIN"));

    let generation = compact(LOCK_RECOVERY_GENERATION_SQL);
    for projection in [
        "g.group_id",
        "g.lifecycle",
        "g.current_state_version",
        "FOR UPDATE OF g",
    ] {
        assert!(
            generation.contains(projection),
            "missing generation fact: {projection}"
        );
    }
    assert!(!generation.contains("JOIN"));

    let state = compact(LOCK_RECOVERY_GENERATION_STATE_SQL);
    for projection in [
        "s.epoch",
        "s.group_context_hash",
        "s.confirmation_tag",
        "s.snapshot_sha256",
        "s.tree_summary_sha256",
        "FOR UPDATE OF s",
    ] {
        assert!(
            state.contains(projection),
            "missing state fact: {projection}"
        );
    }
    assert!(!state.contains("JOIN"));

    let member = compact(LOCK_RECOVERY_MEMBER_DEVICE_SQL);
    assert!(member.contains("md.leaf_period_id"));
    assert!(member.contains("FOR UPDATE OF md"));
    assert!(!member.contains("LEFT JOIN"));

    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    let function = source.split_once("async fn lock_head_graph(").unwrap().1;
    let conversation_pos = function.find("LOCK_RECOVERY_CONVERSATION_SQL").unwrap();
    let generation_pos = function.find("LOCK_RECOVERY_GENERATION_SQL").unwrap();
    let state_pos = function.find("LOCK_RECOVERY_GENERATION_STATE_SQL").unwrap();
    let member_pos = function.find("LOCK_RECOVERY_MEMBER_DEVICE_SQL").unwrap();
    assert!(
        conversation_pos < generation_pos && generation_pos < state_pos && state_pos < member_pos
    );
}

#[test]
fn cancellation_authority_requires_the_exact_requester_device_key_generation() {
    let did = "did:plc:requester";
    let device = uuid::Uuid::from_u128(1);
    let key = "requester-key";
    assert!(cancellation_actor_matches_requester(
        did, device, key, 7, did, device, key, 7
    ));
    assert!(!cancellation_actor_matches_requester(
        "did:plc:other",
        device,
        key,
        7,
        did,
        device,
        key,
        7
    ));
    assert!(!cancellation_actor_matches_requester(
        did,
        uuid::Uuid::from_u128(2),
        key,
        7,
        did,
        device,
        key,
        7
    ));
    assert!(!cancellation_actor_matches_requester(
        did,
        device,
        "other-key",
        7,
        did,
        device,
        key,
        7
    ));
    assert!(!cancellation_actor_matches_requester(
        did, device, key, 8, did, device, key, 7
    ));
}

#[test]
fn persisted_recovery_origin_is_closed_to_the_two_legal_mutation_kinds() {
    assert_eq!(
        persisted_recovery_origin("requestLeafRecovery").unwrap(),
        RecoveryPersistedOrigin::LeafRecoveryRequest
    );
    assert_eq!(
        persisted_recovery_origin("acceptConversation").unwrap(),
        RecoveryPersistedOrigin::ParticipantAcceptance
    );
    assert!(persisted_recovery_origin("commitGroupChange").is_err());
}

#[test]
fn retained_history_accepts_only_identity_that_was_live_when_the_request_was_signed() {
    let requested_at = Utc.timestamp_millis_opt(1_900_000_000_000).unwrap();
    let after = requested_at + Duration::milliseconds(1);
    let before = requested_at - Duration::milliseconds(1);
    assert!(requester_row_liveness_matches(
        RecoveryTerminalClassification::RetainedSuperseded,
        requested_at,
        "revoked",
        Some(after)
    ));
    assert!(requester_key_liveness_matches(
        RecoveryTerminalClassification::RetainedSuperseded,
        requested_at,
        Some(after)
    ));
    assert!(!requester_row_liveness_matches(
        RecoveryTerminalClassification::RetainedSuperseded,
        requested_at,
        "revoked",
        Some(before)
    ));
    assert!(!requester_key_liveness_matches(
        RecoveryTerminalClassification::RetainedSuperseded,
        requested_at,
        Some(before)
    ));
    assert!(!requester_row_liveness_matches(
        RecoveryTerminalClassification::OpenDue,
        requested_at,
        "revoked",
        Some(after)
    ));
    assert!(!requester_key_liveness_matches(
        RecoveryTerminalClassification::OpenDue,
        requested_at,
        Some(after)
    ));
}

#[test]
fn terminal_locks_are_separate_ordered_full_row_projections() {
    let request = compact(LOCK_RECOVERY_REQUEST_SQL);
    for projection in [
        "rr.recovery_request_id",
        "rr.recovery_kind",
        "rr.replaced_leaf_period_id",
        "rr.signed_request_bytes",
        "rr.signing_transcript_bytes",
        "rr.request_digest",
        "rr.signature",
        "rr.fulfilling_transition_id",
        "rr.terminal_signed_request_bytes",
        "rr.terminal_signing_transcript_bytes",
        "rr.terminal_request_digest",
        "rr.terminal_signature",
        "FOR UPDATE OF rr",
    ] {
        assert!(
            request.contains(projection),
            "missing request fact: {projection}"
        );
    }
    let reservation = compact(LOCK_RECOVERY_RESERVATION_SQL);
    for projection in [
        "kr.purpose",
        "kr.consumed_transition_id",
        "kr.terminal_transition_id",
        "kr.terminal_revocation_id",
        "FOR UPDATE OF kr",
    ] {
        assert!(
            reservation.contains(projection),
            "missing reservation fact: {projection}"
        );
    }
    let package = compact(LOCK_RECOVERY_PACKAGE_SQL);
    for projection in [
        "kp.wrapper_bytes",
        "kp.wrapper_sha256",
        "kp.init_key",
        "kp.owner_key_id",
        "kp.owner_auth_generation",
        "kp.terminal_transition_id",
        "kp.terminal_revocation_id",
        "FOR UPDATE OF kp",
    ] {
        assert!(
            package.contains(projection),
            "missing package fact: {projection}"
        );
    }
}

#[test]
fn available_package_lock_is_full_row_deterministic_and_terminal_null() {
    let sql = compact(LOCK_AVAILABLE_RECOVERY_PACKAGE_SQL);
    assert!(sql.contains("ORDER BY kp.created_at, kp.key_package_ref"));
    assert!(sql.contains("LIMIT 1"));
    assert!(sql.contains("FOR UPDATE OF kp"));
    for predicate in [
        "kp.status = 'available'",
        "kp.terminal_transition_id IS NULL",
        "kp.terminal_revocation_id IS NULL",
        "kp.terminal_at IS NULL",
    ] {
        assert!(
            sql.contains(predicate),
            "missing package guard: {predicate}"
        );
    }
}

#[test]
fn fresh_expiry_path_has_a_canonical_identity_prefix_and_database_trusted_millisecond() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    assert!(source.contains("pub(crate) async fn prepare_recovery_expiry_authority("));
    assert!(source.contains("canonical_operation_lock_key(request_id)"));
    assert!(source.contains("date_trunc('milliseconds', transaction_timestamp())"));
    assert!(compact(LOCK_RECOVERY_EXPIRY_PRINCIPAL_SQL).contains("FOR UPDATE"));
    assert!(compact(LOCK_RECOVERY_EXPIRY_DEVICE_SQL).contains("FOR UPDATE"));
    assert!(compact(LOCK_RECOVERY_EXPIRY_KEY_SQL).contains("FOR UPDATE"));

    let function = source
        .split_once("pub(crate) async fn prepare_recovery_expiry_authority(")
        .unwrap()
        .1;
    let principal = function.find("LOCK_RECOVERY_EXPIRY_PRINCIPAL_SQL").unwrap();
    let device = function.find("LOCK_RECOVERY_EXPIRY_DEVICE_SQL").unwrap();
    let key = function.find("LOCK_RECOVERY_EXPIRY_KEY_SQL").unwrap();
    let head = function.find("lock_head_graph(").unwrap();
    let request = function.find("lock_terminal_rows(").unwrap();
    assert!(principal < device && device < key && key < head && head < request);
}

#[test]
fn authority_surface_is_non_cloneable_opaque_and_only_emits_sealed_transition_bindings() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    for authority in [
        "RecoveryRequestAuthority",
        "ReservedRecoveryRequestAuthority",
        "RecoveryCancellationAuthority",
        "RecoveryFulfillmentAuthority",
        "RecoveryExpiryAuthority",
    ] {
        let declaration = format!("pub(crate) struct {authority}");
        let declaration_start = source.find(&declaration).expect("missing authority");
        let prefix = &source[..declaration_start];
        let attributes = &prefix[prefix.rfind("\n\n").unwrap_or(0)..];
        assert!(
            !source.contains(&format!("impl Clone for {authority}")),
            "{authority} must remain linear"
        );
        assert!(
            !attributes.contains("derive(Clone") && !attributes.contains("derive(Debug, Clone"),
            "{authority} must not derive Clone"
        );
        assert!(
            !source.contains(&format!("impl {authority} {{\n    pub(crate) fn new")),
            "{authority} must not gain a loose-value constructor"
        );
    }
    assert!(source.contains("reserve_available_recovery_package("));
    assert!(source.contains("RecoveryTerminalTripleCas::new("));
    assert!(source.contains("RecoveryTerminalTripleTermination::Cancelled"));
    assert!(source.contains("RecoveryTerminalTripleTermination::Fulfilled"));
    assert!(source.contains("RecoveryTerminalTripleTermination::Expired"));
    assert!(source.contains("struct RecoverySqlAuthoritySeal"));
    assert!(!source.contains("impl Clone for RecoverySqlAuthoritySeal"));
}

#[test]
fn client_terminal_outcomes_never_drop_the_consumed_prelude() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    assert!(source.contains("struct RecoveryRetainedTerminal"));
    assert!(source.contains("prelude: PreparedBusinessPrelude"));
    assert!(source.contains("prelude: Option<PreparedBusinessPrelude>"));
    assert!(source.contains("pub(crate) fn into_prelude(self)"));
}

#[test]
fn retained_rows_are_reverified_instead_of_status_only_rehydrated() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    assert!(source.contains("reverify_retained_cancellation("));
    assert!(source.contains("validate_superseded_terminal_shapes("));
    assert!(source.contains("require_persisted_idempotency_key("));
}

#[test]
fn recovery_sql_bindings_require_the_private_repository_seal_everywhere() {
    let transition = include_str!("../src/chat_protocol/repository/transition.rs");
    assert!(transition.contains("use super::recovery::RecoverySqlAuthoritySeal;"));
    assert!(
        transition
            .matches("authority: &'a RecoverySqlAuthoritySeal")
            .count()
            >= 6
    );
    let recovery = include_str!("../src/chat_protocol/repository/recovery.rs");
    assert!(recovery.contains("RecoveryKeyPackageRowCas::new(\n        authority,"));
    assert!(recovery
        .contains("RecoveryTerminalTripleCas::new(\n            &self.context.sql_authority,"));
}

#[test]
fn every_client_recovery_acquisition_consumes_the_exact_operation_claim() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    for endpoint in [
        "RecoveryOperationEndpoint::RequestLeafRecovery",
        "RecoveryOperationEndpoint::CancelLeafRecovery",
        "RecoveryOperationEndpoint::SubmitRecoveryFulfillment",
    ] {
        assert!(
            source.contains(endpoint),
            "missing exact claim for {endpoint}"
        );
    }
    assert_eq!(source.matches(".verify_recovery_operation(").count(), 3);
}
