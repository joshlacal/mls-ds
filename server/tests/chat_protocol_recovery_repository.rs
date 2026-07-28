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
#[path = "../src/chat_protocol/relationship_policy.rs"]
mod relationship_policy_source;
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
}

mod chat_protocol {
    pub mod dpop {
        pub use crate::dpop::*;
    }
    pub mod model {
        pub use crate::model::*;
    }
    pub mod relationship_policy {
        pub use crate::relationship_policy_source::*;
    }
    pub mod snapshot {
        pub use catbird_server::chat_protocol::snapshot::*;
    }
    pub mod transcript {
        pub use crate::transcript::*;
    }
    pub mod validation {
        pub use crate::validation::*;
    }
    pub mod wire {
        pub use catbird_server::chat_protocol::wire::*;
    }
    pub mod public_state {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/public_state.rs"
        ));
    }
    pub mod repository {
        pub mod auth {
            pub use crate::repository::auth::*;
        }
        pub mod prelude {
            pub use crate::repository::prelude::*;
        }
        pub mod core {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/core.rs"
            ));
        }
        pub mod relationship {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/relationship.rs"
            ));
        }
        pub mod transition {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/transition.rs"
            ));
        }
        pub mod delivery {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/delivery.rs"
            ));
        }
        pub mod execution_context {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/execution_context.rs"
            ));
        }
        pub mod recovery {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/recovery.rs"
            ));
        }
    }
    pub mod state_machine {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/state_machine.rs"
        ));
    }
}

use chat_protocol::repository::delivery::{
    canonical_leaf_recovery_event_payload, canonical_welcome_available_event_payload,
    LeafRecoveryEventStatus,
};
use chat_protocol::repository::recovery::{
    cancellation_actor_matches_requester, classify_client_terminal_disposition,
    classify_locked_recovery, expired_recovery_package_shape_valid, persisted_recovery_origin,
    requester_key_liveness_matches, requester_row_liveness_matches, RecoveryClientTerminalAction,
    RecoveryClientTerminalDisposition, RecoveryClientTerminalError, RecoveryLockStage,
    RecoveryPersistedOrigin, RecoveryRowStatus, RecoveryTerminalClassification,
    CANONICAL_RECOVERY_LOCK_ORDER, LOCK_AVAILABLE_RECOVERY_PACKAGE_SQL,
    LOCK_RECOVERY_CONVERSATION_SQL, LOCK_RECOVERY_EXPIRY_DEVICE_SQL, LOCK_RECOVERY_EXPIRY_KEY_SQL,
    LOCK_RECOVERY_EXPIRY_PRINCIPAL_SQL, LOCK_RECOVERY_GENERATION_SQL,
    LOCK_RECOVERY_GENERATION_STATE_SQL, LOCK_RECOVERY_MEMBER_DEVICE_SQL, LOCK_RECOVERY_PACKAGE_SQL,
    LOCK_RECOVERY_REQUEST_SQL, LOCK_RECOVERY_RESERVATION_SQL, RECOVERY_TERMINAL_LOCATOR_SQL,
};
use chrono::{Duration, TimeZone, Utc};
use uuid::Uuid;

fn compact(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn recovery_primary_event_payloads_are_exact_closed_lexicon_bytes() {
    let conversation_id = Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
    let recovery_request_id = Uuid::parse_str("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").unwrap();
    let welcome_id = Uuid::parse_str("99999999-8888-4777-8666-555555555555").unwrap();

    for (status, wire_status) in [
        (LeafRecoveryEventStatus::Open, "open"),
        (LeafRecoveryEventStatus::Cancelled, "cancelled"),
        (LeafRecoveryEventStatus::Expired, "expired"),
    ] {
        assert_eq!(
            canonical_leaf_recovery_event_payload(recovery_request_id, conversation_id, status,),
            format!(
                concat!(
                    r#"{{"$type":"blue.catbird.chat.defs#leafRecoveryEvent","#,
                    r#""recoveryRequestId":"{recovery_request_id}","#,
                    r#""conversationId":"{conversation_id}","#,
                    r#""status":"{wire_status}"}}"#
                ),
                recovery_request_id = recovery_request_id,
                conversation_id = conversation_id,
                wire_status = wire_status,
            )
            .into_bytes()
        );
    }

    assert_eq!(
        canonical_welcome_available_event_payload(welcome_id, conversation_id),
        format!(
            concat!(
                r#"{{"$type":"blue.catbird.chat.defs#welcomeAvailableEvent","#,
                r#""welcomeId":"{welcome_id}","#,
                r#""conversationId":"{conversation_id}"}}"#
            ),
            welcome_id = welcome_id,
            conversation_id = conversation_id,
        )
        .into_bytes()
    );
}

#[test]
fn recovery_business_lock_scope_never_performs_live_relationship_transport() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    assert!(
        !source.contains(".collect_block_projection("),
        "live relationship transport must be completed and persisted before business locks"
    );
    assert!(
        !source.contains("allocate_projection_revision(transaction)"),
        "Recovery business preparation must not allocate transport work after locks"
    );
    assert!(
        !source.contains("observe_locked_relationship_decision(transaction"),
        "the decision must be minted while loading the exact persisted fallback"
    );
    assert_eq!(
        source
            .matches("load_fallback_relationship_projection(")
            .count(),
        2,
        "request and fulfillment must each load their scope-specific frozen fallback"
    );
}

#[test]
fn retained_expired_package_rejects_surplus_terminal_provenance() {
    let terminal_at = Utc.timestamp_millis_opt(1_900_000_000_000).unwrap();
    assert!(expired_recovery_package_shape_valid(
        "expired",
        terminal_at,
        Some(terminal_at),
        None,
        None,
    ));
    assert!(!expired_recovery_package_shape_valid(
        "expired",
        terminal_at,
        Some(terminal_at),
        Some(Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap()),
        None,
    ));
    assert!(!expired_recovery_package_shape_valid(
        "expired",
        terminal_at,
        Some(terminal_at),
        None,
        Some(Uuid::parse_str("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").unwrap()),
    ));
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
            RecoveryLockStage::RelationshipSnapshot,
            RecoveryLockStage::RelationshipEvidence,
            RecoveryLockStage::RelationshipDecision,
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
        "RecoveryCancellationAuthority",
        "RecoveryFulfillmentAuthority",
        "RecoveryClientExpiryAuthority",
        "RecoverySchedulerExpiryAuthority",
        "RecoveryRequestPlanInput",
        "RecoveryCancellationPlanInput",
        "RecoveryFulfillmentPlanInput",
        "RecoveryClientExpiryPlanInput",
        "RecoverySchedulerExpiryPlanInput",
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
    assert!(source.contains("struct RecoveryPersistenceWitness"));
    assert!(source.contains("RecoveryTerminalTripleCas::new("));
    assert!(source.contains("RecoveryKeyPackageRowCas::new("));
    assert!(source.contains("struct RecoverySqlAuthoritySeal"));
    assert!(!source.contains("impl Clone for RecoverySqlAuthoritySeal"));
}

#[test]
fn client_terminal_outcomes_never_drop_the_consumed_prelude() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    assert!(source.contains("struct RecoveryCancellationRetained"));
    assert!(source.contains("struct RecoveryFulfillmentRetained"));
    assert!(source.contains("struct RecoveryClassifiedTerminalOutcome"));
    assert!(source.contains("prelude: PreparedBusinessPrelude"));
    assert!(!source.contains("prelude: Option<PreparedBusinessPrelude>"));
    assert!(!source.contains("struct RecoveryRetainedTerminal"));
    assert!(!source.contains("enum RecoveryTerminalRead<T>"));
}

#[test]
fn retained_rows_are_reverified_instead_of_status_only_rehydrated() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    assert!(source.contains("reverify_retained_cancellation("));
    assert!(source.contains("validate_superseded_terminal_shapes("));
    assert!(source.contains("require_persisted_idempotency_key("));
}

#[test]
fn exact_task4_recovery_sql_bindings_are_sealed_and_consumed_only_by_the_witness() {
    let transition = include_str!("../src/chat_protocol/repository/transition.rs");
    assert!(transition.contains("use super::recovery::RecoverySqlAuthoritySeal;"));
    assert!(
        transition
            .matches("authority: &'a RecoverySqlAuthoritySeal")
            .count()
            >= 6
    );
    let recovery = include_str!("../src/chat_protocol/repository/recovery.rs");
    assert!(recovery.contains("RecoveryKeyPackageRowCas::new("));
    assert!(recovery.contains("RecoveryTerminalTripleCas::new("));
    assert!(recovery.contains("reserve_available_recovery_package("));
    assert!(recovery.contains("terminalize_recovery_triple("));
}

#[test]
fn recovery_prewrite_reloads_custom_head_and_every_exact_row_before_hydration() {
    let recovery = include_str!("../src/chat_protocol/repository/recovery.rs");
    let witness = recovery
        .split_once("pub(in crate::chat_protocol) async fn validate_prewrite(")
        .and_then(|(_, tail)| {
            tail.split_once("\n    pub(in crate::chat_protocol) async fn apply_open")
        })
        .map(|(body, _)| body)
        .expect("Recovery witness prewrite validator");
    let transaction = witness.find("SELECT txid_current()::text").unwrap();
    let custom_head = witness.find("lock_head_graph(").unwrap();
    let cross_binding = witness.find("validates_reloaded_recovery_head").unwrap();
    let package = witness.find("LOCK_RECOVERY_PACKAGE_SQL").unwrap();
    let request = witness.find("LOCK_RECOVERY_REQUEST_SQL").unwrap();
    let reservation = witness.find("LOCK_RECOVERY_RESERVATION_SQL").unwrap();
    assert!(
        transaction < custom_head
            && custom_head < cross_binding
            && cross_binding < package
            && package < request
            && request < reservation,
        "transaction, aggregate/custom-head, package, request, and reservation drift fences \
         must run in deterministic prewrite order"
    );
    assert!(witness.contains("package != self.package"));
    assert!(witness.contains("new_request_from_row(&request).ok().as_ref()"));
    assert!(witness.contains("new_reservation_from_row(&reservation).ok().as_ref()"));

    let execution = include_str!("../src/chat_protocol/repository/execution_context.rs");
    let facade = execution
        .split_once("pub(in crate::chat_protocol) async fn prepare_recovery_execution")
        .and_then(|(_, tail)| {
            tail.split_once(
                "\npub(in crate::chat_protocol) async fn apply_prepared_recovery_execution",
            )
        })
        .map(|(body, _)| body)
        .expect("Recovery execution facade");
    assert!(
        facade.find(".validate_prewrite(").unwrap()
            < facade.find("hydrate_execution_context(").unwrap(),
        "all Recovery-specific drift fences must reject before generic hydration can write"
    );
}

#[test]
fn client_due_for_expiry_types_freeze_action_specific_post_apply_errors() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    let cancellation = source
        .split_once("impl RecoveryCancellationDueForExpiry")
        .and_then(|(_, tail)| tail.split_once("\n}"))
        .map(|(body, _)| body)
        .expect("cancellation DueForExpiry adapter");
    assert!(cancellation.contains("RecoveryClientTerminalError::RecoveryNotFound"));
    assert!(!cancellation.contains("post_apply_error:"));

    let fulfillment = source
        .split_once("impl RecoveryFulfillmentDueForExpiry")
        .and_then(|(_, tail)| tail.split_once("\n}"))
        .map(|(body, _)| body)
        .expect("fulfillment DueForExpiry adapter");
    assert!(fulfillment.contains("RecoveryClientTerminalError::RecoveryExpired"));
    assert!(!fulfillment.contains("post_apply_error:"));

    assert!(source.contains("RecoveryCanonicalMaterial::ClientExpired"));
    assert!(source.contains("post_apply_error: RecoveryClientTerminalError"));
    assert!(source.contains("RecoveryCanonicalMaterial::SchedulerExpired"));
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

#[test]
fn client_terminal_disposition_matrix_matches_frozen_brief() {
    use RecoveryClientTerminalAction::*;
    use RecoveryClientTerminalDisposition::*;
    use RecoveryClientTerminalError::*;
    use RecoveryTerminalClassification::*;
    // (action, classification) -> expected disposition
    let cases: &[(
        RecoveryClientTerminalAction,
        RecoveryTerminalClassification,
        RecoveryClientTerminalDisposition,
    )] = &[
        (Cancel, OpenLive, Execute),
        (Fulfill, OpenLive, Execute),
        (Cancel, OpenDue, ExpireFirst(RecoveryNotFound)),
        (Fulfill, OpenDue, ExpireFirst(RecoveryExpired)),
        (Cancel, RetainedCancelled, Retained(CancellationConflict)),
        (Cancel, RetainedFulfilled, Retained(RecoveryNotFound)),
        (Cancel, RetainedExpired, Retained(RecoveryNotFound)),
        (Cancel, RetainedSuperseded, Retained(RecoveryNotFound)),
        (Fulfill, RetainedExpired, Retained(RecoveryExpired)),
        (Fulfill, RetainedSuperseded, Retained(RecoverySuperseded)),
        (Fulfill, RetainedCancelled, Retained(RecoveryNotFound)),
        (Fulfill, RetainedFulfilled, Retained(RecoveryNotFound)),
    ];
    for (action, classification, expected) in cases {
        assert_eq!(
            classify_client_terminal_disposition(*action, *classification),
            *expected,
            "mismatch for action={action:?} classification={classification:?}"
        );
    }
}

#[test]
fn client_preparation_performs_no_package_reservation_or_terminal_write() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    for function in [
        "prepare_recovery_request_authority(",
        "prepare_recovery_cancellation_authority(",
        "prepare_recovery_fulfillment_authority(",
    ] {
        let body = source
            .split_once(function)
            .map(|(_, tail)| {
                tail.split_once("\npub(crate) async fn")
                    .map_or(tail, |v| v.0)
            })
            .expect("client preparation function");
        for forbidden in [
            "reserve_available_recovery_package(",
            "terminalize_recovery_triple(",
            "RecoveryTerminalTripleTermination::",
        ] {
            assert!(
                !body.contains(forbidden),
                "{function} must not perform executor write {forbidden}"
            );
        }
    }
    assert!(
        !source.contains("fn reserve_available_package"),
        "the reserve method must be removed"
    );
}

#[test]
fn plan_inputs_are_opaque_linear_and_retain_the_prelude() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    for plan in [
        "RecoveryRequestPlanInput",
        "RecoveryCancellationPlanInput",
        "RecoveryFulfillmentPlanInput",
        "RecoveryClientExpiryPlanInput",
        "RecoverySchedulerExpiryPlanInput",
    ] {
        assert!(
            source.contains(&format!("pub(crate) struct {plan}")),
            "{plan} struct must be declared"
        );
        assert!(
            !source.contains(&format!("impl Clone for {plan}")),
            "{plan} must remain linear"
        );
        assert!(
            source.contains(&format!("impl {plan}")),
            "{plan} must have an impl block"
        );
        let body = source
            .split_once(&format!("impl {plan} {{"))
            .map(|(_, tail)| tail.split_once("\n}").map_or(tail, |(body, _)| body))
            .expect("plan input impl");
        assert!(
            body.contains("into_planner_parts(") && body.contains("self"),
            "{plan} must expose only a consuming planner adapter"
        );
    }
    assert_eq!(
        source.matches("validate_same_transaction(").count(),
        3,
        "each client-authored mutation input must retain its tx validator"
    );
    assert!(source.contains("prelude: PreparedBusinessPrelude"));
    assert!(source.contains("trusted_request_instant: TrustedRequestInstant"));
}

#[test]
fn fulfillment_scope_discovery_is_read_only_and_includes_actor_plus_requester() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    assert!(source.contains("pub(crate) async fn discover_recovery_fulfillment_terminal_scope("));
    assert!(
        !compact(RECOVERY_TERMINAL_LOCATOR_SQL).contains("FOR UPDATE"),
        "terminal locator SQL must not acquire a row lock"
    );
    assert!(
        source.contains("mutation_contains_exact_admission"),
        "scope discovery must bind the exact admitted mutation"
    );
    assert!(
        source.contains("let actor_did = authority.subject().as_str().to_owned()"),
        "scope discovery must include the admitted actor DID"
    );
    assert!(
        source
            .contains("let actor_device_id = Uuid::from_bytes(*authority.device_id().as_bytes())"),
        "scope discovery must include the admitted actor device"
    );
    assert!(
        source.contains("CanonicalDeviceIdentity::new(actor_did, actor_device_id)"),
        "canonical scope must lock the actor identity"
    );
    assert!(
        source.contains("CanonicalDeviceIdentity::new(locator.requester_did"),
        "canonical scope must lock the original requester identity"
    );
}

#[test]
fn scheduler_expiry_stays_unclaimed_and_prelude_free() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    assert!(
        source.contains("pub(crate) struct RecoverySchedulerExpiryAuthority"),
        "scheduler-only expiry authority must exist"
    );
    assert!(
        source.contains("pub(crate) struct RecoveryClientExpiryAuthority"),
        "client expiry authority must remain a distinct type"
    );
    let function = source
        .split_once("pub(crate) async fn prepare_recovery_expiry_authority(")
        .map(|(_, tail)| {
            tail.split_once("\npub(crate) async fn")
                .map_or(tail, |(body, _)| body)
        });
    if let Some(expiry_fn) = function {
        assert!(
            !expiry_fn.contains("claim_operation"),
            "scheduler expiry must not claim an operation"
        );
        assert!(
            !expiry_fn.contains("complete_operation"),
            "scheduler expiry must not complete an operation"
        );
        assert!(
            !expiry_fn.contains("verify_recovery_operation"),
            "scheduler expiry must not verify a recovery operation claim"
        );
    }
    let scheduler = source
        .split_once("pub(crate) struct RecoverySchedulerExpiryAuthority")
        .and_then(|(_, tail)| tail.split_once("\n}"))
        .map(|(body, _)| body)
        .expect("scheduler authority");
    assert!(
        !scheduler.contains("PreparedBusinessPrelude")
            && !scheduler.contains("OperationCompletionGuard"),
        "scheduler expiry must not acquire client completion authority"
    );
    assert!(
        !source.contains("fn terminalize("),
        "repository authority preparation must expose no direct terminal writer"
    );
}

#[test]
fn recovery_planners_consume_exact_inputs_and_the_facade_mints_payloads() {
    let state_machine = include_str!("../src/chat_protocol/state_machine.rs");
    for (planner, input) in [
        ("plan_recovery_request_input", "RecoveryRequestPlanInput"),
        (
            "plan_recovery_cancellation_input",
            "RecoveryCancellationPlanInput",
        ),
        (
            "plan_recovery_fulfillment_input",
            "RecoveryFulfillmentPlanInput",
        ),
        (
            "plan_client_recovery_expiry_input",
            "RecoveryClientExpiryPlanInput",
        ),
        (
            "plan_scheduler_recovery_expiry_input",
            "RecoverySchedulerExpiryPlanInput",
        ),
    ] {
        let body = state_machine
            .split_once(&format!("fn {planner}"))
            .map(|(_, tail)| tail.split_once("\n    ///").map_or(tail, |(body, _)| body))
            .expect("recovery planner");
        assert!(
            body.contains(&format!("input: {input}")),
            "{planner} must consume the exact sealed input"
        );
        for forbidden in [
            "VerifiedChatDeviceRequest",
            "PreparedBusinessPrelude",
            "ExecutionContextArtifacts",
            "primary_event_payload",
            "welcome_disposition_event_payloads",
        ] {
            assert!(
                !body.contains(forbidden),
                "{planner} accepts forbidden caller authority/artifact {forbidden}"
            );
        }
    }
    let execution = include_str!("../src/chat_protocol/repository/execution_context.rs");
    let facade = execution
        .split_once("pub(in crate::chat_protocol) async fn prepare_recovery_execution")
        .and_then(|(_, tail)| tail.split_once(") -> Result<"))
        .map(|(signature, _)| signature)
        .expect("recovery execution facade signature");
    assert!(facade.contains("graph: &'plan PreparedRecoveryExecutionGraph"));
    assert!(!facade.contains("accepted_control_entry_bytes"));
    assert!(!facade.contains("ExecutionContextArtifacts"));
    assert!(!facade.contains("primary_event_payload"));
    assert!(!facade.contains("welcome_disposition_event_payloads"));

    let recovery = include_str!("../src/chat_protocol/repository/recovery.rs");
    let graph = recovery
        .split_once("struct PreparedRecoveryExecutionGraph")
        .and_then(|(_, tail)| tail.split_once("\n}"))
        .map(|(body, _)| body)
        .expect("private prepared Recovery graph");
    assert!(graph.contains("plan: ConversationPersistencePlan"));
    assert!(graph.contains("accepted_control_entry_bytes: Option<Vec<u8>>"));
    assert!(!graph.contains("pub(crate)"));
    assert!(!graph.contains("pub(in "));
}

#[test]
fn prepared_scheduler_expiry_has_no_client_completion_guard() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    let scheduler = source
        .split_once("pub(crate) struct PreparedSchedulerRecoveryExpiry")
        .and_then(|(_, tail)| tail.split_once("\n}"))
        .map(|(body, _)| body)
        .expect("prepared scheduler expiry");
    assert!(scheduler.contains("graph: PreparedRecoveryExecutionGraph"));
    assert!(!scheduler.contains("PreparedBusinessPrelude"));
    assert!(!scheduler.contains("OperationCompletionGuard"));
    assert!(
        source.contains("pub(crate) struct RecoveryCompletion"),
        "client recovery mutations retain a consuming completion guard"
    );
    assert!(!source.contains("RecoveryExecutorCapsule"));
    assert!(!source.contains("RecoverySchedulerExpiryCapsule"));
    assert!(!source.contains("into_executor_parts"));
}

#[test]
fn same_transition_fulfilled_row_is_corruption_not_replay() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    assert!(
        source.contains("if context.fulfilling_transition_id == Some(transition_id)"),
        "the fulfillment guard must error on the same transition (corruption)"
    );
    assert!(
        !source.contains("if context.fulfilling_transition_id != Some(transition_id)"),
        "a differing transition is a fulfilled-by-another classification, not corruption"
    );
}

#[test]
fn recovery_terminal_locator_row_carries_request_id() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    assert!(
        source.contains("recovery_request_id: Uuid"),
        "RecoveryTerminalLocatorRow must carry recovery_request_id for \
         cross-binding in scheduler and scope-discovery paths"
    );
    assert!(
        source.contains("struct RecoveryTerminalLocatorRow"),
        "RecoveryTerminalLocatorRow must exist"
    );
    assert!(
        !source.contains("struct RecoveryExpiryLocatorRow"),
        "the old locator row name must be completely renamed"
    );
}
