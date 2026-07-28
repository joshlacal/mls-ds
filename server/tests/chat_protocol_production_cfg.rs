#![cfg(not(feature = "server-bin"))]

mod common;

#[test]
fn production_cfg_target_is_proof_feature_gated() {
    assert!(cfg!(feature = "chat-protocol-production-proof"));
}

#[test]
fn recovery_proof_is_a_real_production_composition_not_a_test_shadow() {
    let source = include_str!("../src/chat_protocol/repository/recovery.rs");
    let proof = source
        .split_once("mod production_composition_proof")
        .map(|(_, body)| body)
        .expect("feature-gated Recovery production proof module");
    for required in [
        "RecoveryRequestAuthority",
        "RecoveryCancellationAuthority",
        "RecoveryFulfillmentAuthority",
        "RecoveryClientExpiryPlanInput",
        "RecoverySchedulerExpiryPlanInput",
        "plan_recovery_request(input",
        "plan_recovery_cancellation(input",
        "plan_recovery_fulfillment(input",
        "plan_client_recovery_expiry(input",
        "plan_scheduler_recovery_expiry(input",
        "PreparedRecoveryExecutionGraph::validate_prewrite",
        "RecoveryPersistenceWitness::validate_prewrite",
        "RecoveryExecutorWriteAuthority::apply_open",
        "RecoveryExecutorWriteAuthority::apply_terminal",
        "prepare_recovery_execution",
        "apply_prepared_recovery_execution",
        "completion.into_parts()",
    ] {
        assert!(
            proof.contains(required),
            "production proof omitted {required}"
        );
    }
}

#[test]
fn recovery_production_facade_has_no_caller_payload_injection_surface() {
    let recovery = include_str!("../src/chat_protocol/repository/recovery.rs");
    let graph = recovery
        .split_once("pub(in crate::chat_protocol) struct PreparedRecoveryExecutionGraph")
        .and_then(|(_, body)| body.split_once("\n}\n").map(|(body, _)| body))
        .expect("private prepared Recovery graph");
    assert!(graph.contains("plan: ConversationPersistencePlan"));
    assert!(graph.contains("accepted_control_entry_bytes: Option<Vec<u8>>"));
    assert!(graph.contains("persistence_witness: RecoveryPersistenceWitness"));
    assert!(graph.contains("origin: RecoveryGraphPrewriteOrigin"));
    assert!(graph.contains("material: RecoveryCanonicalMaterial"));
    for forbidden in [
        "primary_event_payload",
        "welcome_disposition_event_payloads",
        "ExecutionContextArtifacts",
        "OperationCompletionGuard",
    ] {
        assert!(
            !graph.contains(forbidden),
            "private Recovery graph unexpectedly accepts caller artifact {forbidden}"
        );
    }

    let execution = include_str!("../src/chat_protocol/repository/execution_context.rs");
    let generic = execution
        .split_once("pub(crate) async fn hydrate_execution_context<")
        .and_then(|(_, body)| {
            body.split_once("fn is_recovery_plan(")
                .map(|(body, _)| body)
        })
        .expect("bounded generic production hydration facade");
    assert!(generic.contains("if is_recovery_plan(plan)"));
    assert!(generic.contains("ExecutionContextHydrationError::ArtifactMismatch"));

    let facade = execution
        .split_once("pub(in crate::chat_protocol) async fn prepare_recovery_execution")
        .and_then(|(_, body)| {
            body.split_once(
                "pub(in crate::chat_protocol) async fn apply_prepared_recovery_execution",
            )
            .map(|(body, _)| body)
        })
        .expect("bounded production Recovery execution facade");
    assert!(facade.contains("graph.validate_prewrite(transaction).await?"));
    assert!(facade.contains("hydrate_execution_context_after_authority_validation("));
    assert!(!facade.contains("    hydrate_execution_context("));
    assert!(facade.contains("canonical_recovery_primary_event_payload(plan)?"));
    assert!(facade.contains("welcome_disposition_event_payloads: Vec::new()"));
    for forbidden in [
        "primary_event_payload:",
        "welcome_disposition_event_payloads:",
    ] {
        assert_eq!(
            facade.matches(forbidden).count(),
            1,
            "Recovery facade should contain only its internal {forbidden} assignment"
        );
    }
}

#[tokio::test]
#[ignore = "requires the dedicated gate database with one production-valid due Recovery fixture"]
async fn recovery_scheduler_expiry_runs_through_the_real_production_facade() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_scheduler_expiry_lifecycle(&pool)
        .await
        .expect("real production scheduler Recovery lifecycle");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and due Recovery fixture"]
async fn recovery_aggregate_graph_drift_rejects_prewrite_with_zero_residue() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_aggregate_graph_drift_negative(&pool)
        .await
        .expect("aggregate graph drift negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and due Recovery fixture"]
async fn recovery_public_snapshot_drift_rejects_prewrite_with_zero_residue() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_public_snapshot_drift_negative(&pool)
        .await
        .expect("public snapshot drift negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and due Recovery fixture"]
async fn recovery_foreign_transaction_rejects_prewrite_with_zero_residue() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_foreign_transaction_negative(&pool)
        .await
        .expect("foreign transaction negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and due Recovery fixture"]
async fn recovery_request_row_drift_rejects_prewrite_with_zero_residue() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_request_row_drift_negative(&pool)
        .await
        .expect("request full-row drift negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and due Recovery fixture"]
async fn recovery_reservation_row_drift_rejects_prewrite_with_zero_residue() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_reservation_row_drift_negative(&pool)
        .await
        .expect("reservation full-row drift negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and due Recovery fixture"]
async fn recovery_package_row_drift_rejects_prewrite_with_zero_residue() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_package_row_drift_negative(&pool)
        .await
        .expect("package full-row drift negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and due Recovery fixture"]
async fn recovery_prepared_graph_can_be_abandoned_without_writes() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_prepare_abandon_negative(&pool)
        .await
        .expect("prepare-abandon negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and due Recovery fixture"]
async fn recovery_terminal_head_cas_failure_rolls_back_prior_writes() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_terminal_head_cas_rollback_negative(&pool)
        .await
        .expect("late exact head-CAS rollback negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and due Recovery fixture"]
async fn recovery_postwrite_cancellation_rolls_back_savepoint() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_postwrite_cancellation_rollback_negative(
        &pool,
    )
    .await
    .expect("post-write cancellation rollback negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and due Recovery fixture"]
async fn recovery_postwrite_panic_rolls_back_savepoint() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_postwrite_panic_rollback_negative(&pool)
        .await
        .expect("post-write panic rollback negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and a fresh exact singleton Recovery fallback"]
async fn recovery_client_request_runs_through_real_auth_prelude_apply_and_completion() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_request_leaf_recovery_happy_path(&pool)
        .await
        .expect("real client Recovery request lifecycle");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and a fresh exact singleton Recovery fallback"]
async fn recovery_client_operation_claim_drift_rejects_before_executor_writes() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_request_leaf_recovery_operation_claim_drift_negative(&pool)
        .await
        .expect("client Recovery operation-claim drift negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and a fresh exact singleton Recovery fallback"]
async fn recovery_client_scope_drift_rejects_before_executor_writes() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_request_leaf_recovery_scope_drift_negative(
        &pool,
    )
    .await
    .expect("client Recovery canonical-scope drift negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and a fresh exact singleton Recovery fallback"]
async fn recovery_client_completion_mismatch_rolls_back_applied_business_writes() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_request_leaf_recovery_completion_rollback_negative(&pool)
        .await
        .expect("client Recovery completion-mismatch rollback negative");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and a fresh exact singleton Recovery fallback"]
async fn recovery_client_cancellation_runs_through_real_auth_prelude_apply_and_completion() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_leaf_recovery_cancellation_happy_path(
        &pool,
    )
    .await
    .expect("real client Recovery cancellation lifecycle");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and a fresh exact singleton Recovery fallback"]
async fn recovery_client_cancellation_due_for_expiry_orders_expiry_before_client_error() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_leaf_recovery_cancellation_due_for_expiry_ordering(&pool)
        .await
        .expect("Recovery cancellation DueForExpiry ordering");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and a fresh exact singleton Recovery fallback"]
async fn recovery_client_expiry_due_for_expiry_orders_expiry_before_client_error() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_client_recovery_expiry_due_for_expiry_ordering(&pool)
        .await
        .expect("Recovery client expiry DueForExpiry ordering");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and fresh exact two-party Recovery fallbacks"]
async fn recovery_client_fulfillment_runs_through_real_auth_prelude_apply_and_completion() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_leaf_recovery_fulfillment_happy_path(
        &pool,
    )
    .await
    .expect("real client Recovery fulfillment lifecycle");
}

#[tokio::test]
#[ignore = "requires the dedicated owner-controlled gate database and fresh exact two-party Recovery fallbacks"]
async fn recovery_client_fulfillment_due_for_expiry_orders_expiry_before_client_error() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_leaf_recovery_fulfillment_due_for_expiry_ordering(&pool)
        .await
        .expect("Recovery fulfillment DueForExpiry ordering");
}
