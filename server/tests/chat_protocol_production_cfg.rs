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
        "RecoveryPersistenceWitness::validate_prewrite",
        "RecoveryPersistenceWitness::apply_open",
        "RecoveryPersistenceWitness::apply_terminal",
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
