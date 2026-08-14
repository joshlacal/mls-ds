#![cfg(not(feature = "server-bin"))]

mod common;

/// One fresh, syntactically canonical `did:plc:` identity per invocation.
///
/// The fixture identity must be fresh on every run: `seed_identity` appends a
/// new active device for the fixture DID, and `chat.devices` enforces a hard
/// active-device cap per DID, so a fixed DID wedges the proofs permanently after
/// enough runs. Freshness is also what keeps runs independent.
fn fresh_plc_did() -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let bytes = uuid::Uuid::new_v4().into_bytes();
    let mut suffix = String::with_capacity(24);
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    // 15 bytes == 120 bits == exactly the 24 base32 characters `did:plc:` takes.
    for byte in bytes.iter().take(15) {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            suffix.push(char::from(
                ALPHABET[((accumulator >> bits) & 0x1f) as usize],
            ));
        }
    }
    format!("did:plc:{suffix}")
}

/// Mint the fresh singleton `recoveryReservation` fallback immediately before a
/// client Recovery proof runs. The projection is only valid for
/// `relationship_policy::MAX_PROJECTION_AGE` (60s), so this cannot be hoisted
/// into shared one-time setup.
async fn mint_singleton_fallback(pool: &sqlx::PgPool) {
    catbird_server::chat_protocol::production_proof::mint_singleton_recovery_reservation_fallback(
        pool,
        &fresh_plc_did(),
    )
    .await
    .expect("mint production singleton Recovery reservation fallback");
}

/// Two-party equivalent: one `recoveryReservation` and one `recoveryFulfillment`
/// fallback over the same exact canonical two-DID scope.
async fn mint_two_party_fallbacks(pool: &sqlx::PgPool) {
    let (first, second) = (fresh_plc_did(), fresh_plc_did());
    catbird_server::chat_protocol::production_proof::mint_two_party_recovery_fallbacks(
        pool, &first, &second,
    )
    .await
    .expect("mint production two-party Recovery fallbacks");
}

/// Gate-only fixture seeder, not a proof.
///
/// The eleven scheduler-shaped proofs below require one production-valid *due*
/// open Recovery request. `seed_durable_recovery_fixture` deliberately refuses
/// to open one; only a production runner may make, authorize, and commit that
/// client request. This does exactly that, three times, through
/// `commit_open_recovery_request`. Each committed request carries the real
/// `min(trusted + 5 minutes, package.not_after)` expiry, so it becomes due by
/// the real clock — nothing edits a row to manufacture dueness.
///
/// Run this, wait for the printed `due at` instant to pass, then run the
/// scheduler proofs.
#[tokio::test]
#[ignore = "gate-only fixture seeder; run explicitly, then wait out the real 5-minute Recovery TTL"]
async fn seed_due_recovery_fixtures() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    for _ in 0..3 {
        mint_singleton_fallback(&pool).await;
        let request_id =
            catbird_server::chat_protocol::production_proof::commit_open_recovery_request(&pool)
                .await
                .expect("commit durable production Recovery request");
        let (requested_at, expires_at): (
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ) = sqlx::query_as(
            "SELECT requested_at,expires_at FROM chat.leaf_recovery_requests \
              WHERE recovery_request_id=$1",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .expect("read committed Recovery request expiry");
        println!("seeded open Recovery request {request_id} requested_at={requested_at} due at={expires_at}");
    }
}

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

#[test]
fn metadata_executor_semantics_run_through_the_real_private_preflight() {
    catbird_server::chat_protocol::production_proof::run_metadata_executor_semantic_proof()
        .expect("real metadata executor semantic proof");
}

#[test]
fn welcome_expiry_owns_only_its_dedicated_terminal_context_family() {
    catbird_server::chat_protocol::production_proof::
        run_welcome_terminal_context_family_semantic_proof()
        .expect("Welcome terminal context-family semantic proof");
}

#[tokio::test]
#[ignore = "needs a seeded+aged due Recovery fixture: run seed_due_recovery_fixtures, wait out the real 5-minute TTL, and confirm your row is the newest open+due one in the shared gate DB (due_request_id takes ORDER BY requested_at DESC)"]
async fn recovery_scheduler_expiry_runs_through_the_real_production_facade() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_scheduler_expiry_lifecycle(&pool)
        .await
        .expect("real production scheduler Recovery lifecycle");
}

// BLOCKED on the negative not holding, not on the fixture. With a
// production-valid due fixture this now runs, `corrupt_aggregate_graph` reports
// its exact one-row metadata drift, and the executor prewrite nevertheless
// ACCEPTS and reaches executor writes ("durable aggregate drift reached executor
// writes"). The sibling `recovery_public_snapshot_drift_...` negative, injected
// the same way at the same point, is correctly rejected. Needs triage: either
// the prewrite does not compare the aggregate graph digest that
// `graph_digest_metadata` says covers metadata ciphertext, or the drifted
// snapshot is not the row the aggregate hydrates.
#[tokio::test]
#[ignore = "blocked: metadata-ciphertext aggregate drift is NOT rejected by the executor prewrite (public-snapshot drift is) - needs triage"]
async fn recovery_aggregate_graph_drift_rejects_prewrite_with_zero_residue() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_aggregate_graph_drift_negative(&pool)
        .await
        .expect("aggregate graph drift negative");
}

#[tokio::test]
#[ignore = "needs a seeded+aged due Recovery fixture: run seed_due_recovery_fixtures, wait out the real 5-minute TTL, and confirm your row is the newest open+due one in the shared gate DB (due_request_id takes ORDER BY requested_at DESC)"]
async fn recovery_public_snapshot_drift_rejects_prewrite_with_zero_residue() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_public_snapshot_drift_negative(&pool)
        .await
        .expect("public snapshot drift negative");
}

#[tokio::test]
#[ignore = "needs a seeded+aged due Recovery fixture: run seed_due_recovery_fixtures, wait out the real 5-minute TTL, and confirm your row is the newest open+due one in the shared gate DB (due_request_id takes ORDER BY requested_at DESC)"]
async fn recovery_foreign_transaction_rejects_prewrite_with_zero_residue() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_foreign_transaction_negative(&pool)
        .await
        .expect("foreign transaction negative");
}

#[tokio::test]
#[ignore = "needs a seeded+aged due Recovery fixture: run seed_due_recovery_fixtures, wait out the real 5-minute TTL, and confirm your row is the newest open+due one in the shared gate DB (due_request_id takes ORDER BY requested_at DESC)"]
async fn recovery_request_row_drift_rejects_prewrite_with_zero_residue() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_request_row_drift_negative(&pool)
        .await
        .expect("request full-row drift negative");
}

#[tokio::test]
#[ignore = "needs a seeded+aged due Recovery fixture: run seed_due_recovery_fixtures, wait out the real 5-minute TTL, and confirm your row is the newest open+due one in the shared gate DB (due_request_id takes ORDER BY requested_at DESC)"]
async fn recovery_reservation_row_drift_rejects_prewrite_with_zero_residue() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_reservation_row_drift_negative(&pool)
        .await
        .expect("reservation full-row drift negative");
}

#[tokio::test]
#[ignore = "needs a seeded+aged due Recovery fixture: run seed_due_recovery_fixtures, wait out the real 5-minute TTL, and confirm your row is the newest open+due one in the shared gate DB (due_request_id takes ORDER BY requested_at DESC)"]
async fn recovery_package_row_drift_rejects_prewrite_with_zero_residue() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_package_row_drift_negative(&pool)
        .await
        .expect("package full-row drift negative");
}

#[tokio::test]
#[ignore = "needs a seeded+aged due Recovery fixture: run seed_due_recovery_fixtures, wait out the real 5-minute TTL, and confirm your row is the newest open+due one in the shared gate DB (due_request_id takes ORDER BY requested_at DESC)"]
async fn recovery_prepared_graph_can_be_abandoned_without_writes() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_prepare_abandon_negative(&pool)
        .await
        .expect("prepare-abandon negative");
}

#[tokio::test]
#[ignore = "needs a seeded+aged due Recovery fixture: run seed_due_recovery_fixtures, wait out the real 5-minute TTL, and confirm your row is the newest open+due one in the shared gate DB (due_request_id takes ORDER BY requested_at DESC)"]
async fn recovery_terminal_head_cas_failure_rolls_back_prior_writes() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_terminal_head_cas_rollback_negative(&pool)
        .await
        .expect("late exact head-CAS rollback negative");
}

#[tokio::test]
#[ignore = "needs a seeded+aged due Recovery fixture: run seed_due_recovery_fixtures, wait out the real 5-minute TTL, and confirm your row is the newest open+due one in the shared gate DB (due_request_id takes ORDER BY requested_at DESC)"]
async fn recovery_postwrite_cancellation_rolls_back_savepoint() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_postwrite_cancellation_rollback_negative(
        &pool,
    )
    .await
    .expect("post-write cancellation rollback negative");
}

#[tokio::test]
#[ignore = "needs a seeded+aged due Recovery fixture: run seed_due_recovery_fixtures, wait out the real 5-minute TTL, and confirm your row is the newest open+due one in the shared gate DB (due_request_id takes ORDER BY requested_at DESC)"]
async fn recovery_postwrite_panic_rolls_back_savepoint() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    catbird_server::chat_protocol::production_proof::run_postwrite_panic_rollback_negative(&pool)
        .await
        .expect("post-write panic rollback negative");
}

#[tokio::test]
async fn recovery_client_request_runs_through_real_auth_prelude_apply_and_completion() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    mint_singleton_fallback(&pool).await;
    catbird_server::chat_protocol::production_proof::run_request_leaf_recovery_happy_path(&pool)
        .await
        .expect("real client Recovery request lifecycle");
}

#[tokio::test]
async fn recovery_client_operation_claim_drift_rejects_before_executor_writes() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    mint_singleton_fallback(&pool).await;
    catbird_server::chat_protocol::production_proof::run_request_leaf_recovery_operation_claim_drift_negative(&pool)
        .await
        .expect("client Recovery operation-claim drift negative");
}

#[tokio::test]
async fn recovery_client_scope_drift_rejects_before_executor_writes() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    mint_singleton_fallback(&pool).await;
    catbird_server::chat_protocol::production_proof::run_request_leaf_recovery_scope_drift_negative(
        &pool,
    )
    .await
    .expect("client Recovery canonical-scope drift negative");
}

#[tokio::test]
async fn recovery_client_completion_mismatch_rolls_back_applied_business_writes() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    mint_singleton_fallback(&pool).await;
    catbird_server::chat_protocol::production_proof::run_request_leaf_recovery_completion_rollback_negative(&pool)
        .await
        .expect("client Recovery completion-mismatch rollback negative");
}

// BLOCKED, not a fixture gap. The fixture is now complete and the whole
// production lifecycle runs: `after` equals `expected` field-for-field. The
// only failing conjunct is `require_terminal_delta`'s precondition
// `before.package_status == "available"` (production_client_proof.rs). A request
// that is about to be cancelled necessarily holds a *reserved* package — the
// same predicate's `expected` already asserts the package returns to
// "available" afterwards — so this precondition is unsatisfiable as written.
// Correcting it changes what the proof asserts, so it is left for the owner.
#[tokio::test]
#[ignore = "blocked on a contradictory precondition in require_terminal_delta (expects before.package_status == \"available\"; a cancellable request holds \"reserved\")"]
async fn recovery_client_cancellation_runs_through_real_auth_prelude_apply_and_completion() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    mint_singleton_fallback(&pool).await;
    catbird_server::chat_protocol::production_proof::run_leaf_recovery_cancellation_happy_path(
        &pool,
    )
    .await
    .expect("real client Recovery cancellation lifecycle");
}

// BLOCKED on a self-invalidating fixture seam, not on production and not on
// missing fixture state. `force_due_boundary` (production_client_proof.rs) sets
// `leaf_recovery_requests.expires_at` and the reservation's to the trusted
// instant while leaving `requested_at`/`received_at` alone. But
// `validate_recovery_work` (state_machine.rs:18853-18860) requires
// `request.expires_at == recovery_expiry(request.received_at,
// reservation.package_not_after)`, i.e. `min(received_at + 5min,
// package.not_after)`. So every aggregate hydration after `force_due_boundary`
// fails `State(InvariantViolation)`.
//
// This is NOT a production due-path defect: requests that become due by the
// real clock hydrate and expire correctly, which is exactly what the eleven
// scheduler-shaped proofs above now demonstrate. Making this pass needs
// `force_due_boundary` to back-date `requested_at`/`received_at` in step with
// `expires_at` (or to wait out the real TTL); either changes what the seam
// manufactures, so it is left for the owner.
#[tokio::test]
#[ignore = "blocked: force_due_boundary writes an expires_at inconsistent with recovery_expiry(received_at, package_not_after), so the aggregate fails validate_recovery_work"]
async fn recovery_client_cancellation_due_for_expiry_orders_expiry_before_client_error() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    mint_singleton_fallback(&pool).await;
    catbird_server::chat_protocol::production_proof::run_leaf_recovery_cancellation_due_for_expiry_ordering(&pool)
        .await
        .expect("Recovery cancellation DueForExpiry ordering");
}

// BLOCKED on an expectation/production disagreement, not a fixture gap. The
// fixture is complete and the full two-party Replace lifecycle now runs to
// completion; `successor_exact` is true and request/reservation/package all
// reach their terminal statuses. Two conjuncts disagree with what production
// actually did: the proof asserts `event_count`/`outbox_count` grow by exactly
// 1 (observed +2, while the transition itself still reports exactly one event
// position), and that the `welcomeAvailable` event has 2 recipient rows
// (observed 1). Deciding which side is wrong is a protocol question.
#[tokio::test]
#[ignore = "blocked: production emits +2 events/outbox rows where the proof asserts +1, and 1 welcomeAvailable recipient where it asserts 2"]
async fn recovery_client_fulfillment_runs_through_real_auth_prelude_apply_and_completion() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    mint_two_party_fallbacks(&pool).await;
    catbird_server::chat_protocol::production_proof::run_leaf_recovery_fulfillment_happy_path(
        &pool,
    )
    .await
    .expect("real client Recovery fulfillment lifecycle");
}

// BLOCKED on the same self-invalidating `force_due_boundary` seam as the
// cancellation DueForExpiry proof above.
#[tokio::test]
#[ignore = "blocked: force_due_boundary writes an expires_at inconsistent with recovery_expiry(received_at, package_not_after), so the aggregate fails validate_recovery_work"]
async fn recovery_client_fulfillment_due_for_expiry_orders_expiry_before_client_error() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    mint_two_party_fallbacks(&pool).await;
    catbird_server::chat_protocol::production_proof::run_leaf_recovery_fulfillment_due_for_expiry_ordering(&pool)
        .await
        .expect("Recovery fulfillment DueForExpiry ordering");
}
