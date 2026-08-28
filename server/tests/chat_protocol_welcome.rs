//! Welcome-expiry worker + recovery-inbox read tests (Task 2, Slice 4b).
//!
//! Two seams are exercised:
//!   * the pure `recoveryWorkView` closed-union mapping (`map_row`) — a full
//!     structural accept/reject matrix that needs no database; and
//!   * the live-PostgreSQL welcome-expiry worker claim + recovery-inbox reads,
//!     asserted here at the schema-execution level: each new query runs against
//!     the production schema and is device-scoped/empty-safe.
//!
//! The POPULATED path (a pending `chat.welcome_deliveries` row and the
//! `chat.recovery_work_items` it produces) is deliberately NOT hand-seeded: a
//! pending Welcome is only coherent after a completed leaf-recovery fulfillment,
//! and the deferred `chat.assert_welcome_mapping` / roster-coherence triggers
//! reject any raw pre-fulfillment insert. The correct seed is the executor's
//! `apply_conversation_persistence_plan_unscoped_for_test` leaf-recovery Welcome emission (see
//! `tests/chat_protocol_executor.rs`); the populated worker-claim / non-empty
//! read assertions belong beside that harness. See the Slice 4b report for the
//! precise remainder.
//!
//! Like the sibling repository harnesses this `include!`s the production modules
//! directly (they are `pub(crate)`). The live cases run under the standard
//! whole-suite gate: they hard-fail (panic in `setup_chat_protocol_db`) without
//! `TEST_DATABASE_URL` rather than skipping. Run with:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_welcome -- --test-threads=1

#![allow(dead_code)]

mod common;

pub use catbird_server::{auth, federation, handlers, identity, sqlx_jacquard, util};

#[path = "common/chat_protocol_harness.rs"]
mod chat_protocol;

mod repository {
    pub(crate) use crate::chat_protocol::repository::*;
}
#[allow(dead_code)]
mod snapshot {
    pub use catbird_server::chat_protocol::snapshot::*;
}

#[path = "common/executor_seed.rs"]
mod executor_seed;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use repository::delivery::RecoveryWorkSourceKind;
use repository::welcome::{
    claim_due_welcome_deliveries, map_row, read_leaf_recovery_inbox, read_recovery_work_view,
    RecoveryWorkRow, RecoveryWorkView, WelcomeRepositoryError,
};

// ===========================================================================
// Part 1 — pure `map_row` structural accept/reject matrix (no database).
//
// `map_row` is the read-side authority for the closed four-variant
// `recoveryWorkView`: every legal (status, terminal-field) combination maps to
// exactly one variant, and every illegal one rejects.
// ===========================================================================

fn base_row(status: &str) -> RecoveryWorkRow {
    RecoveryWorkRow {
        recovery_work_id: Uuid::new_v4(),
        conversation_id: Uuid::new_v4(),
        recipient_did: "did:plc:ewvi7nxzyoun6zhxrhs64oiz".to_owned(),
        recipient_device_id: Uuid::new_v4(),
        source_kind: "welcomeExpired".to_owned(),
        source_id: Uuid::new_v4(),
        generation: 0,
        state_version: 3,
        status: status.to_owned(),
        terminal_transition_id: None,
        terminal_revocation_id: None,
        terminal_at: None,
        created_at: Utc::now(),
    }
}

#[test]
fn map_row_accepts_pending_with_no_terminal_fields() {
    let view = map_row(&base_row("pending")).expect("pending is a legal variant");
    assert!(matches!(view, RecoveryWorkView::Pending { .. }));
    assert_eq!(view.variant_name(), "recoveryWorkPendingView");
    assert_eq!(
        view.common().source_kind,
        RecoveryWorkSourceKind::WelcomeExpired
    );
    // The bound source coordinate mirrors the row's (conversation, generation,
    // state_version) exactly.
    assert_eq!(view.common().source_coordinate.generation, 0);
    assert_eq!(view.common().source_coordinate.state_version, 3);
}

#[test]
fn map_row_accepts_completed_by_transition() {
    let mut row = base_row("completed");
    row.terminal_transition_id = Some(Uuid::new_v4());
    row.terminal_at = Some(Utc::now());
    let view = map_row(&row).expect("completed-by-transition is legal");
    assert!(matches!(
        view,
        RecoveryWorkView::CompletedByTransition { .. }
    ));
    assert_eq!(view.variant_name(), "recoveryWorkCompletedByTransitionView");
}

#[test]
fn map_row_accepts_superseded_by_transition_and_revocation() {
    let mut by_transition = base_row("superseded");
    by_transition.terminal_transition_id = Some(Uuid::new_v4());
    by_transition.terminal_at = Some(Utc::now());
    assert!(matches!(
        map_row(&by_transition).expect("superseded-by-transition is legal"),
        RecoveryWorkView::SupersededByTransition { .. }
    ));

    let mut by_revocation = base_row("superseded");
    by_revocation.terminal_revocation_id = Some(Uuid::new_v4());
    by_revocation.terminal_at = Some(Utc::now());
    assert!(matches!(
        map_row(&by_revocation).expect("superseded-by-revocation is legal"),
        RecoveryWorkView::SupersededByRevocation { .. }
    ));
}

#[test]
fn map_row_rejects_pending_with_any_terminal_field() {
    let mut with_transition = base_row("pending");
    with_transition.terminal_transition_id = Some(Uuid::new_v4());
    with_transition.terminal_at = Some(Utc::now());
    assert!(matches!(
        map_row(&with_transition),
        Err(WelcomeRepositoryError::MalformedRecoveryWorkVariant)
    ));
}

#[test]
fn map_row_rejects_completed_missing_terminal_fields() {
    // completed status with no terminal transition/instant is not a legal member.
    assert!(matches!(
        map_row(&base_row("completed")),
        Err(WelcomeRepositoryError::MalformedRecoveryWorkVariant)
    ));
    let mut missing_at = base_row("completed");
    missing_at.terminal_transition_id = Some(Uuid::new_v4());
    assert!(matches!(
        map_row(&missing_at),
        Err(WelcomeRepositoryError::MalformedRecoveryWorkVariant)
    ));
}

#[test]
fn map_row_rejects_superseded_missing_terminal_fields() {
    // 'superseded' requires exactly one terminal id + a terminal instant; a bare
    // superseded row is not a legal member of the union.
    assert!(matches!(
        map_row(&base_row("superseded")),
        Err(WelcomeRepositoryError::MalformedRecoveryWorkVariant)
    ));
    // A terminal instant with neither terminal id also rejects.
    let mut at_only = base_row("superseded");
    at_only.terminal_at = Some(Utc::now());
    assert!(matches!(
        map_row(&at_only),
        Err(WelcomeRepositoryError::MalformedRecoveryWorkVariant)
    ));
}

#[test]
fn map_row_rejects_both_terminal_ids_set() {
    let mut both = base_row("superseded");
    both.terminal_transition_id = Some(Uuid::new_v4());
    both.terminal_revocation_id = Some(Uuid::new_v4());
    both.terminal_at = Some(Utc::now());
    assert!(matches!(
        map_row(&both),
        Err(WelcomeRepositoryError::MalformedRecoveryWorkVariant)
    ));
}

#[test]
fn map_row_rejects_revocation_terminal_on_completed_status() {
    // completed must be transition-terminal; a revocation id under 'completed' is
    // a cross-kind shape and rejects.
    let mut cross = base_row("completed");
    cross.terminal_revocation_id = Some(Uuid::new_v4());
    cross.terminal_at = Some(Utc::now());
    assert!(matches!(
        map_row(&cross),
        Err(WelcomeRepositoryError::MalformedRecoveryWorkVariant)
    ));
}

#[test]
fn map_row_rejects_transition_terminal_on_pending_status() {
    let mut cross = base_row("pending");
    cross.terminal_transition_id = Some(Uuid::new_v4());
    cross.terminal_at = Some(Utc::now());
    assert!(matches!(
        map_row(&cross),
        Err(WelcomeRepositoryError::MalformedRecoveryWorkVariant)
    ));
}

#[test]
fn map_row_rejects_unknown_status() {
    assert!(matches!(
        map_row(&base_row("archived")),
        Err(WelcomeRepositoryError::MalformedRecoveryWorkVariant)
    ));
}

#[test]
fn map_row_rejects_unknown_source_kind() {
    let mut row = base_row("pending");
    row.source_kind = "welcomeVaporized".to_owned();
    assert!(matches!(
        map_row(&row),
        Err(WelcomeRepositoryError::MalformedRecoveryWorkSourceKind)
    ));
}

#[test]
fn map_row_rejects_negative_coordinate() {
    let mut row = base_row("pending");
    row.state_version = -1;
    assert!(matches!(
        map_row(&row),
        Err(WelcomeRepositoryError::SafeIntegerOverflow)
    ));
}

// ===========================================================================
// Part 2 — live-PostgreSQL schema-execution checks for the new queries.
//
// These prove each new statement is valid against the production schema (column
// names, joins, and the `FOR UPDATE ... SKIP LOCKED` claim all resolve) and that
// the recovery-inbox reads are strictly device-scoped: a device with no rows
// enumerates nothing. The populated-path assertions require an executor-seeded
// Welcome graph — see the module header and the Slice 4b report.
// ===========================================================================

fn random_plc_did() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = Uuid::new_v4().as_bytes().to_vec();
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    let suffix: String = bytes
        .iter()
        .take(24)
        .map(|byte| ALPHABET[(*byte % 32) as usize] as char)
        .collect();
    format!("did:plc:{suffix}")
}

async fn clock_now(pool: &PgPool) -> chrono::DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .expect("sample trusted database clock")
}

#[tokio::test]
async fn claim_due_welcome_deliveries_query_is_schema_valid_and_skip_locked() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let now = clock_now(&pool).await;

    // The claim SELECT (join to welcome_bundles + FOR UPDATE OF wd SKIP LOCKED,
    // ordered by (expires_at, welcome_id)) must resolve against the schema and
    // return no rows when nothing is due, without locking-error or column drift.
    let mut tx = pool.begin().await.expect("begin claim");
    let claimed = claim_due_welcome_deliveries(&mut tx, now, 32)
        .await
        .expect("claim executes against the production schema");
    // The shared test database is never truncated, so other suites' expired
    // deliveries may exist; the load-bearing assertion is that the statement runs
    // and every returned row is genuinely due (expires_at <= now).
    for due in &claimed {
        assert!(
            due.expires_at <= now,
            "claim must never return a not-yet-due delivery"
        );
        assert!(due.transition_seq >= 0);
    }
    tx.rollback().await.expect("rollback claim");
}

#[tokio::test]
async fn recovery_work_view_read_is_schema_valid_and_device_empty() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    // A fresh, never-seeded device enumerates nothing through the device-scoped
    // read — the query (including the revocation-target EXISTS guard) resolves
    // against the schema and returns empty.
    let mut tx = pool.begin().await.expect("begin read");
    let view = read_recovery_work_view(&mut tx, &random_plc_did(), Uuid::new_v4())
        .await
        .expect("recovery-work read executes against the production schema");
    assert!(
        view.is_empty(),
        "a device with no recovery work enumerates nothing"
    );
    tx.rollback().await.expect("rollback read");
}

#[tokio::test]
async fn leaf_recovery_inbox_read_is_schema_valid_and_device_empty() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    // The flat inbox union assembles the open-request join + the recovery-work
    // read; for an unseeded device both halves resolve and yield an empty inbox.
    let mut tx = pool.begin().await.expect("begin read");
    let inbox = read_leaf_recovery_inbox(&mut tx, &random_plc_did(), Uuid::new_v4())
        .await
        .expect("inbox read executes against the production schema");
    assert!(
        inbox.is_empty(),
        "a device with no inbox items enumerates nothing"
    );
    tx.rollback().await.expect("rollback read");
}

// ===========================================================================
// Part 4 — populated live tests (Seal C), driven by the shared
// `common::executor_seed` fulfillment graph. Each runs on a fresh per-run
// database (its own `FreshDbGuard`) so the seeded corpus identity + the one
// pending Welcome the fulfillment emits are the only rows in scope.
// ===========================================================================

/// Remainder case #1: a real committed leaf-recovery fulfillment leaves exactly
/// one pending `chat.welcome_deliveries` row; observed past its `expires_at`, the
/// worker claim returns exactly that row, carrying the seeded delivery identity
/// (welcome/conversation/recovery-request), the exact recipient device, and the
/// bound coordinate/seq of the fulfillment transition.
#[tokio::test]
async fn claim_returns_the_seeded_due_welcome_delivery() {
    let (pool, _guard) = executor_seed::setup().await;
    let scenario = executor_seed::run_fulfillment_scenario(&pool).await;

    // The seeded delivery's `expires_at` is the consumed Add KeyPackage
    // `not_after` (~24h out); observe well past it so the row is due.
    let observed_at = clock_now(&pool).await + chrono::Duration::hours(48);
    let mut tx = pool.begin().await.expect("begin claim");
    let claimed = claim_due_welcome_deliveries(&mut tx, observed_at, 32)
        .await
        .expect("claim executes against the seeded schema");
    assert_eq!(
        claimed.len(),
        1,
        "exactly the one seeded pending delivery is due on the fresh DB"
    );
    let due = &claimed[0];
    assert_eq!(due.welcome_id, scenario.welcome_id);
    assert_eq!(due.conversation_id, scenario.conversation_id);
    assert_eq!(due.recovery_request_id, scenario.recovery_request_id);
    assert_eq!(due.recipient_did, scenario.bob_did);
    assert_eq!(
        due.recipient_device_id,
        Uuid::from_bytes(*scenario.bob_id.device_id())
    );
    assert!(due.expires_at <= observed_at);
    // The fulfillment committed at entry seq 3 / state_version 2 (run_fulfillment
    // scenario proves allocated_seq == 3 and the sv-2 commit gen state).
    assert_eq!(due.transition_seq, 3);
    assert_eq!(due.state_version, 2);
    tx.rollback().await.expect("rollback claim");
}

/// Remainder case #3: two concurrent workers never double-claim one delivery —
/// the second worker's `FOR UPDATE OF wd SKIP LOCKED` skips exactly the row the
/// first worker already holds, so the due set is partitioned, never duplicated.
#[tokio::test]
async fn two_workers_never_double_claim_the_seeded_delivery() {
    let (pool, _guard) = executor_seed::setup().await;
    let _scenario = executor_seed::run_fulfillment_scenario(&pool).await;
    let observed_at = clock_now(&pool).await + chrono::Duration::hours(48);

    // Worker 1 claims + locks the one due delivery, holding its transaction open.
    let mut tx1 = pool.begin().await.expect("begin worker 1");
    let claimed1 = claim_due_welcome_deliveries(&mut tx1, observed_at, 32)
        .await
        .expect("worker 1 claims");
    assert_eq!(
        claimed1.len(),
        1,
        "worker 1 claims and locks the one due delivery"
    );

    // Worker 2, concurrent, must SKIP LOCKED the row worker 1 holds and see none.
    let mut tx2 = pool.begin().await.expect("begin worker 2");
    let claimed2 = claim_due_welcome_deliveries(&mut tx2, observed_at, 32)
        .await
        .expect("worker 2 claims");
    assert!(
        claimed2.is_empty(),
        "worker 2 never double-claims the delivery worker 1 holds"
    );
    tx2.rollback().await.expect("rollback worker 2");
    tx1.rollback().await.expect("rollback worker 1");
}
