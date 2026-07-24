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
//! `apply_conversation_persistence_plan` leaf-recovery Welcome emission (see
//! `tests/chat_protocol_executor.rs`); the populated worker-claim / non-empty
//! read assertions belong beside that harness. See the Slice 4b report for the
//! precise remainder.
//!
//! Like the sibling repository harnesses this `include!`s the production modules
//! directly (they are `pub(crate)`). The live cases are `#[ignore]`d by default.
//! Run with:
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_welcome -- --include-ignored --test-threads=1

#![allow(dead_code)]

mod common;

// `welcome` reads `super::delivery::RecoveryWorkSourceKind`, so BOTH production
// modules are inlined here exactly as they are laid out under `repository/`.
mod repository {
    pub(crate) mod delivery {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/delivery.rs"
        ));
    }
    pub(crate) mod welcome {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/welcome.rs"
        ));
    }
}

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
#[ignore = "requires the dedicated clean-chat PostgreSQL database"]
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
#[ignore = "requires the dedicated clean-chat PostgreSQL database"]
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
#[ignore = "requires the dedicated clean-chat PostgreSQL database"]
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
