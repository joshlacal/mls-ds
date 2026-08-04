//! TDD-RED tests for the `store_group_info_in_tx` helper that Task 2 will
//! extract from the inline UPDATE SQL currently duplicated across
//! `addMembers` / `processExternalCommit` / `removeMember` arms of
//! `commit_group_change.rs`.
//!
//! The helper signature Task 2 introduces:
//!
//! ```ignore
//! pub async fn store_group_info_in_tx(
//!     tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
//!     convo_id: &str,
//!     group_info_bytes: &[u8],
//!     confirmation_tag: Option<&[u8]>,
//! ) -> sqlx::Result<()>
//! ```
//!
//! Behavior asserted (mirrors the inline SQL at
//! `server/src/handlers/mls_chat/commit_group_change.rs:676-692`):
//!   - `conversations.group_info` <- `group_info_bytes`
//!   - `conversations.group_info_epoch` <- `COALESCE(group_info_epoch, 0) + 1`
//!   - `conversations.group_info_updated_at` <- `NOW()`
//!   - `conversations.confirmation_tag` <- `confirmation_tag`
//!     (Option binds directly: `None` => SQL `NULL`, matching the existing
//!     addMembers behavior that binds `&add_confirmation_tag` of type
//!     `Option<Vec<u8>>` at line 686.)
//!   - All writes inside the provided transaction; rollback discards them.
//!
//! Today's RED state: the symbol does not exist anywhere in
//! `catbird_server::db` (or any other module), so the file fails to compile
//! at the `use` line. Once Task 2 lands, these tests should PASS.
//!
//! Mirrors the test pattern in `tests/commit_group_change_health_counters.rs`
//! and `tests/bootstrap_reset_group.rs` for harness primitives. Requires a
//! live Postgres reachable via `TEST_DATABASE_URL` with the catbird schema
//! applied.
//!
//! Plan: docs/superpowers/plans/2026-05-03-mls-atomic-groupinfo-upload.md
//! (Task 1 — RED).

mod common;

// Task 2 will introduce this symbol. Today the import fails to compile —
// that's the RED state. If you're staring at a compile error pointing at
// this `use`, that's the test working as designed.
use catbird_server::db::store_group_info_in_tx;
use chrono::Utc;
use sqlx::PgPool;
use sqlx::Row;

const CIPHER_SUITE: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
const CREATOR: &str = "did:plc:groupinfo1111111111111";

/// Reserved per-run database prefix owned by this target.
const TEST_DB_PREFIX: &str = "mlsds_gistore_";

/// Mint a private, freshly migrated database for one test case.
///
/// This used to read `TEST_DATABASE_URL` — falling back to a hardcoded
/// connection string when unset — and hand it straight to `db::init_db`, which
/// runs `sqlx::migrate!("./migrations")`. That applied the whole ~56-migration
/// legacy set to whatever database the ambient environment named. With the
/// program's standard environment exported, this target silently took the
/// shared clean-chat database's `_sqlx_migrations` ledger from the reviewed 13
/// to 69 and disabled `validate_exact_reviewed_ledger` for every clean-chat
/// suite — while passing.
///
/// The returned [`DisposableDatabase`] must stay bound for the whole test: it
/// reaps its database on drop, on the normal path and during panic unwind.
async fn setup_test_db() -> (PgPool, common::fresh_db::DisposableDatabase) {
    common::fresh_db::fresh_legacy_pool(TEST_DB_PREFIX, 4, 1).await
}

async fn cleanup(pool: &PgPool, convo_id: &str) {
    let _ = sqlx::query("DELETE FROM members WHERE convo_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
}

/// Insert a `conversations` row with optional initial `group_info` /
/// `group_info_epoch` / `confirmation_tag`. Each test gets a unique
/// `convo_id` + matching `group_id` to avoid collisions on
/// `idx_conversations_group_id_unique` when run in parallel — see the
/// fixture-rot TODOs in `commit_group_change_health_counters.rs`.
async fn seed_convo(
    pool: &PgPool,
    convo_id: &str,
    initial_group_info: Option<&[u8]>,
    initial_group_info_epoch: i32,
    initial_confirmation_tag: Option<&[u8]>,
) {
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, \
             group_id, group_info, group_info_epoch, group_info_updated_at, confirmation_tag) \
         VALUES ($1, $2, 0, $3, $3, $4, false, $1, $5, $6, $3, $7) \
         ON CONFLICT (id) DO UPDATE SET \
            group_info = EXCLUDED.group_info, \
            group_info_epoch = EXCLUDED.group_info_epoch, \
            group_info_updated_at = EXCLUDED.group_info_updated_at, \
            confirmation_tag = EXCLUDED.confirmation_tag",
    )
    .bind(convo_id)
    .bind(CREATOR)
    .bind(now)
    .bind(CIPHER_SUITE)
    .bind(initial_group_info)
    .bind(initial_group_info_epoch)
    .bind(initial_confirmation_tag)
    .execute(pool)
    .await
    .expect("seed conversations row");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — happy path: replaces bytes, increments epoch, writes tag
// ─────────────────────────────────────────────────────────────────────────────

/// `store_group_info_in_tx` MUST:
///   1. Replace `group_info` column bytes verbatim.
///   2. Increment `group_info_epoch` by exactly 1
///      (using `COALESCE(group_info_epoch, 0) + 1` semantics).
///   3. Update `group_info_updated_at` to the tx wall-clock.
///   4. Persist the supplied `confirmation_tag` bytes when `Some`.
///
/// This is the contract the inline SQL at `commit_group_change.rs:676-692`
/// already meets for the `addMembers` arm. Task 2 extracts it into a
/// reusable helper and applies it to `removeMember` (which currently
/// discards `input.group_info` entirely — the bug Task 2 closes).
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL); RED until Task 2 lands the helper"]
async fn store_group_info_in_tx_replaces_bytes_and_increments_epoch() {
    let (pool, _database) = setup_test_db().await;
    let convo_id = format!("convo-gi-helper-replace-{}", uuid::Uuid::new_v4());
    cleanup(&pool, &convo_id).await;

    // Seed: pre-existing GroupInfo at group_info_epoch=0, no confirmation_tag.
    let initial_gi = vec![0xAA_u8; 256];
    seed_convo(&pool, &convo_id, Some(&initial_gi), 0, None).await;

    let new_gi = vec![0xBB_u8; 256];
    let new_tag = vec![0xCC_u8; 32];

    {
        let mut tx = pool.begin().await.expect("begin tx");
        store_group_info_in_tx(&mut tx, &convo_id, &new_gi, Some(&new_tag))
            .await
            .expect("helper returned error");
        tx.commit().await.expect("commit tx");
    }

    let row = sqlx::query(
        "SELECT group_info, group_info_epoch, confirmation_tag \
         FROM conversations WHERE id = $1",
    )
    .bind(&convo_id)
    .fetch_one(&pool)
    .await
    .expect("fetch convo row");

    let stored_gi: Vec<u8> = row.get("group_info");
    let stored_epoch: i32 = row.get("group_info_epoch");
    let stored_tag: Option<Vec<u8>> = row.get("confirmation_tag");

    assert_eq!(
        stored_gi, new_gi,
        "group_info must be replaced verbatim with the helper input"
    );
    assert_eq!(
        stored_epoch, 1,
        "group_info_epoch must increment 0 -> 1 (COALESCE(_, 0) + 1)"
    );
    assert_eq!(
        stored_tag,
        Some(new_tag),
        "confirmation_tag must be persisted when Some(...) is passed"
    );

    cleanup(&pool, &convo_id).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — atomicity: rollback discards the helper's writes
// ─────────────────────────────────────────────────────────────────────────────

/// Atomicity check: if the wrapping tx rolls back (mirroring a downstream
/// failure inside the handler — e.g. the commit-message INSERT errors after
/// the GroupInfo UPDATE), the helper's writes MUST also roll back. This is
/// the load-bearing guarantee Task 2 buys: GroupInfo and epoch CAS land or
/// neither lands, never split-state.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL); RED until Task 2 lands the helper"]
async fn store_group_info_in_tx_rolls_back_on_txn_abort() {
    let (pool, _database) = setup_test_db().await;
    let convo_id = format!("convo-gi-helper-rollback-{}", uuid::Uuid::new_v4());
    cleanup(&pool, &convo_id).await;

    let initial_gi = vec![0xAA_u8; 256];
    seed_convo(&pool, &convo_id, Some(&initial_gi), 0, None).await;

    let attempted_gi = vec![0xBB_u8; 256];

    {
        let mut tx = pool.begin().await.expect("begin tx");
        store_group_info_in_tx(&mut tx, &convo_id, &attempted_gi, None)
            .await
            .expect("helper returned error");
        // Roll back — simulating a downstream error inside the handler that
        // aborts the entire epoch-CAS transaction.
        tx.rollback().await.expect("rollback tx");
    }

    let row = sqlx::query("SELECT group_info, group_info_epoch FROM conversations WHERE id = $1")
        .bind(&convo_id)
        .fetch_one(&pool)
        .await
        .expect("fetch convo row");

    let stored_gi: Vec<u8> = row.get("group_info");
    let stored_epoch: i32 = row.get("group_info_epoch");

    assert_eq!(
        stored_gi, initial_gi,
        "group_info must remain pre-state when wrapping tx rolls back"
    );
    assert_eq!(
        stored_epoch, 0,
        "group_info_epoch must NOT advance when wrapping tx rolls back"
    );

    cleanup(&pool, &convo_id).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — None confirmation_tag overwrites column to SQL NULL
// ─────────────────────────────────────────────────────────────────────────────

/// The existing addMembers SQL at `commit_group_change.rs:686` binds
/// `&add_confirmation_tag` (an `Option<Vec<u8>>`) directly, which means
/// `None` => SQL `NULL` => the `confirmation_tag` column is overwritten
/// to NULL even if it had a previous value. The helper MUST match this
/// behavior so the extraction is a true refactor, not a behavior change.
///
/// Why it matters: a client that omits the tag on a follow-up commit is
/// signaling "no tag for this epoch" — silently preserving the prior
/// epoch's tag would let stale auth bytes leak forward.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL); RED until Task 2 lands the helper"]
async fn store_group_info_in_tx_with_none_tag_writes_null() {
    let (pool, _database) = setup_test_db().await;
    let convo_id = format!("convo-gi-helper-null-tag-{}", uuid::Uuid::new_v4());
    cleanup(&pool, &convo_id).await;

    // Seed: pre-existing tag, so we can observe it being overwritten to NULL.
    let pre_tag = vec![0xCC_u8; 32];
    seed_convo(
        &pool,
        &convo_id,
        Some(&vec![0xAA_u8; 256]),
        0,
        Some(&pre_tag),
    )
    .await;

    {
        let mut tx = pool.begin().await.expect("begin tx");
        store_group_info_in_tx(&mut tx, &convo_id, &vec![0xBB_u8; 256], None)
            .await
            .expect("helper returned error");
        tx.commit().await.expect("commit tx");
    }

    let stored_tag: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT confirmation_tag FROM conversations WHERE id = $1")
            .bind(&convo_id)
            .fetch_one(&pool)
            .await
            .expect("fetch confirmation_tag");

    assert_eq!(
        stored_tag, None,
        "confirmation_tag must be overwritten to SQL NULL when None is passed \
         (matches existing addMembers binding behavior at commit_group_change.rs:686)"
    );

    cleanup(&pool, &convo_id).await;
}
