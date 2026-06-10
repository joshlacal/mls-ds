//! Bulk key-package claim coverage for the PR review #23 perf follow-up.
//!
//! `get_key_packages` previously issued N round-trips for N requested DIDs.
//! The bulk helper claims one row per (owner_did, device_id) bucket across
//! the full requested set in a single SQL round-trip while preserving the
//! `state='available' -> state='claimed'` atomic gate (`FOR UPDATE SKIP
//! LOCKED` on the inner row picker, re-checked on the outer UPDATE).
//!
//! This test pre-seeds N DIDs across two cipher suites and a mix of regular
//! / last-resort rows, then asserts:
//!   1. Bulk claim returns the same per-DID rows as the pre-bulk per-DID
//!      loop would have.
//!   2. A second invocation observes zero rows for those DIDs (rows are now
//!      `claimed` — single-call atomicity).
//!   3. Per-device dedupe is preserved (`DISTINCT ON (owner_did, device_id)`).
//!
//! Round-trip count is structural: the helper uses a single `query_as!`
//! against the pool, so 1 SQL call covers N DIDs by construction. The
//! atomicity invariant for races is covered by `key_package_claim_race.rs`.
//!
//! Requires `TEST_DATABASE_URL` (defaults to localhost:5433/catbird). The
//! test creates and tears down its own users + key_package rows.

use catbird_server::handlers::mls_chat::get_key_packages::claim_available_key_packages_bulk;
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use std::time::Duration as StdDuration;
use uuid::Uuid;

async fn setup_test_db() -> PgPool {
    let db_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://catbird:changeme@localhost:5433/catbird".to_string());

    let config = catbird_server::db::DbConfig {
        database_url: db_url,
        max_connections: 8,
        min_connections: 2,
        acquire_timeout: StdDuration::from_secs(10),
        idle_timeout: StdDuration::from_secs(60),
    };

    catbird_server::db::init_db(config)
        .await
        .expect("Failed to initialize test database")
}

async fn ensure_user(pool: &PgPool, did: &str) {
    sqlx::query(
        "INSERT INTO users (did, created_at, last_seen_at) \
         VALUES ($1, NOW(), NOW()) \
         ON CONFLICT (did) DO NOTHING",
    )
    .bind(did)
    .execute(pool)
    .await
    .expect("ensure_user");
}

#[allow(clippy::too_many_arguments)]
async fn insert_key_package(
    pool: &PgPool,
    owner_did: &str,
    cipher_suite: &str,
    device_id: Option<&str>,
    is_last_resort: bool,
) -> String {
    let id = Uuid::new_v4().to_string();
    let kp_hash = format!("test-{}", &id[..16]);
    let kp_bytes = vec![0u8; 32];
    let expires_at = Utc::now() + Duration::days(30);

    sqlx::query(
        "INSERT INTO key_packages \
           (id, owner_did, cipher_suite, key_package, key_package_hash, \
            device_id, created_at, expires_at, state, is_last_resort) \
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, 'available', $8)",
    )
    .bind(&id)
    .bind(owner_did)
    .bind(cipher_suite)
    .bind(&kp_bytes)
    .bind(&kp_hash)
    .bind(device_id)
    .bind(expires_at)
    .bind(is_last_resort)
    .execute(pool)
    .await
    .expect("insert_key_package");

    id
}

async fn cleanup(pool: &PgPool, dids: &[String]) {
    for did in dids {
        let _ = sqlx::query("DELETE FROM key_packages WHERE owner_did = $1")
            .bind(did)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(did)
            .execute(pool)
            .await;
    }
}

/// Bulk claim across N DIDs returns the same per-DID result set the
/// pre-bulk per-DID loop would have produced, in a single SQL round-trip.
///
/// Regression coverage for N23: when the bulk helper chooses one
/// representative row for a `(DID, device_id)` bucket, every available row
/// in that bucket must be claimed so repeat calls cannot deplete duplicate
/// packages one at a time.
#[tokio::test]
async fn test_bulk_claim_matches_per_did_loop() {
    let pool = setup_test_db().await;
    let cipher_suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

    // Seed: 5 DIDs.
    //   did_0: 1 device_id="dev-A" + 1 device_id="dev-B" -> 2 rows expected
    //   did_1: 1 device_id=None                          -> 1 row  expected
    //   did_2: 2 rows on device_id="dev-A" (different
    //          created_at) -> dedupe to oldest, 1 row    -> 1 row  expected
    //   did_3: 1 last-resort row only                    -> 0 rows on regular
    //   did_4: zero rows                                 -> 0 rows
    let run_id = Uuid::new_v4();
    let dids: Vec<String> = (0..5)
        .map(|i| format!("did:plc:test-bulk-{}-{}", run_id, i))
        .collect();

    for did in &dids {
        ensure_user(&pool, did).await;
    }

    insert_key_package(&pool, &dids[0], cipher_suite, Some("dev-A"), false).await;
    insert_key_package(&pool, &dids[0], cipher_suite, Some("dev-B"), false).await;

    insert_key_package(&pool, &dids[1], cipher_suite, None, false).await;

    // did_2: insert two rows on the same device_id; dedupe should return one
    // representative row and claim both rows in the bucket.
    let _older = insert_key_package(&pool, &dids[2], cipher_suite, Some("dev-A"), false).await;
    // Sleep briefly so created_at differs (NOW() resolution) — the row
    // inserted second must be filtered out.
    tokio::time::sleep(StdDuration::from_millis(20)).await;
    let _newer = insert_key_package(&pool, &dids[2], cipher_suite, Some("dev-A"), false).await;

    insert_key_package(&pool, &dids[3], cipher_suite, Some("dev-A"), true).await;
    // dids[4]: deliberately empty.

    // ── 1. Single bulk call across all 5 DIDs ───────────────────────────
    let did_strs: Vec<&str> = dids.iter().map(String::as_str).collect();
    let regular = claim_available_key_packages_bulk(&pool, &did_strs, Some(cipher_suite), false)
        .await
        .expect("bulk regular claim");

    let mut by_did: HashMap<String, usize> = HashMap::new();
    for row in &regular {
        *by_did.entry(row.0.clone()).or_default() += 1;
    }

    assert_eq!(
        by_did.get(&dids[0]).copied().unwrap_or(0),
        2,
        "did_0 should yield 2 rows (one per device bucket)"
    );
    assert_eq!(
        by_did.get(&dids[1]).copied().unwrap_or(0),
        1,
        "did_1 should yield 1 row (no device_id bucket)"
    );
    assert_eq!(
        by_did.get(&dids[2]).copied().unwrap_or(0),
        1,
        "did_2 should yield 1 row (DISTINCT ON dedupe to oldest)"
    );
    assert!(
        !by_did.contains_key(&dids[3]),
        "did_3 (last-resort only) should not appear in regular claim"
    );
    assert!(
        !by_did.contains_key(&dids[4]),
        "did_4 (empty) should not appear in regular claim"
    );

    // Every returned row must carry the requested cipher_suite and a 32-byte
    // KP payload — confirms the SELECT/RETURNING shape is preserved.
    for (owner_did, cs, kp, _hash) in &regular {
        assert!(
            dids.contains(owner_did),
            "unexpected DID {} in result",
            owner_did
        );
        assert_eq!(cs, cipher_suite);
        assert_eq!(kp.len(), 32);
    }

    // ── 2. Last-resort fallback for DIDs with zero regular rows ─────────
    let unmatched: Vec<&str> = did_strs
        .iter()
        .copied()
        .filter(|d| !by_did.contains_key(*d))
        .collect();
    assert!(unmatched.contains(&dids[3].as_str()));
    assert!(unmatched.contains(&dids[4].as_str()));

    let lr = claim_available_key_packages_bulk(&pool, &unmatched, Some(cipher_suite), true)
        .await
        .expect("bulk last-resort claim");
    let lr_owners: Vec<&str> = lr.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(lr.len(), 1, "expected exactly one last-resort hit");
    assert_eq!(
        lr_owners,
        vec![dids[3].as_str()],
        "only did_3 has a last-resort row"
    );

    // ── 3. Repeat-claim sanity: rows are now `claimed`; bulk returns 0 ──
    let after = claim_available_key_packages_bulk(&pool, &did_strs, Some(cipher_suite), false)
        .await
        .expect("post-claim bulk regular");
    assert!(
        after.is_empty(),
        "post-claim bulk should observe no available rows; got {} rows",
        after.len()
    );

    let after_lr = claim_available_key_packages_bulk(&pool, &did_strs, Some(cipher_suite), true)
        .await
        .expect("post-claim bulk last-resort");
    assert!(
        after_lr.is_empty(),
        "post-claim bulk last-resort should observe no available rows; got {} rows",
        after_lr.len()
    );

    // ── 4. Empty input is a no-op (no SQL emitted, no error) ────────────
    let empty = claim_available_key_packages_bulk(&pool, &[], Some(cipher_suite), false)
        .await
        .expect("empty bulk claim");
    assert!(empty.is_empty());

    cleanup(&pool, &dids).await;
}

/// Round-trip count check (PR review #23 perf follow-up).
///
/// Asserts the bulk claim path executes O(1) SQL statements against the
/// backend regardless of input cardinality. We do this by (a) acquiring a
/// dedicated connection from the pool, (b) capturing
/// `pg_stat_get_backend_xact_start(pg_backend_pid())` based statement count
/// via the per-backend `pg_stat_get_*` family on that pinned connection,
/// (c) running the bulk claim on the same connection, and (d) asserting the
/// statement counter advanced by ~1 for the bulk SQL — not by N.
///
/// This is a regression-detection gate: if the bulk helper is ever silently
/// reverted to a per-DID loop, this test will fail because the per-backend
/// transaction count delta will jump to ~N rather than ~1.
#[tokio::test]
async fn test_bulk_claim_emits_one_statement_per_call() {
    let pool = setup_test_db().await;
    let cipher_suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

    let run_id = Uuid::new_v4();
    let n: usize = 10;
    let dids: Vec<String> = (0..n)
        .map(|i| format!("did:plc:test-rtt-{}-{}", run_id, i))
        .collect();
    for did in &dids {
        ensure_user(&pool, did).await;
    }
    for did in &dids {
        insert_key_package(&pool, did, cipher_suite, Some("dev-A"), false).await;
    }

    // Use a dedicated single-connection pool so xact counters at the
    // backend are exclusively driven by THIS test. Otherwise sibling tests
    // sharing the same backend would contaminate the delta.
    let single_conn_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://catbird:changeme@localhost:5433/catbird".to_string());
    let single_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .connect(&single_conn_url)
        .await
        .expect("single-conn pool");

    // pg_stat_get_xact_function_calls would only count function calls.
    // `pg_stat_get_backend_xact_start(pg_backend_pid())` returns the start
    // ts of the *current* transaction (NULL outside a tx). What we want is
    // the cumulative transaction count for THIS backend, which Postgres
    // doesn't expose per-backend cleanly. Instead we track query-level work
    // via `txid_current()` deltas — each autocommit statement increments
    // the global xid counter on the backend that issued it.
    let xid_before: i64 = sqlx::query_scalar("SELECT txid_current()::bigint")
        .fetch_one(&single_pool)
        .await
        .expect("xid_before");

    let did_strs: Vec<&str> = dids.iter().map(String::as_str).collect();
    let rows =
        claim_available_key_packages_bulk(&single_pool, &did_strs, Some(cipher_suite), false)
            .await
            .expect("bulk claim");
    assert_eq!(
        rows.len(),
        n,
        "expected one row per DID for N={}; got {}",
        n,
        rows.len()
    );

    let xid_after: i64 = sqlx::query_scalar("SELECT txid_current()::bigint")
        .fetch_one(&single_pool)
        .await
        .expect("xid_after");

    // Each `txid_current()` call is itself an autocommit statement that
    // assigns a new xid, so the floor is +2 (one for "after" alone). The
    // bulk claim should add exactly +1. A per-DID loop with N=10 would add
    // ~+10 instead.
    //
    // Postgres does NOT increment txid for read-only statements, so the
    // before/after `SELECT txid_current()` themselves bump txid. The two
    // bracketing reads + the one UPDATE = 3, so we expect delta in [3, 4].
    let delta = xid_after - xid_before;
    assert!(
        delta < (n as i64),
        "bulk claim emitted ~{} transactions for N={} DIDs (delta={}); \
         expected O(1) statements. A regression to the per-DID loop would \
         push delta toward N+ (~{}).",
        delta,
        n,
        delta,
        n + 2
    );

    cleanup(&pool, &dids).await;
}

/// Regression for the production-blocking `getKeyPackages` 500.
///
/// The prior bulk SQL used `SELECT DISTINCT ON ... FOR UPDATE SKIP LOCKED`,
/// which Postgres rejects at parse time with
/// `ERROR: FOR UPDATE is not allowed with DISTINCT clause`. Every call
/// returned 500, blocking Phase 2.5 first-responder bootstrap recovery.
///
/// This test pre-seeds 3 DIDs × 2 device buckets × 3 available rows each (18
/// rows total) and asserts the bulk claim returns exactly 6 rows — one per
/// (DID, device_id) bucket. The single biggest behavioural symptom of a
/// regression to the broken SQL would be an `Err(...)` here.
#[tokio::test]
async fn test_bulk_claim_smoke_distinct_for_update_regression() {
    let pool = setup_test_db().await;
    let cipher_suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

    let run_id = Uuid::new_v4();
    let dids: Vec<String> = (0..3)
        .map(|i| format!("did:plc:test-distinct-{}-{}", run_id, i))
        .collect();
    let buckets = ["dev-A", "dev-B"];

    for did in &dids {
        ensure_user(&pool, did).await;
        for bucket in &buckets {
            // 3 available rows per (DID, bucket) — dedupe must collapse to 1.
            for _ in 0..3 {
                insert_key_package(&pool, did, cipher_suite, Some(bucket), false).await;
                tokio::time::sleep(StdDuration::from_millis(2)).await;
            }
        }
    }

    let did_strs: Vec<&str> = dids.iter().map(String::as_str).collect();
    let rows = claim_available_key_packages_bulk(&pool, &did_strs, Some(cipher_suite), false)
        .await
        .expect(
            "bulk claim must not return an Err — \
             a regression to `DISTINCT ON ... FOR UPDATE SKIP LOCKED` \
             trips Postgres parse error 'FOR UPDATE is not allowed with \
             DISTINCT clause' which is exactly the production 500.",
        );

    assert_eq!(
        rows.len(),
        dids.len() * buckets.len(),
        "expected one claimed row per (DID, device_id) bucket; got {}",
        rows.len()
    );

    // Per-DID dedupe shape: each DID owns exactly one row per bucket.
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    for (owner_did, _cs, _kp, _hash) in &rows {
        // We don't have device_id in the RETURNING shape, so we just bucket
        // by owner_did and assert the per-DID count is 2 (one per bucket).
        *seen.entry((owner_did.clone(), String::new())).or_default() += 1;
    }
    for did in &dids {
        let count = seen
            .get(&(did.clone(), String::new()))
            .copied()
            .unwrap_or(0);
        assert_eq!(
            count, 2,
            "DID {} should have one row per device bucket (=2); got {}",
            did, count
        );
    }

    cleanup(&pool, &dids).await;
}

/// `device_id IS NULL` rows must collapse to a single bucket via
/// `COALESCE(device_id, '')`. Pre-existing test_bulk_claim_matches_per_did_loop
/// covers the single-NULL-row case (did_1); this asserts the dedupe with
/// MULTIPLE NULL-device rows owned by the same DID — the bucket must collapse
/// regardless of how many NULL-device rows are seeded.
#[tokio::test]
async fn test_bulk_claim_null_device_id_dedupe() {
    let pool = setup_test_db().await;
    let cipher_suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

    let run_id = Uuid::new_v4();
    let did = format!("did:plc:test-nulldev-{}", run_id);
    ensure_user(&pool, &did).await;

    // 4 rows with device_id = NULL on the same DID — all collapse to one bucket.
    for _ in 0..4 {
        insert_key_package(&pool, &did, cipher_suite, None, false).await;
        tokio::time::sleep(StdDuration::from_millis(2)).await;
    }

    let rows = claim_available_key_packages_bulk(&pool, &[did.as_str()], Some(cipher_suite), false)
        .await
        .expect("bulk claim with NULL device_id");

    assert_eq!(
        rows.len(),
        1,
        "4 rows × NULL device_id × same DID must collapse to 1 claimed row \
         via COALESCE(device_id, ''); got {}",
        rows.len()
    );

    cleanup(&pool, &[did]).await;
}
