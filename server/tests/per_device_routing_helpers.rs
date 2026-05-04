//! TDD-RED tests for the `store_welcomes_per_device_in_tx` helper that
//! Task 3 will extract from the inline per-device welcome fan-out loop in
//! `bootstrap_reset_group.rs:562-594`. The same helper will be reused by
//! the `addMembers` and `processExternalCommit` arms of `commit_group_change`
//! (the call sites the plan converges on per-device routing across).
//!
//! The helper signature Task 3 introduces:
//!
//! ```ignore
//! pub async fn store_welcomes_per_device_in_tx(
//!     tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
//!     convo_id: &str,
//!     welcome_bytes: &[u8],
//!     kp_hashes: &[KeyPackageHashEntry<'_>],
//!     sender_did: &str,
//! ) -> sqlx::Result<()>
//! ```
//!
//! Behavior asserted (mirrors the inline loop at
//! `server/src/handlers/mls_chat/bootstrap_reset_group.rs:562-594`, with one
//! deliberate addition: the helper also persists `created_by_did = sender_did`,
//! which the inline loop does not bind today — this is the per-device routing
//! audit-trail fix the plan calls out):
//!   - One `welcome_messages` row per `kp_hashes` entry.
//!   - `convo_id` ← input; `recipient_did` ← `did_to_string(&entry.did)`;
//!     `welcome_data` ← `welcome_bytes`;
//!     `key_package_hash` ← `hex::decode(&entry.hash)`;
//!     `created_by_did` ← `sender_did`;
//!     `consumed` ← `false` (default); `id` ← fresh UUID.
//!   - Operates inside the supplied transaction; rollback discards rows.
//!   - Empty `kp_hashes` slice ⇒ no-op (consistent with addMembers'
//!     "no welcomes to deliver" arm).
//!   - ON CONFLICT against the schema's
//!     `idx_welcome_messages_unique` (UNIQUE on
//!     `(convo_id, recipient_did, COALESCE(key_package_hash, '\x00'::bytea))`
//!     `WHERE consumed = false`) ⇒ DO NOTHING.
//!
//! Today's RED state: the symbol does not exist in `catbird_server::db`
//! (or anywhere else), so this file fails to compile at the `use` line.
//! Once Task 3 lands, these tests should PASS.
//!
//! Note: `KeyPackageHashEntry<'a>` is a jacquard-generated type with a
//! borrow lifetime. The tests construct `KeyPackageHashEntry<'static>`
//! via `string_to_did` (returns `Did<'static>`) and `&str -> CowStr<'static>`.
//! Task 3's `&[KeyPackageHashEntry<'_>]` parameter must accept that.
//!
//! Note: the plan's example DIDs use fragment form (e.g.
//! `did:plc:alice#device-a`). The jacquard `Did` regex rejects `#`, and in
//! production the device suffix lives in `WelcomeEnvelope.recipient_device_id`,
//! not the DID itself. The helper's contract is passthrough — `entry.did`
//! lands in `recipient_did` verbatim — so the test uses bare-form DIDs with
//! deliberate "device" suffixes (`perdev1alicea`, `perdev2aliceb`,
//! `perdev3bobaa`) that exercise the per-row INSERT loop without falling
//! foul of DID validation.
//!
//! Mirrors the test pattern in `tests/group_info_store_helper.rs`
//! (Phase 1 RED) for structure and `#[ignore]` semantics. Requires a
//! live Postgres reachable via `TEST_DATABASE_URL` with the catbird schema
//! applied.
//!
//! Plan: docs/superpowers/plans/2026-05-04-mls-per-device-welcome-and-members-routing.md
//! (Task 2 — RED).

mod common;

// Task 3 will introduce this symbol. Today the import fails to compile —
// that's the RED state. If you're staring at a compile error pointing at
// this `use`, that's the test working as designed.
use catbird_server::db::store_welcomes_per_device_in_tx;
use catbird_server::generated::blue_catbird::mlsChat::bootstrap_reset_group::KeyPackageHashEntry;
use catbird_server::sqlx_jacquard::string_to_did;
use chrono::Utc;
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

const CIPHER_SUITE: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
const CREATOR: &str = "did:plc:perdev0caller00000";

/// Insert a `conversations` row sufficient for the FK on
/// `welcome_messages.convo_id`. Each test uses a UUID-suffixed `convo_id`
/// (and matching `group_id`) to avoid collisions on
/// `idx_conversations_group_id_unique` when run in parallel.
async fn seed_convo(pool: &PgPool, convo_id: &str) {
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, group_id) \
         VALUES ($1, $2, 0, $3, $3, $4, false, $1) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(convo_id)
    .bind(CREATOR)
    .bind(now)
    .bind(CIPHER_SUITE)
    .execute(pool)
    .await
    .expect("seed conversations row");
}

/// Construct a `KeyPackageHashEntry` for tests. Uses the same direct-struct
/// form as `tests/bootstrap_reset_group.rs:649` so the test stays robust to
/// any reshuffling of the lexicon-generated builder API.
fn make_kp_entry(did_str: &'static str, hash_hex: &'static str) -> KeyPackageHashEntry<'static> {
    KeyPackageHashEntry {
        did: string_to_did(did_str),
        hash: hash_hex.into(),
        extra_data: Default::default(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — happy path: writes one row per kp_hash entry
// ─────────────────────────────────────────────────────────────────────────────

/// `store_welcomes_per_device_in_tx` MUST insert one row per
/// `KeyPackageHashEntry` into `welcome_messages`, with each row carrying
/// the entry's `recipient_did`, `hex::decode(entry.hash)` as the
/// `key_package_hash` BYTEA, the supplied `welcome_bytes`, and
/// `created_by_did = sender_did`.
///
/// This is the contract the inline loop at
/// `bootstrap_reset_group.rs:562-594` already meets for the per-row INSERT,
/// minus `created_by_did` (which Task 3 adds — see module docs).
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL); RED until Task 3 lands the helper"]
async fn store_welcomes_per_device_writes_one_row_per_kp_hash() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-welcome-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    // Three "devices" expressed as bare-form DIDs with deliberately distinct
    // PLC suffixes that sort lexicographically in the assertion order below.
    let alice_dev_a = "did:plc:perdev1alicea";
    let alice_dev_b = "did:plc:perdev2aliceb";
    let bob_dev_a = "did:plc:perdev3bobaa";

    let kp_hashes = vec![
        make_kp_entry(alice_dev_a, "aa11"),
        make_kp_entry(alice_dev_b, "bb22"),
        make_kp_entry(bob_dev_a, "cc33"),
    ];

    let welcome_bytes = vec![0xAA_u8; 256];
    let sender = "did:plc:perdev0caller00000";

    {
        let mut tx = pool.begin().await.expect("begin tx");
        store_welcomes_per_device_in_tx(&mut tx, &convo_id, &welcome_bytes, &kp_hashes, sender)
            .await
            .expect("helper returned error");
        tx.commit().await.expect("commit tx");
    }

    let rows = sqlx::query(
        "SELECT recipient_did, encode(key_package_hash, 'hex') AS hash_hex, welcome_data, created_by_did, consumed \
         FROM welcome_messages \
         WHERE convo_id = $1 \
         ORDER BY recipient_did",
    )
    .bind(&convo_id)
    .fetch_all(&pool)
    .await
    .expect("fetch rows");

    assert_eq!(rows.len(), 3, "expected one row per kp_hash entry");

    let recipients: Vec<String> = rows.iter().map(|r| r.get("recipient_did")).collect();
    assert_eq!(
        recipients,
        vec![alice_dev_a, alice_dev_b, bob_dev_a],
        "recipient_did must be entry.did verbatim, one row per entry"
    );

    let hashes: Vec<String> = rows.iter().map(|r| r.get("hash_hex")).collect();
    assert_eq!(
        hashes,
        vec!["aa11", "bb22", "cc33"],
        "key_package_hash must be hex::decode(entry.hash) per row"
    );

    let bodies: Vec<Vec<u8>> = rows.iter().map(|r| r.get("welcome_data")).collect();
    assert!(
        bodies.iter().all(|b| b == &welcome_bytes),
        "welcome_data must be the supplied welcome_bytes for every row"
    );

    let creators: Vec<Option<String>> = rows.iter().map(|r| r.get("created_by_did")).collect();
    assert!(
        creators.iter().all(|c| c.as_deref() == Some(sender)),
        "created_by_did must be the supplied sender_did for every row"
    );

    let consumeds: Vec<bool> = rows.iter().map(|r| r.get("consumed")).collect();
    assert!(
        consumeds.iter().all(|c| !*c),
        "consumed must default to false for newly inserted welcomes"
    );

    common::cleanup(&pool, &convo_id).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — atomicity: rollback discards all per-device rows
// ─────────────────────────────────────────────────────────────────────────────

/// Atomicity: if the wrapping tx rolls back (mirroring a downstream failure
/// inside the handler — e.g. the commit-message INSERT errors after the
/// per-device fan-out), the helper's writes MUST also roll back. This is
/// the load-bearing guarantee: Welcomes and the rest of the chokepoint tx
/// land or none land, never split-state where some recipients see a
/// pending Welcome but the convo itself is in an inconsistent state.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL); RED until Task 3 lands the helper"]
async fn store_welcomes_per_device_rolls_back_on_txn_abort() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-rollback-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let kp_hashes = vec![make_kp_entry("did:plc:perdev1alicea", "aa11")];
    let welcome_bytes = vec![0xAA_u8; 256];

    {
        let mut tx = pool.begin().await.expect("begin tx");
        store_welcomes_per_device_in_tx(
            &mut tx,
            &convo_id,
            &welcome_bytes,
            &kp_hashes,
            "did:plc:perdev0caller00000",
        )
        .await
        .expect("helper returned error");
        // Roll back — simulating a downstream failure inside the handler
        // that aborts the entire transaction.
        tx.rollback().await.expect("rollback tx");
    }

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM welcome_messages WHERE convo_id = $1")
            .bind(&convo_id)
            .fetch_one(&pool)
            .await
            .expect("count welcome rows");
    assert_eq!(
        count, 0,
        "rollback must leave zero welcome_messages rows for this convo"
    );

    common::cleanup(&pool, &convo_id).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — empty kp_hashes is a no-op
// ─────────────────────────────────────────────────────────────────────────────

/// Empty `kp_hashes` slice ⇒ helper writes nothing and returns Ok.
/// This matches the addMembers' "no welcomes to deliver" semantics: a
/// commit that adds zero new devices (e.g. all proposals were leave-only)
/// MUST NOT manufacture phantom welcome rows. Crucially, the helper does
/// NOT fall through to a fan-out-to-all-active-members branch on empty
/// input — that legacy behavior lives in the inline `else` arm at
/// `bootstrap_reset_group.rs:595-636` and is intentionally NOT part of
/// this helper's contract.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL); RED until Task 3 lands the helper"]
async fn store_welcomes_per_device_empty_kp_hashes_writes_nothing() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-empty-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let welcome_bytes = vec![0xAA_u8; 256];
    let empty: Vec<KeyPackageHashEntry<'static>> = Vec::new();

    {
        let mut tx = pool.begin().await.expect("begin tx");
        store_welcomes_per_device_in_tx(
            &mut tx,
            &convo_id,
            &welcome_bytes,
            &empty,
            "did:plc:perdev0caller00000",
        )
        .await
        .expect("helper returned error on empty input — must be no-op Ok");
        tx.commit().await.expect("commit tx");
    }

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM welcome_messages WHERE convo_id = $1")
            .bind(&convo_id)
            .fetch_one(&pool)
            .await
            .expect("count welcome rows");
    assert_eq!(
        count, 0,
        "empty kp_hashes must produce zero welcome_messages rows"
    );

    common::cleanup(&pool, &convo_id).await;
}
