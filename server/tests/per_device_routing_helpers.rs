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
//!     `WHERE consumed = false`) ⇒ backfill a missing `recipient_device_id`
//!     while preserving a previously known device binding.
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
// Task 7 will introduce this symbol — see the per-device-members section
// at the bottom of this file. Today's import fails to compile (RED).
use catbird_server::db::insert_members_per_device_in_tx;
use catbird_server::generated::blue_catbird::mlsChat::bootstrap_reset_group::KeyPackageHashEntry;
use catbird_server::handlers::mls_chat::get_group_state::fetch_welcome_row_for_recipient;
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
fn make_kp_entry(did_str: &'static str, hash_hex: &'static str) -> KeyPackageHashEntry {
    KeyPackageHashEntry {
        did: string_to_did(did_str),
        hash: hash_hex.into(),
        extra_data: Default::default(),
    }
}

/// Seed a `users` row so the `key_packages.owner_did → users(did)` FK is
/// satisfied. Idempotent across reruns (same DID).
async fn seed_user(pool: &PgPool, did: &str) {
    sqlx::query("INSERT INTO users (did) VALUES ($1) ON CONFLICT (did) DO NOTHING")
        .bind(did)
        .execute(pool)
        .await
        .expect("seed users row");
}

/// Seed a `key_packages` row that the per-device-members helper will look up
/// via `(owner_did, key_package_hash)` to recover the device_id. `device_id`
/// may be `None` to exercise the user-flat fallback path.
///
/// Note: `key_packages.key_package_hash` is `TEXT` (the hex string), NOT
/// `BYTEA`. This is intentionally different from `welcome_messages.key_package_hash`
/// which IS `BYTEA`. Task 7's lookup query MUST bind the hex string directly
/// (i.e. `entry.hash`), not `hex::decode(&entry.hash)` — otherwise every
/// lookup silently misses and the helper falls into the user-flat fallback
/// path, which would make tests 1 and 3 fail with `device_id = NULL`.
async fn seed_key_package(pool: &PgPool, owner_did: &str, hash_hex: &str, device_id: Option<&str>) {
    seed_user(pool, owner_did).await;
    sqlx::query(
        "INSERT INTO key_packages \
            (id, owner_did, device_id, cipher_suite, key_package, key_package_hash, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW() + INTERVAL '30 days') \
         ON CONFLICT DO NOTHING",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(owner_did)
    .bind(device_id)
    .bind(CIPHER_SUITE)
    .bind::<&[u8]>(&[]) // dummy key_package bytes — content irrelevant to the lookup
    .bind(hash_hex)
    .execute(pool)
    .await
    .expect("seed key_packages row");
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
    let empty: Vec<KeyPackageHashEntry> = Vec::new();

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

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn store_welcomes_per_device_binds_recipient_device_id_from_key_package() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-welcome-device-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let alice_did = "did:plc:perdevwelcomedevice";
    seed_key_package(&pool, alice_did, "aa11", Some("alice-device-a")).await;
    seed_key_package(&pool, alice_did, "bb22", Some("alice-device-b")).await;

    let kp_hashes = vec![
        make_kp_entry(alice_did, "aa11"),
        make_kp_entry(alice_did, "bb22"),
    ];
    let welcome_bytes = vec![0xE1_u8; 256];

    {
        let mut tx = pool.begin().await.unwrap();
        store_welcomes_per_device_in_tx(
            &mut tx,
            &convo_id,
            &welcome_bytes,
            &kp_hashes,
            "did:plc:senderxxxxx",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let rows: Vec<(Option<String>, Vec<u8>)> = sqlx::query_as(
        "SELECT recipient_device_id, key_package_hash \
         FROM welcome_messages \
         WHERE convo_id = $1 AND recipient_did = $2 \
         ORDER BY recipient_device_id",
    )
    .bind(&convo_id)
    .bind(alice_did)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0.as_deref(), Some("alice-device-a"));
    assert_eq!(rows[0].1, hex::decode("aa11").unwrap());
    assert_eq!(rows[1].0.as_deref(), Some("alice-device-b"));
    assert_eq!(rows[1].1, hex::decode("bb22").unwrap());

    common::cleanup(&pool, &convo_id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn store_welcomes_per_device_leaves_recipient_device_id_null_when_hash_unmapped() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-welcome-device-null-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let alice_did = "did:plc:perdevwelcomenull";
    let kp_hashes = vec![make_kp_entry(alice_did, "cc33")];
    let welcome_bytes = vec![0xE2_u8; 256];

    {
        let mut tx = pool.begin().await.unwrap();
        store_welcomes_per_device_in_tx(
            &mut tx,
            &convo_id,
            &welcome_bytes,
            &kp_hashes,
            "did:plc:senderxxxxx",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let recipient_device_id: Option<String> = sqlx::query_scalar(
        "SELECT recipient_device_id \
         FROM welcome_messages \
         WHERE convo_id = $1 AND recipient_did = $2",
    )
    .bind(&convo_id)
    .bind(alice_did)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(
        recipient_device_id.is_none(),
        "unmapped legacy key package hashes must stay NULL and use read-side fallback"
    );

    common::cleanup(&pool, &convo_id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn store_welcomes_per_device_upsert_backfills_null_and_preserves_existing_device_id() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-welcome-upsert-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let alice_did = "did:plc:perdevwelcomeupsert";
    seed_key_package(&pool, alice_did, "aa11", Some("alice-device-a")).await;
    seed_key_package(&pool, alice_did, "bb22", Some("alice-device-b-resolved")).await;
    seed_key_package(&pool, alice_did, "cc33", Some("alice-device-c")).await;

    let welcome_existing_null = vec![0xA1_u8; 256];
    let welcome_existing_bound = vec![0xB2_u8; 256];
    let welcome_existing_creator_null = vec![0xC3_u8; 256];
    let old_sender = "did:plc:oldsenderxxx";
    sqlx::query(
        "INSERT INTO welcome_messages \
            (id, convo_id, recipient_did, recipient_device_id, welcome_data, key_package_hash, created_by_did, created_at, consumed) \
         VALUES \
            ($1, $2, $3, NULL, $4, $5, $9, NOW(), false), \
            ($6, $2, $3, 'alice-device-b-original', $7, $8, $9, NOW(), false), \
            ($10, $2, $3, NULL, $11, $12, NULL, NOW(), false)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&convo_id)
    .bind(alice_did)
    .bind(&welcome_existing_null)
    .bind(hex::decode("aa11").unwrap())
    .bind(Uuid::new_v4().to_string())
    .bind(&welcome_existing_bound)
    .bind(hex::decode("bb22").unwrap())
    .bind(old_sender)
    .bind(Uuid::new_v4().to_string())
    .bind(&welcome_existing_creator_null)
    .bind(hex::decode("cc33").unwrap())
    .execute(&pool)
    .await
    .unwrap();

    let kp_hashes = vec![
        make_kp_entry(alice_did, "aa11"),
        make_kp_entry(alice_did, "bb22"),
        make_kp_entry(alice_did, "cc33"),
    ];
    let welcome_bytes = vec![0xE3_u8; 256];

    {
        let mut tx = pool.begin().await.unwrap();
        store_welcomes_per_device_in_tx(
            &mut tx,
            &convo_id,
            &welcome_bytes,
            &kp_hashes,
            "did:plc:newsenderxxx",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    type WelcomeRow = (String, Option<String>, Vec<u8>, Option<String>);
    let rows: Vec<WelcomeRow> = sqlx::query_as(
        "SELECT encode(key_package_hash, 'hex'), recipient_device_id, welcome_data, created_by_did \
         FROM welcome_messages \
         WHERE convo_id = $1 AND recipient_did = $2 \
         ORDER BY encode(key_package_hash, 'hex')",
    )
    .bind(&convo_id)
    .bind(alice_did)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].0, "aa11");
    assert_eq!(rows[0].1.as_deref(), Some("alice-device-a"));
    assert_eq!(
        rows[0].2, welcome_existing_null,
        "conflict updates must preserve existing Welcome bytes"
    );
    assert_eq!(
        rows[0].3.as_deref(),
        Some(old_sender),
        "conflict updates must not replace existing created_by_did while preserving Welcome bytes"
    );
    assert_eq!(rows[1].0, "bb22");
    assert_eq!(
        rows[1].1.as_deref(),
        Some("alice-device-b-original"),
        "conflict updates must not replace an existing recipient_device_id"
    );
    assert_eq!(
        rows[1].2, welcome_existing_bound,
        "conflict updates must preserve existing Welcome bytes"
    );
    assert_eq!(
        rows[1].3.as_deref(),
        Some(old_sender),
        "conflict updates must not replace existing created_by_did while preserving Welcome bytes"
    );
    assert_eq!(rows[2].0, "cc33");
    assert_eq!(rows[2].1.as_deref(), Some("alice-device-c"));
    assert_eq!(
        rows[2].2, welcome_existing_creator_null,
        "conflict updates must preserve existing Welcome bytes when created_by_did is NULL"
    );
    assert!(
        rows[2].3.is_none(),
        "conflict updates must preserve NULL created_by_did instead of backfilling the new sender"
    );

    common::cleanup(&pool, &convo_id).await;
}

// ═════════════════════════════════════════════════════════════════════════════
//
//                  insert_members_per_device_in_tx — RED
//
// Task 7 will introduce this helper. Today's import at the top of this file
// fails to compile, which is the RED state.
//
// Helper signature Task 7 will land:
//
// ```ignore
// pub async fn insert_members_per_device_in_tx<'a>(
//     tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
//     convo_id: &str,
//     kp_hashes: &[KeyPackageHashEntry<'a>],
//     joined_at: chrono::DateTime<chrono::Utc>,
//     is_admin: bool,
// ) -> sqlx::Result<()>
// ```
//
// Behavior:
//   - For each `KeyPackageHashEntry`:
//       1. `user_did = did_to_string(&entry.did)` (jacquard `Did` rejects `#`,
//          so this is the bare-form user DID).
//       2. `hash_bytes = hex::decode(&entry.hash)`. On error, `continue`
//          (defensive skip — same pattern as the welcomes helper).
//       3. Lookup `device_id` via
//          `SELECT device_id FROM key_packages WHERE owner_did = $1 AND key_package_hash = $2`.
//          IMPORTANT: `key_packages.key_package_hash` is `TEXT` (hex string),
//          so the second bind MUST be `&entry.hash` (the hex string), NOT
//          `hash_bytes` (the decoded BYTEA). The decoded form is for
//          `welcome_messages.key_package_hash` when writing welcome rows.
//       4. If `device_id = Some(d)`: `member_did = format!("{}#{}", user_did, d)`,
//          store with `device_id = Some(d)`. Note: `members.member_did` is
//          plain TEXT — we deliberately bypass jacquard's `#`-rejection by
//          building the string here and storing it as TEXT.
//       5. If `device_id = None` (kp_hash not in table OR null device_id):
//          fall back to user-flat — `member_did = user_did`, `device_id = NULL`.
//          This preserves the legacy behavior of the inline addMembers loop
//          at `commit_group_change.rs:595-616`.
//       6. INSERT into `members (convo_id, member_did, user_did, device_id, joined_at, is_admin)`
//          with ON CONFLICT (convo_id, member_did) DO UPDATE SET
//          left_at = NULL, needs_rejoin = false (mirrors the existing re-add
//          pattern in addMembers).
//   - Empty `kp_hashes` slice ⇒ no-op return Ok(()).
//
// ═════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// Test 4 — happy path: per-device member rows when device_id is known
// ─────────────────────────────────────────────────────────────────────────────

/// `insert_members_per_device_in_tx` MUST insert one row per
/// `KeyPackageHashEntry` into `members`, with each row carrying a
/// `member_did` of the form `"{user_did}#{device_id}"`, the bare `user_did`
/// in the `user_did` column, and the looked-up `device_id` populated. This
/// is the per-device routing contract: each device has a unique MLS leaf,
/// each leaf gets its own row, and SSE/push fan-out can target devices
/// individually instead of flooding every active session for a given user.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL); RED until Task 7 lands the helper"]
async fn insert_members_per_device_writes_one_row_per_kp_hash_with_device_id() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-mem-1-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    // Bare-form DIDs (jacquard-valid). Per-test unique prefixes bound the
    // blast radius of accumulated key_packages rows across reruns —
    // there's no UNIQUE constraint on (owner_did, key_package_hash), so
    // distinct DID prefixes per test prevent cross-test contamination.
    let alice_did = "did:plc:perdev1aliceaaa";
    let bob_did = "did:plc:perdev1bobbbbbbb";

    // Three "devices" — Alice on devices a + b, Bob on device x.
    let alice_a_hash_hex = "aa11";
    let alice_b_hash_hex = "bb22";
    let bob_a_hash_hex = "cc33";

    seed_key_package(&pool, alice_did, alice_a_hash_hex, Some("device-a")).await;
    seed_key_package(&pool, alice_did, alice_b_hash_hex, Some("device-b")).await;
    seed_key_package(&pool, bob_did, bob_a_hash_hex, Some("device-x")).await;

    let kp_hashes = vec![
        make_kp_entry(alice_did, alice_a_hash_hex),
        make_kp_entry(alice_did, alice_b_hash_hex),
        make_kp_entry(bob_did, bob_a_hash_hex),
    ];

    {
        let mut tx = pool.begin().await.expect("begin tx");
        insert_members_per_device_in_tx(&mut tx, &convo_id, &kp_hashes, Utc::now(), false)
            .await
            .expect("helper returned error");
        tx.commit().await.expect("commit tx");
    }

    let rows = sqlx::query(
        "SELECT member_did, user_did, device_id, is_admin, left_at, needs_rejoin \
         FROM members \
         WHERE convo_id = $1 \
         ORDER BY member_did",
    )
    .bind(&convo_id)
    .fetch_all(&pool)
    .await
    .expect("fetch members rows");

    assert_eq!(rows.len(), 3, "expected one row per kp_hash entry");

    // Row 0: alice#device-a (sorts before alice#device-b lexicographically)
    let r0_member: String = rows[0].get("member_did");
    let r0_user: Option<String> = rows[0].get("user_did");
    let r0_device: Option<String> = rows[0].get("device_id");
    let r0_admin: bool = rows[0].get("is_admin");
    let r0_left: Option<chrono::DateTime<Utc>> = rows[0].get("left_at");
    let r0_rejoin: bool = rows[0].get("needs_rejoin");
    assert_eq!(
        r0_member,
        format!("{}#{}", alice_did, "device-a"),
        "member_did must be {{user_did}}#{{device_id}}"
    );
    assert_eq!(r0_user, Some(alice_did.to_string()));
    assert_eq!(r0_device, Some("device-a".to_string()));
    assert!(!r0_admin, "is_admin must be false (input)");
    assert!(r0_left.is_none(), "fresh row left_at NULL");
    assert!(!r0_rejoin, "fresh row needs_rejoin false");

    // Row 1: alice#device-b
    let r1_member: String = rows[1].get("member_did");
    let r1_user: Option<String> = rows[1].get("user_did");
    let r1_device: Option<String> = rows[1].get("device_id");
    assert_eq!(r1_member, format!("{}#{}", alice_did, "device-b"));
    assert_eq!(r1_user, Some(alice_did.to_string()));
    assert_eq!(r1_device, Some("device-b".to_string()));

    // Row 2: bob#device-x
    let r2_member: String = rows[2].get("member_did");
    let r2_user: Option<String> = rows[2].get("user_did");
    let r2_device: Option<String> = rows[2].get("device_id");
    assert_eq!(r2_member, format!("{}#{}", bob_did, "device-x"));
    assert_eq!(r2_user, Some(bob_did.to_string()));
    assert_eq!(r2_device, Some("device-x".to_string()));

    common::cleanup(&pool, &convo_id).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5 — fallback: user-flat row when device_id can't be resolved
// ─────────────────────────────────────────────────────────────────────────────

/// When a `KeyPackageHashEntry`'s `(owner_did, key_package_hash)` does NOT
/// match a `key_packages` row (legacy clients without device_id, or the
/// kp_hash isn't in the table), the helper MUST fall back to user-flat
/// semantics: `member_did = user_did`, `device_id = NULL`. This preserves
/// the existing inline addMembers behavior at `commit_group_change.rs:595-616`,
/// where the bare user DID is used both as `member_did` and `user_did`.
///
/// Without this fallback, legacy clients would simply not appear in the
/// roster — a regression. The fallback path is the migration safety net.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL); RED until Task 7 lands the helper"]
async fn insert_members_per_device_falls_back_to_user_flat_when_device_id_missing() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-mem-2-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let alice_did = "did:plc:perdev2alicedddd";

    // Deliberately do NOT seed key_packages — the helper's lookup MUST miss
    // and the fallback path MUST run. (We could alternatively seed with
    // device_id = NULL; the contract is the same either way.)
    let kp_hashes = vec![make_kp_entry(alice_did, "ddee")];

    {
        let mut tx = pool.begin().await.expect("begin tx");
        insert_members_per_device_in_tx(&mut tx, &convo_id, &kp_hashes, Utc::now(), false)
            .await
            .expect("helper returned error");
        tx.commit().await.expect("commit tx");
    }

    let row =
        sqlx::query("SELECT member_did, user_did, device_id FROM members WHERE convo_id = $1")
            .bind(&convo_id)
            .fetch_one(&pool)
            .await
            .expect("fetch members row");

    let member: String = row.get("member_did");
    let user: Option<String> = row.get("user_did");
    let device: Option<String> = row.get("device_id");

    assert_eq!(
        member, alice_did,
        "fallback MUST use the bare user-form DID as member_did"
    );
    assert_eq!(
        user,
        Some(alice_did.to_string()),
        "user_did mirrors member_did in fallback (legacy parity)"
    );
    assert_eq!(
        device, None,
        "fallback MUST leave device_id NULL — there's no device to record"
    );

    common::cleanup(&pool, &convo_id).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6 — re-add: ON CONFLICT clears `left_at` and `needs_rejoin`
// ─────────────────────────────────────────────────────────────────────────────

/// `insert_members_per_device_in_tx` MUST mirror the inline addMembers
/// re-add behavior from `commit_group_change.rs:597-616`: ON CONFLICT
/// `(convo_id, member_did)` DO UPDATE SET `left_at = NULL,
/// needs_rejoin = false`. This is what makes "rejoin a group I previously
/// left" idempotent — the second commit doesn't blow up on a primary-key
/// violation, and the device row is reactivated rather than duplicated.
///
/// Without this clause, post-leave rejoins would error and the user would
/// be stranded outside the group despite a valid Welcome.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL); RED until Task 7 lands the helper"]
async fn insert_members_per_device_re_add_clears_left_at() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-mem-3-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let alice_did = "did:plc:perdev3alicefffff";
    let hash_hex = "eeff";
    seed_key_package(&pool, alice_did, hash_hex, Some("device-r")).await;

    let kp_hashes = vec![make_kp_entry(alice_did, hash_hex)];

    // First add — establishes the device row.
    {
        let mut tx = pool.begin().await.expect("begin tx");
        insert_members_per_device_in_tx(&mut tx, &convo_id, &kp_hashes, Utc::now(), false)
            .await
            .expect("first insert returned error");
        tx.commit().await.expect("commit first tx");
    }

    // Simulate the user leaving and being marked for rejoin.
    sqlx::query(
        "UPDATE members SET left_at = NOW(), needs_rejoin = true \
         WHERE convo_id = $1 AND member_did = $2",
    )
    .bind(&convo_id)
    .bind(format!("{}#{}", alice_did, "device-r"))
    .execute(&pool)
    .await
    .expect("mark left/rejoin");

    // Sanity: assert the simulated-leave UPDATE actually took effect, so
    // the post-re-add assertion can't pass vacuously.
    let pre = sqlx::query("SELECT left_at, needs_rejoin FROM members WHERE convo_id = $1")
        .bind(&convo_id)
        .fetch_one(&pool)
        .await
        .expect("pre-readback");
    let pre_left: Option<chrono::DateTime<Utc>> = pre.get("left_at");
    let pre_rejoin: bool = pre.get("needs_rejoin");
    assert!(
        pre_left.is_some(),
        "sanity: simulated-leave must populate left_at"
    );
    assert!(pre_rejoin, "sanity: simulated-leave must set needs_rejoin");

    // Re-add with the same kp_hashes — ON CONFLICT path.
    {
        let mut tx = pool.begin().await.expect("begin tx");
        insert_members_per_device_in_tx(&mut tx, &convo_id, &kp_hashes, Utc::now(), false)
            .await
            .expect("re-add returned error");
        tx.commit().await.expect("commit re-add tx");
    }

    let row = sqlx::query("SELECT left_at, needs_rejoin FROM members WHERE convo_id = $1")
        .bind(&convo_id)
        .fetch_one(&pool)
        .await
        .expect("post-readback");
    let left: Option<chrono::DateTime<Utc>> = row.get("left_at");
    let rejoin: bool = row.get("needs_rejoin");
    assert!(
        left.is_none(),
        "re-add MUST clear left_at via ON CONFLICT DO UPDATE"
    );
    assert!(
        !rejoin,
        "re-add MUST clear needs_rejoin via ON CONFLICT DO UPDATE"
    );

    common::cleanup(&pool, &convo_id).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7 — empty kp_hashes is a no-op
// ─────────────────────────────────────────────────────────────────────────────

/// Empty `kp_hashes` slice ⇒ helper writes nothing and returns Ok. Mirrors
/// the welcomes helper's empty-input contract: a commit with zero
/// new-member proposals must NOT manufacture phantom roster rows. This
/// matters because `commit_group_change` calls the per-device helpers
/// unconditionally on the addMembers path; the no-op-on-empty contract is
/// what lets the caller skip the kp_hashes-presence guard at the call site.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL); RED until Task 7 lands the helper"]
async fn insert_members_per_device_empty_kp_hashes_writes_nothing() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-mem-4-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let empty: Vec<KeyPackageHashEntry> = Vec::new();

    {
        let mut tx = pool.begin().await.expect("begin tx");
        insert_members_per_device_in_tx(&mut tx, &convo_id, &empty, Utc::now(), false)
            .await
            .expect("helper returned error on empty input — must be no-op Ok");
        tx.commit().await.expect("commit tx");
    }

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM members WHERE convo_id = $1")
        .bind(&convo_id)
        .fetch_one(&pool)
        .await
        .expect("count members rows");
    assert_eq!(count, 0, "empty kp_hashes MUST produce zero members rows");

    common::cleanup(&pool, &convo_id).await;
}

// ═════════════════════════════════════════════════════════════════════════════
//
//                Phase D / Task 9 — get_group_state lookup parity
//
// Verifies that the existing welcome lookup in
// `server/src/handlers/mls_chat/get_group_state.rs` works against
// the legacy per-device storage shape Phase B writes (user-form `recipient_did`,
// `key_package_hash` as the legacy discriminator, identical
// `welcome_data` across N rows per (convo, user)).
//
// Architectural correction recap: Task 2 found jacquard's `Did<'a>` regex
// rejects `#`, so we cannot use device-form (`did:plc:user#device-x`) as
// the `recipient_did`. Phase B stores user-form (`entry.did`) instead and
// legacy rows can still be distinguished via `key_package_hash`. The MLS Welcome
// bytes are themselves multi-recipient — each device decrypts its own
// `EncryptedGroupSecrets` entry locally — so identical `welcome_data`
// across N rows is correct, and the existing `LIMIT 1` lookup returning
// ANY of those rows yields the right bytes for the calling device.
//
// Caveat: per the workspace's earlier verification (commit fddf62b),
// `auth_user.did` may currently be device-form INDIRECT for getGroupState
// callers. If that's the case, the production query's user-form bind
// would NOT match. This test still confirms the storage→query path works
// for user-form binding (the contract this plan establishes), so any
// future change that breaks user-form lookup will fail this test.
//
// ═════════════════════════════════════════════════════════════════════════════

/// Asserts that per-device welcomes (multiple rows for the same
/// `recipient_did = user_did`, distinct `key_package_hash`) are findable
/// by the legacy lookup path used in `get_group_state.rs`. Locks
/// in the contract: future schema or handler changes that break user-form
/// lookup will fail this test instead of silently returning no welcomes.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn per_device_welcome_findable_by_user_form_did() {
    // Verifies get_group_state.rs:375-392's existing query shape returns
    // a row when the welcome was stored per-device (multiple rows with
    // same user-form recipient_did, distinct key_package_hash).
    //
    // The MLS Welcome bytes are multi-recipient; LIMIT 1 returning ANY
    // of alice's rows is correct because each device decrypts its own
    // EncryptedGroupSecrets entry locally.
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-lookup-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let alice_did = "did:plc:perdevlookup1aaa";
    let kp_hashes = vec![
        make_kp_entry(alice_did, "aa11"),
        make_kp_entry(alice_did, "bb22"),
    ];

    let welcome_bytes = vec![0xCC_u8; 256];

    {
        let mut tx = pool.begin().await.unwrap();
        store_welcomes_per_device_in_tx(
            &mut tx,
            &convo_id,
            &welcome_bytes,
            &kp_hashes,
            "did:plc:senderxxxxx",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    // Mirror get_group_state.rs:375-378's exact query shape.
    let row: Option<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, welcome_data FROM welcome_messages \
         WHERE convo_id = $1 AND recipient_did = $2 AND consumed = false \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&convo_id)
    .bind(alice_did) // user-form auth_user.did
    .fetch_optional(&pool)
    .await
    .unwrap();

    let (welcome_id, body) = row.expect("welcome should be findable by user-form recipient_did");
    assert_eq!(
        body, welcome_bytes,
        "welcome_data should match what we stored"
    );
    assert!(!welcome_id.is_empty());

    // Sanity check: there are 2 rows, but LIMIT 1 returned one.
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM welcome_messages WHERE convo_id = $1 AND recipient_did = $2",
    )
    .bind(&convo_id)
    .bind(alice_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(total, 2, "per-device storage should have written 2 rows");

    common::cleanup(&pool, &convo_id).await;
}

/// Companion to `per_device_welcome_findable_by_user_form_did`. Asserts the
/// C1 fix in `get_group_state.rs:373-411`: when `auth_user.did` arrives as
/// device-form (e.g. `did:plc:alice#deviceA`) but the welcome was stored
/// with user-form `recipient_did` (which Phase B always does — jacquard's
/// `Did<'a>` regex rejects '#'), the OR-clause on both forms in the
/// retrieval SELECT MUST find the row.
///
/// Exercise: this test FAILS (returns None) without the OR-clause, and
/// PASSES with it. The negative-control branch below confirms that
/// device-form alone (single bind, no OR) misses — locking in the
/// "OR-clause is what rescues device-form callers" contract.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn per_device_welcome_findable_by_device_form_did() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-devform-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    // user-form for storage (recipient_did goes in user-form per Phase B)
    let alice_did_user = "did:plc:perdevdevform1aaa";
    // device-form is what the C1 site MAY receive as `auth_user.did`
    let alice_did_device = format!("{}#deviceA", alice_did_user);

    // Single per-device row stored with user-form recipient_did.
    let kp_hashes = vec![make_kp_entry(alice_did_user, "aa11")];
    let welcome_bytes = vec![0xCC_u8; 256];

    {
        let mut tx = pool.begin().await.unwrap();
        store_welcomes_per_device_in_tx(
            &mut tx,
            &convo_id,
            &welcome_bytes,
            &kp_hashes,
            "did:plc:senderxxxxx",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    // ── Positive case: mirror the FIXED get_group_state SQL (OR on both forms). ──
    let user_form: String = match alice_did_device.split_once('#') {
        Some((u, _)) => u.to_string(),
        None => alice_did_device.clone(),
    };

    let row: Option<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, welcome_data FROM welcome_messages \
         WHERE convo_id = $1 \
           AND (recipient_did = $2 OR recipient_did = $3) \
           AND consumed = false \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&convo_id)
    .bind(&alice_did_device)
    .bind(&user_form)
    .fetch_optional(&pool)
    .await
    .unwrap();

    let (welcome_id, body) =
        row.expect("device-form auth_user.did MUST find user-form recipient_did via OR-clause");
    assert_eq!(
        body, welcome_bytes,
        "welcome_data must match what we stored"
    );
    assert!(!welcome_id.is_empty());

    // ── Negative control: pre-fix SQL (single bind on device-form only). ──
    // This must MISS, proving the OR-clause is load-bearing — without the
    // user-form leg, the lookup returns None for device-form callers.
    let pre_fix_row: Option<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, welcome_data FROM welcome_messages \
         WHERE convo_id = $1 AND recipient_did = $2 AND consumed = false \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&convo_id)
    .bind(&alice_did_device)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(
        pre_fix_row.is_none(),
        "negative control: device-form-only bind MUST miss user-form-stored welcomes \
         (this is the bug the OR-clause fixes)"
    );

    common::cleanup(&pool, &convo_id).await;
}

/// Regression for the production shape from 2026-06-18: iOS omitted a large
/// local key-package hash manifest and supplied only `deviceId`. If the
/// selected Welcome row's key_package_hash cannot be joined back to the
/// current device_id (stale/null device metadata), getGroupState must still
/// return the sole unconsumed Welcome for the authenticated DID instead of
/// hiding it behind a device metadata miss.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn device_hint_miss_returns_sole_user_welcome() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-devicehint-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let alice_did = "did:plc:perdevdevicehint1";
    let kp_hashes = vec![make_kp_entry(alice_did, "aa11")];
    let welcome_bytes = vec![0xDD_u8; 256];

    {
        let mut tx = pool.begin().await.unwrap();
        store_welcomes_per_device_in_tx(
            &mut tx,
            &convo_id,
            &welcome_bytes,
            &kp_hashes,
            "did:plc:senderxxxxx",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let row = fetch_welcome_row_for_recipient(
        &pool,
        &convo_id,
        alice_did,
        alice_did,
        None,
        &["current-device".to_string()],
    )
    .await
    .expect("welcome lookup should not error")
    .expect("sole user welcome should survive a device metadata miss");

    assert_eq!(row.1, welcome_bytes);

    common::cleanup(&pool, &convo_id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn device_hint_returns_exact_recipient_device_id_when_multiple_user_welcomes_exist() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-devicehint-exact-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let alice_did = "did:plc:perdevdeviceexact";
    seed_user(&pool, alice_did).await;
    let welcome_a = vec![0xA1_u8; 256];
    let welcome_b = vec![0xB2_u8; 256];

    sqlx::query(
        "INSERT INTO welcome_messages \
            (id, convo_id, recipient_did, recipient_device_id, welcome_data, key_package_hash, created_by_did, created_at, consumed) \
         VALUES \
            ($1, $2, $3, 'device-a', $4, $5, 'did:plc:senderxxxxx', NOW(), false), \
            ($6, $2, $3, 'device-b', $7, $8, 'did:plc:senderxxxxx', NOW(), false)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&convo_id)
    .bind(alice_did)
    .bind(&welcome_a)
    .bind(hex::decode("aa11").unwrap())
    .bind(Uuid::new_v4().to_string())
    .bind(&welcome_b)
    .bind(hex::decode("bb22").unwrap())
    .execute(&pool)
    .await
    .unwrap();

    let row = fetch_welcome_row_for_recipient(
        &pool,
        &convo_id,
        alice_did,
        alice_did,
        None,
        &["device-b".to_string()],
    )
    .await
    .expect("welcome lookup should not error")
    .expect("device-bound welcome should be returned");

    assert_eq!(row.1, welcome_b);

    common::cleanup(&pool, &convo_id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn device_hint_miss_does_not_return_other_device_bound_welcome() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-devicehint-wrong-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let alice_did = "did:plc:perdevdevicewrong";
    seed_user(&pool, alice_did).await;
    let welcome_a = vec![0xC3_u8; 256];

    sqlx::query(
        "INSERT INTO welcome_messages \
            (id, convo_id, recipient_did, recipient_device_id, welcome_data, key_package_hash, created_by_did, created_at, consumed) \
         VALUES \
            ($1, $2, $3, 'device-a', $4, $5, 'did:plc:senderxxxxx', NOW(), false)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&convo_id)
    .bind(alice_did)
    .bind(&welcome_a)
    .bind(hex::decode("aa11").unwrap())
    .execute(&pool)
    .await
    .unwrap();

    let row = fetch_welcome_row_for_recipient(
        &pool,
        &convo_id,
        alice_did,
        alice_did,
        None,
        &["device-b".to_string()],
    )
    .await
    .expect("welcome lookup should not error");

    assert!(
        row.is_none(),
        "device-hinted lookup must not fall back to a welcome bound to another device"
    );

    common::cleanup(&pool, &convo_id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn device_hint_with_hash_returns_stale_device_bound_welcome() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-devicehint-hash-wrong-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let alice_did = "did:plc:perdevdevicehashwrong";
    seed_user(&pool, alice_did).await;
    let welcome_a = vec![0xE5_u8; 256];

    sqlx::query(
        "INSERT INTO welcome_messages \
            (id, convo_id, recipient_did, recipient_device_id, welcome_data, key_package_hash, created_by_did, created_at, consumed) \
         VALUES \
            ($1, $2, $3, 'device-a', $4, $5, 'did:plc:senderxxxxx', NOW(), false)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&convo_id)
    .bind(alice_did)
    .bind(&welcome_a)
    .bind(hex::decode("aa11").unwrap())
    .execute(&pool)
    .await
    .unwrap();

    let requested_hashes = vec![hex::decode("aa11").unwrap()];
    let row = fetch_welcome_row_for_recipient(
        &pool,
        &convo_id,
        alice_did,
        alice_did,
        Some(requested_hashes.as_slice()),
        &["device-b".to_string()],
    )
    .await
    .expect("welcome lookup should not error");

    assert!(
        row.is_some(),
        "hash-matched lookup proves local key-package ownership and must survive a stale device hint"
    );
    assert_eq!(row.unwrap().1, welcome_a);

    common::cleanup(&pool, &convo_id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn device_hint_miss_does_not_return_other_device_bound_null_hash_welcome() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-perdev-devicehint-nullhash-{}", Uuid::new_v4());
    common::cleanup(&pool, &convo_id).await;
    seed_convo(&pool, &convo_id).await;

    let alice_did = "did:plc:perdevdevicenullhash";
    seed_user(&pool, alice_did).await;
    let welcome_a = vec![0xD4_u8; 256];

    sqlx::query(
        "INSERT INTO welcome_messages \
            (id, convo_id, recipient_did, recipient_device_id, welcome_data, key_package_hash, created_by_did, created_at, consumed) \
         VALUES \
            ($1, $2, $3, 'device-a', $4, NULL, 'did:plc:senderxxxxx', NOW(), false)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&convo_id)
    .bind(alice_did)
    .bind(&welcome_a)
    .execute(&pool)
    .await
    .unwrap();

    let row = fetch_welcome_row_for_recipient(
        &pool,
        &convo_id,
        alice_did,
        alice_did,
        None,
        &["device-b".to_string()],
    )
    .await
    .expect("welcome lookup should not error");

    assert!(
        row.is_none(),
        "legacy lookup must not return a null-hash welcome bound to another device"
    );

    common::cleanup(&pool, &convo_id).await;
}
