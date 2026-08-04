mod common;

use catbird_server::db::*;
use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;

/// Reserved per-run database prefix owned by this target.
const DB_TESTS_DB_PREFIX: &str = "mlsds_dbtests_";

/// Mint a private, freshly migrated database for one test case.
///
/// This used to connect to whatever `TEST_DATABASE_URL` named — the one
/// database every concurrent task in this program shares — and every test then
/// called `cleanup_test_data`, which `TRUNCATE`d `messages, members,
/// conversations, key_packages CASCADE` in that shared database. Worse,
/// `init_db` runs the *whole* migration set, so pointing this target at the
/// shared clean-chat database also rewrote its `_sqlx_migrations` ledger. Both
/// are cross-task destruction, not isolation.
///
/// The returned [`DisposableDatabase`] must stay bound for the whole test: it
/// reaps its database on drop, on the normal path and during panic unwind.
async fn setup_test_db() -> (PgPool, common::fresh_db::DisposableDatabase) {
    let database = common::fresh_db::fresh_fully_migrated_db(DB_TESTS_DB_PREFIX).await;

    let config = DbConfig {
        database_url: database.url().to_owned(),
        max_connections: 10,
        min_connections: 2,
        acquire_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(600),
    };

    let pool = init_db(config)
        .await
        .expect("Failed to initialize test database");
    (pool, database)
}

/// The fixture model of this file used to be a DB-global reset: every test
/// began by TRUNCATE-ing shared tables, which made the tests mutually exclusive
/// by construction (this is the "shared IDs" fixture rot that kept the file
/// `#[ignore]`d). Each test now owns a private database, so the fixtures no
/// longer collide at all. The lock is retained as a *resource* bound: each test
/// runs the full migration set against a new database, and letting eleven of
/// those run concurrently multiplies both connection count and migration cost
/// with no correctness benefit.
static DB_FIXTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The disposable-database name guard is the backstop that makes "reset the
/// shared database" unrepresentable rather than merely unused. These cases live
/// in this target (rather than beside the guard in `tests/common/fresh_db.rs`)
/// because `tests/common/` is compiled into ~20 integration targets and adding
/// tests there would change the reported test counts of targets whose counts
/// are pinned by this program's gate reports.
///
/// Each case names the input that makes the guard fail. Together with
/// `disposable_name_guard_accepts_a_minted_name`, the guard is proven
/// falsifiable in both directions.
#[test]
fn disposable_name_guard_refuses_the_shared_chat_protocol_database() {
    let error =
        common::fresh_db::validate_disposable_database_name("catbird_chat_protocol_test_20260722")
            .expect_err("the shared clean-chat database must never be disposable");
    assert!(error.contains("protected"), "unexpected refusal: {error}");
}

#[test]
fn disposable_name_guard_refuses_protected_names_and_unreserved_prefixes() {
    for (name, expected) in [
        ("catbird", "protected"),
        ("catbird_test", "protected"),
        ("postgres", "protected"),
        ("template1", "protected"),
        // The executor harness's own namespace is not ours to reap: the 73
        // leaked `chat_exec_*` databases on this host belong to someone else.
        (
            "chat_exec_07622ab680c14b53b8434da37765a381",
            "reserved prefix",
        ),
        (
            "scratch_0123456789abcdef0123456789abcdef",
            "reserved prefix",
        ),
    ] {
        let error = common::fresh_db::validate_disposable_database_name(name)
            .expect_err("name was accepted as disposable");
        assert!(
            error.contains(expected),
            "{name}: expected {expected:?} refusal, got {error}"
        );
    }
}

#[test]
fn disposable_name_guard_requires_a_32_lowercase_hex_suffix() {
    for name in [
        "mlsds_dbtests_short",
        "mlsds_dbtests_",
        "mlsds_dbtests_0123456789abcdef0123456789abcdefff",
        "mlsds_dbtests_0123456789abcdef0123456789abcdeg",
        "mlsds_dbtests_0123456789ABCDEF0123456789abcdef",
    ] {
        assert!(
            common::fresh_db::validate_disposable_database_name(name).is_err(),
            "{name} was accepted as disposable"
        );
    }
}

#[test]
fn disposable_name_guard_accepts_a_minted_name() {
    for prefix in common::fresh_db::DISPOSABLE_PREFIXES {
        let name = format!("{prefix}{}", uuid::Uuid::new_v4().simple());
        common::fresh_db::validate_disposable_database_name(&name)
            .unwrap_or_else(|error| panic!("minted {name} was refused: {error}"));
    }
    assert!(
        common::fresh_db::validate_disposable_prefix("chat_exec_").is_err(),
        "an unreserved prefix must not be mintable"
    );
    common::fresh_db::validate_disposable_prefix(DB_TESTS_DB_PREFIX)
        .expect("this target's own prefix must be mintable");
}

/// Every `.rs` file under `server/tests`, recursively, paired with its source.
///
/// Used by the source-authority guards below. Panics rather than returning an
/// empty vector if the directory cannot be walked, because a guard that silently
/// sweeps nothing proves nothing.
fn integration_test_sources() -> Vec<(String, String)> {
    fn walk(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(path).expect("read integration-test source directory") {
            let path = entry.expect("read integration-test source entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(
        files.len() > 50,
        "integration-test sweep found only {} files — the corpus is not being walked",
        files.len()
    );
    files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&root)
                .expect("test source under tests/")
                .to_string_lossy()
                .into_owned();
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", relative));
            (relative, source)
        })
        .collect()
}

/// True for a line that is entirely a `//`, `///` or `//!` comment.
///
/// Deliberately does not model block comments: there are none carrying a
/// connection literal in this corpus, and a guard that guessed at `/* … */`
/// nesting would be less trustworthy than one that over-reports.
fn is_line_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

/// `db::init_db` runs `sqlx::migrate!("./migrations")` against whatever URL it
/// is handed. That is the mechanism that took the shared clean-chat database's
/// `_sqlx_migrations` ledger from the reviewed 13 to 69 — silently, while the
/// calling target passed — and it is reachable from any test that reads an
/// ambient environment variable.
///
/// Converting the twenty-one targets that did so removes the *instances*. This
/// guard removes the *class*: a new caller must come here and justify itself,
/// and the reviewed callers must keep minting their own database.
///
/// Falsifying inputs:
/// * a new `server/tests/**.rs` file calling `init_db(` → set mismatch, the
///   offending path is named in the message;
/// * an approved caller dropping its `fresh_db` mint → second assertion;
/// * this guard silently sweeping nothing → the corpus assertion in
///   [`integration_test_sources`].
#[test]
fn init_db_is_only_reachable_from_targets_that_mint_their_own_database() {
    // Assembled at runtime so this guard's own source does not match itself.
    let init_db_call = ["init_db", "("].concat();
    let mint_needle = ["fresh_db", "::"].concat();

    /// Files allowed to call `init_db`, each of which must mint the database it
    /// passes. `common/fresh_db.rs` is the harness itself.
    const APPROVED_INIT_DB_CALLERS: &[&str] = &[
        "common/fresh_db.rs",
        "db_tests.rs",
        "federation_hostile_peers.rs",
        "migration_repair_smoke.rs",
    ];

    let mut callers: Vec<String> = Vec::new();
    for (relative, source) in integration_test_sources() {
        let calls = source
            .lines()
            .any(|line| !is_line_comment(line) && line.contains(&init_db_call));
        if calls {
            let mints = source
                .lines()
                .any(|line| !is_line_comment(line) && line.contains(&mint_needle));
            assert!(
                mints || relative == "common/fresh_db.rs",
                "{relative} calls init_db without minting a disposable database"
            );
            callers.push(relative);
        }
    }
    callers.sort();
    let mut approved: Vec<String> = APPROVED_INIT_DB_CALLERS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    approved.sort();
    assert_eq!(
        callers, approved,
        "unreviewed init_db caller under server/tests — it will migrate whatever \
         TEST_DATABASE_URL names. Mint a disposable database via common::fresh_db instead."
    );
}

/// The silent-default-database-name defect, in its exact source shape:
///
/// ```ignore
/// let url = std::env::var("TEST_DATABASE_URL")
///     .unwrap_or_else(|_| "postgres://localhost/catbird_test".to_string());
/// ```
///
/// A test written this way adopts, migrates and mutates whatever database
/// answers to that name, and it does so *most* eagerly in the environment where
/// nobody set the variable. This is how `db_tests::test_health_check` escaped
/// its `#[ignore]` tag, and twenty-one targets carried the same fallback until
/// this task removed it — three of them not `#[ignore]`d at all.
///
/// The guard targets the fallback specifically rather than every connection
/// literal, because bare literals in this corpus are legitimate: negative
/// inputs proving `validate_chat_protocol_database_url` rejects them, and
/// `connect_lazy` targets that exist to prove a router never connects. Corpus
/// of that classification: every line under `server/tests` whose trimmed start
/// is not `//` and that contains a connection literal, counted by
/// `literal_sites` below. The count is derived from the current source corpus
/// rather than maintained as a prose inventory; the positive control requires
/// at least ten sites.
///
/// Falsifying input: restore any removed fallback — e.g. put
/// `std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| "postgres://…")`
/// back into any test — and the file and line are named in the failure.
#[test]
fn no_test_source_defaults_a_database_connection_to_a_hardcoded_name() {
    // BOTH schemes. `postgresql://` does not contain `postgres://`, and every
    // fallback this task removed used the longer form — a needle of only
    // `postgres://` makes this guard unable to fail, which is exactly what a
    // mutant caught before this line was written.
    let schemes = [["postgres", "://"].concat(), ["postgresql", "://"].concat()];
    let fallback = ["unwrap_or", ""].concat();

    let sources = integration_test_sources();
    let mut offenders: Vec<String> = Vec::new();
    let mut literal_sites = 0usize;
    for (relative, source) in &sources {
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if is_line_comment(line) || !schemes.iter().any(|scheme| line.contains(scheme)) {
                continue;
            }
            literal_sites += 1;
            // The fallback combinator may sit on this line or on either of the
            // two preceding ones, since rustfmt breaks the chain.
            let window = lines[index.saturating_sub(2)..=index].join("\n");
            if window.contains(&fallback) {
                offenders.push(format!("{relative}:{}", index + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "test sources default a database connection to a hardcoded name: \
         {offenders:?}. A test must never adopt a database it did not create — \
         mint one via common::fresh_db instead."
    );

    // Positive control, so an empty offender list cannot pass vacuously: the
    // sweep must actually be seeing connection literals to classify.
    assert!(
        literal_sites >= 10,
        "sweep saw only {literal_sites} connection literals — it is not \
         reading the corpus, so its empty offender list proves nothing"
    );
}

/// Prefix hygiene for [`common::fresh_db::DISPOSABLE_PREFIXES`].
///
/// Attribution of a leaked database to its owning target is the only thing that
/// makes the leak-on-SIGKILL behaviour tolerable, and it silently breaks if two
/// prefixes overlap: a name minted under the longer prefix also validates under
/// the shorter one, so the wrong target gets blamed. `chat_exec_` must stay
/// unreserved because those 73 databases are not ours to reap.
///
/// Falsifying inputs: a duplicate entry; an entry that is a prefix of another
/// (e.g. adding `mlsds_`); adding `chat_exec_`; an entry not ending in `_`.
#[test]
fn disposable_prefixes_are_disjoint_and_exclude_the_executor_namespace() {
    let prefixes = common::fresh_db::DISPOSABLE_PREFIXES;
    assert!(!prefixes.is_empty(), "no disposable prefixes are reserved");
    for (i, outer) in prefixes.iter().enumerate() {
        assert!(
            outer.ends_with('_'),
            "{outer:?} must end with '_' so a prefix cannot run into a hex suffix"
        );
        assert_ne!(
            *outer, "chat_exec_",
            "the executor harness namespace must never be reservable here"
        );
        for (j, inner) in prefixes.iter().enumerate() {
            if i == j {
                continue;
            }
            assert!(
                !outer.starts_with(inner),
                "{outer:?} starts with {inner:?}: a leaked database would be \
                 attributable to two different targets"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_conversation_crud() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let (pool, _database) = setup_test_db().await;

    // Create
    let convo = create_conversation(&pool, "did:plc:creator123")
        .await
        .expect("Failed to create conversation");

    assert_eq!(convo.creator_did, "did:plc:creator123");
    assert_eq!(convo.current_epoch, 0);

    // Read
    let fetched = get_conversation(&pool, &convo.id)
        .await
        .expect("Failed to get conversation")
        .expect("Conversation not found");

    assert_eq!(fetched.id, convo.id);
    assert_eq!(fetched.creator_did, "did:plc:creator123");

    // Update epoch
    update_conversation_epoch(&pool, &convo.id, 5)
        .await
        .expect("Failed to update epoch");

    let epoch = get_current_epoch(&pool, &convo.id)
        .await
        .expect("Failed to get epoch");

    assert_eq!(epoch, 5);

    // Delete
    delete_conversation(&pool, &convo.id)
        .await
        .expect("Failed to delete conversation");

    let deleted = get_conversation(&pool, &convo.id)
        .await
        .expect("Failed to get conversation");

    assert!(deleted.is_none());
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_member_operations() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let (pool, _database) = setup_test_db().await;

    let convo = create_conversation(&pool, "did:plc:creator")
        .await
        .expect("Failed to create conversation");

    // Add members
    add_member(&pool, &convo.id, "did:plc:alice")
        .await
        .expect("Failed to add alice");

    add_member(&pool, &convo.id, "did:plc:bob")
        .await
        .expect("Failed to add bob");

    // Check membership
    assert!(is_member(&pool, "did:plc:alice", &convo.id)
        .await
        .expect("Failed to check alice membership"));

    assert!(is_member(&pool, "did:plc:bob", &convo.id)
        .await
        .expect("Failed to check bob membership"));

    assert!(!is_member(&pool, "did:plc:charlie", &convo.id)
        .await
        .expect("Failed to check charlie membership"));

    // List members
    let members = list_members(&pool, &convo.id)
        .await
        .expect("Failed to list members");

    assert_eq!(members.len(), 2);

    // Get specific membership
    let alice_membership = get_membership(&pool, &convo.id, "did:plc:alice")
        .await
        .expect("Failed to get membership")
        .expect("Membership not found");

    assert_eq!(alice_membership.member_did, "did:plc:alice");
    assert!(alice_membership.is_active());

    // Update unread count
    update_unread_count(&pool, &convo.id, "did:plc:alice", 5)
        .await
        .expect("Failed to update unread count");

    let updated = get_membership(&pool, &convo.id, "did:plc:alice")
        .await
        .expect("Failed to get membership")
        .expect("Membership not found");

    assert_eq!(updated.unread_count, 5);

    // Reset unread count
    reset_unread_count(&pool, &convo.id, "did:plc:alice")
        .await
        .expect("Failed to reset unread count");

    let reset = get_membership(&pool, &convo.id, "did:plc:alice")
        .await
        .expect("Failed to get membership")
        .expect("Membership not found");

    assert_eq!(reset.unread_count, 0);

    // Remove member
    remove_member(&pool, &convo.id, "did:plc:bob")
        .await
        .expect("Failed to remove bob");

    assert!(!is_member(&pool, "did:plc:bob", &convo.id)
        .await
        .expect("Failed to check bob membership"));

    let active_members = list_members(&pool, &convo.id)
        .await
        .expect("Failed to list members");

    assert_eq!(active_members.len(), 1);
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_message_operations() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let (pool, _database) = setup_test_db().await;

    let convo = create_conversation(&pool, "did:plc:creator")
        .await
        .expect("Failed to create conversation");

    // Create messages
    let msg1 = create_message(
        &pool,
        &convo.id,
        "msg-alice-1",
        vec![1, 2, 3, 4],
        0,
        4,
        None,
    )
    .await
    .expect("Failed to create message 1");

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let msg2 = create_message(&pool, &convo.id, "msg-bob-1", vec![5, 6, 7, 8], 0, 4, None)
        .await
        .expect("Failed to create message 2");

    // Get message
    let fetched = get_message(&pool, &msg1.id)
        .await
        .expect("Failed to get message")
        .expect("Message not found");

    assert_eq!(fetched.ciphertext, vec![1, 2, 3, 4]);
    // sender_did is intentionally stored as NULL for privacy; clients
    // derive sender identity from decrypted MLS content.
    assert_eq!(fetched.sender_did, None);

    // List messages (current API: ASC by epoch/seq)
    let messages = list_messages(&pool, &convo.id, None, 10)
        .await
        .expect("Failed to list messages");

    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].id, msg1.id); // Oldest first under ASC ordering

    // List with pagination
    let page1 = list_messages(&pool, &convo.id, None, 1)
        .await
        .expect("Failed to list messages");

    assert_eq!(page1.len(), 1);
    assert_eq!(page1[0].id, msg1.id);

    let page2 = list_messages(&pool, &convo.id, Some(msg2.created_at), 1)
        .await
        .expect("Failed to list messages");

    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].id, msg1.id);

    // List since seq (replaces removed list_messages_since which keyed on time)
    let recent = list_messages_since_seq(&pool, &convo.id, msg1.seq, 10)
        .await
        .expect("Failed to list messages since");

    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].id, msg2.id);

    // Get count
    let count = get_message_count(&pool, &convo.id)
        .await
        .expect("Failed to get message count");

    assert_eq!(count, 2);

    // Delete message
    delete_message(&pool, &msg1.id)
        .await
        .expect("Failed to delete message");

    let deleted = get_message(&pool, &msg1.id)
        .await
        .expect("Failed to get message");

    assert!(deleted.is_none());
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_key_package_operations() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let (pool, _database) = setup_test_db().await;

    let cipher_suite = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
    let expires_at = Utc::now() + chrono::Duration::hours(24);
    // store_key_package validates real KeyPackage bytes (and binds the
    // credential identity to the owner DID) — dummy bytes are rejected.
    let key_data1 = common::generate_key_package_bytes("did:plc:alice");
    let key_data2 = common::generate_key_package_bytes("did:plc:alice");

    // Store key packages
    store_key_package(
        &pool,
        "did:plc:alice",
        cipher_suite,
        key_data1.clone(),
        expires_at,
    )
    .await
    .expect("Failed to store key package 1");

    store_key_package(
        &pool,
        "did:plc:alice",
        cipher_suite,
        key_data2.clone(),
        expires_at,
    )
    .await
    .expect("Failed to store key package 2");

    // Count key packages
    let count = count_key_packages(&pool, "did:plc:alice", cipher_suite)
        .await
        .expect("Failed to count key packages");

    assert_eq!(count, 2);

    // Get key package (should return oldest first)
    let kp = get_key_package(&pool, "did:plc:alice", cipher_suite)
        .await
        .expect("Failed to get key package")
        .expect("Key package not found");

    assert_eq!(kp.key_data, key_data1);
    assert!(kp.is_valid());

    // Consume key package
    consume_key_package(&pool, "did:plc:alice", cipher_suite, &key_data1)
        .await
        .expect("Failed to consume key package");

    // Count should be 1 now
    let count_after = count_key_packages(&pool, "did:plc:alice", cipher_suite)
        .await
        .expect("Failed to count key packages");

    assert_eq!(count_after, 1);

    // Next fetch should return second key package
    let kp2 = get_key_package(&pool, "did:plc:alice", cipher_suite)
        .await
        .expect("Failed to get key package")
        .expect("Key package not found");

    assert_eq!(kp2.key_data, key_data2);
}

/// Regression: the 7-day unconsumed sweep must NOT delete last-resort key
/// packages. It previously deleted every KP (including last-resort) of any
/// user inactive for `days_old`, making them unreachable — group creates
/// against them failed with "Key package exhausted" even though clients
/// publish last-resort KPs with a 30-day expiry precisely to survive
/// inactivity.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_old_unconsumed_sweep_preserves_last_resort() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let (pool, _database) = setup_test_db().await;

    let cipher_suite = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
    let expires_at = Utc::now() + chrono::Duration::days(30);
    let regular_bytes = common::generate_key_package_bytes("did:plc:alice");
    let last_resort_bytes = common::generate_key_package_bytes("did:plc:alice");

    store_key_package(
        &pool,
        "did:plc:alice",
        cipher_suite,
        regular_bytes,
        expires_at,
    )
    .await
    .expect("Failed to store regular key package");

    store_key_package_with_device_bound_to_signature(
        &pool,
        "did:plc:alice",
        cipher_suite,
        last_resort_bytes,
        expires_at,
        None,
        None,
        None,
        /* last_resort = */ true,
    )
    .await
    .expect("Failed to store last-resort key package");

    // Age both rows past the sweep cutoff while keeping them unexpired.
    sqlx::query("UPDATE key_packages SET created_at = NOW() - INTERVAL '8 days'")
        .execute(&pool)
        .await
        .expect("Failed to backdate key packages");

    let deleted = delete_old_unconsumed_key_packages(&pool, 7)
        .await
        .expect("Failed to run unconsumed sweep");
    assert_eq!(deleted, 1, "sweep must delete only the regular key package");

    let survivors: Vec<(bool,)> =
        sqlx::query_as("SELECT is_last_resort FROM key_packages WHERE owner_did = 'did:plc:alice'")
            .fetch_all(&pool)
            .await
            .expect("Failed to query survivors");
    assert_eq!(survivors.len(), 1);
    assert!(
        survivors[0].0,
        "the surviving key package must be the last-resort one"
    );
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_last_resort_key_package_store_flag_and_replacement() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let (pool, _database) = setup_test_db().await;

    let did = "did:plc:lastresort-store";
    let cipher_suite = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
    let expires_at = Utc::now() + chrono::Duration::hours(24);
    let device_id = Some("device-A".to_string());

    let regular = common::generate_key_package_bytes(did);
    let first_last_resort = common::generate_key_package_bytes(did);
    let second_last_resort = common::generate_key_package_bytes(did);

    let regular_row = store_key_package_with_device_bound_to_signature(
        &pool,
        did,
        cipher_suite,
        regular,
        expires_at,
        device_id.clone(),
        None,
        None,
        false,
    )
    .await
    .expect("store regular key package");

    let first_last_resort_row = store_key_package_with_device_bound_to_signature(
        &pool,
        did,
        cipher_suite,
        first_last_resort,
        expires_at,
        device_id.clone(),
        None,
        None,
        true,
    )
    .await
    .expect("store first last-resort key package");

    let second_last_resort_row = store_key_package_with_device_bound_to_signature(
        &pool,
        did,
        cipher_suite,
        second_last_resort,
        expires_at,
        device_id,
        None,
        None,
        true,
    )
    .await
    .expect("store replacement last-resort key package");

    let regular_is_last_resort: bool =
        sqlx::query_scalar("SELECT is_last_resort FROM key_packages WHERE key_package_hash = $1")
            .bind(&regular_row.key_package_hash)
            .fetch_one(&pool)
            .await
            .expect("fetch regular last-resort flag");
    assert!(!regular_is_last_resort);

    let first_state: (String, bool, bool) = sqlx::query_as(
        "SELECT state, dead_at IS NOT NULL, is_last_resort \
         FROM key_packages \
         WHERE key_package_hash = $1",
    )
    .bind(&first_last_resort_row.key_package_hash)
    .fetch_one(&pool)
    .await
    .expect("fetch first last-resort state");
    assert_eq!(first_state, ("revoked".to_string(), true, true));

    let second_state: (String, bool, bool) = sqlx::query_as(
        "SELECT state, dead_at IS NOT NULL, is_last_resort \
         FROM key_packages \
         WHERE key_package_hash = $1",
    )
    .bind(&second_last_resort_row.key_package_hash)
    .fetch_one(&pool)
    .await
    .expect("fetch replacement last-resort state");
    assert_eq!(second_state, ("available".to_string(), false, true));

    let active_last_resort_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM key_packages \
         WHERE owner_did = $1 \
           AND device_id = 'device-A' \
           AND is_last_resort = true \
           AND state = 'available' \
           AND dead_at IS NULL",
    )
    .bind(did)
    .fetch_one(&pool)
    .await
    .expect("count active last-resort rows");
    assert_eq!(active_last_resort_count, 1);
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_expired_key_package_cleanup() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let (pool, _database) = setup_test_db().await;

    let cipher_suite = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
    let expired = Utc::now() - chrono::Duration::hours(1);
    let valid = Utc::now() + chrono::Duration::hours(24);
    let expired_bytes = common::generate_key_package_bytes("did:plc:bob");
    let valid_bytes = common::generate_key_package_bytes("did:plc:bob");

    // Store expired and valid key packages
    store_key_package(
        &pool,
        "did:plc:bob",
        cipher_suite,
        expired_bytes.clone(),
        expired,
    )
    .await
    .expect("Failed to store expired key package");

    store_key_package(
        &pool,
        "did:plc:bob",
        cipher_suite,
        valid_bytes.clone(),
        valid,
    )
    .await
    .expect("Failed to store valid key package");

    // Expired key package should not be returned
    let kp = get_key_package(&pool, "did:plc:bob", cipher_suite)
        .await
        .expect("Failed to get key package")
        .expect("Key package not found");

    assert_eq!(kp.key_data, valid_bytes);

    // Clean up expired
    let deleted = delete_expired_key_packages(&pool)
        .await
        .expect("Failed to delete expired key packages");

    assert!(deleted >= 1);
}

// Blob operations have been removed - system is now text-only with PostgreSQL storage

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_transaction_conversation_with_members() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let (pool, _database) = setup_test_db().await;

    // Create conversation with members in transaction
    let convo = create_conversation_with_members(
        &pool,
        "did:plc:creator",
        vec![
            "did:plc:alice".to_string(),
            "did:plc:bob".to_string(),
            "did:plc:charlie".to_string(),
        ],
    )
    .await
    .expect("Failed to create conversation with members");

    // Verify all members were added
    let members = list_members(&pool, &convo.id)
        .await
        .expect("Failed to list members");

    assert_eq!(members.len(), 3);

    let member_dids: Vec<&str> = members.iter().map(|m| m.member_did.as_str()).collect();
    assert!(member_dids.contains(&"did:plc:alice"));
    assert!(member_dids.contains(&"did:plc:bob"));
    assert!(member_dids.contains(&"did:plc:charlie"));
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_list_conversations_for_user() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let (pool, _database) = setup_test_db().await;

    // Create multiple conversations
    let convo1 = create_conversation(&pool, "did:plc:creator")
        .await
        .expect("Failed to create convo 1");

    let convo2 = create_conversation(&pool, "did:plc:creator")
        .await
        .expect("Failed to create convo 2");

    let convo3 = create_conversation(&pool, "did:plc:other")
        .await
        .expect("Failed to create convo 3");

    // Add user to conversations
    add_member(&pool, &convo1.id, "did:plc:alice")
        .await
        .unwrap();
    add_member(&pool, &convo2.id, "did:plc:alice")
        .await
        .unwrap();
    add_member(&pool, &convo3.id, "did:plc:alice")
        .await
        .unwrap();

    // List conversations for alice
    let convos = list_conversations(&pool, "did:plc:alice", 10, 0)
        .await
        .expect("Failed to list conversations");

    assert_eq!(convos.len(), 3);

    // Leave one conversation
    remove_member(&pool, &convo2.id, "did:plc:alice")
        .await
        .unwrap();

    // Should only see 2 now
    let active_convos = list_conversations(&pool, "did:plc:alice", 10, 0)
        .await
        .expect("Failed to list conversations");

    assert_eq!(active_convos.len(), 2);
}

// This case has always required a live PostgreSQL server; it was the only one
// in the file not marked as such, and it got away with it because
// `setup_test_db` silently fell back to a hardcoded default database name when
// `TEST_DATABASE_URL` was unset. That fallback is the shared-state hazard in
// miniature — a test quietly adopting, migrating and truncating whatever
// database happened to answer to that name — so it is gone, and the case is now
// tagged like its ten siblings.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_health_check() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let (pool, _database) = setup_test_db().await;

    let healthy = health_check(&pool).await.expect("Health check failed");

    assert!(healthy);
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn test_concurrent_operations() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let (pool, _database) = setup_test_db().await;

    let convo = create_conversation(&pool, "did:plc:creator")
        .await
        .expect("Failed to create conversation");

    // Concurrent message creation.
    //
    // `db::create_message` computes `seq` with a read-then-insert
    // (MAX(seq)+1), so concurrent writers on the same convo can collide on
    // the `messages_convo_seq_unique` constraint and get a clean error back.
    // Production never hits this: message writes are serialized
    // per-conversation by the ConversationActor (`actors/conversation.rs`),
    // and this helper has no production call sites. The DB constraint is the
    // integrity guarantee under test, so each task retries on a seq
    // collision exactly as a concurrent caller would have to.
    let mut handles = vec![];
    for i in 0..10 {
        let pool_clone = pool.clone();
        let convo_id = convo.id.clone();
        let handle = tokio::spawn(async move {
            let mut last_err = None;
            for _attempt in 0..32 {
                match create_message(
                    &pool_clone,
                    &convo_id,
                    &format!("concurrent-msg-{}", i),
                    vec![i as u8],
                    0,
                    1,
                    None,
                )
                .await
                {
                    Ok(msg) => return Ok(msg),
                    Err(e) => {
                        let is_seq_collision = e
                            .downcast_ref::<sqlx::Error>()
                            .and_then(|se| se.as_database_error())
                            .and_then(|dbe| dbe.constraint())
                            .map(|c| c == "messages_convo_seq_unique")
                            .unwrap_or(false);
                        if is_seq_collision {
                            last_err = Some(e);
                            continue;
                        }
                        return Err(e);
                    }
                }
            }
            Err(last_err.expect("retry loop exited without an error"))
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap().expect("Failed to create message");
    }

    let count = get_message_count(&pool, &convo.id)
        .await
        .expect("Failed to get count");

    assert_eq!(count, 10);
}
