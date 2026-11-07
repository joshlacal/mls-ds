mod common;

use catbird_server::db::*;
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

fn src_rust_sources() -> Vec<(String, String)> {
    fn walk(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(path).expect("read src source directory") {
            let path = entry.expect("read src source entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(
        files.len() > 30,
        "src sweep found only {} files — the corpus is not being walked",
        files.len()
    );
    files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&root)
                .expect("source under src/")
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

/// In-crate test modules that are EXEMPT from the two "src tests must mint
/// their own database" guards below.
///
/// These came in with the encrypted-requests line. They deliberately connect to
/// the reviewed gate databases — the fixed-target clean-chat DB pinned to the
/// reviewed migration ledger (`catbird_chat_protocol_test_20260722`, via
/// `TEST_DATABASE_URL`) and the dedicated direct-request DB
/// (`catbird_direct_requests_test_20260919`, via `REQUEST_TEST_DATABASE_URL`).
/// Those targets are validation-only and are never migrated or repaired by the
/// tests, so adopting them is the point of the test rather than an isolation
/// leak. Exempting them was an explicit decision (2026-10-04 line merge);
/// do NOT rewrite them onto `fresh_db`, and do NOT add entries without the same
/// justification. Exception (Main ruling 2026-11-04): the two Recovery
/// production proofs that opened extra connections from `TEST_DATABASE_URL` now
/// reuse their gated private proof database, so their entries were removed.
/// Likewise (2026-11-07) `rollback_tests.rs`: each case resolves a fresh
/// application `Accept`, which writes `chat.application_send_order`, a table the
/// fixed target predates, so it now mints a private clean-protocol database.
///
/// Each entry is `(path relative to src/, first line marker)`. Only lines at or
/// after the first line containing the marker are exempt (`""` = whole file,
/// for files that are test-only modules in their entirety). Every entry must
/// still match at least one guarded site, so a stale exemption fails loudly.
const REVIEWED_GATE_DB_TEST_EXEMPTIONS: &[(&str, &str)] = &[
    (
        "chat_protocol/repository/conversation_substrate_tests.rs",
        "",
    ),
    ("chat_protocol/repository/delivery/read_tests.rs", ""),
    ("chat_protocol/repository/reset/tests.rs", ""),
    ("chat_protocol/repository/ticket/tests.rs", ""),
    ("chat_protocol/repository/transition/tests.rs", ""),
    ("chat_protocol/state_machine/executor_tests.rs", ""),
];

/// Splits `offenders` (`"<relative>:<line>"`) into still-failing offenders,
/// dropping sites covered by `REVIEWED_GATE_DB_TEST_EXEMPTIONS`, and asserts no
/// exemption has gone stale for this guard.
fn without_reviewed_gate_db_exemptions(
    guard: &str,
    sources: &[(String, String)],
    offenders: Vec<String>,
    exemptions_expected_to_match: &[&str],
) -> Vec<String> {
    let mut used = std::collections::BTreeSet::new();
    let remaining = offenders
        .into_iter()
        .filter(|offender| {
            let (relative, line) = offender.rsplit_once(':').expect("offender is path:line");
            let line: usize = line.parse().expect("offender line number");
            let Some((path, marker)) = REVIEWED_GATE_DB_TEST_EXEMPTIONS
                .iter()
                .find(|(path, _)| *path == relative)
            else {
                return true;
            };
            let source = &sources
                .iter()
                .find(|(candidate, _)| candidate == relative)
                .expect("offender source present")
                .1;
            let start = if marker.is_empty() {
                1
            } else {
                match source.lines().position(|text| text.contains(marker)) {
                    Some(index) => index + 1,
                    None => return true,
                }
            };
            if line >= start {
                used.insert(*path);
                false
            } else {
                true
            }
        })
        .collect();
    let stale: Vec<&&str> = exemptions_expected_to_match
        .iter()
        .filter(|path| !used.contains(**path))
        .collect();
    assert!(
        stale.is_empty(),
        "{guard}: reviewed-gate exemptions no longer match any site: {stale:?}. \
         Remove them from REVIEWED_GATE_DB_TEST_EXEMPTIONS."
    );
    remaining
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
        "chat_protocol_remote_prefix_bootstrap.rs",
        // federation_hostile_peers.rs was deleted with its approval left
        // behind by 7b1f093b4 (2026-10-31); a re-added caller must be re-reviewed.
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

#[test]
fn inline_src_tests_do_not_run_unisolated_migrations_from_test_database_url() {
    let src_sources = src_rust_sources();
    let mut offenders: Vec<String> = Vec::new();

    let migrate_run = ["migrate", "!", "(", ")", ".run"].concat();
    let migrate_run_explicit = ["migrate", "!", "(\"./migrations\").run"].concat();
    let init_db_call = ["init_db", "("].concat();
    let fresh_db_needle = ["fresh_db", "::"].concat();

    for (relative, source) in &src_sources {
        if relative.starts_with("test_support") {
            continue;
        }

        let lines: Vec<&str> = source.lines().collect();
        let mut in_test_module = false;

        for (index, line) in lines.iter().enumerate() {
            if is_line_comment(line) {
                continue;
            }
            if line.contains("#[cfg(test)]")
                || line.contains("mod tests")
                || line.contains("mod outbox_db_tests")
                || line.contains("mod self_heal_db_tests")
                || line.contains("mod transition_repository_tests")
            {
                in_test_module = true;
            }

            if in_test_module {
                if line.contains(&migrate_run) || line.contains(&migrate_run_explicit) {
                    offenders.push(format!(
                        "{relative}:{} runs inline migration without isolation harness",
                        index + 1
                    ));
                }
                if line.contains(&init_db_call) && !source.contains(&fresh_db_needle) {
                    offenders.push(format!(
                        "{relative}:{} calls init_db in tests without minting a disposable database",
                        index + 1
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "inline src test sources run unisolated migrations: {offenders:?}. Use crate::test_support::fresh_db instead."
    );
}

#[test]
fn no_src_test_source_defaults_a_database_connection_to_a_hardcoded_name() {
    let schemes = [["postgres", "://"].concat(), ["postgresql", "://"].concat()];
    let fallback = ["unwrap_or", ""].concat();

    let sources = src_rust_sources();
    let mut offenders: Vec<String> = Vec::new();
    for (relative, source) in &sources {
        if relative == "db.rs" {
            let lines: Vec<&str> = source.lines().collect();
            let mut in_tests = false;
            for (index, line) in lines.iter().enumerate() {
                if line.contains("#[cfg(test)]") {
                    in_tests = true;
                }
                if in_tests
                    && !is_line_comment(line)
                    && schemes.iter().any(|scheme| line.contains(scheme))
                {
                    let window = lines[index.saturating_sub(2)..=index].join("\n");
                    if window.contains(&fallback) {
                        offenders.push(format!("{relative}:{}", index + 1));
                    }
                }
            }
            continue;
        }

        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if is_line_comment(line) || !schemes.iter().any(|scheme| line.contains(scheme)) {
                continue;
            }
            let window = lines[index.saturating_sub(2)..=index].join("\n");
            if window.contains(&fallback) {
                offenders.push(format!("{relative}:{}", index + 1));
            }
        }
    }
    let offenders = without_reviewed_gate_db_exemptions(
        "hardcoded-name guard",
        &sources,
        offenders,
        &[
            "chat_protocol/repository/delivery/read_tests.rs",
            "chat_protocol/repository/ticket/tests.rs",
        ],
    );
    assert!(
        offenders.is_empty(),
        "src test sources default a database connection to a hardcoded name: \
         {offenders:?}. A test must never adopt a database it did not create — \
         mint one via crate::test_support::fresh_db instead."
    );
}

#[test]
fn no_src_test_adopts_connection_directly_from_test_database_url() {
    let src_sources = src_rust_sources();
    let mut offenders: Vec<String> = Vec::new();
    let test_db_env = ["TEST_DATABASE", "_URL"].concat();

    for (relative, source) in &src_sources {
        if relative.starts_with("test_support") {
            continue;
        }

        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if is_line_comment(line) || !line.contains(&test_db_env) {
                continue;
            }

            // Also exclude comment doc lines or ignore reasons like `#[ignore = "..."]`
            if line.contains("#[ignore") {
                continue;
            }

            // Check if this is a connection/migration adoption
            let window = lines[index..=index.saturating_add(5).min(lines.len() - 1)].join("\n");
            if window.contains("connect")
                || window.contains("PgPool")
                || window.contains("migrate")
                || window.contains("init_db")
            {
                offenders.push(format!("{relative}:{}", index + 1));
            }
        }
    }

    let all_exempt_paths: Vec<&str> = REVIEWED_GATE_DB_TEST_EXEMPTIONS
        .iter()
        .map(|(path, _)| *path)
        .collect();
    let offenders = without_reviewed_gate_db_exemptions(
        "TEST_DATABASE_URL adoption guard",
        &src_sources,
        offenders,
        &all_exempt_paths,
    );
    assert!(
        offenders.is_empty(),
        "src tests adopt connections directly from TEST_DATABASE_URL: {offenders:?}. Use crate::test_support::fresh_db instead."
    );
}

#[test]
fn src_disposable_prefixes_are_disjoint() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let content = std::fs::read_to_string(manifest_dir.join("src/test_support/fresh_db.rs"))
        .expect("read fresh_db.rs");
    let mut prefixes = Vec::new();
    let mut in_prefixes = false;
    for line in content.lines() {
        if line.contains("pub const DISPOSABLE_PREFIXES") {
            in_prefixes = true;
            continue;
        }
        if in_prefixes {
            if line.contains("];") {
                break;
            }
            let trimmed = line
                .trim()
                .trim_matches('"')
                .trim_matches(',')
                .trim_matches('"');
            if !trimmed.is_empty() && !trimmed.starts_with("//") {
                prefixes.push(trimmed.to_string());
            }
        }
    }
    assert!(
        !prefixes.is_empty(),
        "no disposable prefixes found in src fresh_db.rs"
    );
    for (i, outer) in prefixes.iter().enumerate() {
        assert!(
            outer.ends_with('_'),
            "{outer:?} must end with '_' so a prefix cannot run into a hex suffix"
        );
        assert_ne!(
            outer.as_str(),
            "chat_exec_",
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
async fn test_health_check() {
    let _fixture_guard = DB_FIXTURE_LOCK.lock().await;
    let (pool, _database) = setup_test_db().await;

    let healthy = health_check(&pool).await.expect("Health check failed");

    assert!(healthy);
}
