mod common;

use common::chat_protocol::{
    validate_chat_protocol_activation_approval, validate_chat_protocol_database_url,
    CHAT_OPERATION_CLAIM_ACTIVATION_APPROVAL, CHAT_PROTOCOL_TEST_DATABASE_NAME,
};

fn compact_whitespace(source: &str) -> String {
    source.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_migrator_approval_is_scoped_to_one_connection(relative_path: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let source = compact_whitespace(&source);

    let acquire = source
        .find("let mut migration_connection = pool .acquire()")
        .unwrap_or_else(|| panic!("{} must acquire a specific connection", path.display()));
    let set = source
        .find(
            "SET chat.operation_claim_activation_approved = \\ \
             'handlers-and-legacy-apis-sealed'",
        )
        .or_else(|| {
            source.find(
                "SET chat.operation_claim_activation_approved = \
                 'handlers-and-legacy-apis-sealed'",
            )
        })
        .unwrap_or_else(|| panic!("{} must set the exact approval value", path.display()));
    let set_execute = source[set..]
        .find(".execute(&mut *migration_connection)")
        .map(|offset| set + offset)
        .unwrap_or_else(|| {
            panic!(
                "{} must set approval on the acquired connection",
                path.display()
            )
        });
    let migrate = source
        .find(".run(&mut *migration_connection)")
        .or_else(|| source.find(".run_direct(&mut *migration_connection)"))
        .unwrap_or_else(|| panic!("{} must migrate on the acquired connection", path.display()));
    let reset = source
        .find("RESET chat.operation_claim_activation_approved")
        .unwrap_or_else(|| panic!("{} must reset migration approval", path.display()));
    let reset_execute = source[reset..]
        .find(".execute(&mut *migration_connection)")
        .map(|offset| reset + offset)
        .unwrap_or_else(|| {
            panic!(
                "{} must reset approval on the acquired connection",
                path.display()
            )
        });
    let close = source
        .find("migration_connection .close()")
        .unwrap_or_else(|| panic!("{} must close the acquired connection", path.display()));

    assert!(
        acquire < set
            && set < set_execute
            && set_execute < migrate
            && migrate < reset
            && reset < reset_execute
            && reset_execute < close,
        "{} must set, migrate, reset, and close in order on one connection",
        path.display()
    );
    assert!(
        !source.contains(".run(&pool)"),
        "{} must not run the migrator through the pool",
        path.display()
    );
    assert!(
        !source.contains(
            "SET chat.operation_claim_activation_approved = \
             'handlers-and-legacy-apis-sealed' ) .execute(&pool)"
        ),
        "{} must not set migration approval through the pool",
        path.display()
    );
}

fn assert_schema_migrator_preserves_its_session_connection(relative_path: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let source = compact_whitespace(&source);

    let connect = source
        .find("let mut target = PgConnection::connect")
        .unwrap_or_else(|| {
            panic!(
                "{} must connect a specific target connection",
                path.display()
            )
        });
    let set = source[connect..]
        .find("SET chat.operation_claim_activation_approved")
        .map(|offset| connect + offset)
        .unwrap_or_else(|| panic!("{} must set activation approval", path.display()));
    let migrate = source[set..]
        .find(".run_direct(&mut target)")
        .map(|offset| set + offset)
        .unwrap_or_else(|| panic!("{} must migrate on the target connection", path.display()));
    let reset = source[migrate..]
        .find("RESET chat.operation_claim_activation_approved")
        .map(|offset| migrate + offset)
        .unwrap_or_else(|| panic!("{} must reset migration approval", path.display()));

    assert!(
        connect < set && set < migrate && migrate < reset,
        "{} must connect, set, migrate, and reset in order on target connection",
        path.display()
    );
    assert!(
        !source.contains(".run(&pool)"),
        "{} must not run the migrator through the pool",
        path.display()
    );
}

#[test]
fn clean_repository_harness_requires_the_exact_activation_approval() {
    for invalid in [
        None,
        Some(""),
        Some("handlers-and-legacy-apis-sealed "),
        Some("handlers-and-legacy-apis-sealed\n"),
        Some("true"),
    ] {
        assert!(
            validate_chat_protocol_activation_approval(invalid).is_err(),
            "accepted invalid activation approval {invalid:?}"
        );
    }
    assert_eq!(
        validate_chat_protocol_activation_approval(Some(CHAT_OPERATION_CLAIM_ACTIVATION_APPROVAL)),
        Ok(())
    );
}

#[test]
fn production_migrators_scope_activation_approval_to_the_exact_connection() {
    for relative_path in [
        "tests/common/chat_protocol.rs",
        "tests/common/executor_seed.rs",
        "tests/common/fresh_db.rs",
        "src/test_support/fresh_db.rs",
    ] {
        let full_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
        if full_path.exists() {
            assert_migrator_approval_is_scoped_to_one_connection(relative_path);
        }
    }
}

#[test]
fn schema_migrator_preserves_session_state_before_returning_its_connection() {
    assert_schema_migrator_preserves_its_session_connection("tests/chat_protocol_schema.rs");
}

#[test]
fn every_documented_chat_database_test_requires_activation_approval() {
    const DATABASE_HEADER: &str =
        "//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722";
    const APPROVAL_HEADER: &str =
        "//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed";

    let tests_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut documented_database_tests = 0;
    for entry in std::fs::read_dir(&tests_dir).expect("read server test directory") {
        let path = entry.expect("read server test entry").path();
        let Some(file_name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
            continue;
        };
        if file_name == "chat_protocol_repository_harness.rs"
            || !file_name.starts_with("chat_protocol_")
            || path.extension().and_then(|ext| ext.to_str()) != Some("rs")
        {
            continue;
        }
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        if !source.contains(DATABASE_HEADER) {
            continue;
        }
        documented_database_tests += 1;
        assert!(
            source.contains(APPROVAL_HEADER),
            "{} documents the dedicated database but omits the exact activation approval",
            path.display()
        );
    }

    assert_eq!(
        documented_database_tests, 19,
        "unexpected documented chat database test inventory"
    );
}

#[test]
fn clean_repository_harness_requires_the_exact_dedicated_database() {
    assert!(validate_chat_protocol_database_url(None).is_err());
    assert!(validate_chat_protocol_database_url(Some("")).is_err());
    assert!(
        validate_chat_protocol_database_url(Some("postgres://localhost/catbird_test")).is_err()
    );
    assert_eq!(
        validate_chat_protocol_database_url(Some(
            common::chat_protocol::CHAT_PROTOCOL_TEST_DATABASE_URL
        ))
        .unwrap(),
        CHAT_PROTOCOL_TEST_DATABASE_NAME,
    );
}

#[test]
fn clean_repository_harness_rejects_database_override_and_non_postgres_urls() {
    for invalid in [
        "https://localhost/catbird_chat_protocol_test_20260722",
        "postgres://localhost/",
        "postgres://localhost/catbird_chat_protocol_test_20260722?dbname=catbird_test",
        "postgres://localhost/catbird_chat_protocol_test_20260722#catbird_test",
    ] {
        assert!(
            validate_chat_protocol_database_url(Some(invalid)).is_err(),
            "accepted unsafe test database URL {invalid}",
        );
    }
}
