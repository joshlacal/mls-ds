mod common;

use common::chat_protocol::{
    validate_chat_protocol_database_url, CHAT_PROTOCOL_TEST_DATABASE_NAME,
};

#[test]
fn clean_repository_harness_requires_the_exact_dedicated_database() {
    assert!(validate_chat_protocol_database_url(None).is_err());
    assert!(validate_chat_protocol_database_url(Some("")).is_err());
    assert!(
        validate_chat_protocol_database_url(Some("postgres://localhost/catbird_test")).is_err()
    );
    assert!(validate_chat_protocol_database_url(Some(
        "postgresql://localhost/catbird_chat_protocol_test_20260722_extra",
    ))
    .is_err());
    assert!(validate_chat_protocol_database_url(Some(
        "postgresql://localhost/catbird_chat_protocol_test_20260722/other",
    ))
    .is_err());

    for valid in [
        "postgres://localhost/catbird_chat_protocol_test_20260722",
        "postgresql://localhost/catbird_chat_protocol_test_20260722",
    ] {
        assert_eq!(
            validate_chat_protocol_database_url(Some(valid)).unwrap(),
            CHAT_PROTOCOL_TEST_DATABASE_NAME,
        );
    }
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
