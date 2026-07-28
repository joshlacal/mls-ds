//! Source-level closure gate for Task 7 Seal B.
//!
//! These assertions deliberately inspect the production repository source from
//! a normal integration-test target. They ensure retired handler completion
//! APIs cannot return to the non-test library surface while keeping narrow
//! executor-fixture support visibly test-only.

#[test]
fn retired_device_completion_apis_are_not_production_exports() {
    let source = include_str!("../src/chat_protocol/repository/auth.rs");

    for retired_declaration in [
        "pub(crate) async fn arbitrate_business_idempotency",
        "pub(crate) async fn recheck_business_authority",
        "pub(crate) async fn record_completed_idempotency",
        "pub(crate) async fn prepare_enrollment_business",
        "pub(crate) async fn prepare_rebind_business",
        "pub(crate) async fn persist_enrollment_and_completion",
        "pub(crate) async fn persist_rebind_and_completion",
        "pub(crate) enum BusinessIdempotencyOutcome",
        "pub(crate) struct BusinessIdempotencyGuard",
        "pub(crate) enum EnrollmentBusinessOutcome",
        "pub(crate) struct EnrollmentBusinessGuard",
        "pub(crate) enum RebindBusinessOutcome",
        "pub(crate) struct RebindBusinessGuard",
        "test_prepare_enrollment_business",
        "test_prepare_rebind_business",
        "test_persist_enrollment_and_completion",
        "test_persist_rebind_and_completion",
    ] {
        assert!(
            !source.contains(retired_declaration),
            "retired completion API remains production-visible: {retired_declaration}"
        );
    }
}

#[test]
fn generic_executor_fixture_bridge_is_explicitly_test_gated() {
    let source = include_str!("../src/chat_protocol/repository/auth.rs");

    for bridge in [
        "#[cfg(test)]\npub(crate) async fn test_arbitrate_business_idempotency",
        "#[cfg(test)]\npub(crate) async fn test_recheck_business_authority",
        "#[cfg(test)]\npub(crate) async fn test_record_completed_idempotency",
    ] {
        assert!(
            source.contains(bridge),
            "generic lower-level executor fixture bridge is not test-gated: {bridge}"
        );
    }
}
