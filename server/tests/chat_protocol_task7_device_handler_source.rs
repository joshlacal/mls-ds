//! Source-level composition checks for the three active device handlers.
//!
//! This independent target builds the real production library without the
//! legacy `#[path]` fixture topology used by the ignored live-DB handler suite.

#[test]
fn active_device_handlers_use_consuming_operation_preludes_not_legacy_receipts() {
    for (source, admission, preparation, effects, completion) in [
        (
            include_str!("../src/handlers/chat/enroll_device.rs"),
            "admit_enrollment_operation_only",
            "prepare_enrollment_operation",
            "persist_enrollment_bootstrap_effects",
            "complete_enrollment_bootstrap_operation",
        ),
        (
            include_str!("../src/handlers/chat/replenish_key_packages.rs"),
            "admit_replenishment_operation_only",
            "prepare_replenishment_operation",
            "publish_replenishment_key_packages",
            "complete_replenishment_operation",
        ),
    ] {
        for required in [
            admission,
            preparation,
            effects,
            completion,
            "into_completion_guard",
            ".commit()",
        ] {
            assert!(source.contains(required), "missing Task 7 seam: {required}");
        }
        for legacy in [
            "arbitrate_business_idempotency",
            "recheck_business_authority",
            "record_completed_idempotency",
            "prepare_enrollment_business",
            "prepare_rebind_business",
            "persist_enrollment_and_completion",
            "persist_rebind_and_completion",
        ] {
            assert!(
                !source.contains(legacy),
                "legacy receipt helper remains in active handler: {legacy}"
            );
        }
        for repository_internal in [
            "VerifiedChatDeviceRequest",
            "OperationReplayGuard",
            "OperationReservationGuard",
            "validate_enrollment_operation_replay",
            "validate_rebind_operation_replay",
            "validate_replenishment_operation_replay",
        ] {
            assert!(
                !source.contains(repository_internal),
                "repository authority escaped into active handler: {repository_internal}"
            );
        }
    }
}

#[test]
fn active_device_handlers_complete_only_after_their_mutation_effects_and_response() {
    let enroll = include_str!("../src/handlers/chat/enroll_device.rs");
    let replenish = include_str!("../src/handlers/chat/replenish_key_packages.rs");

    assert_in_handler_order(
        enroll,
        &[
            "persist_enrollment_bootstrap_effects",
            "publish_enrollment_key_packages",
            "complete_enrollment_bootstrap_operation",
            ".commit()",
        ],
    );
    assert_in_handler_order(
        replenish,
        &[
            "publish_replenishment_key_packages",
            "read_device_view(&mut transaction",
            "complete_replenishment_operation",
            ".commit()",
        ],
    );
}

fn assert_in_handler_order(source: &str, ordered_seams: &[&str]) {
    let handler = source
        .split_once("pub(super) async fn handle")
        .expect("handler entrypoint exists")
        .1;
    let mut offset = 0;
    for seam in ordered_seams {
        let relative = handler[offset..]
            .find(seam)
            .unwrap_or_else(|| panic!("missing ordered Task 7 seam: {seam}"));
        offset += relative + seam.len();
    }
}

#[test]
fn bootstrap_completion_and_effect_adapters_keep_verified_authority_internal() {
    let auth = include_str!("../src/chat_protocol/repository/auth.rs");
    let prelude = include_str!("../src/chat_protocol/repository/prelude.rs");

    for admission in [
        "impl EnrollmentOperationAdmission",
        "impl RebindOperationAdmission",
    ] {
        let block = auth
            .split_once(admission)
            .expect("admission implementation exists")
            .1;
        assert!(block.contains("pub(super) fn into_first_authority"));
        assert!(block.contains("pub(super) fn into_replay_authority"));
        assert!(!block.contains("pub(crate) fn into_first_authority"));
    }
    for wrapper in [
        "prepare_enrollment_operation",
        "prepare_rebind_operation",
        "prepare_replenishment_operation",
    ] {
        assert!(
            prelude.contains(wrapper),
            "missing endpoint wrapper: {wrapper}"
        );
    }
    for completion in [
        "EnrollmentBootstrapCompletion",
        "RebindBootstrapCompletion",
        "ReplenishmentCompletion",
    ] {
        assert!(
            prelude.contains(completion),
            "missing owned completion: {completion}"
        );
    }
    for writer in [
        "persist_enrollment_bootstrap_effects",
        "persist_rebind_bootstrap_effects",
        "publish_enrollment_key_packages",
        "publish_replenishment_key_packages",
    ] {
        assert!(
            prelude.contains(writer),
            "missing effects-only adapter: {writer}"
        );
    }
}

#[test]
fn task7_uses_narrow_effect_capabilities_and_the_existing_device_completion_family() {
    let enrollment = include_str!("../src/handlers/chat/enroll_device.rs");
    let replenish = include_str!("../src/handlers/chat/replenish_key_packages.rs");
    let prelude = include_str!("../src/chat_protocol/repository/prelude.rs");

    for source in [enrollment, replenish] {
        for forbidden in [
            "KeyPackageOwner",
            "key_packages::publish_key_packages",
            ".authority()",
            ".request()",
            "VerifiedChatDeviceRequest",
        ] {
            assert!(
                !source.contains(forbidden),
                "active handler must not escape or reconstruct authority: {forbidden}"
            );
        }
    }

    for forbidden in [
        "pub(crate) fn authority(&self) -> &VerifiedChatDeviceRequest",
        "pub(crate) fn request(&self) -> &VerifiedChatDeviceRequest",
    ] {
        assert!(
            !prelude.contains(forbidden),
            "effect/prelude authority escape remains public to handlers: {forbidden}"
        );
    }
    let replenishment_completion = prelude
        .split_once("pub(crate) struct ReplenishmentCompletion")
        .expect("replenishment completion exists")
        .1
        .split_once("#[cfg(test)]")
        .expect("completion type boundary exists")
        .0;
    assert!(replenishment_completion.contains("completion: OperationCompletionGuard"));
    assert!(!replenishment_completion.contains("BootstrapCompletionGuard"));

    let replenish_split = prelude
        .split_once("impl PreparedReplenishmentPrelude")
        .expect("replenishment prelude exists")
        .1;
    assert!(replenish_split.contains("let (scope, completion) = inner.into_execution_parts()"));
    assert!(replenish_split.contains("ReplenishmentCompletion {"));
    let completion_fn = prelude
        .split_once("pub(crate) async fn complete_replenishment_operation")
        .expect("replenishment completion function exists")
        .1
        .split_once("async fn validate_bootstrap_completion")
        .expect("completion function boundary exists")
        .0;
    assert!(completion_fn.contains("complete_operation("));
    assert!(!completion_fn.contains("validate_bootstrap_completion"));
}

#[test]
fn bootstrap_effect_writers_bind_the_live_transaction_to_the_locked_scope() {
    let auth = include_str!("../src/chat_protocol/repository/auth.rs");
    for writer in [
        "pub(super) async fn persist_enrollment_bootstrap_effects",
        "pub(super) async fn persist_rebind_bootstrap_effects",
    ] {
        let implementation = auth
            .split_once(writer)
            .expect("Task 7 effects writer exists")
            .1;
        assert!(
            implementation.contains("SELECT txid_current()::text"),
            "{writer} must capture the executing SQL transaction"
        );
        assert!(
            implementation.contains("transaction_id != scope.transaction_id()"),
            "{writer} must reject a scope borrowed from another transaction"
        );
    }

    let prelude = include_str!("../src/chat_protocol/repository/prelude.rs");
    for adapter in [
        "pub(crate) async fn publish_enrollment_key_packages",
        "pub(crate) async fn publish_replenishment_key_packages",
    ] {
        let implementation = prelude
            .split_once(adapter)
            .expect("Task 7 package adapter exists")
            .1;
        let transaction_check = implementation
            .find("ensure_effect_transaction(transaction")
            .expect("package adapter binds its effect scope to the live transaction");
        let generic_writer = implementation
            .find("key_packages::publish_key_packages")
            .expect("package adapter reaches the generic writer");
        assert!(
            transaction_check < generic_writer,
            "{adapter} must reject a foreign transaction before package publication"
        );
    }
    let transaction_check = prelude
        .split_once("async fn ensure_effect_transaction")
        .expect("Task 7 package transaction verifier exists")
        .1;
    assert!(transaction_check.contains("SELECT txid_current()::text"));
    assert!(transaction_check.contains("transaction_id != expected_transaction_id"));
    assert!(transaction_check.contains("KeyPackageRepositoryError::ForeignTransaction"));
}
