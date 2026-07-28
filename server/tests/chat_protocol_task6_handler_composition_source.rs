//! Database-free source contracts for the Task 6 HTTP compositors.
//!
//! These tests deliberately inspect production source: a behavior test cannot
//! prove that a handler did not quietly regain SQL, executor, or response
//! projection authority.

struct HandlerContract {
    name: &'static str,
    source: &'static str,
    facade_call: &'static str,
}

const RESET: &str = include_str!("../src/handlers/chat/reset.rs");
const REVOCATION: &str = include_str!("../src/handlers/chat/revoke_device.rs");
const RECOVERY: &str = include_str!("../src/handlers/chat/recovery.rs");
const WELCOME: &str = include_str!("../src/handlers/chat/welcome.rs");
const SUBMIT_TRANSITION: &str = include_str!("../src/handlers/chat/submit_transition.rs");

/// Remove comments while preserving code and string literals.  The latter are
/// intentionally retained so the SQL-string prohibition below is meaningful.
fn without_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut cursor = 0;
    let mut block_depth = 0_u32;
    let mut quoted: Option<u8> = None;

    while cursor < bytes.len() {
        if let Some(quote) = quoted {
            let byte = bytes[cursor];
            output.push(byte as char);
            if byte == b'\\' && cursor + 1 < bytes.len() {
                cursor += 1;
                output.push(bytes[cursor] as char);
            } else if byte == quote {
                quoted = None;
            }
            cursor += 1;
            continue;
        }

        if block_depth > 0 {
            if bytes[cursor..].starts_with(b"/*") {
                block_depth += 1;
                cursor += 2;
            } else if bytes[cursor..].starts_with(b"*/") {
                block_depth -= 1;
                cursor += 2;
            } else {
                if bytes[cursor] == b'\n' {
                    output.push('\n');
                }
                cursor += 1;
            }
            continue;
        }

        if bytes[cursor..].starts_with(b"//") {
            cursor += 2;
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
            continue;
        }
        if bytes[cursor..].starts_with(b"/*") {
            block_depth = 1;
            cursor += 2;
            continue;
        }

        let byte = bytes[cursor];
        output.push(byte as char);
        if matches!(byte, b'\'' | b'\"') {
            quoted = Some(byte);
        }
        cursor += 1;
    }
    output
}

fn occurrences(source: &str, needle: &str) -> usize {
    source.match_indices(needle).count()
}

fn without_whitespace(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn assert_absent(source: &str, handler: &str, forbidden: &[&str]) {
    for needle in forbidden {
        assert!(
            !source.contains(needle),
            "{handler} handler must delegate `{needle}` rather than own it"
        );
    }
}

#[test]
fn task6_handlers_are_one_transaction_operation_only_compositors() {
    let contracts = [
        HandlerContract {
            name: "reset",
            source: RESET,
            facade_call: "reset::execute_prepared_reset(",
        },
        HandlerContract {
            name: "revoke_device",
            source: REVOCATION,
            facade_call: "revocation::prepare_device_revocation(",
        },
        HandlerContract {
            name: "recovery",
            source: RECOVERY,
            facade_call: "recovery::execute_prepared_recovery(",
        },
        HandlerContract {
            name: "welcome",
            source: WELCOME,
            facade_call: "welcome_terminal::prepare_welcome_terminal(",
        },
        HandlerContract {
            name: "submit_transition",
            source: SUBMIT_TRANSITION,
            facade_call: "submit_transition::execute_prepared_submit_transition(",
        },
    ];

    for contract in contracts {
        let source = without_comments(contract.source);
        assert!(
            source.contains("context::admit_signed_operation_only("),
            "{} must admit only an opaque signed operation",
            contract.name
        );
        assert_eq!(
            occurrences(&source, ".begin()"),
            1,
            "{} must open exactly one caller-owned outer transaction",
            contract.name
        );
        assert!(
            source.contains("prelude::prepare_signed_operation("),
            "{} must arbitrate the signed operation in that transaction",
            contract.name
        );
        assert!(
            source.contains(contract.facade_call),
            "{} must invoke its sealed repository facade",
            contract.name
        );
        assert_eq!(
            occurrences(&source, ".commit()"),
            1,
            "{} must commit exactly once, at the handler boundary",
            contract.name
        );
    }
}

#[test]
fn task6_handlers_cannot_reclaim_repository_or_executor_authority() {
    let handlers = [
        ("reset", RESET),
        ("revoke_device", REVOCATION),
        ("recovery", RECOVERY),
        ("welcome", WELCOME),
        ("submit_transition", SUBMIT_TRANSITION),
    ];
    let forbidden = [
        "sqlx::query(",
        "sqlx::query_as(",
        "sqlx::query_scalar(",
        "INSERT INTO ",
        "UPDATE ",
        "DELETE FROM ",
        "ExecutionContextArtifacts {",
        "ConversationExecutionArtifacts::new",
        "PreparedExecutionArtifacts {",
        "build_verified_control_entry(",
        "CanonicalControlEntryProducts::mint",
        "canonical_submit_transition_primary_event_payload(",
        "primary_event_payload:",
        "welcome_disposition_event_payloads:",
        "serde_json::to_string(",
        "serde_json::to_value(",
    ];

    for (name, source) in handlers {
        assert_absent(&without_comments(source), name, &forbidden);
    }
}

#[test]
fn every_handler_transmits_only_facade_owned_canonical_bytes() {
    for (name, source) in [
        ("reset", RESET),
        ("revoke_device", REVOCATION),
        ("recovery", RECOVERY),
        ("welcome", WELCOME),
        ("submit_transition", SUBMIT_TRANSITION),
    ] {
        assert_absent(
            &without_comments(source),
            name,
            &[
                "serde_json::to_vec(",
                "chat_dto::",
                "device_view_from_directory(",
            ],
        );
    }

    let revocation = without_comments(REVOCATION);
    assert!(revocation.contains(".complete(&mut transaction)"));
    assert!(revocation.contains("completed.into_response_bytes()"));
}

#[test]
fn submit_transition_has_a_closed_recovery_routing_union() {
    let source = without_comments(SUBMIT_TRANSITION);
    let recovery = source
        .find("SignedMutationKind::LeafRecoveryFulfillment =>")
        .expect("submitTransition must explicitly route recovery fulfillment");
    let recovery_call = source[recovery..]
        .find("recovery::execute_prepared(")
        .expect("recovery fulfillment must use recovery::execute_prepared");
    let non_recovery = source
        .find("SignedMutationKind::CommitTransition")
        .expect("submitTransition must enumerate the non-Recovery union");
    let non_recovery_call = source[non_recovery..]
        .find("submit_transition::execute_prepared_submit_transition(")
        .expect("non-Recovery union must use its sealed facade");
    assert!(recovery < non_recovery);
    assert!(recovery_call < non_recovery - recovery);
    assert!(non_recovery_call > 0);

    for kind in [
        "SignedMutationKind::CommitTransition",
        "SignedMutationKind::PolicyTransition",
        "SignedMutationKind::MetadataTransition",
        "SignedMutationKind::LeaveCommitFulfillment",
    ] {
        assert!(source.contains(kind), "non-Recovery union omitted {kind}");
    }
    assert!(
        !source.contains("SignedMutationKind::ZeroLeafLeave"),
        "submitTransition must never admit or dispatch ZeroLeafLeave"
    );
}

#[test]
fn repository_facades_never_commit_the_callers_outer_transaction() {
    for (name, source) in [
        (
            "reset",
            include_str!("../src/chat_protocol/repository/reset.rs"),
        ),
        (
            "revocation",
            include_str!("../src/chat_protocol/repository/revocation.rs"),
        ),
        (
            "welcome",
            include_str!("../src/chat_protocol/repository/welcome_terminal.rs"),
        ),
        (
            "recovery",
            include_str!("../src/chat_protocol/repository/recovery.rs"),
        ),
        (
            "submit_transition",
            include_str!("../src/chat_protocol/repository/submit_transition.rs"),
        ),
    ] {
        assert!(
            !without_whitespace(&without_comments(source)).contains("transaction.commit().await"),
            "{name} repository facade must leave the outer transaction open"
        );
    }
}
