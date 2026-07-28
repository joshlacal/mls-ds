#![allow(dead_code)]

mod transition {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/chat_protocol/repository/transition.rs"
    ));
}

use chrono::{TimeZone, Utc};
use transition::{
    RecoveryTerminalTripleTermination, AVAILABLE_RECOVERY_PACKAGE_RESERVATION_SQL,
    RECOVERY_TERMINAL_TRIPLE_SQL,
};
use uuid::Uuid;

fn compact(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn terminal_triple_is_one_atomic_exact_count_statement() {
    let sql = compact(RECOVERY_TERMINAL_TRIPLE_SQL);
    assert_eq!(sql.matches("UPDATE chat.").count(), 3);
    assert!(sql.contains("UPDATE chat.leaf_recovery_requests AS rr"));
    assert!(sql.contains("UPDATE chat.key_package_reservations AS kr"));
    assert!(sql.contains("UPDATE chat.key_packages AS kp"));
    assert!(sql.contains("FROM request_terminal"));
    assert!(sql.contains("FROM reservation_terminal"));
    assert!(sql.contains(
        "1 / CASE WHEN request_count = 1 AND reservation_count = 1 \
         AND package_count = 1 THEN 1 ELSE 0 END"
    ));
}

#[test]
fn terminal_triple_guards_every_preterminal_nullable_column() {
    let sql = compact(RECOVERY_TERMINAL_TRIPLE_SQL);
    for predicate in [
        "rr.fulfilling_transition_id IS NULL",
        "rr.terminal_transition_id IS NULL",
        "rr.terminal_revocation_id IS NULL",
        "rr.terminal_signed_request_bytes IS NULL",
        "rr.terminal_signing_transcript_bytes IS NULL",
        "rr.terminal_request_digest IS NULL",
        "rr.terminal_signature IS NULL",
        "rr.terminal_at IS NULL",
        "kr.consumed_transition_id IS NULL",
        "kr.terminal_transition_id IS NULL",
        "kr.terminal_revocation_id IS NULL",
        "kr.terminal_request_digest IS NULL",
        "kr.terminal_at IS NULL",
        "kp.terminal_transition_id IS NULL",
        "kp.terminal_revocation_id IS NULL",
        "kp.terminal_at IS NULL",
    ] {
        assert!(
            sql.contains(predicate),
            "missing terminal guard: {predicate}"
        );
    }
}

#[test]
fn terminal_triple_guards_complete_immutable_rows() {
    let sql = compact(RECOVERY_TERMINAL_TRIPLE_SQL);
    for predicate in [
        "rr.recovery_request_id = $2",
        "rr.conversation_id = $3",
        "rr.generation = $4",
        "rr.requester_did = $5",
        "rr.requester_device_id = $6",
        "rr.requester_key_id = $7",
        "rr.requester_auth_generation = $8",
        "rr.recovery_kind = $9",
        "rr.source = $10",
        "rr.bound_state_version = $11",
        "rr.bound_group_id = $12",
        "rr.bound_epoch = $13",
        "rr.bound_group_context_hash = $14",
        "rr.bound_confirmation_tag = $15",
        "rr.reservation_request_id = $16",
        "rr.replaced_leaf_period_id IS NOT DISTINCT FROM $17",
        "rr.signed_request_bytes = $18",
        "rr.signing_transcript_bytes = $19",
        "rr.request_digest = $20",
        "rr.signature = $21",
        "rr.requested_at = $22",
        "rr.expires_at = $23",
        "kr.recovery_request_id = $24",
        "kr.key_package_ref = $25",
        "kr.conversation_id = $26",
        "kr.generation = $27",
        "kr.requester_did = $28",
        "kr.requester_device_id = $29",
        "kr.requester_key_id = $30",
        "kr.requester_auth_generation = $31",
        "kr.recipient_did = $32",
        "kr.recipient_device_id = $33",
        "kr.bound_state_version = $34",
        "kr.bound_group_id = $35",
        "kr.bound_epoch = $36",
        "kr.bound_group_context_hash = $37",
        "kr.bound_confirmation_tag = $38",
        "kr.expires_at = $39",
        "kr.created_at = $40",
        "kr.purpose = 'leafRecovery'",
        "kp.key_package_ref = $41",
        "kp.wrapper_bytes = $42",
        "kp.wrapper_sha256 = $43",
        "kp.init_key = $44",
        "kp.owner_did = $45",
        "kp.owner_device_id = $46",
        "kp.owner_key_id = $47",
        "kp.owner_auth_generation = $48",
        "kp.not_before = $49",
        "kp.not_after = $50",
        "kp.created_at = $51",
    ] {
        assert!(
            sql.contains(predicate),
            "missing immutable guard: {predicate}"
        );
    }
}

#[test]
fn terminal_triple_cross_binds_the_three_complete_rows() {
    let sql = compact(RECOVERY_TERMINAL_TRIPLE_SQL);
    for predicate in [
        "$24 = $2",
        "$24 = $16",
        "$26 = $3",
        "$27 = $4",
        "$28 = $5",
        "$29 = $6",
        "$30 = $7",
        "$31 = $8",
        "$34 = $11",
        "$35 = $12",
        "$36 = $13",
        "$37 = $14",
        "$38 = $15",
        "$39 = $23",
        "$41 = $25",
        "$45 = $32",
        "$46 = $33",
        "$47 = $30",
        "$48 = $31",
    ] {
        assert!(
            sql.contains(predicate),
            "missing triple cross-bind: {predicate}"
        );
    }
}

#[test]
fn terminal_arms_share_exact_transition_evidence_and_time_rules() {
    let terminal_at = Utc.timestamp_opt(1_900_000_000, 0).unwrap();
    assert_eq!(
        RecoveryTerminalTripleTermination::Fulfilled {
            transition_id: Uuid::from_u128(1),
            terminal_at,
        }
        .sql_projection(),
        ("fulfilled", "consumed", "consumed")
    );
    assert_eq!(
        RecoveryTerminalTripleTermination::Cancelled {
            terminal_signed_request_bytes: b"signed",
            terminal_signing_transcript_bytes: b"transcript",
            terminal_request_digest: &[3; 32],
            terminal_signature: &[4; 64],
            terminal_at,
        }
        .sql_projection(),
        ("cancelled", "released", "available")
    );
    assert_eq!(
        RecoveryTerminalTripleTermination::Expired { terminal_at }.sql_projection(),
        ("expired", "expired", "availableOrExpired")
    );
    let sql = compact(RECOVERY_TERMINAL_TRIPLE_SQL);
    assert!(sql.contains("$58 = rr.expires_at"));
    assert!(sql.contains("$58 = kr.expires_at"));
    assert!(sql.contains("kp.not_after = $58 THEN 'expired' ELSE 'available'"));
    assert_eq!(
        sql.matches("terminal_request_digest = CASE WHEN $52 = 'cancelled' THEN $56 ELSE NULL END")
            .count(),
        2
    );
    assert!(sql
        .contains("fulfilling_transition_id = CASE WHEN $52 = 'fulfilled' THEN $53 ELSE NULL END"));
    assert!(
        sql.contains("consumed_transition_id = CASE WHEN $52 = 'fulfilled' THEN $53 ELSE NULL END")
    );
    assert!(
        sql.contains("terminal_transition_id = CASE WHEN $52 = 'fulfilled' THEN $53 ELSE NULL END")
    );
}

#[test]
fn available_package_reservation_is_a_full_row_cas() {
    let sql = compact(AVAILABLE_RECOVERY_PACKAGE_RESERVATION_SQL);
    assert!(sql.contains("UPDATE chat.key_packages AS kp SET status = 'reserved'"));
    assert!(sql.contains("txid_current()::text = $1"));
    for predicate in [
        "kp.key_package_ref = $2",
        "kp.wrapper_bytes = $3",
        "kp.wrapper_sha256 = $4",
        "kp.init_key = $5",
        "kp.owner_did = $6",
        "kp.owner_device_id = $7",
        "kp.owner_key_id = $8",
        "kp.owner_auth_generation = $9",
        "kp.not_before = $10",
        "kp.not_after = $11",
        "kp.created_at = $12",
        "kp.status = 'available'",
        "kp.terminal_transition_id IS NULL",
        "kp.terminal_revocation_id IS NULL",
        "kp.terminal_at IS NULL",
    ] {
        assert!(
            sql.contains(predicate),
            "missing package CAS guard: {predicate}"
        );
    }
}
