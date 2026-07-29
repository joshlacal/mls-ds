//! Durable global-operation claim contract for clean chat.
//!
//! Run against the dedicated local database:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_operation_claims -- --test-threads=1

mod common;

use std::collections::BTreeSet;
use std::path::Path;

use sha2::{Digest, Sha256, Sha384};
use sqlx::{PgPool, Postgres, Row, Transaction};

fn rust_sources_under(directory: &Path, sources: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("read Rust source directory") {
        let path = entry.expect("read Rust source entry").path();
        if path.is_dir() {
            rust_sources_under(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

#[test]
fn installed_operation_claim_migration_keeps_its_frozen_raw_bytes() {
    let migration = include_bytes!("../migrations/20260728000001_chat_operation_claims.sql");

    assert_eq!(
        migration.len(),
        6_299,
        "the installed 00001 migration changed byte length"
    );
    assert_eq!(
        hex::encode(Sha384::digest(migration)),
        "fd71f2eb5235226371f113b5738b752b27e901b72810e9ec1e1f201e979606e0b09a16be087103e4146b4fb9f8bdff8f",
        "the installed 00001 migration changed raw-byte SHA-384"
    );
}

#[test]
fn exact_kind_migration_keeps_its_frozen_raw_bytes() {
    let migration =
        include_bytes!("../migrations/20260728000002_exact_operation_claim_mutation_kind.sql");

    assert_eq!(
        migration.len(),
        16_972,
        "the installed 00002 migration changed byte length"
    );
    assert_eq!(
        hex::encode(Sha384::digest(migration)),
        "a5c0225818e350415e0ad3a88c5016d621a75bb64563f97023de9d27498cf113d8ef9d95c98621036c15ac3398dbee17",
        "the installed 00002 migration changed raw-byte SHA-384"
    );
}

#[test]
fn enrollment_claim_fk_deferral_migration_is_frozen_fail_closed_and_narrow() {
    let migration =
        include_bytes!("../migrations/20260728000003_defer_operation_claim_principal_fk.sql");
    let sql = std::str::from_utf8(migration).expect("migration is UTF-8");

    assert_eq!(
        migration.len(),
        6_570,
        "the reviewed 00003 migration changed byte length"
    );
    assert_eq!(
        hex::encode(Sha384::digest(migration)),
        "67cd6f9033b97d206f478a2baeee31dbd337a4e6d5e3bb5158467afc95064b91a6a81b202e11eae86f8d909de040b467",
        "the reviewed 00003 migration changed raw-byte SHA-384"
    );
    assert!(!sql.lines().any(|line| line.trim() == "BEGIN;"));
    assert!(!sql.lines().any(|line| line.trim() == "COMMIT;"));

    let lock = sql
        .find("LOCK TABLE chat.operation_claims IN ACCESS EXCLUSIVE MODE")
        .expect("claim writer lock");
    let preflight = sql.find("DO $$").expect("preflight");
    let drop_fk = sql
        .find("DROP CONSTRAINT operation_claims_principal_fk")
        .expect("drop exact principal FK");
    let add_fk = sql
        .find("ADD CONSTRAINT operation_claims_principal_fk")
        .expect("add exact principal FK");
    let postflight = sql.rfind("DO $$").expect("postflight");
    assert!(lock < preflight && preflight < drop_fk && drop_fk < add_fk && add_fk < postflight);

    assert_eq!(
        sql.matches("DROP CONSTRAINT operation_claims_principal_fk")
            .count(),
        1
    );
    assert_eq!(
        sql.matches("ADD CONSTRAINT operation_claims_principal_fk")
            .count(),
        1
    );
    assert_eq!(sql.matches("ALTER TABLE chat.operation_claims").count(), 2);
    for forbidden in [
        "ALTER TABLE chat.principals",
        "ALTER COLUMN",
        "CREATE TABLE",
        "CREATE INDEX",
        "INSERT INTO",
        "UPDATE chat.",
        "DELETE FROM",
    ] {
        assert!(
            !sql.contains(forbidden),
            "00003 must alter only the exact claim principal FK: {forbidden}"
        );
    }

    let compact = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    for required in [
        "constraint.conrelid = 'chat.operation_claims'::regclass",
        "constraint.connamespace = 'chat'::regnamespace",
        "constraint.conname = 'operation_claims_principal_fk'",
        "actual_type IS DISTINCT FROM 'f'",
        "actual_validated IS DISTINCT FROM TRUE",
        "actual_referenced_table IS DISTINCT FROM 'chat.principals'::regclass",
        "actual_match_type IS DISTINCT FROM 's'",
        "actual_update_action IS DISTINCT FROM 'a'",
        "actual_delete_action IS DISTINCT FROM 'a'",
        "actual_parent IS DISTINCT FROM 0",
        "actual_source_columns IS DISTINCT FROM ARRAY['principal_did']::TEXT[]",
        "actual_referenced_columns IS DISTINCT FROM ARRAY['user_did']::TEXT[]",
        "FROM unnest(constraint.conkey) WITH ORDINALITY",
        "FROM unnest(constraint.confkey) WITH ORDINALITY",
        "FOREIGN KEY (principal_did) REFERENCES chat.principals(user_did) DEFERRABLE INITIALLY DEFERRED",
    ] {
        assert!(
            compact.contains(required),
            "missing exact deferral invariant: {required}"
        );
    }
    assert_eq!(
        compact
            .matches("actual_deferrable IS DISTINCT FROM FALSE")
            .count(),
        1,
        "preflight must require an immediate FK"
    );
    assert_eq!(
        compact
            .matches("actual_deferred IS DISTINCT FROM FALSE")
            .count(),
        1,
        "preflight must require an initially-immediate FK"
    );
    assert_eq!(
        compact
            .matches("actual_deferrable IS DISTINCT FROM TRUE")
            .count(),
        1,
        "postflight must require a deferrable FK"
    );
    assert_eq!(
        compact
            .matches("actual_deferred IS DISTINCT FROM TRUE")
            .count(),
        1,
        "postflight must require an initially-deferred FK"
    );
}

#[test]
fn operation_claim_completeness_migration_keeps_its_review_bytes() {
    let migration =
        include_bytes!("../migrations/20260728000004_activate_operation_claim_completeness.sql");

    assert_eq!(
        migration.len(),
        15_837,
        "the reviewed 00004 migration changed byte length"
    );
    assert_eq!(
        hex::encode(Sha384::digest(migration)),
        "d7f92b96421a33f0385789f44c0fc2986321e8c7487e79e96c9c4880a1853e4c9d7d32f36bf3dfd22ff07a1cd6fb1674",
        "the reviewed 00004 migration changed raw-byte SHA-384"
    );
}

#[test]
fn operation_claim_rollout_inventory_orders_deferral_before_activation() {
    let readme = include_str!("../migrations/README.md");
    let claims = readme
        .find("20260728000001_chat_operation_claims.sql")
        .expect("claim migration docs");
    let exact_kind = readme
        .find("20260728000002_exact_operation_claim_mutation_kind.sql")
        .expect("exact-kind migration docs");
    let deferred_principal = readme
        .find("20260728000003_defer_operation_claim_principal_fk.sql")
        .expect("principal-FK migration docs");
    let activation = readme
        .find("20260728000004_activate_operation_claim_completeness.sql")
        .expect("activation migration docs");

    assert!(
        claims < exact_kind && exact_kind < deferred_principal && deferred_principal < activation
    );
    assert!(readme.contains(
        "SET LOCAL chat.operation_claim_activation_approved = \
         'handlers-and-legacy-apis-sealed'"
    ));
    assert!(readme.contains("normalized live constraint-catalog fingerprint remains pending"));
}

#[test]
fn exact_kind_migration_is_nul_safe_and_stages_legacy_receipts() {
    let sql = include_str!("../migrations/20260728000002_exact_operation_claim_mutation_kind.sql");
    assert!(sql.contains("sanitized := set_byte(sanitized,cursor + 4,49)"));
    assert!(sql.contains("document := convert_from(sanitized,'UTF8')::json"));
    assert!(sql.contains("FROM json_each(document)"));
    assert!(sql.contains("FROM json_each(body_value)"));
    assert!(sql.contains("body_count <> 1"));
    assert!(sql.contains("type_count <> 1"));
    assert!(!sql.contains("all_type_count"));
    assert!(sql.contains("WHEN OTHERS THEN"));
    assert!(!sql.contains("::jsonb"));
    assert!(sql.contains("chat.transcript_has_exact_domain"));
    assert!(sql.contains("chat.exact_wrapper_body_type"));
    assert!(sql.contains("chat.operation_mutation_kind_from_wrapper"));
    assert!(sql.contains("octet_length(transcript)"));
    assert!(sql.contains("substring("));
    assert!(sql.contains("DROP CONSTRAINT idempotency_records_operation_claim_fk"));
    assert!(sql.contains("IF claim_count = 0 THEN"));
    assert_eq!(
        sql.matches("WHEN chat.transcript_has_exact_domain").count(),
        25,
        "every frozen signed mutation domain needs one byte-safe classifier arm"
    );
    assert_eq!(
        sql.matches("WHEN exact_type = 'blue.catbird.chat.defs#")
            .count(),
        25,
        "every frozen decoded wrapper body needs one exact classifier arm"
    );
    assert!(sql.contains("claimed_kind <> wrapper_kind"));
    assert!(sql.contains("claimed_kind <> transcript_kind"));
    assert!(sql.contains("wrapper_kind <> transcript_kind"));

    let wrapper = serde_json::to_vec(&serde_json::json!({
        "body": {
            "$type": "blue.catbird.chat.defs#resetRequestBody",
            "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\u{0000}",
        },
        "signature": "test-only",
    }))
    .unwrap();
    assert!(
        wrapper
            .windows(br#"\u0000"#.len())
            .any(|window| window == br#"\u0000"#),
        "real canonical wrapper fixture must carry escaped NUL"
    );
    assert!(
        !wrapper.contains(&0),
        "JSON wrapper itself must remain valid UTF-8"
    );
}

#[test]
fn completeness_activation_drains_writers_and_preserves_only_bounded_legacy_orphans() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let mut sources = Vec::new();
    rust_sources_under(&source_root, &mut sources);
    let relative_writer_paths = sources
        .iter()
        .filter_map(|path| {
            let source = std::fs::read_to_string(path).expect("read Rust source");
            let compact = source.split_whitespace().collect::<Vec<_>>().join(" ");
            (compact.contains("INSERT INTO chat.idempotency_records"))
                .then(|| path.strip_prefix(manifest).unwrap().to_path_buf())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        relative_writer_paths,
        [
            Path::new("src/chat_protocol/repository/auth.rs").to_path_buf(),
            Path::new("src/chat_protocol/repository/prelude.rs").to_path_buf(),
        ]
        .into_iter()
        .collect(),
        "only the shared prelude and cfg(test) compatibility fixtures may insert receipts"
    );
    let claim_writer_paths = sources
        .iter()
        .filter_map(|path| {
            let source = std::fs::read_to_string(path).expect("read Rust source");
            let compact = source.split_whitespace().collect::<Vec<_>>().join(" ");
            (compact.contains("INSERT INTO chat.operation_claims"))
                .then(|| path.strip_prefix(manifest).unwrap().to_path_buf())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        claim_writer_paths,
        [Path::new("src/chat_protocol/repository/prelude.rs").to_path_buf()]
            .into_iter()
            .collect(),
        "the shared operation prelude must remain the only claim writer"
    );

    let auth_source = std::fs::read_to_string(source_root.join("chat_protocol/repository/auth.rs"))
        .expect("read authentication repository");
    for test_only_api in [
        "test_arbitrate_business_idempotency",
        "test_recheck_business_authority",
        "test_record_completed_idempotency",
    ] {
        let marker = format!("#[cfg(test)]\npub(crate) async fn {test_only_api}");
        assert!(
            auth_source.contains(&marker),
            "{test_only_api} must remain visibly test-only"
        );
    }
    for retired_api in [
        "pub(crate) async fn arbitrate_business_idempotency",
        "pub(crate) async fn recheck_business_authority",
        "pub(crate) async fn record_completed_idempotency",
    ] {
        assert!(
            !auth_source.contains(retired_api),
            "retired production receipt bypass resurfaced: {retired_api}"
        );
    }

    for (handler, prepare, complete) in [
        (
            "enroll_device.rs",
            "prelude::prepare_enrollment_operation",
            "prelude::complete_enrollment_bootstrap_operation",
        ),
        (
            "rebind_device_authentication.rs",
            "prelude::prepare_rebind_operation",
            "prelude::complete_rebind_bootstrap_operation",
        ),
        (
            "replenish_key_packages.rs",
            "prelude::prepare_replenishment_operation",
            "prelude::complete_replenishment_operation",
        ),
    ] {
        let source = std::fs::read_to_string(source_root.join("handlers/chat").join(handler))
            .unwrap_or_else(|error| panic!("read {handler}: {error}"));
        assert!(
            source.contains(prepare),
            "{handler} bypasses claim preparation"
        );
        assert!(
            source.contains(complete),
            "{handler} bypasses sealed completion"
        );
        assert!(
            !source.contains("INSERT INTO"),
            "{handler} writes around the repository boundary"
        );
    }

    let migration_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations/20260728000004_activate_operation_claim_completeness.sql");
    let migration = std::fs::read(&migration_path).expect("read activation migration");
    let sql = std::str::from_utf8(&migration).expect("activation migration is UTF-8");
    let template = include_bytes!("../docs/operation_claim_completeness_activation.sql");
    assert_eq!(
        migration, template,
        "the reviewed activation template must mirror the forward migration exactly"
    );

    for handler in [
        "blue.catbird.chat.enrollDevice",
        "blue.catbird.chat.rebindDeviceAuthentication",
        "blue.catbird.chat.replenishKeyPackages",
    ] {
        assert!(sql.contains(handler));
    }
    for retired_api in [
        "arbitrate_business_idempotency",
        "recheck_business_authority",
        "record_completed_idempotency",
    ] {
        assert!(sql.contains(retired_api));
    }

    assert!(sql.contains("ACCESS EXCLUSIVE MODE"));
    assert!(sql.contains("operation_claim_completeness_cutover"));
    assert!(sql.contains("cutover_at TIMESTAMPTZ NOT NULL"));
    assert!(sql.contains("legacy_receipt_set_sha256 BYTEA NOT NULL"));
    assert!(sql.contains("octet_length(legacy_receipt_set_sha256) = 32"));
    assert!(sql.contains("operation_claim_required BOOLEAN"));
    assert!(sql.contains("ALTER COLUMN operation_claim_required SET DEFAULT TRUE"));
    assert!(sql.contains("MATCH FULL"));
    assert!(!sql.contains("INSERT INTO chat.operation_claims"));
    assert!(!sql.lines().any(|line| line.trim() == "BEGIN;"));
    assert!(!sql.lines().any(|line| line.trim() == "COMMIT;"));
    let approval_gate = sql
        .find("chat.operation_claim_activation_approved")
        .unwrap();
    let first_writer_lock = sql.find("LOCK TABLE chat.operation_claims").unwrap();
    assert!(approval_gate < first_writer_lock);
    assert_eq!(
        sql.matches("LOCK TABLE chat.operation_claims IN ACCESS EXCLUSIVE MODE")
            .count(),
        1
    );
    assert_eq!(
        sql.matches("LOCK TABLE chat.idempotency_records IN ACCESS EXCLUSIVE MODE")
            .count(),
        1
    );

    let corrected_endpoint_mapping = sql
        .split_once("CREATE OR REPLACE FUNCTION chat.operation_endpoint_accepts_kind")
        .expect("corrected endpoint-kind mapping")
        .1
        .split_once("-- PRE-FK PREFLIGHT 1")
        .expect("mapping ends before the first preflight")
        .0
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(corrected_endpoint_mapping.contains(
        "WHEN 'blue.catbird.chat.requestLeave' THEN kind = ANY (ARRAY[ \
         'blue.catbird.chat.defs#leaveRequestBody', \
         'blue.catbird.chat.defs#zeroLeafLeaveBody' ])"
    ));
    let submit_transition = corrected_endpoint_mapping
        .split_once("WHEN 'blue.catbird.chat.submitTransition'")
        .expect("submitTransition endpoint-kind arm")
        .1
        .split_once("ELSE FALSE")
        .expect("submitTransition arm ends before the fallback")
        .0;
    assert!(submit_transition.contains("commitTransitionBody"));
    assert!(submit_transition.contains("policyTransitionBody"));
    assert!(submit_transition.contains("metadataTransitionBody"));
    assert!(submit_transition.contains("leafRecoveryFulfillmentBody"));
    assert!(submit_transition.contains("leaveCommitFulfillmentBody"));
    assert!(!submit_transition.contains("zeroLeafLeaveBody"));

    assert_eq!(
        sql.matches("CATBIRD-CHAT-LEGACY-RECEIPT-SET").count(),
        2,
        "baseline and post-classification must use the same domain-separated digest"
    );
    assert_eq!(
        sql.matches("string_agg(receipt.operation_id::text, ',' ORDER BY receipt.operation_id)")
            .count(),
        2,
        "baseline and post-classification must hash the exact sorted legacy set"
    );
    assert!(sql.contains("classified_legacy_set_sha256 BYTEA"));
    assert!(sql.contains("recorded_legacy_set_sha256 BYTEA"));
    assert!(sql.contains("classified_legacy_set_sha256 <> recorded_legacy_set_sha256"));

    let classify_legacy = sql.find("SET operation_claim_required = EXISTS").unwrap();
    let enforce_future_rows = sql
        .find("ADD CONSTRAINT idempotency_records_operation_claim_required_after_cutover")
        .unwrap();
    let marker_check = sql[enforce_future_rows..]
        .find("CHECK (operation_claim_required)")
        .unwrap()
        + enforce_future_rows;
    let marker_end = sql[enforce_future_rows..]
        .find("CREATE TRIGGER idempotency_records_immutable")
        .unwrap()
        + enforce_future_rows;
    let marker_statement = &sql[enforce_future_rows..marker_end];
    assert!(classify_legacy < enforce_future_rows);
    assert!(enforce_future_rows < marker_check);
    assert!(marker_statement.contains("CHECK (operation_claim_required)"));
    assert!(marker_statement.contains("NOT VALID;"));
    assert!(!sql.contains(
        "VALIDATE CONSTRAINT idempotency_records_operation_claim_required_after_cutover"
    ));

    assert!(sql.contains("operation_claim_completeness_cutover_immutable"));
    assert!(sql.contains("classified_legacy_count <> recorded_legacy_count"));
    assert!(sql.contains("CREATE OR REPLACE FUNCTION chat.assert_operation_claim_mapping"));
    assert!(sql.contains("receipt_required IS DISTINCT FROM TRUE"));
    assert!(sql.contains("receipt_completed_at <= activation_cutover"));
    assert!(!sql.contains("temporary unconditional"));
    let mapping = sql
        .split_once("CREATE OR REPLACE FUNCTION chat.assert_operation_claim_mapping")
        .unwrap()
        .1
        .split_once("-- MATCH FULL prevents")
        .unwrap()
        .0;
    let normalized_mapping = mapping.split_whitespace().collect::<Vec<_>>().join(" ");
    for exact_equality in [
        "receipt.operation_id = claim.operation_id",
        "receipt.principal_did = claim.principal_did",
        "receipt.endpoint_nsid = claim.endpoint_nsid",
        "receipt.request_digest = claim.request_digest",
        "digest(receipt.accepted_request_bytes, 'sha256') = claim.accepted_request_sha256",
        "receipt.signature = claim.signature",
        "claimed_kind <> wrapper_kind",
        "claimed_kind <> transcript_kind",
        "wrapper_kind <> transcript_kind",
    ] {
        assert!(normalized_mapping.contains(exact_equality));
    }

    let final_preflight = sql.rfind("DO $$").unwrap();
    let mapping_function = sql
        .find("CREATE OR REPLACE FUNCTION chat.assert_operation_claim_mapping")
        .unwrap();
    let add_fk = sql
        .find("ADD CONSTRAINT idempotency_records_operation_claim_fk")
        .unwrap();
    let fk_not_valid = sql[add_fk..].find("NOT VALID;").unwrap() + add_fk;
    let fk_validate = sql
        .find("VALIDATE CONSTRAINT idempotency_records_operation_claim_fk")
        .unwrap();
    assert!(final_preflight < mapping_function && mapping_function < add_fk);
    assert!(add_fk < fk_not_valid && fk_not_valid < fk_validate);
}

#[tokio::test]
async fn wrapper_classifier_accepts_decoder_equivalence_but_rejects_ambiguous_authority() {
    let pool = operation_claim_pool().await;
    let canonical = br#"{"body":{"$type":"blue.catbird.chat.defs#resetRequestBody","signatureDomain":"CATBIRD-CHAT-RESET-REQUEST\u0000"},"signature":"test-only"}"#;
    let kind: Option<String> =
        sqlx::query_scalar("SELECT chat.operation_mutation_kind_from_wrapper($1)")
            .bind(canonical.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        kind.as_deref(),
        Some("blue.catbird.chat.defs#resetRequestBody")
    );

    let pretty_wrapper = serde_json::to_vec_pretty(&serde_json::json!({
        "body": {
            "$type": "blue.catbird.chat.defs#resetRequestBody",
            "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\u{0000}",
        },
        "signature": "x",
    }))
    .unwrap();
    let reordered_wrapper =
        br#"{"signature":"x","body":{"$type":"blue.catbird.chat.defs#resetRequestBody"}}"#;
    let escaped_discriminator =
        br#"{"signature":"x","body":{"\u0024type":"blue.catbird.chat.defs#reset\u0052equestBody","signatureDomain":"CATBIRD-CHAT-RESET-REQUEST\u0000"}}"#;
    let literal_backslash_nul =
        br#"{"body":{"$type":"blue.catbird.chat.defs#resetRequestBody","signatureDomain":"CATBIRD-CHAT-RESET-REQUEST\u0000"},"signature":"\\u0000"}"#;
    let nested_policy_union = serde_json::to_vec(&serde_json::json!({
        "body": {
            "$type": "blue.catbird.chat.defs#policyTransitionBody",
            "participantChanges": [{
                "$type": "blue.catbird.chat.defs#removeParticipant",
                "userDid": "did:web:departing.example.com",
            }],
        },
        "signature": "x",
    }))
    .unwrap();
    let nested_commit_union = serde_json::to_vec(&serde_json::json!({
        "body": {
            "$type": "blue.catbird.chat.defs#commitTransitionBody",
            "manifest": {
                "participantChanges": [],
                "leafChanges": [{
                    "$type": "blue.catbird.chat.defs#removeLeaf",
                    "userDid": "did:web:departing.example.com",
                    "deviceId": "11111111-1111-4111-8111-111111111111",
                }],
            },
        },
        "signature": "x",
    }))
    .unwrap();
    let nested_leave_union = serde_json::to_vec(&serde_json::json!({
        "body": {
            "$type": "blue.catbird.chat.defs#leaveCommitFulfillmentBody",
            "manifest": {
                "participantChanges": [{
                    "$type": "blue.catbird.chat.defs#removeParticipant",
                    "userDid": "did:web:departing.example.com",
                }],
                "leafChanges": [{
                    "$type": "blue.catbird.chat.defs#removeLeaf",
                    "userDid": "did:web:departing.example.com",
                    "deviceId": "11111111-1111-4111-8111-111111111111",
                }],
            },
        },
        "signature": "x",
    }))
    .unwrap();
    for (equivalent, expected_kind) in [
        (
            pretty_wrapper.as_slice(),
            "blue.catbird.chat.defs#resetRequestBody",
        ),
        (
            reordered_wrapper.as_slice(),
            "blue.catbird.chat.defs#resetRequestBody",
        ),
        (
            escaped_discriminator.as_slice(),
            "blue.catbird.chat.defs#resetRequestBody",
        ),
        (
            literal_backslash_nul.as_slice(),
            "blue.catbird.chat.defs#resetRequestBody",
        ),
        (
            nested_policy_union.as_slice(),
            "blue.catbird.chat.defs#policyTransitionBody",
        ),
        (
            nested_commit_union.as_slice(),
            "blue.catbird.chat.defs#commitTransitionBody",
        ),
        (
            nested_leave_union.as_slice(),
            "blue.catbird.chat.defs#leaveCommitFulfillmentBody",
        ),
    ] {
        let kind: Option<String> =
            sqlx::query_scalar("SELECT chat.operation_mutation_kind_from_wrapper($1)")
                .bind(equivalent)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(kind.as_deref(), Some(expected_kind));
    }

    for noncanonical in [
        br#"x{"body":{"$type":"blue.catbird.chat.defs#resetRequestBody"},"signature":"x"}"#
            .as_slice(),
        br#"{"body":{"$type":"blue.catbird.chat.defs#resetRequestBody"},"b\u006fdy":{"$type":"blue.catbird.chat.defs#resetRequestBody"},"signature":"x"}"#
            .as_slice(),
        br#"{"body":{"$type":"blue.catbird.chat.defs#resetRequestBody","$type":"blue.catbird.chat.defs#resetRequestBody"},"signature":"x"}"#
            .as_slice(),
        br#"{"body":{"$type":"blue.catbird.chat.defs#resetRequestBody","\u0024type":"blue.catbird.chat.defs#resetRequestBody"},"signature":"x"}"#
            .as_slice(),
        br#"{"body":{"$type":"blue.catbird.chat.defs#resetRequestBody"},"signature":"x"}arbitrary-suffix"#
            .as_slice(),
        &[0xff, 0xfe, 0xfd],
    ] {
        let kind: Option<String> =
            sqlx::query_scalar("SELECT chat.operation_mutation_kind_from_wrapper($1)")
                .bind(noncanonical)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            kind.is_none(),
            "noncanonical, injected, or ambiguous wrapper bytes must not classify"
        );
    }
}

#[tokio::test]
async fn operation_claims_reserve_one_global_operation_identity() {
    let pool = common::chat_protocol::setup_chat_protocol_db(1).await;

    let row = sqlx::query(
        r#"
        SELECT
            EXISTS (
                SELECT 1
                  FROM pg_constraint
                 WHERE conrelid = 'chat.operation_claims'::regclass
                   AND contype = 'p'
                   AND pg_get_constraintdef(oid) = 'PRIMARY KEY (operation_id)'
            ) AS operation_id_is_global_primary_key,
            EXISTS (
                SELECT 1
                  FROM pg_constraint
                 WHERE conrelid = 'chat.idempotency_records'::regclass
                   AND contype = 'u'
                   AND pg_get_constraintdef(oid) = 'UNIQUE (operation_id)'
            ) AS receipt_operation_id_is_global
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("inspect the migrated global-operation claim constraints");

    assert!(
        row.get::<bool, _>("operation_id_is_global_primary_key"),
        "operation IDs must be globally claimed, independent of principal and endpoint"
    );
    assert!(
        row.get::<bool, _>("receipt_operation_id_is_global"),
        "completed receipts must preserve the same global operation-ID namespace"
    );
}

async fn insert_claim_and_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    endpoint: &str,
    wrapper_kind: &str,
    transcript_kind: &str,
    claimed_kind: &str,
) -> uuid::Uuid {
    fn signature_domain(kind: &str) -> &'static str {
        match kind {
            "blue.catbird.chat.defs#resetRequestBody" => "CATBIRD-CHAT-RESET-REQUEST",
            "blue.catbird.chat.defs#deviceRevocationBody" => "CATBIRD-CHAT-DEVICE-REVOKE",
            "blue.catbird.chat.defs#commitTransitionBody" => "CATBIRD-CHAT-COMMIT",
            "blue.catbird.chat.defs#policyTransitionBody" => "CATBIRD-CHAT-POLICY",
            other => panic!("missing test signature domain for {other}"),
        }
    }

    let operation_id = uuid::Uuid::new_v4();
    let principal = "did:web:operation-claim.example.com";
    let wrapper_signature_domain = signature_domain(wrapper_kind);
    let transcript_signature_domain = signature_domain(transcript_kind);
    let accepted_request_bytes = serde_json::to_vec(&serde_json::json!({
        "body": {
            "$type": wrapper_kind,
            "signatureDomain": format!("{wrapper_signature_domain}\u{0000}"),
            "idempotencyKey": operation_id,
        },
        "signature": "test-only"
    }))
    .unwrap();
    let mut signing_transcript_bytes = transcript_signature_domain.as_bytes().to_vec();
    signing_transcript_bytes.push(0);
    signing_transcript_bytes
        .extend_from_slice(format!("operation-claim:{operation_id}").as_bytes());
    let request_digest: [u8; 32] = Sha256::digest(&signing_transcript_bytes).into();
    let accepted_request_sha256: [u8; 32] = Sha256::digest(&accepted_request_bytes).into();
    let signature = [37_u8; 64];
    let response_bytes = br#"{"ok":true}"#;
    let response_sha256: [u8; 32] = Sha256::digest(response_bytes).into();

    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at)
         VALUES($1,clock_timestamp()) ON CONFLICT DO NOTHING",
    )
    .bind(principal)
    .execute(&mut **transaction)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.operation_claims(
            operation_id,principal_did,endpoint_nsid,mutation_kind,
            request_digest,accepted_request_sha256,signature,claimed_at
        ) VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp())
        "#,
    )
    .bind(operation_id)
    .bind(principal)
    .bind(endpoint)
    .bind(claimed_kind)
    .bind(request_digest.as_slice())
    .bind(accepted_request_sha256.as_slice())
    .bind(signature.as_slice())
    .execute(&mut **transaction)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records(
            principal_did,endpoint_nsid,operation_id,request_digest,
            accepted_request_bytes,signing_transcript_bytes,signature,
            completed_status,response_bytes,response_sha256,completed_at
        ) VALUES($1,$2,$3,$4,$5,$6,$7,200,$8,$9,clock_timestamp())
        "#,
    )
    .bind(principal)
    .bind(endpoint)
    .bind(operation_id)
    .bind(request_digest.as_slice())
    .bind(&accepted_request_bytes)
    .bind(&signing_transcript_bytes)
    .bind(signature.as_slice())
    .bind(response_bytes.as_slice())
    .bind(response_sha256.as_slice())
    .execute(&mut **transaction)
    .await
    .unwrap();
    operation_id
}

fn assert_deferred_mapping_rejection(error: sqlx::Error) {
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database| database.code()),
        Some(std::borrow::Cow::Borrowed("23514")),
        "wrong operation claim mapping must fail as a check violation: {error:?}"
    );
}

async fn operation_claim_pool() -> PgPool {
    common::chat_protocol::setup_chat_protocol_db(1).await
}

#[tokio::test]
async fn transcript_classifier_is_exact_nul_safe_and_closed_over_all_kinds() {
    let pool = operation_claim_pool().await;
    let cases = [
        ("CATBIRD-CHAT-DEVICE-ENROLL", "deviceEnrollmentBody"),
        (
            "CATBIRD-CHAT-DEVICE-REPLENISH",
            "keyPackageReplenishmentBody",
        ),
        (
            "CATBIRD-CHAT-DEVICE-REBIND",
            "deviceAuthenticationRebindBody",
        ),
        ("CATBIRD-CHAT-DEVICE-REVOKE", "deviceRevocationBody"),
        ("CATBIRD-CHAT-BLOB-PREPARE", "blobUploadPreparationBody"),
        ("CATBIRD-CHAT-BLOB-DELETE", "blobDeletionBody"),
        ("CATBIRD-CHAT-CREATE", "creationBody"),
        ("CATBIRD-CHAT-COMMIT", "commitTransitionBody"),
        ("CATBIRD-CHAT-POLICY", "policyTransitionBody"),
        ("CATBIRD-CHAT-ACCEPT", "participantAcceptanceBody"),
        ("CATBIRD-CHAT-MESSAGE", "applicationSendBody"),
        ("CATBIRD-CHAT-TYPING", "typingBody"),
        ("CATBIRD-CHAT-METADATA", "metadataTransitionBody"),
        ("CATBIRD-CHAT-RESET-REQUEST", "resetRequestBody"),
        ("CATBIRD-CHAT-RESET-ACTIVATE", "resetActivationBody"),
        (
            "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST",
            "leafRecoveryRequestBody",
        ),
        (
            "CATBIRD-CHAT-LEAF-RECOVERY-CANCEL",
            "leafRecoveryCancellationBody",
        ),
        (
            "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL",
            "leafRecoveryFulfillmentBody",
        ),
        ("CATBIRD-CHAT-CLOSE", "conversationCloseBody"),
        ("CATBIRD-CHAT-LEAVE-REQUEST", "leaveRequestBody"),
        ("CATBIRD-CHAT-LEAVE-ZERO-LEAF", "zeroLeafLeaveBody"),
        ("CATBIRD-CHAT-LEAVE-CANCEL", "leaveCancellationBody"),
        (
            "CATBIRD-CHAT-LEAVE-FULFILL-COMMIT",
            "leaveCommitFulfillmentBody",
        ),
        ("CATBIRD-CHAT-WELCOME-ACK", "welcomeAcknowledgementBody"),
        ("CATBIRD-CHAT-WELCOME-REJECT", "welcomeRejectionBody"),
    ];
    for (domain, body) in cases {
        let mut transcript = domain.as_bytes().to_vec();
        transcript.push(0);
        transcript.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        let kind: Option<String> =
            sqlx::query_scalar("SELECT chat.operation_mutation_kind_from_transcript($1)")
                .bind(&transcript)
                .fetch_one(&pool)
                .await
                .unwrap();
        let expected = format!("blue.catbird.chat.defs#{body}");
        assert_eq!(kind.as_deref(), Some(expected.as_str()));
    }

    for malformed in [
        b"CATBIRD-CHAT-RESET-REQUEST".to_vec(),
        b"CATBIRD-CHAT-RESET-REQUEST\0".to_vec(),
        b"CATBIRD-CHAT-RESET-REQUEST\x01payload".to_vec(),
        b"CATBIRD-CHAT-UNKNOWN\0payload".to_vec(),
    ] {
        let kind: Option<String> =
            sqlx::query_scalar("SELECT chat.operation_mutation_kind_from_transcript($1)")
                .bind(malformed)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(kind.is_none());
    }
}

#[tokio::test]
async fn activated_endpoint_kind_mapping_matches_the_frozen_rust_authority() {
    let pool = operation_claim_pool().await;
    for (endpoint, kind, expected) in [
        (
            "blue.catbird.chat.requestLeave",
            "blue.catbird.chat.defs#leaveRequestBody",
            true,
        ),
        (
            "blue.catbird.chat.requestLeave",
            "blue.catbird.chat.defs#zeroLeafLeaveBody",
            true,
        ),
        (
            "blue.catbird.chat.submitTransition",
            "blue.catbird.chat.defs#zeroLeafLeaveBody",
            false,
        ),
        (
            "blue.catbird.chat.submitTransition",
            "blue.catbird.chat.defs#commitTransitionBody",
            true,
        ),
        (
            "blue.catbird.chat.submitTransition",
            "blue.catbird.chat.defs#policyTransitionBody",
            true,
        ),
        (
            "blue.catbird.chat.submitTransition",
            "blue.catbird.chat.defs#metadataTransitionBody",
            true,
        ),
        (
            "blue.catbird.chat.submitTransition",
            "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
            true,
        ),
        (
            "blue.catbird.chat.submitTransition",
            "blue.catbird.chat.defs#leaveCommitFulfillmentBody",
            true,
        ),
    ] {
        let accepted: bool =
            sqlx::query_scalar("SELECT chat.operation_endpoint_accepts_kind($1,$2)")
                .bind(endpoint)
                .bind(kind)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            accepted, expected,
            "wrong live endpoint-kind mapping for {endpoint} / {kind}"
        );
    }
}

#[tokio::test]
async fn deferred_mapping_rejects_allowed_but_wrong_exact_kind() {
    let pool = operation_claim_pool().await;
    let mut transaction = pool.begin().await.unwrap();
    insert_claim_and_receipt(
        &mut transaction,
        "blue.catbird.chat.submitTransition",
        "blue.catbird.chat.defs#commitTransitionBody",
        "blue.catbird.chat.defs#commitTransitionBody",
        "blue.catbird.chat.defs#policyTransitionBody",
    )
    .await;

    let error = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .unwrap_err();
    assert_deferred_mapping_rejection(error);
    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn deferred_mapping_rejects_endpoint_incompatible_submit_transition_kind() {
    let pool = operation_claim_pool().await;
    let mut transaction = pool.begin().await.unwrap();
    insert_claim_and_receipt(
        &mut transaction,
        "blue.catbird.chat.submitTransition",
        "blue.catbird.chat.defs#deviceRevocationBody",
        "blue.catbird.chat.defs#deviceRevocationBody",
        "blue.catbird.chat.defs#commitTransitionBody",
    )
    .await;

    let error = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .unwrap_err();
    assert_deferred_mapping_rejection(error);
    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn deferred_mapping_rejects_wrapper_kind_that_disagrees_with_transcript() {
    let pool = operation_claim_pool().await;
    let mut transaction = pool.begin().await.unwrap();
    insert_claim_and_receipt(
        &mut transaction,
        "blue.catbird.chat.requestReset",
        "blue.catbird.chat.defs#deviceRevocationBody",
        "blue.catbird.chat.defs#resetRequestBody",
        "blue.catbird.chat.defs#resetRequestBody",
    )
    .await;

    let error = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .unwrap_err();
    assert_deferred_mapping_rejection(error);
    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn exact_claim_receipt_mapping_passes_and_rollback_releases_the_id() {
    let pool = operation_claim_pool().await;
    let mut transaction = pool.begin().await.unwrap();
    let operation_id = insert_claim_and_receipt(
        &mut transaction,
        "blue.catbird.chat.requestReset",
        "blue.catbird.chat.defs#resetRequestBody",
        "blue.catbird.chat.defs#resetRequestBody",
        "blue.catbird.chat.defs#resetRequestBody",
    )
    .await;
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .expect("an exact one-claim/one-receipt mapping must pass");
    transaction.rollback().await.unwrap();

    let retained: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.operation_claims WHERE operation_id=$1)",
    )
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!retained, "rollback must not burn the global operation ID");
}

#[tokio::test]
async fn claim_without_exactly_one_receipt_is_rejected_and_rollback_releases_the_id() {
    let pool = operation_claim_pool().await;
    let operation_id = uuid::Uuid::new_v4();
    let principal = "did:web:unpaired-operation-claim.example.com";
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at)
         VALUES($1,clock_timestamp()) ON CONFLICT DO NOTHING",
    )
    .bind(principal)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.operation_claims(
            operation_id,principal_did,endpoint_nsid,mutation_kind,
            request_digest,accepted_request_sha256,signature,claimed_at
        ) VALUES(
            $1,$2,'blue.catbird.chat.requestReset',
            'blue.catbird.chat.defs#resetRequestBody',
            $3,$4,$5,clock_timestamp()
        )
        "#,
    )
    .bind(operation_id)
    .bind(principal)
    .bind([41_u8; 32].as_slice())
    .bind([42_u8; 32].as_slice())
    .bind([43_u8; 64].as_slice())
    .execute(&mut *transaction)
    .await
    .unwrap();

    let error = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .unwrap_err();
    assert_deferred_mapping_rejection(error);
    transaction.rollback().await.unwrap();

    let retained: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.operation_claims WHERE operation_id=$1)",
    )
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!retained, "failed claim transaction must not burn the ID");
}

#[tokio::test]
async fn post_cutover_receipts_cannot_bypass_operation_claim_completeness() {
    let pool = operation_claim_pool().await;
    let principal = "did:web:post-cutover-receipt.example.com";
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at)
         VALUES($1,clock_timestamp()) ON CONFLICT DO NOTHING",
    )
    .bind(principal)
    .execute(&pool)
    .await
    .unwrap();

    for (label, marker_sql, expected_code) in [
        ("default TRUE without a claim", "", "23503"),
        (
            "explicit FALSE exception forgery",
            ",operation_claim_required",
            "23514",
        ),
        (
            "explicit NULL exception bypass",
            ",operation_claim_required",
            "23502",
        ),
    ] {
        let operation_id = uuid::Uuid::new_v4();
        let accepted_request_bytes = serde_json::to_vec(&serde_json::json!({
            "body": {
                "$type": "blue.catbird.chat.defs#resetRequestBody",
                "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\u{0000}",
                "idempotencyKey": operation_id,
            },
            "signature": "test-only"
        }))
        .unwrap();
        let mut signing_transcript_bytes = b"CATBIRD-CHAT-RESET-REQUEST\0".to_vec();
        signing_transcript_bytes.extend_from_slice(operation_id.as_bytes());
        let request_digest: [u8; 32] = Sha256::digest(&signing_transcript_bytes).into();
        let response_bytes = br#"{"ok":true}"#;
        let response_sha256: [u8; 32] = Sha256::digest(response_bytes).into();
        let sql = if marker_sql.is_empty() {
            r#"
            INSERT INTO chat.idempotency_records(
                principal_did,endpoint_nsid,operation_id,request_digest,
                accepted_request_bytes,signing_transcript_bytes,signature,
                completed_status,response_bytes,response_sha256,completed_at
            ) VALUES(
                $1,'blue.catbird.chat.requestReset',$2,$3,$4,$5,$6,
                200,$7,$8,clock_timestamp()
            )
            "#
        } else if label.starts_with("explicit FALSE") {
            r#"
            INSERT INTO chat.idempotency_records(
                principal_did,endpoint_nsid,operation_id,request_digest,
                accepted_request_bytes,signing_transcript_bytes,signature,
                completed_status,response_bytes,response_sha256,completed_at,
                operation_claim_required
            ) VALUES(
                $1,'blue.catbird.chat.requestReset',$2,$3,$4,$5,$6,
                200,$7,$8,clock_timestamp(),FALSE
            )
            "#
        } else {
            r#"
            INSERT INTO chat.idempotency_records(
                principal_did,endpoint_nsid,operation_id,request_digest,
                accepted_request_bytes,signing_transcript_bytes,signature,
                completed_status,response_bytes,response_sha256,completed_at,
                operation_claim_required
            ) VALUES(
                $1,'blue.catbird.chat.requestReset',$2,$3,$4,$5,$6,
                200,$7,$8,clock_timestamp(),NULL
            )
            "#
        };
        let error = sqlx::query(sql)
            .bind(principal)
            .bind(operation_id)
            .bind(request_digest.as_slice())
            .bind(&accepted_request_bytes)
            .bind(&signing_transcript_bytes)
            .bind([51_u8; 64].as_slice())
            .bind(response_bytes.as_slice())
            .bind(response_sha256.as_slice())
            .execute(&pool)
            .await
            .unwrap_err();
        assert_eq!(
            error
                .as_database_error()
                .and_then(|database| database.code())
                .as_deref(),
            Some(expected_code),
            "{label} must fail closed: {error:?}"
        );
    }
}
