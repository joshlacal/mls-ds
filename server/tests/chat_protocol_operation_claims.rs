//! Durable global-operation claim contract for clean chat.
//!
//! Run against the dedicated local database:
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_operation_claims -- --test-threads=1

mod common;

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};

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
    let sql = include_str!("../docs/operation_claim_completeness_activation.sql");

    for handler in [
        "blue.catbird.chat.enrollDevice",
        "blue.catbird.chat.rebindDeviceAuthentication",
        "blue.catbird.chat.replenishKeyPackages",
    ] {
        assert!(sql.contains(handler));
    }
    for legacy_api in [
        "arbitrate_business_idempotency",
        "recheck_business_authority",
        "record_completed_idempotency",
    ] {
        assert!(sql.contains(legacy_api));
    }

    assert!(sql.contains("ACCESS EXCLUSIVE MODE"));
    assert!(sql.contains("operation_claim_completeness_cutover"));
    assert!(sql.contains("cutover_at TIMESTAMPTZ NOT NULL"));
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
async fn staged_rollout_temporarily_allows_legacy_receipt_without_claim() {
    let pool = operation_claim_pool().await;
    let operation_id = uuid::Uuid::new_v4();
    let principal = "did:web:legacy-receipt.example.com";
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
    signing_transcript_bytes.extend_from_slice(b"canonical-projection");
    let request_digest: [u8; 32] = Sha256::digest(&signing_transcript_bytes).into();
    let response_bytes = br#"{"ok":true}"#;
    let response_sha256: [u8; 32] = Sha256::digest(response_bytes).into();
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
        INSERT INTO chat.idempotency_records(
            principal_did,endpoint_nsid,operation_id,request_digest,
            accepted_request_bytes,signing_transcript_bytes,signature,
            completed_status,response_bytes,response_sha256,completed_at
        ) VALUES(
            $1,'blue.catbird.chat.requestReset',$2,$3,$4,$5,$6,
            200,$7,$8,clock_timestamp()
        )
        "#,
    )
    .bind(principal)
    .bind(operation_id)
    .bind(request_digest.as_slice())
    .bind(&accepted_request_bytes)
    .bind(&signing_transcript_bytes)
    .bind([51_u8; 64].as_slice())
    .bind(response_bytes.as_slice())
    .bind(response_sha256.as_slice())
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .expect("legacy receipt-only completion remains staged until handler migration");
    transaction.rollback().await.unwrap();
}
