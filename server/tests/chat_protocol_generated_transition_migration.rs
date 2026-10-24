//! Local PostgreSQL compatibility for the generated-transition classifier.
//!
//! The deliberately minimal wrapper/transcript/signature values below are SQL
//! authority fixtures, not valid signed protocol messages. Real cryptographic
//! admission and persistence are covered by the separate authenticated handler
//! target. Every test creates and reaps its own guarded loopback database.

mod common;

use std::borrow::Cow;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{migrate::Migrator, PgPool};
use uuid::Uuid;

const MIGRATION_VERSION: i64 = 20261025000001;
const MIGRATION_SQL: &str =
    include_str!("../migrations/20261025000001_generated_transition_wrapper_kind.sql");
const PREFIX: &str = "blue.catbird.chat.defs#";
const SUBMIT: &str = "blue.catbird.chat.submitTransition";
const VARIANTS: [(&str, &str, &str); 5] = [
    (
        "signedCommitTransition",
        "commitTransitionBody",
        "CATBIRD-CHAT-COMMIT",
    ),
    (
        "signedPolicyTransition",
        "policyTransitionBody",
        "CATBIRD-CHAT-POLICY",
    ),
    (
        "signedLeafRecoveryFulfillment",
        "leafRecoveryFulfillmentBody",
        "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL",
    ),
    (
        "signedMetadataTransition",
        "metadataTransitionBody",
        "CATBIRD-CHAT-METADATA",
    ),
    (
        "signedLeaveCommitFulfillment",
        "leaveCommitFulfillmentBody",
        "CATBIRD-CHAT-LEAVE-FULFILL-COMMIT",
    ),
];

fn wrapper(variant: (&str, &str, &str), body_tag: bool) -> Value {
    let mut value = json!({
        "$type": format!("{PREFIX}{}", variant.0),
        "body": {"signatureDomain": format!("{}\0", variant.2)},
        "signature": "sql-authority-fixture",
    });
    if body_tag {
        value["body"]["$type"] = json!(format!("{PREFIX}{}", variant.1));
    }
    value
}

async fn classify(pool: &PgPool, bytes: &[u8]) -> Option<String> {
    sqlx::query_scalar("SELECT chat.operation_mutation_kind_from_wrapper($1)")
        .bind(bytes)
        .fetch_one(pool)
        .await
        .expect("run exact wrapper classifier")
}

async fn apply_catalog(pool: &PgPool, include_successor: bool) {
    let full = sqlx::migrate!("./migrations");
    assert_eq!(
        full.iter()
            .filter(|migration| migration.version == MIGRATION_VERSION)
            .count(),
        1,
        "the new 14-digit migration version must be unique"
    );
    let migrator = Migrator {
        migrations: Cow::Owned(
            full.iter()
                .filter(|migration| include_successor || migration.version != MIGRATION_VERSION)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
    };
    let mut connection = pool.acquire().await.unwrap();
    sqlx::query("SET chat.operation_claim_activation_approved='handlers-and-legacy-apis-sealed'")
        .execute(&mut *connection)
        .await
        .unwrap();
    let result = migrator.run_direct(&mut *connection).await;
    sqlx::query("RESET chat.operation_claim_activation_approved")
        .execute(&mut *connection)
        .await
        .unwrap();
    result.expect("apply the catalog on an owned disposable database");
}

async fn classifier_matrix(pool: &PgPool) {
    for variant in VARIANTS {
        for body_tag in [false, true] {
            let value = wrapper(variant, body_tag);
            let expected = format!("{PREFIX}{}", variant.1);
            for bytes in [
                serde_json::to_vec(&value).unwrap(),
                serde_json::to_vec_pretty(&value).unwrap(),
            ] {
                assert_eq!(
                    classify(pool, &bytes).await.as_deref(),
                    Some(expected.as_str())
                );
            }
        }
        let mut legacy = wrapper(variant, true);
        legacy.as_object_mut().unwrap().remove("$type");
        assert_eq!(
            classify(pool, &serde_json::to_vec(&legacy).unwrap()).await,
            Some(format!("{PREFIX}{}", variant.1)),
            "existing untagged wrappers retain their explicit body authority"
        );
    }
    // Other legacy operations remain accepted only with their explicit body tag.
    let legacy = br#"{"body":{"$type":"blue.catbird.chat.defs#resetRequestBody","signatureDomain":"CATBIRD-CHAT-RESET-REQUEST\u0000"},"signature":"\\u0000"}"#;
    assert_eq!(
        classify(pool, legacy).await.as_deref(),
        Some("blue.catbird.chat.defs#resetRequestBody")
    );
    let escaped = br#"{"\u0024type":"blue.catbird.chat.defs#signedPolicyTransition","b\u006fdy":{"\u0024type":"blue.catbird.chat.defs#policyTransitionBody","signatureDomain":"CATBIRD-CHAT-POLICY\u0000"},"signature":"\\u0000"}"#;
    assert_eq!(
        classify(pool, escaped).await.as_deref(),
        Some("blue.catbird.chat.defs#policyTransitionBody")
    );

    let good = wrapper(VARIANTS[1], false);
    let mut invalid: Vec<(&str, Vec<u8>)> = Vec::new();
    for (label, tag) in [
        ("unknown outer tag", json!("blue.catbird.chat.defs#unknown")),
        (
            "other namespace",
            json!("other.namespace#signedPolicyTransition"),
        ),
        (
            "non-transition wrapper",
            json!("blue.catbird.chat.defs#signedResetRequest"),
        ),
        ("null outer tag", Value::Null),
        ("number outer tag", json!(7)),
        (
            "object outer tag",
            json!({"$type": "blue.catbird.chat.defs#signedPolicyTransition"}),
        ),
    ] {
        let mut value = good.clone();
        value["$type"] = tag;
        invalid.push((label, serde_json::to_vec(&value).unwrap()));
    }
    for (label, body) in [
        ("null body", Value::Null),
        ("array body", json!([])),
        ("string body", json!("body")),
        ("number body", json!(1)),
    ] {
        let mut value = good.clone();
        value["body"] = body;
        invalid.push((label, serde_json::to_vec(&value).unwrap()));
    }
    for (label, tag) in [
        (
            "wrong body tag",
            json!("blue.catbird.chat.defs#commitTransitionBody"),
        ),
        ("unknown body tag", json!("blue.catbird.chat.defs#unknown")),
        ("null body tag", Value::Null),
        ("numeric body tag", json!(1)),
    ] {
        let mut value = good.clone();
        value["body"]["$type"] = tag;
        invalid.push((label, serde_json::to_vec(&value).unwrap()));
    }
    for field in ["$type", "body", "signature"] {
        let mut value = good.clone();
        value.as_object_mut().unwrap().remove(field);
        invalid.push((
            "missing required authority field",
            serde_json::to_vec(&value).unwrap(),
        ));
    }
    let mut extra = good.clone();
    extra["unexpected"] = json!(true);
    invalid.push(("extra root field", serde_json::to_vec(&extra).unwrap()));
    let text = serde_json::to_string(&good).unwrap();
    for (label, duplicate) in [
        (
            "duplicate outer tag",
            r#""$type":"blue.catbird.chat.defs#signedPolicyTransition","#,
        ),
        (
            "escaped duplicate outer tag",
            r#""\u0024type":"blue.catbird.chat.defs#signedPolicyTransition","#,
        ),
        ("duplicate body", r#""body":{},"#),
        ("escaped duplicate body", r#""b\u006fdy":{},"#),
        ("duplicate signature", r#""signature":"other","#),
        (
            "escaped duplicate signature",
            r#""sign\u0061ture":"other","#,
        ),
    ] {
        invalid.push((label, format!("{{{duplicate}{}", &text[1..]).into_bytes()));
    }
    for (label, bytes) in [
        ("duplicate body tag", br#"{"$type":"blue.catbird.chat.defs#signedPolicyTransition","body":{"$type":"blue.catbird.chat.defs#policyTransitionBody","$type":"blue.catbird.chat.defs#policyTransitionBody"},"signature":"x"}"#.as_slice()),
        ("escaped duplicate body tag", br#"{"$type":"blue.catbird.chat.defs#signedPolicyTransition","body":{"$type":"blue.catbird.chat.defs#policyTransitionBody","\u0024type":"blue.catbird.chat.defs#policyTransitionBody"},"signature":"x"}"#.as_slice()),
        ("legacy missing body tag", br#"{"body":{},"signature":"x"}"#.as_slice()),
        ("root array", b"[]".as_slice()),
        ("root null", b"null".as_slice()),
        ("invalid UTF-8", &[0xff, 0xfe]),
    ] {
        invalid.push((label, bytes.to_vec()));
    }
    invalid.push(("trailing JSON", format!("{text} null").into_bytes()));
    for (label, bytes) in invalid {
        assert_eq!(classify(pool, &bytes).await, None, "must reject {label}");
    }
}

#[derive(Clone, Copy, Debug)]
enum Mismatch {
    None,
    BodyTag,
    ClaimKind,
    TranscriptKind,
    TranscriptDomain,
    Endpoint,
    RequestDigest,
    ExactWrapper,
    Signature,
}

/// The SQL gate must bind the independently stored products, even though these
/// fixture signatures and transcript suffixes are not cryptographic products.
async fn insert_authority_fixture(
    pool: &PgPool,
    variant: (&str, &str, &str),
    body_tag: bool,
    tagged: bool,
    mismatch: Mismatch,
) -> (Uuid, Result<(), sqlx::Error>) {
    let operation_id = Uuid::new_v4();
    let principal = "did:web:generated-migration.example.com";
    let mut value = wrapper(variant, body_tag);
    if !tagged {
        value.as_object_mut().unwrap().remove("$type");
    }
    if matches!(mismatch, Mismatch::BodyTag) {
        value["body"]["$type"] = json!(format!("{PREFIX}commitTransitionBody"));
    }
    let raw = serde_json::to_vec(&value).unwrap();
    let domain = match mismatch {
        Mismatch::TranscriptKind => "CATBIRD-CHAT-COMMIT",
        Mismatch::TranscriptDomain => "CATBIRD-CHAT-POLICY-OTHER",
        _ => variant.2,
    };
    let mut transcript = format!("{domain}\0sql-fixture:").into_bytes();
    transcript.extend_from_slice(operation_id.as_bytes());
    let digest = Sha256::digest(&transcript).to_vec();
    let mut claimed_digest = digest.clone();
    if matches!(mismatch, Mismatch::RequestDigest) {
        claimed_digest[0] ^= 1;
    }
    let mut claimed_raw_hash = Sha256::digest(&raw).to_vec();
    if matches!(mismatch, Mismatch::ExactWrapper) {
        // Same semantics, different retained bytes still cannot replace custody.
        claimed_raw_hash = Sha256::digest(serde_json::to_vec_pretty(&value).unwrap()).to_vec();
    }
    let signature = [37u8; 64];
    let mut claimed_signature = signature;
    if matches!(mismatch, Mismatch::Signature) {
        claimed_signature[0] ^= 1;
    }
    let (endpoint, claimed_kind) = match mismatch {
        Mismatch::Endpoint => ("blue.catbird.chat.requestReset", "resetRequestBody"),
        Mismatch::ClaimKind => (SUBMIT, "commitTransitionBody"),
        _ => (SUBMIT, variant.1),
    };
    let response = br#"{"sqlFixture":true}"#;
    let response_hash = Sha256::digest(response).to_vec();
    let mut transaction = pool.begin().await.unwrap();
    let result = async {
        sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,clock_timestamp()) ON CONFLICT DO NOTHING")
            .bind(principal).execute(&mut *transaction).await?;
        sqlx::query(
            "INSERT INTO chat.operation_claims(operation_id,principal_did,endpoint_nsid,mutation_kind,request_digest,accepted_request_sha256,signature,claimed_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp())",
        )
        .bind(operation_id).bind(principal).bind(endpoint).bind(format!("{PREFIX}{claimed_kind}"))
        .bind(&claimed_digest).bind(&claimed_raw_hash).bind(claimed_signature.as_slice())
        .execute(&mut *transaction).await?;
        sqlx::query(
            "INSERT INTO chat.idempotency_records(principal_did,endpoint_nsid,operation_id,request_digest,accepted_request_bytes,signing_transcript_bytes,signature,completed_status,response_bytes,response_sha256,completed_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,200,$8,$9,clock_timestamp())",
        )
        .bind(principal).bind(endpoint).bind(operation_id).bind(&digest).bind(&raw)
        .bind(&transcript).bind(signature.as_slice()).bind(response.as_slice()).bind(&response_hash)
        .execute(&mut *transaction).await?;
        Ok::<(), sqlx::Error>(())
    }.await;
    let result = match result {
        Ok(()) => transaction.commit().await,
        Err(error) => {
            transaction.rollback().await.unwrap();
            Err(error)
        }
    };
    (operation_id, result)
}

async fn authority_matrix(pool: &PgPool) {
    for variant in VARIANTS {
        for body_tag in [false, true] {
            let (operation, result) =
                insert_authority_fixture(pool, variant, body_tag, true, Mismatch::None).await;
            result.unwrap_or_else(|error| panic!("valid SQL authority {}: {error}", variant.0));
            let raw: Vec<u8> = sqlx::query_scalar(
                "SELECT accepted_request_bytes FROM chat.idempotency_records WHERE operation_id=$1",
            )
            .bind(operation)
            .fetch_one(pool)
            .await
            .unwrap();
            assert_eq!(
                raw,
                serde_json::to_vec(&wrapper(variant, body_tag)).unwrap()
            );
        }
    }
    for mismatch in [
        Mismatch::BodyTag,
        Mismatch::ClaimKind,
        Mismatch::TranscriptKind,
        Mismatch::TranscriptDomain,
        Mismatch::Endpoint,
        Mismatch::RequestDigest,
        Mismatch::ExactWrapper,
        Mismatch::Signature,
    ] {
        let (operation, result) =
            insert_authority_fixture(pool, VARIANTS[1], false, true, mismatch).await;
        let error =
            result.expect_err("inconsistent authority must fail at SQL admission or commit");
        assert_eq!(
            error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("23514"),
            "{mismatch:?}: {error}"
        );
        let retained: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM chat.operation_claims WHERE operation_id=$1) + \
                    (SELECT count(*) FROM chat.idempotency_records WHERE operation_id=$1)",
        )
        .bind(operation)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            retained, 0,
            "{mismatch:?}: rejected transaction must retain no authority rows"
        );
    }
}

async fn immutable_authority_catalog(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT 'function:' || p.oid::regprocedure::text, pg_get_functiondef(p.oid) \
         FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace \
         WHERE n.nspname='chat' AND p.proname <> 'exact_wrapper_body_type' \
         UNION ALL SELECT 'constraint:' || c.conrelid::regclass::text || ':' || c.conname, pg_get_constraintdef(c.oid) \
         FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='chat' \
         UNION ALL SELECT 'trigger:' || t.tgrelid::regclass::text || ':' || t.tgname, pg_get_triggerdef(t.oid) \
         FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname='chat' AND NOT t.tgisinternal ORDER BY 1",
    ).fetch_all(pool).await.unwrap()
}

#[tokio::test]
async fn generated_transition_classifier_fresh_catalog_preserves_authority() {
    let migration_guard = common::fresh_db::acquire_migration_lock().await;
    let database = common::fresh_db::DisposableDatabase::mint("chat_freshdb_").await;
    let pool = database.connect(2).await;
    apply_catalog(&pool, true).await;
    drop(migration_guard);
    classifier_matrix(&pool).await;
    authority_matrix(&pool).await;
    pool.close().await;
}

#[tokio::test]
async fn generated_transition_classifier_upgrade_is_additive_and_idempotent() {
    let migration_guard = common::fresh_db::acquire_migration_lock().await;
    let database = common::fresh_db::DisposableDatabase::mint("chat_freshdb_").await;
    let pool = database.connect(2).await;
    apply_catalog(&pool, false).await;
    let (legacy_operation, legacy_result) =
        insert_authority_fixture(&pool, VARIANTS[1], true, false, Mismatch::None).await;
    legacy_result.expect("pre-upgrade native authority commits");
    assert_eq!(
        classify(
            &pool,
            &serde_json::to_vec(&wrapper(VARIANTS[1], false)).unwrap()
        )
        .await,
        None,
        "old classifier reproduces missing-body-tag rejection"
    );
    let before_catalog = immutable_authority_catalog(&pool).await;
    let before_ledger: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version,checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    let before_rows: Value = sqlx::query_scalar(
        "SELECT jsonb_build_object('claim', to_jsonb(c), 'receipt', to_jsonb(i)) \
         FROM chat.operation_claims c JOIN chat.idempotency_records i USING(operation_id) WHERE operation_id=$1",
    ).bind(legacy_operation).fetch_one(&pool).await.unwrap();
    apply_catalog(&pool, true).await;
    // Explicit second execution tests SQL idempotency independently of SQLx's
    // already-applied migration skip. It does not edit the migration ledger.
    sqlx::raw_sql(MIGRATION_SQL)
        .execute(&pool)
        .await
        .expect("reapply the additive classifier SQL");
    drop(migration_guard);
    assert_eq!(
        immutable_authority_catalog(&pool).await,
        before_catalog,
        "only the wrapper classifier may change"
    );
    let after_ledger: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT version,checksum FROM _sqlx_migrations WHERE version <> $1 ORDER BY version",
    )
    .bind(MIGRATION_VERSION)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        after_ledger, before_ledger,
        "old migration checksums remain untouched"
    );
    let after_rows: Value = sqlx::query_scalar(
        "SELECT jsonb_build_object('claim', to_jsonb(c), 'receipt', to_jsonb(i)) \
         FROM chat.operation_claims c JOIN chat.idempotency_records i USING(operation_id) WHERE operation_id=$1",
    ).bind(legacy_operation).fetch_one(&pool).await.unwrap();
    assert_eq!(
        after_rows, before_rows,
        "upgrade never rewrites existing wrapper custody or authority rows"
    );
    sqlx::query("SELECT chat.assert_operation_claim_mapping($1)")
        .bind(legacy_operation)
        .execute(&pool)
        .await
        .unwrap();
    classifier_matrix(&pool).await;
    authority_matrix(&pool).await;
    pool.close().await;
}
