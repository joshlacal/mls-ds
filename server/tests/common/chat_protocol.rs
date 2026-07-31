//! Shared database gate for clean `blue.catbird.chat` repository tests.
//!
//! The clean protocol never falls back to the legacy integration database.
//! Every connection is checked before the migrator or a test mutation runs.

#![allow(dead_code)]

use std::borrow::Cow;
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use sha2::{Digest, Sha256};
use sqlx::error::BoxDynError;
use sqlx::migrate::{Migration, MigrationSource, MigrationType, Migrator};
use sqlx::{postgres::PgPoolOptions, PgConnection, PgPool, Row};

pub const CHAT_PROTOCOL_TEST_DATABASE_NAME: &str = "catbird_chat_protocol_test_20260722";
pub const CHAT_PROTOCOL_TEST_DATABASE_URL: &str =
    "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722";
pub const CHAT_OPERATION_CLAIM_ACTIVATION_APPROVAL: &str = "handlers-and-legacy-apis-sealed";

#[derive(Clone, Debug)]
pub struct CleanProtocol13ManifestEntry {
    pub filename: &'static str,
    pub reviewed_sha384: &'static str,
    pub migration: Migration,
}

pub static CLEAN_PROTOCOL_13_MANIFEST: LazyLock<[CleanProtocol13ManifestEntry; 13]> = LazyLock::new(
    || {
        [
            CleanProtocol13ManifestEntry {
                filename: "20260722000001_chat_protocol_core.sql",
                reviewed_sha384: "dd48feea7beafae59fbc11516e8c1ae91382b356b80366056f71d2493c10923bd39ff0739fe08cb4b0452b0ec82132ff",
                migration: Migration::new(
                    20260722000001,
                    Cow::Borrowed("chat protocol core"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260722000001_chat_protocol_core.sql")),
                ),
            },
            CleanProtocol13ManifestEntry {
                filename: "20260722000002_chat_protocol_delivery.sql",
                reviewed_sha384: "86952763aaeb8f4cf8a8a18dd5d022a5357d450193e265a18da5a771513b9d4c7c8408bad27c4f4ba3b712b41b80e504",
                migration: Migration::new(
                    20260722000002,
                    Cow::Borrowed("chat protocol delivery"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260722000002_chat_protocol_delivery.sql")),
                ),
            },
            CleanProtocol13ManifestEntry {
                filename: "20260722000003_chat_protocol_blobs.sql",
                reviewed_sha384: "310101886f60d3a663ee5df829bbc86a96a45e23adee754220d3b06fd74acfd708d23a138124872a5177244d3e14e8eb",
                migration: Migration::new(
                    20260722000003,
                    Cow::Borrowed("chat protocol blobs"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260722000003_chat_protocol_blobs.sql")),
                ),
            },
            CleanProtocol13ManifestEntry {
                filename: "20260725000001_prepare_welcome_provenance_backfill.sql",
                reviewed_sha384: "3f3d1660193bc37aa8c9876e636a4918f59404f0e055f509b9a67158b6028d947adc299c4d776a693bf8b75e647d90a8",
                migration: Migration::new(
                    20260725000001,
                    Cow::Borrowed("prepare welcome provenance backfill"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260725000001_prepare_welcome_provenance_backfill.sql")),
                ),
            },
            CleanProtocol13ManifestEntry {
                filename: "20260725000002_refine_welcome_provenance_quarantine.sql",
                reviewed_sha384: "8dd0a595288182e2c36aed67d7155138a0817deb5d236dd1eaea50f066a90d7949f60c0de6bff5c9e8bd28e4a1c50de2",
                migration: Migration::new(
                    20260725000002,
                    Cow::Borrowed("refine welcome provenance quarantine"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260725000002_refine_welcome_provenance_quarantine.sql")),
                ),
            },
            CleanProtocol13ManifestEntry {
                filename: "20260726000001_welcome_supersession_provenance.sql",
                reviewed_sha384: "78c31ff78db5b8889fb00cb7024186a0f048975fc7a059c667e326162e3f338396d9760143367c9206802d21269484f4",
                migration: Migration::new(
                    20260726000001,
                    Cow::Borrowed("welcome supersession provenance"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260726000001_welcome_supersession_provenance.sql")),
                ),
            },
            CleanProtocol13ManifestEntry {
                filename: "20260726000002_restore_welcome_provenance_deferred_triggers.sql",
                reviewed_sha384: "1b29d045575aea2552ac10bdb61451662d51bca5afa75827e030e5dd859eee0d1664e12a69ecea9692e0fadb2a8df4af",
                migration: Migration::new(
                    20260726000002,
                    Cow::Borrowed("restore welcome provenance deferred triggers"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260726000002_restore_welcome_provenance_deferred_triggers.sql")),
                ),
            },
            CleanProtocol13ManifestEntry {
                filename: "20260726000003_finalize_welcome_provenance_triggers.sql",
                reviewed_sha384: "8bd956b8383bea542c6d591ae7721b92b898cb07e49b503131bedfbb511937147766569bcd2b23da11b226decffec495",
                migration: Migration::new(
                    20260726000003,
                    Cow::Borrowed("finalize welcome provenance triggers"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260726000003_finalize_welcome_provenance_triggers.sql")),
                ),
            },
            CleanProtocol13ManifestEntry {
                filename: "20260728000001_chat_operation_claims.sql",
                reviewed_sha384: "fd71f2eb5235226371f113b5738b752b27e901b72810e9ec1e1f201e979606e0b09a16be087103e4146b4fb9f8bdff8f",
                migration: Migration::new(
                    20260728000001,
                    Cow::Borrowed("chat operation claims"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260728000001_chat_operation_claims.sql")),
                ),
            },
            CleanProtocol13ManifestEntry {
                filename: "20260728000002_exact_operation_claim_mutation_kind.sql",
                reviewed_sha384: "a5c0225818e350415e0ad3a88c5016d621a75bb64563f97023de9d27498cf113d8ef9d95c98621036c15ac3398dbee17",
                migration: Migration::new(
                    20260728000002,
                    Cow::Borrowed("exact operation claim mutation kind"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260728000002_exact_operation_claim_mutation_kind.sql")),
                ),
            },
            CleanProtocol13ManifestEntry {
                filename: "20260728000003_defer_operation_claim_principal_fk.sql",
                reviewed_sha384: "d42c64d98f6af2042ecf5d08b925aaadae01efcd7d1f6d1887c5485e0862d80304bb9ba54506a1876eba54b505d4114a",
                migration: Migration::new(
                    20260728000003,
                    Cow::Borrowed("defer operation claim principal fk"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260728000003_defer_operation_claim_principal_fk.sql")),
                ),
            },
            CleanProtocol13ManifestEntry {
                filename: "20260728000004_activate_operation_claim_completeness.sql",
                reviewed_sha384: "7de97f6f84a9cfcbf535b990b5aec87930450cf6661c7d8cf11920bdf53fd0fe94623e9ed222a8eeb562c1ee596c5bd6",
                migration: Migration::new(
                    20260728000004,
                    Cow::Borrowed("activate operation claim completeness"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260728000004_activate_operation_claim_completeness.sql")),
                ),
            },
            CleanProtocol13ManifestEntry {
                filename: "20260729000001_chat_g7_inventory_entitlement.sql",
                reviewed_sha384: "2c00fc11f1d96b79c3c86320e769d70d52fecb477a8a2bc351151fd2d01e3d4c5df19cbf7a3ac482edbe16a33a0dd60e",
                migration: Migration::new(
                    20260729000001,
                    Cow::Borrowed("chat g7 inventory entitlement"),
                    MigrationType::Simple,
                    Cow::Borrowed(include_str!("../../migrations/20260729000001_chat_g7_inventory_entitlement.sql")),
                ),
            },
        ]
    },
);

#[derive(Clone, Copy, Debug)]
pub struct CleanProtocol13MigrationSource;

impl MigrationSource<'static> for CleanProtocol13MigrationSource {
    fn resolve(self) -> BoxFuture<'static, Result<Vec<Migration>, BoxDynError>> {
        Box::pin(async move {
            Ok(CLEAN_PROTOCOL_13_MANIFEST
                .iter()
                .map(|entry| entry.migration.clone())
                .collect())
        })
    }
}

pub async fn reviewed_clean_protocol_migrator() -> Result<Migrator, String> {
    if CLEAN_PROTOCOL_13_MANIFEST.len() != 13 {
        return Err("reviewed clean-protocol manifest must contain exactly 13 migrations".into());
    }
    for (index, entry) in CLEAN_PROTOCOL_13_MANIFEST.iter().enumerate() {
        let filename_version = entry
            .filename
            .split_once('_')
            .and_then(|(version, _)| version.parse::<i64>().ok())
            .ok_or_else(|| format!("invalid reviewed migration filename: {}", entry.filename))?;
        if filename_version != entry.migration.version {
            return Err(format!(
                "reviewed migration filename/version mismatch at index {index}"
            ));
        }
        if index > 0
            && CLEAN_PROTOCOL_13_MANIFEST[index - 1].migration.version >= entry.migration.version
        {
            return Err("reviewed clean-protocol migrations are not strictly ordered".into());
        }
        if hex::encode(entry.migration.checksum.as_ref()) != entry.reviewed_sha384 {
            return Err(format!(
                "reviewed migration checksum mismatch for {}",
                entry.filename
            ));
        }
    }

    let mut migrator = Migrator::new(CleanProtocol13MigrationSource)
        .await
        .map_err(|error| format!("resolve reviewed clean-protocol migrator: {error}"))?;
    migrator.set_ignore_missing(false);
    migrator.set_locking(true);
    if migrator.ignore_missing || !migrator.locking || migrator.iter().count() != 13 {
        return Err("reviewed clean-protocol migrator policy mismatch".into());
    }
    for (entry, migration) in CLEAN_PROTOCOL_13_MANIFEST.iter().zip(migrator.iter()) {
        if migration.version != entry.migration.version
            || migration.description != entry.migration.description
            || migration.checksum != entry.migration.checksum
        {
            return Err("resolved reviewed clean-protocol migrator projection mismatch".into());
        }
    }
    Ok(migrator)
}

pub fn validate_chat_protocol_activation_approval(value: Option<&str>) -> Result<(), &'static str> {
    match value {
        Some(CHAT_OPERATION_CLAIM_ACTIVATION_APPROVAL) => Ok(()),
        _ => Err(
            "CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED must exactly equal \
             handlers-and-legacy-apis-sealed",
        ),
    }
}

pub fn validate_chat_protocol_database_url(
    value: Option<&str>,
) -> Result<&'static str, &'static str> {
    match value {
        Some(CHAT_PROTOCOL_TEST_DATABASE_URL) => Ok(CHAT_PROTOCOL_TEST_DATABASE_NAME),
        _ => {
            Err("TEST_DATABASE_URL must exactly equal the reviewed literal local clean-chat target")
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DurableOperationClaimCompletenessEvidence {
    pub(crate) cutover_at: DateTime<Utc>,
    pub(crate) total_receipt_count: i64,
    pub(crate) legacy_receipt_count: i64,
    pub(crate) legacy_receipt_set_sha256: [u8; 32],
    pub(crate) required_receipt_count: i64,
    pub(crate) column_contract_sha256: [u8; 32],
    pub(crate) trigger_contract_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DurableOperationClaimCompletenessError {
    Query { stage: &'static str, detail: String },
    Decode { stage: &'static str, detail: String },
    Invariant { code: &'static str, detail: String },
}

fn durable_query_error(
    stage: &'static str,
    error: sqlx::Error,
) -> DurableOperationClaimCompletenessError {
    DurableOperationClaimCompletenessError::Query {
        stage,
        detail: error.to_string(),
    }
}

fn durable_decode_error(
    stage: &'static str,
    error: sqlx::Error,
) -> DurableOperationClaimCompletenessError {
    DurableOperationClaimCompletenessError::Decode {
        stage,
        detail: error.to_string(),
    }
}

fn durable_invariant(
    code: &'static str,
    detail: impl Into<String>,
) -> DurableOperationClaimCompletenessError {
    DurableOperationClaimCompletenessError::Invariant {
        code,
        detail: detail.into(),
    }
}

pub(crate) fn canonical_legacy_receipt_set_sha256(sorted_operation_ids: &[String]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LEGACY-RECEIPT-SET");
    digest.update([0]);
    for (index, operation_id) in sorted_operation_ids.iter().enumerate() {
        if index != 0 {
            digest.update(b",");
        }
        digest.update(operation_id.as_bytes());
    }
    digest.finalize().into()
}

fn stable_contract_sha256(domain: &[u8], rows: &[String]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    for row in rows {
        digest.update((row.len() as u64).to_be_bytes());
        digest.update(row.as_bytes());
    }
    digest.finalize().into()
}

fn normalized_generated_expression(column: &str, expression: &str) -> Option<&'static str> {
    let compact = expression.split_whitespace().collect::<Vec<_>>().join(" ");
    let compact = compact
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or(&compact);
    match (column, compact) {
        (
            "operation_claim_fk_operation_id",
            "CASE WHEN operation_claim_required THEN operation_id ELSE NULL::uuid END",
        )
        | (
            "operation_claim_fk_operation_id",
            "CASE WHEN operation_claim_required THEN operation_id END",
        ) => Some("CASE WHEN operation_claim_required THEN operation_id END"),
        (
            "operation_claim_fk_principal_did",
            "CASE WHEN operation_claim_required THEN principal_did ELSE NULL::text END",
        )
        | (
            "operation_claim_fk_principal_did",
            "CASE WHEN operation_claim_required THEN principal_did END",
        ) => Some("CASE WHEN operation_claim_required THEN principal_did END"),
        (
            "operation_claim_fk_endpoint_nsid",
            "CASE WHEN operation_claim_required THEN endpoint_nsid ELSE NULL::text END",
        )
        | (
            "operation_claim_fk_endpoint_nsid",
            "CASE WHEN operation_claim_required THEN endpoint_nsid END",
        ) => Some("CASE WHEN operation_claim_required THEN endpoint_nsid END"),
        _ => None,
    }
}

pub(crate) async fn validate_durable_operation_claim_completeness(
    connection: &mut PgConnection,
) -> Result<DurableOperationClaimCompletenessEvidence, DurableOperationClaimCompletenessError> {
    const CUTOVER_STAGE: &str = "operation_claim_completeness_cutover";
    let cutover_rows = sqlx::query(
        "SELECT singleton,cutover_at,legacy_receipt_count,legacy_receipt_set_sha256 \
         FROM chat.operation_claim_completeness_cutover ORDER BY singleton",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| durable_query_error(CUTOVER_STAGE, error))?;
    if cutover_rows.len() != 1 {
        return Err(durable_invariant(
            "cutover_singleton_count",
            format!(
                "expected exactly one completeness cutover row, observed {}",
                cutover_rows.len()
            ),
        ));
    }
    let cutover_row = &cutover_rows[0];
    let singleton: bool = cutover_row
        .try_get("singleton")
        .map_err(|error| durable_decode_error(CUTOVER_STAGE, error))?;
    let cutover_at: DateTime<Utc> = cutover_row
        .try_get("cutover_at")
        .map_err(|error| durable_decode_error(CUTOVER_STAGE, error))?;
    let recorded_legacy_count: i64 = cutover_row
        .try_get("legacy_receipt_count")
        .map_err(|error| durable_decode_error(CUTOVER_STAGE, error))?;
    let recorded_legacy_digest: Vec<u8> = cutover_row
        .try_get("legacy_receipt_set_sha256")
        .map_err(|error| durable_decode_error(CUTOVER_STAGE, error))?;
    if !singleton {
        return Err(durable_invariant(
            "cutover_singleton_false",
            "completeness cutover singleton is not true",
        ));
    }
    if recorded_legacy_count < 0 {
        return Err(durable_invariant(
            "cutover_negative_legacy_count",
            format!("recorded legacy count is {recorded_legacy_count}"),
        ));
    }
    let recorded_legacy_digest: [u8; 32] =
        recorded_legacy_digest
            .try_into()
            .map_err(|digest: Vec<u8>| {
                durable_invariant(
                    "cutover_legacy_digest_length",
                    format!(
                        "recorded legacy-set digest has {} bytes, expected 32",
                        digest.len()
                    ),
                )
            })?;

    const RECEIPT_COUNT_STAGE: &str = "idempotency_receipt_counts";
    let count_row = sqlx::query(
        "SELECT count(*)::bigint AS total_receipt_count,\
                count(*) FILTER (WHERE operation_claim_required IS FALSE)::bigint \
                    AS legacy_receipt_count,\
                count(*) FILTER (WHERE operation_claim_required IS TRUE)::bigint \
                    AS required_receipt_count,\
                count(*) FILTER (WHERE operation_claim_required IS NULL)::bigint \
                    AS null_authority_count \
           FROM chat.idempotency_records",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(|error| durable_query_error(RECEIPT_COUNT_STAGE, error))?;
    let total_receipt_count: i64 = count_row
        .try_get("total_receipt_count")
        .map_err(|error| durable_decode_error(RECEIPT_COUNT_STAGE, error))?;
    let legacy_receipt_count: i64 = count_row
        .try_get("legacy_receipt_count")
        .map_err(|error| durable_decode_error(RECEIPT_COUNT_STAGE, error))?;
    let required_receipt_count: i64 = count_row
        .try_get("required_receipt_count")
        .map_err(|error| durable_decode_error(RECEIPT_COUNT_STAGE, error))?;
    let null_authority_count: i64 = count_row
        .try_get("null_authority_count")
        .map_err(|error| durable_decode_error(RECEIPT_COUNT_STAGE, error))?;
    if null_authority_count != 0 {
        return Err(durable_invariant(
            "receipt_null_authority",
            format!("{null_authority_count} receipts have a NULL authority bit"),
        ));
    }
    if total_receipt_count != legacy_receipt_count + required_receipt_count {
        return Err(durable_invariant(
            "receipt_count_partition",
            format!(
                "total={total_receipt_count}, legacy={legacy_receipt_count}, \
                 required={required_receipt_count}"
            ),
        ));
    }

    const LEGACY_STAGE: &str = "legacy_receipt_set";
    let legacy_rows = sqlx::query(
        "SELECT receipt.operation_id::text AS operation_id,\
                receipt.completed_at,\
                EXISTS (\
                    SELECT 1 FROM chat.operation_claims claim \
                    WHERE claim.operation_id=receipt.operation_id\
                ) AS has_claim \
           FROM chat.idempotency_records receipt \
          WHERE receipt.operation_claim_required IS FALSE \
          ORDER BY receipt.operation_id",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| durable_query_error(LEGACY_STAGE, error))?;
    let mut legacy_operation_ids = Vec::with_capacity(legacy_rows.len());
    for row in legacy_rows {
        let operation_id: String = row
            .try_get("operation_id")
            .map_err(|error| durable_decode_error(LEGACY_STAGE, error))?;
        let completed_at: DateTime<Utc> = row
            .try_get("completed_at")
            .map_err(|error| durable_decode_error(LEGACY_STAGE, error))?;
        let has_claim: bool = row
            .try_get("has_claim")
            .map_err(|error| durable_decode_error(LEGACY_STAGE, error))?;
        if has_claim {
            return Err(durable_invariant(
                "legacy_receipt_has_claim",
                format!("legacy receipt {operation_id} has an operation claim"),
            ));
        }
        if completed_at > cutover_at {
            return Err(durable_invariant(
                "legacy_receipt_after_cutover",
                format!("legacy receipt {operation_id} completed after the cutover"),
            ));
        }
        legacy_operation_ids.push(operation_id);
    }
    if legacy_operation_ids.len() as i64 != legacy_receipt_count {
        return Err(durable_invariant(
            "legacy_receipt_query_count",
            format!(
                "count projection reported {legacy_receipt_count}, row proof observed {}",
                legacy_operation_ids.len()
            ),
        ));
    }
    let legacy_receipt_set_sha256 = canonical_legacy_receipt_set_sha256(&legacy_operation_ids);
    if legacy_receipt_count != recorded_legacy_count
        || legacy_receipt_set_sha256 != recorded_legacy_digest
    {
        return Err(durable_invariant(
            "legacy_receipt_set_mismatch",
            format!(
                "recorded count/digest do not match recomputation: \
                 recorded_count={recorded_legacy_count}, \
                 recomputed_count={legacy_receipt_count}, \
                 recorded_digest={}, recomputed_digest={}",
                hex::encode(recorded_legacy_digest),
                hex::encode(legacy_receipt_set_sha256)
            ),
        ));
    }

    const REQUIRED_STAGE: &str = "required_receipt_claim_mapping";
    let invalid_required_rows = sqlx::query(
        "SELECT receipt.operation_id::text AS operation_id \
           FROM chat.idempotency_records receipt \
           LEFT JOIN chat.operation_claims claim \
             ON claim.operation_id=receipt.operation_id \
          WHERE receipt.operation_claim_required IS TRUE \
          GROUP BY receipt.operation_id,receipt.principal_did,receipt.endpoint_nsid,\
                   receipt.request_digest,receipt.accepted_request_bytes,\
                   receipt.signing_transcript_bytes,receipt.signature \
         HAVING count(claim.operation_id) <> 1 \
             OR NOT coalesce(bool_and(\
                    claim.principal_did=receipt.principal_did \
                AND claim.endpoint_nsid=receipt.endpoint_nsid \
                AND claim.request_digest=receipt.request_digest \
                AND claim.accepted_request_sha256=\
                    digest(receipt.accepted_request_bytes,'sha256') \
                AND claim.signature=receipt.signature \
                AND claim.mutation_kind IS NOT NULL \
                AND chat.operation_mutation_kind_from_wrapper(\
                        receipt.accepted_request_bytes\
                    ) IS NOT NULL \
                AND chat.operation_mutation_kind_from_transcript(\
                        receipt.signing_transcript_bytes\
                    ) IS NOT NULL \
                AND claim.mutation_kind=chat.operation_mutation_kind_from_wrapper(\
                        receipt.accepted_request_bytes\
                    ) \
                AND claim.mutation_kind=chat.operation_mutation_kind_from_transcript(\
                        receipt.signing_transcript_bytes\
                    ) \
                AND chat.operation_mutation_kind_from_wrapper(\
                        receipt.accepted_request_bytes\
                    )=chat.operation_mutation_kind_from_transcript(\
                        receipt.signing_transcript_bytes\
                    ) \
                AND chat.operation_endpoint_accepts_kind(\
                        receipt.endpoint_nsid,claim.mutation_kind\
                    )\
             ),FALSE) \
          LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await
    .map_err(|error| durable_query_error(REQUIRED_STAGE, error))?;
    if let Some(row) = invalid_required_rows {
        let operation_id: String = row
            .try_get("operation_id")
            .map_err(|error| durable_decode_error(REQUIRED_STAGE, error))?;
        return Err(durable_invariant(
            "required_receipt_claim_mismatch",
            format!("required receipt {operation_id} lacks one exact accepted claim"),
        ));
    }

    const CLAIM_STAGE: &str = "operation_claim_receipt_mapping";
    let invalid_claim_row = sqlx::query(
        "SELECT claim.operation_id::text AS operation_id \
           FROM chat.operation_claims claim \
           LEFT JOIN chat.idempotency_records receipt \
             ON receipt.operation_id=claim.operation_id \
            AND receipt.operation_claim_required IS TRUE \
            AND receipt.principal_did=claim.principal_did \
            AND receipt.endpoint_nsid=claim.endpoint_nsid \
            AND receipt.request_digest=claim.request_digest \
            AND digest(receipt.accepted_request_bytes,'sha256')=\
                claim.accepted_request_sha256 \
            AND receipt.signature=claim.signature \
            AND claim.mutation_kind IS NOT NULL \
            AND chat.operation_mutation_kind_from_wrapper(\
                    receipt.accepted_request_bytes\
                ) IS NOT NULL \
            AND chat.operation_mutation_kind_from_transcript(\
                    receipt.signing_transcript_bytes\
                ) IS NOT NULL \
            AND claim.mutation_kind=chat.operation_mutation_kind_from_wrapper(\
                    receipt.accepted_request_bytes\
                ) \
            AND claim.mutation_kind=chat.operation_mutation_kind_from_transcript(\
                    receipt.signing_transcript_bytes\
                ) \
            AND chat.operation_endpoint_accepts_kind(\
                    receipt.endpoint_nsid,claim.mutation_kind\
                ) \
          WHERE receipt.operation_id IS NULL \
          LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await
    .map_err(|error| durable_query_error(CLAIM_STAGE, error))?;
    if let Some(row) = invalid_claim_row {
        let operation_id: String = row
            .try_get("operation_id")
            .map_err(|error| durable_decode_error(CLAIM_STAGE, error))?;
        return Err(durable_invariant(
            "operation_claim_receipt_mismatch",
            format!("operation claim {operation_id} lacks one exact required receipt"),
        ));
    }

    const COLUMN_STAGE: &str = "operation_claim_column_contract";
    let column_rows = sqlx::query(
        "SELECT attribute.attname,\
                attribute.attnum::integer AS ordinal,\
                format_type(attribute.atttypid,attribute.atttypmod) AS sql_type,\
                attribute.attnotnull,\
                CASE WHEN attribute.attgenerated='' \
                     THEN coalesce(pg_get_expr(definition.adbin,definition.adrelid,true),'') \
                     ELSE '' END AS default_expression,\
                attribute.attgenerated::text AS generation_kind,\
                attribute.attgenerated='s' AS stored,\
                CASE WHEN attribute.attgenerated='s' \
                     THEN coalesce(pg_get_expr(definition.adbin,definition.adrelid,true),'') \
                     ELSE '' END AS generated_expression \
           FROM pg_attribute attribute \
           JOIN pg_class relation ON relation.oid=attribute.attrelid \
           JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace \
           LEFT JOIN pg_attrdef definition \
                  ON definition.adrelid=attribute.attrelid \
                 AND definition.adnum=attribute.attnum \
          WHERE namespace.nspname='chat' \
            AND relation.relname='idempotency_records' \
            AND attribute.attnum>0 \
            AND NOT attribute.attisdropped \
            AND (attribute.attname='operation_claim_required' \
                 OR attribute.attname LIKE 'operation_claim_fk_%') \
          ORDER BY attribute.attnum",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| durable_query_error(COLUMN_STAGE, error))?;
    let expected_columns = [
        (
            "operation_claim_required",
            15,
            "boolean",
            true,
            "true",
            "",
            false,
            "",
        ),
        (
            "operation_claim_fk_operation_id",
            16,
            "uuid",
            false,
            "",
            "s",
            true,
            "CASE WHEN operation_claim_required THEN operation_id END",
        ),
        (
            "operation_claim_fk_principal_did",
            17,
            "text",
            false,
            "",
            "s",
            true,
            "CASE WHEN operation_claim_required THEN principal_did END",
        ),
        (
            "operation_claim_fk_endpoint_nsid",
            18,
            "text",
            false,
            "",
            "s",
            true,
            "CASE WHEN operation_claim_required THEN endpoint_nsid END",
        ),
    ];
    if column_rows.len() != expected_columns.len() {
        return Err(durable_invariant(
            "operation_claim_column_count",
            format!(
                "expected {} operation-claim authority columns, observed {}",
                expected_columns.len(),
                column_rows.len()
            ),
        ));
    }
    let mut column_projection = Vec::with_capacity(expected_columns.len());
    for (row, expected) in column_rows.iter().zip(expected_columns) {
        let name: String = row
            .try_get("attname")
            .map_err(|error| durable_decode_error(COLUMN_STAGE, error))?;
        let ordinal: i32 = row
            .try_get("ordinal")
            .map_err(|error| durable_decode_error(COLUMN_STAGE, error))?;
        let sql_type: String = row
            .try_get("sql_type")
            .map_err(|error| durable_decode_error(COLUMN_STAGE, error))?;
        let not_null: bool = row
            .try_get("attnotnull")
            .map_err(|error| durable_decode_error(COLUMN_STAGE, error))?;
        let default_expression: String = row
            .try_get("default_expression")
            .map_err(|error| durable_decode_error(COLUMN_STAGE, error))?;
        let generation_kind: String = row
            .try_get("generation_kind")
            .map_err(|error| durable_decode_error(COLUMN_STAGE, error))?;
        let stored: bool = row
            .try_get("stored")
            .map_err(|error| durable_decode_error(COLUMN_STAGE, error))?;
        let raw_generated_expression: String = row
            .try_get("generated_expression")
            .map_err(|error| durable_decode_error(COLUMN_STAGE, error))?;
        let generated_expression = if generation_kind == "s" {
            normalized_generated_expression(&name, &raw_generated_expression)
                .ok_or_else(|| {
                    durable_invariant(
                        "operation_claim_generated_expression",
                        format!(
                            "column {name} has an unreviewed generated expression: \
                             {raw_generated_expression}"
                        ),
                    )
                })?
                .to_owned()
        } else {
            raw_generated_expression
        };
        let observed = (
            name.as_str(),
            ordinal,
            sql_type.as_str(),
            not_null,
            default_expression.as_str(),
            generation_kind.as_str(),
            stored,
            generated_expression.as_str(),
        );
        if observed != expected {
            return Err(durable_invariant(
                "operation_claim_column_contract",
                format!("column contract mismatch: observed={observed:?}, expected={expected:?}"),
            ));
        }
        column_projection.push(format!(
            "{name}|{ordinal}|{sql_type}|{not_null}|{default_expression}|\
             {generation_kind}|{stored}|{generated_expression}"
        ));
    }
    let column_contract_sha256 =
        stable_contract_sha256(b"CATBIRD-CHAT-OPERATION-CLAIM-COLUMNS", &column_projection);

    const TRIGGER_STAGE: &str = "operation_claim_trigger_contract";
    let trigger_rows = sqlx::query(
        "SELECT trigger_row.tgname,\
                trigger_row.tgenabled::text AS enabled,\
                trigger_row.tgtype::integer AS trigger_type,\
                trigger_row.tgconstraint<>0 AS is_constraint,\
                constraint_row.condeferrable,\
                constraint_row.condeferred,\
                trigger_row.tgqual IS NULL AS no_qualification,\
                trigger_row.tgnargs::integer AS argument_count,\
                octet_length(trigger_row.tgargs)::integer AS argument_bytes,\
                function_namespace.nspname AS function_schema,\
                function_row.proname AS function_name,\
                function_row.pronargs::integer AS function_argument_count \
           FROM pg_trigger trigger_row \
           JOIN pg_class relation ON relation.oid=trigger_row.tgrelid \
           JOIN pg_namespace relation_namespace \
             ON relation_namespace.oid=relation.relnamespace \
           LEFT JOIN pg_constraint constraint_row \
             ON constraint_row.oid=trigger_row.tgconstraint \
           JOIN pg_proc function_row ON function_row.oid=trigger_row.tgfoid \
           JOIN pg_namespace function_namespace \
             ON function_namespace.oid=function_row.pronamespace \
          WHERE relation_namespace.nspname='chat' \
            AND relation.relname='idempotency_records' \
            AND NOT trigger_row.tgisinternal \
            AND trigger_row.tgconstraint<>0 \
          ORDER BY trigger_row.tgname",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|error| durable_query_error(TRIGGER_STAGE, error))?;
    let expected_triggers = [
        (
            "idempotency_records_operation_claim_mapping_deferred",
            "chat",
            "enforce_operation_claim_mapping",
        ),
        (
            "idempotency_records_revocation_mapping_deferred",
            "chat",
            "enforce_device_revocation_mapping",
        ),
    ];
    if trigger_rows.len() != expected_triggers.len() {
        return Err(durable_invariant(
            "operation_claim_trigger_count",
            format!(
                "expected {} authority triggers, observed {}",
                expected_triggers.len(),
                trigger_rows.len()
            ),
        ));
    }
    let mut trigger_projection = Vec::with_capacity(expected_triggers.len());
    for (row, (expected_name, expected_schema, expected_function)) in
        trigger_rows.iter().zip(expected_triggers)
    {
        let name: String = row
            .try_get("tgname")
            .map_err(|error| durable_decode_error(TRIGGER_STAGE, error))?;
        let enabled: String = row
            .try_get("enabled")
            .map_err(|error| durable_decode_error(TRIGGER_STAGE, error))?;
        let trigger_type: i32 = row
            .try_get("trigger_type")
            .map_err(|error| durable_decode_error(TRIGGER_STAGE, error))?;
        let is_constraint: bool = row
            .try_get("is_constraint")
            .map_err(|error| durable_decode_error(TRIGGER_STAGE, error))?;
        let deferrable: bool = row
            .try_get("condeferrable")
            .map_err(|error| durable_decode_error(TRIGGER_STAGE, error))?;
        let initially_deferred: bool = row
            .try_get("condeferred")
            .map_err(|error| durable_decode_error(TRIGGER_STAGE, error))?;
        let no_qualification: bool = row
            .try_get("no_qualification")
            .map_err(|error| durable_decode_error(TRIGGER_STAGE, error))?;
        let argument_count: i32 = row
            .try_get("argument_count")
            .map_err(|error| durable_decode_error(TRIGGER_STAGE, error))?;
        let argument_bytes: i32 = row
            .try_get("argument_bytes")
            .map_err(|error| durable_decode_error(TRIGGER_STAGE, error))?;
        let function_schema: String = row
            .try_get("function_schema")
            .map_err(|error| durable_decode_error(TRIGGER_STAGE, error))?;
        let function_name: String = row
            .try_get("function_name")
            .map_err(|error| durable_decode_error(TRIGGER_STAGE, error))?;
        let function_argument_count: i32 = row
            .try_get("function_argument_count")
            .map_err(|error| durable_decode_error(TRIGGER_STAGE, error))?;
        if name != expected_name
            || enabled != "O"
            || trigger_type != 29
            || !is_constraint
            || !deferrable
            || !initially_deferred
            || !no_qualification
            || argument_count != 0
            || argument_bytes != 0
            || function_schema != expected_schema
            || function_name != expected_function
            || function_argument_count != 0
        {
            return Err(durable_invariant(
                "operation_claim_trigger_contract",
                format!(
                    "trigger contract mismatch for {name}: enabled={enabled}, \
                     tgtype={trigger_type}, constraint={is_constraint}, \
                     deferrable={deferrable}, initially_deferred={initially_deferred}, \
                     no_qualification={no_qualification}, arguments={argument_count}/\
                     {argument_bytes}, function={function_schema}.{function_name}/\
                     {function_argument_count}"
                ),
            ));
        }
        trigger_projection.push(format!(
            "{name}|{enabled}|{trigger_type}|{is_constraint}|{deferrable}|\
             {initially_deferred}|{no_qualification}|{argument_count}|{argument_bytes}|\
             {function_schema}.{function_name}()|{function_argument_count}"
        ));
    }
    let trigger_contract_sha256 = stable_contract_sha256(
        b"CATBIRD-CHAT-OPERATION-CLAIM-TRIGGERS",
        &trigger_projection,
    );

    Ok(DurableOperationClaimCompletenessEvidence {
        cutover_at,
        total_receipt_count,
        legacy_receipt_count,
        legacy_receipt_set_sha256,
        required_receipt_count,
        column_contract_sha256,
        trigger_contract_sha256,
    })
}

async fn validate_exact_reviewed_ledger(
    pool: &PgPool,
) -> Result<Vec<(i64, String, bool, Vec<u8>)>, String> {
    let ledger_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(pool)
            .await
            .map_err(|error| format!("inspect clean-chat migration ledger: {error}"))?;
    if !ledger_exists {
        return Err(
            "clean-chat fixed target is not installed; A0/A-final must precede ordinary gates"
                .into(),
        );
    }
    let actual: Vec<(i64, String, bool, Vec<u8>)> = sqlx::query_as(
        "SELECT version,description,success,checksum \
         FROM public._sqlx_migrations ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .map_err(|error| format!("read clean-chat migration ledger: {error}"))?;
    let expected = CLEAN_PROTOCOL_13_MANIFEST
        .iter()
        .map(|entry| {
            (
                entry.migration.version,
                entry.migration.description.to_string(),
                true,
                entry.migration.checksum.to_vec(),
            )
        })
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(
            "clean-chat fixed target is not the exact reviewed 13-row installation; \
             validation-only setup refuses migration or repair"
                .into(),
        );
    }
    Ok(actual)
}

#[allow(dead_code)]
pub async fn setup_chat_protocol_db(max_connections: u32) -> PgPool {
    assert!(
        max_connections > 0,
        "clean-chat pool must have a connection"
    );
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must explicitly name catbird_chat_protocol_test_20260722");
    validate_chat_protocol_database_url(Some(&database_url))
        .expect("unsafe TEST_DATABASE_URL for clean-chat repository test");
    let activation_approval = std::env::var("CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED")
        .expect("CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED must authorize migration 00004");
    validate_chat_protocol_activation_approval(Some(&activation_approval))
        .expect("invalid operation-claim activation approval");
    let migrator = reviewed_clean_protocol_migrator()
        .await
        .expect("validate the exact reviewed clean-protocol migration manifest");

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&database_url)
        .await
        .expect("connect to the dedicated clean-chat PostgreSQL database");

    let (current_database, current_user, database_owner, server_address): (
        String,
        String,
        String,
        Option<String>,
    ) = sqlx::query_as(
        r#"
        SELECT current_database(),
               current_user,
               pg_get_userbyid(d.datdba),
               host(inet_server_addr())
          FROM pg_database d
         WHERE d.datname = current_database()
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("inspect the clean-chat database gate before migration");
    assert_eq!(current_database, CHAT_PROTOCOL_TEST_DATABASE_NAME);
    assert_eq!(
        current_user, database_owner,
        "connected role is not database owner"
    );
    assert_eq!(
        server_address.as_deref(),
        Some("127.0.0.1"),
        "refusing a non-local clean-chat database at {server_address:?}",
    );
    let ledger_before = validate_exact_reviewed_ledger(&pool)
        .await
        .expect("fixed-target setup is validation-only");

    let mut migration_connection = pool
        .acquire()
        .await
        .expect("acquire the exact clean-chat migration connection");
    sqlx::query(
        "SET chat.operation_claim_activation_approved = \
         'handlers-and-legacy-apis-sealed'",
    )
    .execute(&mut *migration_connection)
    .await
    .expect("authorize operation-claim activation on the exact migration connection");
    let migration_result = migrator.run_direct(&mut *migration_connection).await;
    sqlx::query("RESET chat.operation_claim_activation_approved")
        .execute(&mut *migration_connection)
        .await
        .expect("reset operation-claim activation approval on the migration connection");
    migration_connection
        .close()
        .await
        .expect("close the exact clean-chat migration connection");
    migration_result.expect("reviewed exact-13 migrator must be a fixed-target no-op");
    let ledger_after = validate_exact_reviewed_ledger(&pool)
        .await
        .expect("fixed-target ledger must remain exact after reviewed no-op");
    assert_eq!(
        ledger_after, ledger_before,
        "fixed-target setup attempted to mutate the exact reviewed ledger"
    );
    pool
}
