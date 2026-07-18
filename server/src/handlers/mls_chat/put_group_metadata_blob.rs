use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{auth::AuthUser, storage::DbPool};

const NSID: &str = "blue.catbird.mlsChat.putGroupMetadataBlob";

/// Maximum metadata blob size: 1 MB
const MAX_METADATA_BLOB_SIZE: usize = 1_048_576;

/// Retention bound: keep at most this many metadata blobs per conversation
/// (newest first). Superseded blobs beyond the bound are pruned on write,
/// capping per-convo accumulation at
/// `MAX_METADATA_BLOBS_PER_CONVO * MAX_METADATA_BLOB_SIZE` (64 MB) instead
/// of growing without bound (finding F9). The bound is generous: only the
/// newest metadata/avatar blobs are live — late joiners fetch the current
/// locator from group state, not historical ones.
pub const MAX_METADATA_BLOBS_PER_CONVO: i64 = 64;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutGroupMetadataBlobParams {
    pub blob_locator: String,
    pub group_id: String,
    pub convo_id: Option<String>,
    pub reset_generation: Option<i64>,
    pub metadata_version: Option<i64>,
    pub kind: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PutGroupMetadataBlobOutput {
    pub blob_locator: String,
    pub size: i64,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// POST /xrpc/blue.catbird.mlsChat.putGroupMetadataBlob?blobLocator=<id>&groupId=<hex>
///
/// Stores an encrypted group metadata blob. Input is raw binary bytes
/// (Content-Type: application/octet-stream or */*) with blobLocator and
/// groupId as query parameters. The server stores opaque bytes — it never
/// sees plaintext metadata.
#[tracing::instrument(skip(pool, auth_user, body))]
pub async fn put_group_metadata_blob(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<PutGroupMetadataBlobParams>,
    body: Bytes,
) -> Result<Json<PutGroupMetadataBlobOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [putGroupMetadataBlob] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let owner_did = &auth_user.did;
    let blob_locator = &params.blob_locator;
    let group_id = &params.group_id;
    let data = body.to_vec();
    let size = data.len();

    let kind = params.kind.as_deref().unwrap_or("metadata");
    if !matches!(kind, "metadata" | "avatar") {
        warn!("❌ [putGroupMetadataBlob] Invalid blob kind: {}", kind);
        return Err(StatusCode::BAD_REQUEST);
    }

    if matches!(params.metadata_version, Some(v) if v < 1) {
        warn!("❌ [putGroupMetadataBlob] Invalid metadata_version");
        return Err(StatusCode::BAD_REQUEST);
    }

    if matches!(params.reset_generation, Some(v) if v < 0) {
        warn!("❌ [putGroupMetadataBlob] Invalid reset_generation");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Verify caller is a member of the stable conversation. Older clients only
    // send groupId, so derive convoId from the current group in that case.
    let conversation_row: Option<(String, i32)> = match params.convo_id.as_deref() {
        Some(convo_id) => {
            sqlx::query_as(
                "SELECT id, COALESCE(reset_count, 0) \
                 FROM conversations \
                 WHERE id = $1 AND group_id = $2",
            )
            .bind(convo_id)
            .bind(group_id)
            .fetch_optional(&pool)
            .await
        }
        None => {
            sqlx::query_as(
                "SELECT id, COALESCE(reset_count, 0) \
                 FROM conversations \
                 WHERE group_id = $1",
            )
            .bind(group_id)
            .fetch_optional(&pool)
            .await
        }
    }
    .map_err(|e| {
        error!(
            "❌ [putGroupMetadataBlob] Failed to look up conversation for metadata blob: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (convo_id, server_generation) = match conversation_row {
        Some(id) => id,
        None => {
            warn!(
                "❌ [putGroupMetadataBlob] No conversation found for group_id {}",
                crate::crypto::redact_for_log(group_id)
            );
            return Err(StatusCode::NOT_FOUND);
        }
    };

    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL)",
    )
    .bind(&convo_id)
    .bind(owner_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [putGroupMetadataBlob] membership check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        warn!("❌ [putGroupMetadataBlob] Caller is not a member of the group");
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate size
    if size == 0 {
        warn!("❌ [putGroupMetadataBlob] Empty blob body");
        return Err(StatusCode::BAD_REQUEST);
    }

    if size > MAX_METADATA_BLOB_SIZE {
        warn!(
            "❌ [putGroupMetadataBlob] Blob too large: {} bytes from {}",
            size,
            crate::crypto::redact_for_log(owner_did)
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate blob_locator is a valid UUID
    if uuid::Uuid::parse_str(blob_locator).is_err() {
        warn!(
            "❌ [putGroupMetadataBlob] Invalid blob_locator format: {}",
            crate::crypto::redact_for_log(blob_locator)
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate group_id is non-empty
    if group_id.is_empty() {
        warn!("❌ [putGroupMetadataBlob] Empty group_id");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Idempotency: check if blob already exists
    let existing = sqlx::query_scalar::<_, i32>(
        "SELECT size FROM group_metadata_blobs WHERE blob_locator = $1",
    )
    .bind(blob_locator)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(
            "❌ [putGroupMetadataBlob] DB error checking existing blob: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Some(existing_size) = existing {
        if let Err(e) = sqlx::query(
            "UPDATE group_metadata_blobs \
             SET convo_id = COALESCE(convo_id, $2), \
                 reset_generation = COALESCE(reset_generation, $3), \
                 metadata_version = COALESCE(metadata_version, $4), \
                 kind = COALESCE(kind, $5) \
             WHERE blob_locator = $1",
        )
        .bind(blob_locator)
        .bind(&convo_id)
        .bind(
            params
                .reset_generation
                .map(|v| v as i32)
                .or(Some(server_generation)),
        )
        .bind(params.metadata_version)
        .bind(kind)
        .execute(&pool)
        .await
        {
            warn!(
                "⚠️ [putGroupMetadataBlob] Failed to backfill existing blob scope: {}",
                e
            );
        }
        return Ok(Json(PutGroupMetadataBlobOutput {
            blob_locator: blob_locator.clone(),
            size: existing_size as i64,
        }));
    }

    // Insert blob directly into the database
    sqlx::query(
        "INSERT INTO group_metadata_blobs \
            (blob_locator, group_id, convo_id, reset_generation, metadata_version, kind, owner_did, data, size) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(blob_locator)
    .bind(group_id)
    .bind(&convo_id)
    .bind(params.reset_generation.map(|v| v as i32).unwrap_or(server_generation))
    .bind(params.metadata_version)
    .bind(kind)
    .bind(owner_did)
    .bind(&data)
    .bind(size as i32)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [putGroupMetadataBlob] DB error inserting blob: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Retention-on-write (finding F9): prune superseded blobs for this
    // conversation beyond the newest MAX_METADATA_BLOBS_PER_CONVO. Matched
    // by convo_id (current scoping) OR group_id (legacy rows with NULL
    // convo_id, and pre-reset generations of the same conversation).
    // Best-effort — a pruning failure must not fail the upload.
    match sqlx::query(
        "DELETE FROM group_metadata_blobs \
         WHERE blob_locator IN ( \
             SELECT blob_locator FROM group_metadata_blobs \
             WHERE convo_id = $1 OR group_id = $2 \
             ORDER BY created_at DESC, blob_locator DESC \
             OFFSET $3 \
         )",
    )
    .bind(&convo_id)
    .bind(group_id)
    .bind(MAX_METADATA_BLOBS_PER_CONVO)
    .execute(&pool)
    .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            info!(
                "🧹 [putGroupMetadataBlob] Pruned {} superseded metadata blobs for convo {}",
                result.rows_affected(),
                crate::crypto::redact_for_log(&convo_id)
            );
        }
        Ok(_) => {}
        Err(e) => {
            warn!(
                "⚠️ [putGroupMetadataBlob] Metadata blob retention pruning failed: {}",
                e
            );
        }
    }

    info!(
        "✅ [putGroupMetadataBlob] Stored blob {} ({} bytes) for group {} by {}",
        crate::crypto::redact_for_log(blob_locator),
        size,
        crate::crypto::redact_for_log(group_id),
        crate::crypto::redact_for_log(owner_did)
    );

    Ok(Json(PutGroupMetadataBlobOutput {
        blob_locator: blob_locator.clone(),
        size: size as i64,
    }))
}
