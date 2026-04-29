use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, StatusCode},
    response::Response,
};
use serde::Deserialize;
use tracing::{error, info, warn};

use crate::{auth::AuthUser, storage::DbPool};

const NSID: &str = "blue.catbird.mlsChat.getGroupMetadataBlob";

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetGroupMetadataBlobParams {
    /// Optional — when omitted or empty, the server returns the latest blob for the group.
    pub blob_locator: Option<String>,
    pub convo_id: Option<String>,
    pub group_id: Option<String>,
    pub reset_generation: Option<i64>,
    pub metadata_version: Option<i64>,
    pub kind: Option<String>,
}

// ---------------------------------------------------------------------------
// Row type for sqlx
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct BlobRow {
    data: Vec<u8>,
    size: i32,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// GET /xrpc/blue.catbird.mlsChat.getGroupMetadataBlob?groupId=<hex>[&blobLocator=<id>]
///
/// Downloads an encrypted group metadata blob as raw bytes.
/// When `blobLocator` is provided (and non-empty), returns the exact matching blob.
/// When omitted or empty, returns the latest blob for the given `groupId`.
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_group_metadata_blob(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<GetGroupMetadataBlobParams>,
) -> Result<Response, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [getGroupMetadataBlob] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let caller_did = &auth_user.did;
    let kind = params.kind.as_deref().unwrap_or("metadata");
    if !matches!(kind, "metadata" | "avatar") {
        warn!("❌ [getGroupMetadataBlob] Invalid blob kind: {}", kind);
        return Err(StatusCode::BAD_REQUEST);
    }

    if matches!(params.metadata_version, Some(v) if v < 1) {
        warn!("❌ [getGroupMetadataBlob] Invalid metadata_version");
        return Err(StatusCode::BAD_REQUEST);
    }

    if matches!(params.reset_generation, Some(v) if v < 0) {
        warn!("❌ [getGroupMetadataBlob] Invalid reset_generation");
        return Err(StatusCode::BAD_REQUEST);
    }

    let group_id = params.group_id.as_deref().filter(|s| !s.is_empty());

    // Verify caller is a member of the stable conversation. If convoId is not
    // provided, preserve legacy behavior by deriving it from the current groupId.
    let convo_id: Option<String> = match params.convo_id.as_deref() {
        Some(convo_id) => {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1)")
                    .bind(convo_id)
                    .fetch_one(&pool)
                    .await
                    .map_err(|e| {
                        error!(
                            "❌ [getGroupMetadataBlob] Failed to look up conversation: {}",
                            e
                        );
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;
            if exists {
                Some(convo_id.to_string())
            } else {
                None
            }
        }
        None => {
            let Some(group_id) = group_id else {
                warn!("❌ [getGroupMetadataBlob] Missing both convoId and groupId");
                return Err(StatusCode::BAD_REQUEST);
            };

            sqlx::query_scalar("SELECT id FROM conversations WHERE group_id = $1")
                .bind(group_id)
                .fetch_optional(&pool)
                .await
                .map_err(|e| {
                    error!(
                        "❌ [getGroupMetadataBlob] Failed to look up conversation for group: {}",
                        e
                    );
                    StatusCode::INTERNAL_SERVER_ERROR
                })?
        }
    };

    let convo_id = match convo_id {
        Some(id) => id,
        None => {
            warn!("❌ [getGroupMetadataBlob] No conversation found for metadata blob lookup");
            return Err(StatusCode::NOT_FOUND);
        }
    };

    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL)",
    )
    .bind(&convo_id)
    .bind(caller_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [getGroupMetadataBlob] membership check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        warn!("❌ [getGroupMetadataBlob] Caller is not a member of the group");
        return Err(StatusCode::FORBIDDEN);
    }

    // Treat empty string the same as None (Swift client sends "" when no locator)
    let effective_locator = params.blob_locator.as_deref().filter(|s| !s.is_empty());

    let row = fetch_metadata_blob(
        &pool,
        &convo_id,
        group_id,
        effective_locator,
        params.reset_generation.map(|v| v as i32),
        params.metadata_version,
        kind,
    )
    .await
    .map_err(|e| {
        error!("❌ [getGroupMetadataBlob] DB error fetching blob: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match row {
        Some(blob) => {
            info!(
                "✅ [getGroupMetadataBlob] Returning blob ({} bytes) for group {}",
                blob.size,
                group_id
                    .map(crate::crypto::redact_for_log)
                    .unwrap_or_else(|| "<conversation-scoped>".to_string())
            );
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_LENGTH, blob.data.len().to_string())
                .body(Body::from(blob.data))
                .unwrap())
        }
        None => {
            warn!(
                "❌ [getGroupMetadataBlob] Blob not found: locator={:?} group={}",
                effective_locator.map(crate::crypto::redact_for_log),
                group_id
                    .map(crate::crypto::redact_for_log)
                    .unwrap_or_else(|| "<conversation-scoped>".to_string())
            );
            Err(StatusCode::NOT_FOUND)
        }
    }
}

async fn fetch_metadata_blob(
    pool: &DbPool,
    convo_id: &str,
    group_id: Option<&str>,
    locator: Option<&str>,
    reset_generation: Option<i32>,
    metadata_version: Option<i64>,
    kind: &str,
) -> Result<Option<BlobRow>, sqlx::Error> {
    match (locator, group_id) {
        (Some(locator), Some(group_id)) => {
            sqlx::query_as::<_, BlobRow>(
                "SELECT data, size FROM group_metadata_blobs \
                 WHERE blob_locator = $1 \
                   AND group_id = $2 \
                   AND (convo_id = $3 OR convo_id IS NULL) \
                   AND kind = $4",
            )
            .bind(locator)
            .bind(group_id)
            .bind(convo_id)
            .bind(kind)
            .fetch_optional(pool)
            .await
        }
        (Some(locator), None) => {
            sqlx::query_as::<_, BlobRow>(
                "SELECT data, size FROM group_metadata_blobs \
                 WHERE blob_locator = $1 \
                   AND convo_id = $2 \
                   AND kind = $3",
            )
            .bind(locator)
            .bind(convo_id)
            .bind(kind)
            .fetch_optional(pool)
            .await
        }
        (None, Some(group_id)) => {
            sqlx::query_as::<_, BlobRow>(
                "SELECT data, size FROM group_metadata_blobs \
                 WHERE group_id = $1 \
                   AND (convo_id = $2 OR convo_id IS NULL) \
                   AND ($3::INTEGER IS NULL OR reset_generation = $3) \
                   AND ($4::BIGINT IS NULL OR metadata_version = $4) \
                   AND kind = $5 \
                 ORDER BY reset_generation DESC NULLS LAST, metadata_version DESC NULLS LAST, created_at DESC \
                 LIMIT 1",
            )
            .bind(group_id)
            .bind(convo_id)
            .bind(reset_generation)
            .bind(metadata_version)
            .bind(kind)
            .fetch_optional(pool)
            .await
        }
        (None, None) => {
            sqlx::query_as::<_, BlobRow>(
                "SELECT data, size FROM group_metadata_blobs \
                 WHERE convo_id = $1 \
                   AND ($2::INTEGER IS NULL OR reset_generation = $2) \
                   AND ($3::BIGINT IS NULL OR metadata_version = $3) \
                   AND kind = $4 \
                 ORDER BY reset_generation DESC NULLS LAST, metadata_version DESC NULLS LAST, created_at DESC \
                 LIMIT 1",
            )
            .bind(convo_id)
            .bind(reset_generation)
            .bind(metadata_version)
            .bind(kind)
            .fetch_optional(pool)
            .await
        }
    }
}
