use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
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
    pub group_id: String,
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

    // Treat empty string the same as None (Swift client sends "" when no locator)
    let effective_locator = params
        .blob_locator
        .as_deref()
        .filter(|s| !s.is_empty());

    let row = match effective_locator {
        Some(locator) => {
            // Exact match: both blob_locator and group_id
            sqlx::query_as::<_, BlobRow>(
                "SELECT data, size FROM group_metadata_blobs \
                 WHERE blob_locator = $1 AND group_id = $2",
            )
            .bind(locator)
            .bind(&params.group_id)
            .fetch_optional(&pool)
            .await
        }
        None => {
            // Latest blob for the group
            sqlx::query_as::<_, BlobRow>(
                "SELECT data, size FROM group_metadata_blobs \
                 WHERE group_id = $1 \
                 ORDER BY created_at DESC \
                 LIMIT 1",
            )
            .bind(&params.group_id)
            .fetch_optional(&pool)
            .await
        }
    }
    .map_err(|e| {
        error!(
            "❌ [getGroupMetadataBlob] DB error fetching blob: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match row {
        Some(blob) => {
            info!(
                "✅ [getGroupMetadataBlob] Returning blob ({} bytes) for group {}",
                blob.size, params.group_id
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
                effective_locator, params.group_id
            );
            Err(StatusCode::NOT_FOUND)
        }
    }
}
