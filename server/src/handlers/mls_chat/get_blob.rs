use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use tracing::{error, warn};

use crate::{auth::AuthUser, blob_store::BlobStore, storage::DbPool};

const NSID: &str = "blue.catbird.mlsChat.getBlob";

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlobParams {
    pub blob_id: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// GET /xrpc/blue.catbird.mlsChat.getBlob?blobId=<id>
///
/// Downloads an encrypted blob from S3-compatible storage.
/// No ownership check — the blob is encrypted and useless without the
/// decryption key from the MLS message.
#[tracing::instrument(skip(pool, blob_store, auth_user))]
pub async fn get_blob(
    State(pool): State<DbPool>,
    State(blob_store): State<BlobStore>,
    auth_user: AuthUser,
    Query(params): Query<GetBlobParams>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [getBlob] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Check blob exists and is not expired/deleted
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM blobs WHERE id = $1 AND deleted_at IS NULL AND expires_at > now())",
    )
    .bind(&params.blob_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [getBlob] DB error checking blob: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !exists {
        warn!("❌ [getBlob] Blob not found or expired: {}", params.blob_id);
        return Err(StatusCode::NOT_FOUND);
    }

    // Fetch from S3
    let data = blob_store.get(&params.blob_id).await.map_err(|e| {
        error!("❌ [getBlob] S3 fetch failed: {}", e);
        StatusCode::NOT_FOUND
    })?;

    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        data,
    ))
}
