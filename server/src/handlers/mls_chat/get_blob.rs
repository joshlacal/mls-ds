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
/// Only active members of the blob's conversation can download it.
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

    // Look up blob metadata: existence, expiry, and owning conversation
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT convo_id FROM blobs WHERE id = $1 AND deleted_at IS NULL AND expires_at > now()",
    )
    .bind(&params.blob_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("❌ [getBlob] DB error checking blob: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let convo_id = match row {
        Some((cid,)) => cid,
        None => {
            warn!(
                "❌ [getBlob] Blob not found or expired: {}",
                crate::crypto::redact_for_log(&params.blob_id)
            );
            return Err(StatusCode::NOT_FOUND);
        }
    };

    // Verify requester is a member of the blob's conversation
    if let Err(e) =
        crate::middleware::mls_auth::verify_group_membership(&auth_user.did, &convo_id, &pool).await
    {
        warn!(
            "❌ [getBlob] {} not a member of convo {} for blob {}: {}",
            crate::crypto::redact_for_log(&auth_user.did),
            crate::crypto::redact_for_log(&convo_id),
            crate::crypto::redact_for_log(&params.blob_id),
            e
        );
        return Err(StatusCode::FORBIDDEN);
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
