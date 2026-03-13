use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    Json,
};
use chrono::{Duration, Utc};
use serde::Serialize;
use tracing::{error, info, warn};

use crate::{auth::AuthUser, blob_store::BlobStore, storage::DbPool};

const NSID: &str = "blue.catbird.mlsChat.uploadBlob";

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadBlobOutput {
    pub blob_id: String,
    pub size: i64,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// POST /xrpc/blue.catbird.mlsChat.uploadBlob
///
/// Uploads encrypted blob bytes to S3-compatible storage (SeaweedFS).
/// The server assigns a blob_id (UUIDv4) for the uploaded blob.
#[tracing::instrument(skip(pool, blob_store, auth_user, body))]
pub async fn upload_blob(
    State(pool): State<DbPool>,
    State(blob_store): State<BlobStore>,
    auth_user: AuthUser,
    body: Bytes,
) -> Result<Json<UploadBlobOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [uploadBlob] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let owner_did = &auth_user.did;
    let size = body.len() as i64;
    let blob_id = uuid::Uuid::new_v4().to_string().to_lowercase();

    // Validate size
    if size == 0 {
        warn!("❌ [uploadBlob] Empty blob body");
        return Err(StatusCode::BAD_REQUEST);
    }

    if size > blob_store.max_blob_size() {
        warn!(
            "❌ [uploadBlob] Blob too large: {} bytes from {}",
            size, owner_did
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check quota
    let used_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM blobs WHERE owner_did = $1 AND deleted_at IS NULL",
    )
    .bind(owner_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [uploadBlob] DB error checking quota: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if used_bytes + size > blob_store.quota_bytes() {
        warn!(
            "❌ [uploadBlob] Quota exceeded for {}: used={}, new={}, quota={}",
            owner_did,
            used_bytes,
            size,
            blob_store.quota_bytes()
        );
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    // Upload to S3
    blob_store
        .put(&blob_id, body.to_vec())
        .await
        .map_err(|e| {
            error!("❌ [uploadBlob] S3 upload failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Insert metadata
    let expires_at = Utc::now() + Duration::days(blob_store.ttl_days());
    sqlx::query(
        "INSERT INTO blobs (id, owner_did, size_bytes, created_at, expires_at) \
         VALUES ($1, $2, $3, now(), $4)",
    )
    .bind(&blob_id)
    .bind(owner_did)
    .bind(size)
    .bind(expires_at)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [uploadBlob] DB error inserting blob metadata: {}", e);
        // Best effort: try to clean up S3
        let bs = blob_store.clone();
        let bid = blob_id.clone();
        tokio::spawn(async move {
            let _ = bs.delete(&bid).await;
        });
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        "✅ [uploadBlob] Uploaded blob {} ({} bytes) for {}",
        blob_id, size, owner_did
    );

    Ok(Json(UploadBlobOutput {
        blob_id,
        size,
    }))
}
