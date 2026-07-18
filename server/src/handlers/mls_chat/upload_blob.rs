use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{auth::AuthUser, blob_store::BlobStore, storage::DbPool};

const NSID: &str = "blue.catbird.mlsChat.uploadBlob";

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadBlobParams {
    pub convo_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadBlobOutput {
    pub blob_id: String,
    pub size: i64,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// POST /xrpc/blue.catbird.mlsChat.uploadBlob?convoId=<id>
///
/// Uploads encrypted blob bytes to S3-compatible storage (SeaweedFS).
/// The server assigns a blob_id (UUIDv4) for the uploaded blob.
/// Requires the uploader to be an active member of the target conversation.
#[tracing::instrument(skip(pool, blob_store, auth_user, body))]
pub async fn upload_blob(
    State(pool): State<DbPool>,
    State(blob_store): State<BlobStore>,
    auth_user: AuthUser,
    Query(params): Query<UploadBlobParams>,
    body: Bytes,
) -> Result<Json<UploadBlobOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [uploadBlob] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let owner_did = &auth_user.did;
    let size = body.len() as i64;
    let blob_id = uuid::Uuid::new_v4().to_string().to_lowercase();

    // Verify uploader is a member of the target conversation
    if let Err(e) =
        crate::middleware::mls_auth::verify_group_membership(owner_did, &params.convo_id, &pool)
            .await
    {
        warn!(
            "❌ [uploadBlob] {} is not a member of {}: {}",
            crate::crypto::redact_for_log(owner_did),
            crate::crypto::redact_for_log(&params.convo_id),
            e
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate size
    if size == 0 {
        warn!("❌ [uploadBlob] Empty blob body");
        return Err(StatusCode::BAD_REQUEST);
    }

    if size > blob_store.max_blob_size() {
        warn!(
            "❌ [uploadBlob] Blob too large: {} bytes from {}",
            size,
            crate::crypto::redact_for_log(owner_did)
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Fast-fail quota pre-check before paying for the S3 upload. This is
    // advisory only — the authoritative, race-free check happens inside
    // `insert_blob_within_quota` below (finding F39).
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
            crate::crypto::redact_for_log(owner_did),
            used_bytes,
            size,
            blob_store.quota_bytes()
        );
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    // Upload to S3
    blob_store.put(&blob_id, body.to_vec()).await.map_err(|e| {
        error!("❌ [uploadBlob] S3 upload failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Insert metadata with convo_id. The quota is re-checked atomically
    // (per-owner advisory lock + SUM + INSERT in one transaction) so
    // concurrent uploads cannot both slip past the pre-check above.
    let expires_at = Utc::now() + Duration::days(blob_store.ttl_days());
    let inserted = crate::db::insert_blob_within_quota(
        &pool,
        &blob_id,
        owner_did,
        &params.convo_id,
        size,
        blob_store.quota_bytes(),
        expires_at,
    )
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

    if !inserted {
        warn!(
            "❌ [uploadBlob] Quota exceeded (concurrent uploads) for {}: new={}, quota={}",
            crate::crypto::redact_for_log(owner_did),
            size,
            blob_store.quota_bytes()
        );
        // The blob row was never inserted — remove the orphaned S3 object.
        let bs = blob_store.clone();
        let bid = blob_id.clone();
        tokio::spawn(async move {
            let _ = bs.delete(&bid).await;
        });
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    info!(
        "✅ [uploadBlob] Uploaded blob {} ({} bytes) for {} in convo {}",
        crate::crypto::redact_for_log(&blob_id),
        size,
        crate::crypto::redact_for_log(owner_did),
        crate::crypto::redact_for_log(&params.convo_id)
    );

    Ok(Json(UploadBlobOutput { blob_id, size }))
}
