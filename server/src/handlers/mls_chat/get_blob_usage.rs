use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use tracing::error;

use crate::{
    auth::AuthUser,
    blob_store::BlobStore,
    generated::blue_catbird::mlsChat::get_blob_usage::{GetBlobUsageOutput, GetBlobUsageRequest},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getBlobUsage";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// GET /xrpc/blue.catbird.mlsChat.getBlobUsage
///
/// Returns the authenticated user's current blob storage usage, quota, and
/// blob count.
#[tracing::instrument(skip(pool, blob_store, auth_user, _input))]
pub async fn get_blob_usage(
    State(pool): State<DbPool>,
    State(blob_store): State<BlobStore>,
    auth_user: AuthUser,
    ExtractXrpc(_input): ExtractXrpc<GetBlobUsageRequest>,
) -> Result<Json<GetBlobUsageOutput<'static>>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [getBlobUsage] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let owner_did = &auth_user.did;

    let row: (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(size_bytes), 0)::BIGINT, COUNT(*) FROM blobs WHERE owner_did = $1 AND deleted_at IS NULL",
    )
    .bind(owner_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [getBlobUsage] DB error fetching usage: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(GetBlobUsageOutput {
        used_bytes: row.0,
        quota_bytes: blob_store.quota_bytes(),
        blob_count: row.1,
        extra_data: Default::default(),
    }))
}
