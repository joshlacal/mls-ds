use axum::{extract::State, http::StatusCode};
use jacquard_axum::ExtractXrpc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::delete_blob::DeleteBlobRequest,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.deleteBlob";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// POST /xrpc/blue.catbird.mlsChat.deleteBlob
///
/// Soft-deletes an encrypted blob. Only the blob owner can delete it.
#[tracing::instrument(skip(pool, auth_user, input))]
pub async fn delete_blob(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<DeleteBlobRequest>,
) -> Result<StatusCode, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [deleteBlob] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let owner_did = &auth_user.did;

    // Verify ownership and soft-delete
    let result = sqlx::query(
        "UPDATE blobs SET deleted_at = now() WHERE id = $1 AND owner_did = $2 AND deleted_at IS NULL",
    )
    .bind(input.blob_id.as_ref())
    .bind(owner_did)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [deleteBlob] DB error deleting blob: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if result.rows_affected() == 0 {
        warn!(
            "❌ [deleteBlob] Blob not found or not owned by {}: {}",
            crate::crypto::redact_for_log(owner_did), crate::crypto::redact_for_log(input.blob_id.as_ref())
        );
        return Err(StatusCode::NOT_FOUND);
    }

    info!(
        "✅ [deleteBlob] Soft-deleted blob {} for {}",
        crate::crypto::redact_for_log(input.blob_id.as_ref()), crate::crypto::redact_for_log(owner_did)
    );
    Ok(StatusCode::OK)
}
