use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use crate::{auth::AuthUser, blob_store::BlobStore, storage::DbPool};

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
    // The legacy blob table path has no transaction-bound device/interval
    // capability and must not be treated as an authorization implementation.
    // Keep the route fail-closed until it is composed from
    // `authorize_blob_read -> PendingAuthorizedBlobFetch::publicize ->
    // BlobStore::get_authorized`.
    let _ = (pool, blob_store, auth_user, params);
    Err::<axum::response::Response, _>(StatusCode::NOT_IMPLEMENTED)
}

#[cfg(test)]
mod tests {
    #[test]
    fn legacy_get_route_is_fail_closed() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/handlers/mls_chat/get_blob.rs"
        ));
        assert!(source.contains("NOT_IMPLEMENTED"));
        assert!(!source.contains(&["blob_store", ".get(&"].concat()));
        assert!(!source
            .contains(&["crate::middleware::mls_auth::", "verify_group_membership("].concat()));
    }
}
