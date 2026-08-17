use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{auth::AuthUser, blob_store::BlobStore, storage::DbPool};

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
    // The legacy upload path writes an unretrievable object before the clean
    // chat blob lifecycle can authorize it. Keep it fail-closed until the
    // handler is composed from prepare_blob -> put_for_blob -> complete_upload
    // under the same deterministic CID and metadata contract as getBlob.
    let _ = (pool, blob_store, auth_user, params, body);
    Err(StatusCode::NOT_IMPLEMENTED)
}

#[cfg(test)]
mod tests {
    #[test]
    fn legacy_upload_route_is_fail_closed() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/handlers/mls_chat/upload_blob.rs"
        ));
        assert!(source.contains("Err(StatusCode::NOT_IMPLEMENTED)"));
        assert!(!source.contains(&["blob_store", ".put(&"].concat()));
        assert!(!source.contains(&["crate::db::", "insert_blob_within_quota("].concat()));
    }
}
