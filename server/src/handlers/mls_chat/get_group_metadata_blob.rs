use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use tracing::{error, warn};

use crate::{auth::AuthUser, storage::DbPool};

const NSID: &str = "blue.catbird.mlsChat.getGroupMetadataBlob";

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetGroupMetadataBlobParams {
    pub blob_locator: String,
    pub group_id: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// GET /xrpc/blue.catbird.mlsChat.getGroupMetadataBlob?blobLocator=<id>&groupId=<hex>
///
/// Downloads an encrypted group metadata blob. Returns raw encrypted bytes.
/// The blob is opaque — decryption requires the MLS epoch key derived by
/// group members.
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_group_metadata_blob(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<GetGroupMetadataBlobParams>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [getGroupMetadataBlob] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Fetch blob data from the database
    let data: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT data FROM group_metadata_blobs WHERE blob_locator = $1 AND group_id = $2",
    )
    .bind(&params.blob_locator)
    .bind(&params.group_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(
            "❌ [getGroupMetadataBlob] DB error fetching blob: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match data {
        Some(bytes) => Ok((
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )),
        None => {
            warn!(
                "❌ [getGroupMetadataBlob] Blob not found: locator={} group={}",
                params.blob_locator, params.group_id
            );
            Err(StatusCode::NOT_FOUND)
        }
    }
}
