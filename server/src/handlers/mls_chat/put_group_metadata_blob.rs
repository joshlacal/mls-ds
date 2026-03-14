use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{auth::AuthUser, storage::DbPool};

const NSID: &str = "blue.catbird.mlsChat.putGroupMetadataBlob";

/// Maximum metadata blob size: 1 MB
const MAX_METADATA_BLOB_SIZE: usize = 1_048_576;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutGroupMetadataBlobParams {
    pub blob_locator: String,
    pub group_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PutGroupMetadataBlobOutput {
    pub blob_locator: String,
    pub size: i64,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// POST /xrpc/blue.catbird.mlsChat.putGroupMetadataBlob?blobLocator=<id>&groupId=<hex>
///
/// Stores an encrypted group metadata blob. Input is raw binary bytes
/// (Content-Type: application/octet-stream or */*) with blobLocator and
/// groupId as query parameters. The server stores opaque bytes — it never
/// sees plaintext metadata.
#[tracing::instrument(skip(pool, auth_user, body))]
pub async fn put_group_metadata_blob(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<PutGroupMetadataBlobParams>,
    body: Bytes,
) -> Result<Json<PutGroupMetadataBlobOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [putGroupMetadataBlob] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let owner_did = &auth_user.did;
    let blob_locator = &params.blob_locator;
    let group_id = &params.group_id;
    let data = body.to_vec();
    let size = data.len();

    // Validate size
    if size == 0 {
        warn!("❌ [putGroupMetadataBlob] Empty blob body");
        return Err(StatusCode::BAD_REQUEST);
    }

    if size > MAX_METADATA_BLOB_SIZE {
        warn!(
            "❌ [putGroupMetadataBlob] Blob too large: {} bytes from {}",
            size, owner_did
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate blob_locator is a valid UUID
    if uuid::Uuid::parse_str(blob_locator).is_err() {
        warn!(
            "❌ [putGroupMetadataBlob] Invalid blob_locator format: {}",
            blob_locator
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate group_id is non-empty
    if group_id.is_empty() {
        warn!("❌ [putGroupMetadataBlob] Empty group_id");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Idempotency: check if blob already exists
    let existing = sqlx::query_scalar::<_, i32>(
        "SELECT size FROM group_metadata_blobs WHERE blob_locator = $1",
    )
    .bind(blob_locator)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(
            "❌ [putGroupMetadataBlob] DB error checking existing blob: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Some(existing_size) = existing {
        return Ok(Json(PutGroupMetadataBlobOutput {
            blob_locator: blob_locator.clone(),
            size: existing_size as i64,
        }));
    }

    // Insert blob directly into the database
    sqlx::query(
        "INSERT INTO group_metadata_blobs (blob_locator, group_id, owner_did, data, size) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(blob_locator)
    .bind(group_id)
    .bind(owner_did)
    .bind(&data)
    .bind(size as i32)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(
            "❌ [putGroupMetadataBlob] DB error inserting blob: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        "✅ [putGroupMetadataBlob] Stored blob {} ({} bytes) for group {} by {}",
        blob_locator, size, group_id, owner_did
    );

    Ok(Json(PutGroupMetadataBlobOutput {
        blob_locator: blob_locator.clone(),
        size: size as i64,
    }))
}
