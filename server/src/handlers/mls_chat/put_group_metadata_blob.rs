use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{self, Deserialize, Deserializer, Serialize};
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
pub struct PutGroupMetadataBlobInput {
    pub blob_locator: String,
    pub group_id: String,
    #[serde(deserialize_with = "deserialize_atproto_bytes")]
    pub data: Vec<u8>,
}

/// Deserialize AT Protocol `bytes` type: `{"$bytes": "<base64>"}`.
fn deserialize_atproto_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct AtProtoBytes {
        #[serde(rename = "$bytes")]
        bytes: String,
    }

    let wrapper = AtProtoBytes::deserialize(deserializer)?;
    STANDARD
        .decode(&wrapper.bytes)
        .map_err(serde::de::Error::custom)
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

/// POST /xrpc/blue.catbird.mlsChat.putGroupMetadataBlob
///
/// Stores an encrypted group metadata blob. Input is JSON with blobLocator,
/// groupId, and data (AT Protocol bytes type). The server stores opaque bytes —
/// it never sees plaintext metadata.
#[tracing::instrument(skip(pool, auth_user, input))]
pub async fn put_group_metadata_blob(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<PutGroupMetadataBlobInput>,
) -> Result<Json<PutGroupMetadataBlobOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [putGroupMetadataBlob] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let owner_did = &auth_user.did;
    let blob_locator = &input.blob_locator;
    let group_id = &input.group_id;
    let size = input.data.len();

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
    .bind(&input.data)
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
