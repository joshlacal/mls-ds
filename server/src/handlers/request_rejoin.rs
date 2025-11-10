use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    storage::DbPool,
};

#[derive(Debug, Deserialize)]
pub struct RequestRejoinInput {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    #[serde(rename = "keyPackage")]
    pub key_package: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RequestRejoinOutput {
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub pending: bool,
    #[serde(rename = "approvedAt", skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
}

/// Request to rejoin an MLS conversation after local state loss
/// POST /xrpc/blue.catbird.mls.requestRejoin
#[tracing::instrument(skip(pool, input))]
pub async fn request_rejoin(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<RequestRejoinInput>,
) -> Result<Json<RequestRejoinOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.requestRejoin") {
        error!("Unauthorized - failed auth check");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = &auth_user.did;

    // Validate input
    if input.convo_id.is_empty() {
        warn!("Empty convo_id provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    if input.key_package.is_empty() {
        warn!("Empty keyPackage provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Decode and validate KeyPackage
    let key_package_bytes = URL_SAFE_NO_PAD.decode(&input.key_package)
        .map_err(|e| {
            warn!("Invalid base64url KeyPackage: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    if key_package_bytes.is_empty() {
        warn!("Empty KeyPackage after decoding");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Compute KeyPackage hash for tracking
    let mut hasher = Sha256::new();
    hasher.update(&key_package_bytes);
    let key_package_hash = hex::encode(hasher.finalize());

    info!("Processing rejoin request");

    // Check if conversation exists
    let convo_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1)"
    )
    .bind(&input.convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to check conversation existence: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !convo_exists {
        warn!("Conversation not found");
        return Err(StatusCode::NOT_FOUND);
    }

    // Check member status
    let member = sqlx::query_as::<_, (Option<chrono::DateTime<chrono::Utc>>, bool)>(
        "SELECT left_at, needs_rejoin FROM members WHERE convo_id = $1 AND member_did = $2"
    )
    .bind(&input.convo_id)
    .bind(&did)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch member: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match member {
        None => {
            // User was never a member of this conversation
            warn!("User was never a member of conversation");
            return Err(StatusCode::FORBIDDEN);
        }
        Some((left_at, needs_rejoin)) if left_at.is_none() && !needs_rejoin => {
            // User is still an active member with valid state
            warn!("User is already an active member of conversation");
            return Err(StatusCode::CONFLICT);
        }
        Some(_) => {
            // User needs rejoin - mark the request
            info!("Marking rejoin request for user");

            sqlx::query(
                "UPDATE members
                 SET needs_rejoin = true,
                     rejoin_requested_at = NOW(),
                     rejoin_key_package_hash = $3
                 WHERE convo_id = $1 AND member_did = $2"
            )
            .bind(&input.convo_id)
            .bind(did)
            .bind(&key_package_hash)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to mark rejoin request: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            // Store the KeyPackage for when admin re-adds the user
            sqlx::query(
                "INSERT INTO key_packages (did, cipher_suite, key_data, key_package_hash, expires_at)
                 VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')
                 ON CONFLICT (did, cipher_suite, key_data) DO NOTHING"
            )
            .bind(did)
            .bind("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519") // Default cipher suite
            .bind(&key_package_bytes)
            .bind(&key_package_hash)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to store rejoin KeyPackage: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            // Generate request ID from conversation + member + timestamp
            let request_id = format!("{}-{}-rejoin", input.convo_id, did);

            // TODO: In a full implementation, this would:
            // 1. Notify other conversation members of rejoin request
            // 2. Create a pending approval workflow
            // 3. Auto-approve for single-member convos or based on policy
            // 4. Generate Welcome message when approved and admin re-adds member

            // For now, mark as pending - requires manual admin action to re-add
            info!("✅ Rejoin request created: {}", request_id);

            Ok(Json(RequestRejoinOutput {
                request_id,
                pending: true,
                approved_at: None,
            }))
        }
    }
}
