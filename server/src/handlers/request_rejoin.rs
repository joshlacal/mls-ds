use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use serde::{Deserialize, Serialize};
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
    let key_package_bytes = base64::engine::general_purpose::STANDARD.decode(&input.key_package)
        .map_err(|e| {
            warn!("Invalid base64 KeyPackage: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    if key_package_bytes.is_empty() {
        warn!("Empty KeyPackage after decoding");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Compute MLS-compliant hash_ref using OpenMLS
    use openmls::prelude::{KeyPackageIn, ProtocolVersion};
    use openmls::prelude::tls_codec::Deserialize;

    // Create crypto provider (RustCrypto implements OpenMlsCrypto)
    let provider = openmls_rust_crypto::RustCrypto::default();

    // Deserialize and validate the key package
    let kp_in = KeyPackageIn::tls_deserialize(&mut key_package_bytes.as_slice())
        .map_err(|e| {
            warn!("Failed to deserialize key package: {:?}", e);
            StatusCode::BAD_REQUEST
        })?;
    let kp = kp_in
        .validate(&provider, ProtocolVersion::default())
        .map_err(|e| {
            warn!("Failed to validate key package: {:?}", e);
            StatusCode::BAD_REQUEST
        })?;

    // Compute the MLS-defined hash reference
    let hash_ref = kp
        .hash_ref(&provider)
        .map_err(|e| {
            error!("Failed to compute hash_ref: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let key_package_hash = hex::encode(hash_ref.as_slice());

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
            let kp_id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO key_packages (id, owner_did, cipher_suite, key_package, key_package_hash, expires_at)
                 VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '7 days')
                 ON CONFLICT DO NOTHING"
            )
            .bind(&kp_id)
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
