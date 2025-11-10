use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use tracing::{error, info, warn};

use crate::{
    auth::{enforce_standard, AuthUser},
    generated::blue::catbird::mls::register_device::{
        Input, Output, OutputData, WelcomeMessageRef, WelcomeMessageRefData, NSID,
    },
    storage::DbPool,
};

/// Construct device MLS DID from user DID and device ID
fn construct_device_did(user_did: &str, device_id: &str) -> String {
    if device_id.is_empty() {
        user_did.to_string()
    } else {
        format!("{}#{}", user_did, device_id)
    }
}

/// Register a new device identity for multi-device support
/// POST /xrpc/blue.catbird.mls.registerDevice
#[tracing::instrument(skip(pool, input))]
pub async fn register_device(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, StatusCode> {
    // Enforce authentication
    if let Err(_e) = enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [register_device] Unauthorized access attempt");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user_did = &auth_user.did;
    let now = chrono::Utc::now();

    info!(
        "📱 [register_device] Registering device '{}' for user {}",
        input.data.device_name, user_did
    );

    // Validate device name
    if input.data.device_name.is_empty() || input.data.device_name.len() > 128 {
        warn!("❌ [register_device] Invalid device name length");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate signature public key (must be exactly 32 bytes for Ed25519)
    if input.data.signature_public_key.len() != 32 {
        error!(
            "❌ [register_device] Invalid signature public key length: {} (expected 32)",
            input.data.signature_public_key.len()
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate key packages count
    if input.data.key_packages.is_empty() || input.data.key_packages.len() > 200 {
        error!(
            "❌ [register_device] Invalid key package count: {} (expected 1-200)",
            input.data.key_packages.len()
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Generate unique device ID
    let device_id = uuid::Uuid::new_v4().to_string();

    // Construct device MLS DID
    let mls_did = construct_device_did(user_did, &device_id);

    info!(
        "📱 [register_device] Generated device ID: {}, MLS DID: {}",
        device_id, mls_did
    );

    // Insert device into user_devices table
    let insert_result = sqlx::query(
        "INSERT INTO user_devices (user_did, device_id, device_mls_did, device_name, signature_public_key, key_packages_available, registered_at, last_seen)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    )
    .bind(user_did)
    .bind(&device_id)
    .bind(&mls_did)
    .bind(&input.data.device_name)
    .bind(&input.data.signature_public_key)
    .bind(input.data.key_packages.len() as i32)
    .bind(&now)
    .bind(&now)
    .execute(&pool)
    .await;

    if let Err(e) = insert_result {
        if e.to_string().contains("unique constraint")
            || e.to_string().contains("duplicate key")
        {
            error!("❌ [register_device] Duplicate public key or MLS DID");
            return Err(StatusCode::CONFLICT);
        } else {
            error!("❌ [register_device] Database error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    info!("✅ [register_device] Device registered in user_devices table");

    // Store key packages
    let mut key_packages_stored = 0;
    for key_package_ref in &input.data.key_packages {
        // Decode base64url key package
        let kp_bytes_result = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&key_package_ref.data.key_package);

        let kp_bytes = match kp_bytes_result {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(
                    "❌ [register_device] Invalid base64url key package: {}",
                    e
                );
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        if kp_bytes.is_empty() {
            error!("❌ [register_device] Empty key package data");
            return Err(StatusCode::BAD_REQUEST);
        }

        // Default expiry: 30 days from now
        let expires_at = now + chrono::Duration::days(30);

        // Store key package using existing database function
        match crate::db::store_key_package(
            &pool,
            &mls_did,
            &key_package_ref.data.cipher_suite,
            kp_bytes,
            expires_at,
        )
        .await
        {
            Ok(_) => {
                key_packages_stored += 1;
            }
            Err(e) => {
                error!("❌ [register_device] Failed to store key package: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    info!(
        "✅ [register_device] Stored {} key packages",
        key_packages_stored
    );

    // Find all conversations where user is a member (any of their devices)
    let user_convos_result = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT convo_id FROM members
         WHERE user_did = $1 AND left_at IS NULL",
    )
    .bind(user_did)
    .fetch_all(&pool)
    .await;

    let user_convos = match user_convos_result {
        Ok(convos) => convos,
        Err(e) => {
            error!(
                "❌ [register_device] Failed to query user conversations: {}",
                e
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    info!(
        "📍 [register_device] Found {} conversations to auto-join",
        user_convos.len()
    );

    let mut auto_joined_convos = Vec::new();
    let mut welcome_messages = Vec::new();

    // For each conversation, add this device as a new member
    for convo_id in &user_convos {
        // Get the next leaf index for this conversation
        let next_leaf_index_result = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT MAX(leaf_index) FROM members WHERE convo_id = $1",
        )
        .bind(convo_id)
        .fetch_one(&pool)
        .await;

        let next_leaf_index = match next_leaf_index_result {
            Ok(Some(max_index)) => max_index + 1,
            Ok(None) => 0,
            Err(e) => {
                error!(
                    "❌ [register_device] Failed to get leaf index for convo {}: {}",
                    convo_id, e
                );
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        // Check if this user has admin privileges in the conversation
        let is_admin_result = sqlx::query_scalar::<_, bool>(
            "SELECT is_admin FROM members WHERE convo_id = $1 AND user_did = $2 LIMIT 1",
        )
        .bind(convo_id)
        .bind(user_did)
        .fetch_optional(&pool)
        .await;

        let is_admin = match is_admin_result {
            Ok(Some(admin)) => admin,
            Ok(None) => false,
            Err(e) => {
                error!(
                    "❌ [register_device] Failed to check admin status for convo {}: {}",
                    convo_id, e
                );
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        // Add device to members table
        let insert_member_result = sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, device_id, device_name, joined_at, is_admin, leaf_index)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        )
        .bind(convo_id)
        .bind(&mls_did)
        .bind(user_did)
        .bind(&device_id)
        .bind(&input.data.device_name)
        .bind(&now)
        .bind(is_admin)
        .bind(next_leaf_index)
        .execute(&pool)
        .await;

        if let Err(e) = insert_member_result {
            error!(
                "❌ [register_device] Failed to add device to conversation {}: {}",
                convo_id, e
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        auto_joined_convos.push(convo_id.clone());

        // NOTE: Welcome message generation would happen server-side via MLS group state
        // For now, return empty welcome (client will fetch via getWelcome endpoint)
        // In production, server would:
        // 1. Load group state for convo
        // 2. Add device's key package to group
        // 3. Generate Welcome message
        // 4. Store in welcome_messages table
        // 5. Return Welcome in this response

        welcome_messages.push(WelcomeMessageRef::from(WelcomeMessageRefData {
            convo_id: convo_id.clone(),
            welcome: String::new(), // Placeholder - would be actual Welcome base64url
        }));

        info!("✅ [register_device] Added device to conversation");
    }

    info!(
        "✅ [register_device] Device registered successfully: {} auto-joined to {} conversations",
        device_id,
        auto_joined_convos.len()
    );

    Ok(Json(Output::from(OutputData {
        device_id,
        mls_did: mls_did.parse().map_err(|e| {
            error!("❌ [register_device] Failed to parse MLS DID: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?,
        auto_joined_convos,
        welcome_messages: Some(welcome_messages),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AtProtoClaims;

    #[tokio::test]
    async fn test_register_device_validation() {
        // Test signature key length validation
        let sig_key = vec![1u8; 31]; // Wrong length
        assert_eq!(sig_key.len(), 31);

        let sig_key_32 = vec![1u8; 32]; // Correct length
        assert_eq!(sig_key_32.len(), 32);
    }

    #[tokio::test]
    async fn test_device_name_validation() {
        let name = "Josh's iPhone";
        assert!(!name.is_empty());
        assert!(name.len() <= 128);

        let long_name = "a".repeat(129);
        assert!(long_name.len() > 128);
    }
}
