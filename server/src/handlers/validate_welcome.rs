use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};
use openmls::prelude::*;
use openmls::messages::Welcome;

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    storage::DbPool,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateWelcomeInput {
    #[serde(with = "crate::atproto_bytes")]
    welcome_message: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateWelcomeOutput {
    valid: bool,
    key_package_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reserved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reserved_until: Option<String>,
}

/// Validate a Welcome message and reserve the referenced key package
/// POST /xrpc/blue.catbird.mls.validateWelcome
#[tracing::instrument(skip(pool, input))]
pub async fn validate_welcome(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<ValidateWelcomeInput>,
) -> Result<Json<ValidateWelcomeOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.validateWelcome") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = &auth_user.did;

    // Extract user DID from device DID (handles both single and multi-device mode)
    let (user_did, _device_id) = parse_device_did(did)
        .map_err(|e| {
            error!("Invalid device DID format: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    if input.welcome_message.is_empty() {
        warn!("Empty welcome message");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Parse MLS Welcome message using TLS codec
    let welcome = match Welcome::tls_deserialize(&mut input.welcome_message.as_slice()) {
        Ok(w) => w,
        Err(e) => {
            warn!("Failed to deserialize Welcome message: {:?}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Extract ALL candidate key package refs from the Welcome
    let secrets = welcome.secrets();
    if secrets.is_empty() {
        warn!("Welcome message has no secrets");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Build set of all key package hashes referenced in the Welcome
    let candidate_hashes: Vec<String> = secrets.iter()
        .map(|encrypted_secret| {
            let kp_ref = encrypted_secret.new_member();
            hex::encode(kp_ref.as_slice())
        })
        .collect();

    if candidate_hashes.is_empty() {
        warn!("No key package refs extracted from Welcome");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Find intersection: which of these hashes belong to the authenticated DID
    // and are available (not consumed/reserved)?
    let matching_rows = sqlx::query!(
        r#"
        SELECT key_package_hash, owner_did
        FROM key_packages
        WHERE owner_did = $1
          AND key_package_hash = ANY($2)
          AND consumed_at IS NULL
          AND (reserved_at IS NULL OR reserved_at < NOW() - INTERVAL '5 minutes')
        "#,
        did,
        &candidate_hashes
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("Failed to query matching key packages: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if matching_rows.is_empty() {
        warn!(
            "No available key packages for {} match Welcome (candidates: {:?})",
            did, candidate_hashes
        );
        return Ok(Json(ValidateWelcomeOutput {
            valid: false,
            key_package_hash: candidate_hashes.get(0).unwrap_or(&String::new()).to_string(),
            recipient_did: Some(did.clone()),
            group_id: None,
            reserved: Some(false),
            reserved_until: None,
        }));
    }

    if matching_rows.len() > 1 {
        error!(
            "Multiple key packages match for {}: {:?} (BUG: duplicate issuance or ambiguous Welcome)",
            did,
            matching_rows.iter().map(|r| &r.key_package_hash).collect::<Vec<_>>()
        );
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Exactly one match - this is the key package to reserve
    let key_package_hash = &matching_rows[0].key_package_hash;

    // Get the group_id from the welcome_messages table (server created this when adding members)
    // NOTE: We use user_did (not device_did) because welcome messages are stored per user
    let welcome_row = sqlx::query!(
        r#"
        SELECT convo_id, key_package_hash
        FROM welcome_messages
        WHERE recipient_did = $1
          AND key_package_hash = decode($2, 'hex')
          AND consumed = false
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        user_did,
        key_package_hash
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to lookup welcome message: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let group_id = match welcome_row {
        Some(row) => row.convo_id,
        None => {
            warn!(
                "No welcome_messages row found for user_did={}, key_package_hash={}",
                user_did, key_package_hash
            );
            return Ok(Json(ValidateWelcomeOutput {
                valid: false,
                key_package_hash: key_package_hash.to_string(),
                recipient_did: Some(did.clone()),
                group_id: None,
                reserved: Some(false),
                reserved_until: None,
            }));
        }
    };

    // Reserve the key package
    let reserved = match crate::db::reserve_key_package(&pool, did, key_package_hash, &group_id).await {
        Ok(success) => success,
        Err(e) => {
            error!("Failed to reserve key package: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let reserved_until = if reserved {
        Some((chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339())
    } else {
        None
    };

    Ok(Json(ValidateWelcomeOutput {
        valid: true,
        key_package_hash: key_package_hash.to_string(),
        recipient_did: Some(did.clone()),
        group_id: Some(group_id.clone()),
        reserved: Some(reserved),
        reserved_until,
    }))

}
