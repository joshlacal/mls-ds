use axum::{extract::State, http::StatusCode, Json};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{auth::AuthUser, device_utils::parse_device_did, storage::DbPool};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimPendingDeviceAdditionInput {
    pending_addition_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackageRef {
    did: String,
    key_package: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_package_hash: Option<String>,
    cipher_suite: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimPendingDeviceAdditionOutput {
    claimed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    convo_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_credential_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_package: Option<KeyPackageRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_by: Option<String>,
}

/// Claim a pending device addition to prevent race conditions
/// POST /xrpc/blue.catbird.mls.claimPendingDeviceAddition
#[tracing::instrument(skip(pool))]
pub async fn claim_pending_device_addition(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<ClaimPendingDeviceAdditionInput>,
) -> Result<Json<ClaimPendingDeviceAdditionOutput>, StatusCode> {
    // Auth already enforced by AuthUser extractor.
    // Skipping v1 NSID check here to allow v2 (mlsChat) delegation.

    // Extract user DID from potentially device-qualified DID
    let (user_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
        error!("Invalid DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let now = Utc::now();
    let claim_expires = now + Duration::seconds(60);

    info!(
        user = %crate::crypto::redact_for_log(&user_did),
        pending_id = %crate::crypto::redact_for_log(&input.pending_addition_id),
        "Attempting to claim pending device addition"
    );

    // Release any expired claims before attempting to claim
    // This ensures claims don't stay locked forever if a client crashes
    let released = sqlx::query!(
        r#"
        UPDATE pending_device_additions
        SET status = 'pending',
            claimed_by_did = NULL,
            claimed_at = NULL,
            claim_expires_at = NULL,
            updated_at = NOW()
        WHERE status = 'in_progress'
          AND claim_expires_at < $1
        "#,
        now
    )
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to release expired claims: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();

    if released > 0 {
        info!(
            "Released {} expired pending addition claims before claim attempt",
            released
        );
    }

    // First, get the pending addition to verify membership and status
    let pending: Option<PendingAdditionRow> = sqlx::query_as!(
        PendingAdditionRow,
        r#"
        SELECT
            id,
            convo_id,
            user_did,
            new_device_id,
            new_device_credential_did,
            device_name,
            status,
            claimed_by_did
        FROM pending_device_additions
        WHERE id = $1
        "#,
        input.pending_addition_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch pending addition: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let pending = match pending {
        Some(p) => p,
        None => {
            warn!("Pending addition not found: {}", input.pending_addition_id);
            // Return structured response instead of 404 for better ATProto proxy compatibility
            return Ok(Json(ClaimPendingDeviceAdditionOutput {
                claimed: false,
                convo_id: None,
                device_credential_did: None,
                key_package: None,
                claimed_by: None,
            }));
        }
    };

    // Check if already completed
    if pending.status != "pending" && pending.status != "in_progress" {
        warn!(
            "Pending addition {} already in terminal state: {}",
            input.pending_addition_id, pending.status
        );
        // Return structured response indicating already completed instead of 404
        return Ok(Json(ClaimPendingDeviceAdditionOutput {
            claimed: false,
            convo_id: Some(pending.convo_id),
            device_credential_did: Some(pending.new_device_credential_did),
            key_package: None,
            claimed_by: pending.claimed_by_did,
        }));
    }

    // Verify caller is a member of the conversation
    // Note: SELECT 1 returns PostgreSQL INTEGER (4 bytes), so we use i32 to match
    let is_member: Option<(i32,)> = sqlx::query_as(
        r#"
        SELECT 1
        FROM members
        WHERE convo_id = $1
          AND user_did = $2
          AND left_at IS NULL
        "#,
    )
    .bind(&pending.convo_id)
    .bind(&user_did)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if is_member.is_none() {
        warn!(
            "User {} is not a member of conversation {}",
            user_did, pending.convo_id
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Prevent user from claiming their own device addition
    // Return a clear response rather than an error - this is expected behavior
    // when the device sync manager hasn't been properly configured with deviceUUID
    if pending.user_did == user_did {
        info!(
            "User {} attempted to claim their own device addition - returning not claimed",
            crate::crypto::redact_for_log(&user_did)
        );
        return Ok(Json(ClaimPendingDeviceAdditionOutput {
            claimed: false,
            convo_id: Some(pending.convo_id),
            device_credential_did: Some(pending.new_device_credential_did),
            key_package: None,
            claimed_by: None, // No claimed_by for self-claim - client detects via claimed=false + no claimedBy
        }));
    }

    // Attempt to atomically claim the pending addition
    // This uses a CTE to handle the race condition properly
    let claim_result = sqlx::query!(
        r#"
        UPDATE pending_device_additions
        SET status = 'in_progress',
            claimed_by_did = $2,
            claimed_at = $3,
            claim_expires_at = $4,
            updated_at = $3
        WHERE id = $1
          AND (status = 'pending' OR (status = 'in_progress' AND claim_expires_at < $3))
        RETURNING id
        "#,
        input.pending_addition_id,
        user_did,
        now,
        claim_expires
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to claim pending addition: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if claim_result.is_none() {
        // Already claimed by someone else
        info!(
            "Pending addition {} already claimed by {}",
            input.pending_addition_id,
            pending.claimed_by_did.as_deref().unwrap_or("unknown")
        );
        return Ok(Json(ClaimPendingDeviceAdditionOutput {
            claimed: false,
            convo_id: Some(pending.convo_id),
            device_credential_did: Some(pending.new_device_credential_did),
            key_package: None,
            claimed_by: pending.claimed_by_did,
        }));
    }

    info!(
        "Successfully claimed pending addition {} for conversation {}",
        input.pending_addition_id, pending.convo_id
    );

    // Fetch an available key package for the new device
    let key_package: Option<KeyPackageRow> = sqlx::query_as!(
        KeyPackageRow,
        r#"
        SELECT
            kp.owner_did as did,
            encode(kp.key_package, 'base64') as key_package,
            kp.key_package_hash,
            kp.cipher_suite
        FROM key_packages kp
        WHERE kp.owner_did = $1
          AND kp.device_id = $2
          AND kp.consumed_at IS NULL
          AND kp.expires_at > $3
          AND (kp.reserved_at IS NULL OR kp.reserved_at < $4)
        ORDER BY kp.created_at ASC
        LIMIT 1
        "#,
        pending.user_did,
        pending.new_device_id,
        now,
        now - Duration::minutes(5)
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch key package: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let key_package_ref = key_package.map(|kp| KeyPackageRef {
        did: kp.did,
        key_package: kp.key_package.unwrap_or_default(),
        key_package_hash: kp.key_package_hash,
        cipher_suite: kp.cipher_suite,
    });

    if key_package_ref.is_none() {
        warn!(
            "No available key package for device {} (user {})",
            pending.new_device_id, pending.user_did
        );
        // Still return success - the client can decide what to do
        // They may need to wait for the device to upload more key packages
    }

    Ok(Json(ClaimPendingDeviceAdditionOutput {
        claimed: true,
        convo_id: Some(pending.convo_id),
        device_credential_did: Some(pending.new_device_credential_did),
        key_package: key_package_ref,
        claimed_by: Some(user_did),
    }))
}

// Internal row types for sqlx queries
#[derive(Debug)]
struct PendingAdditionRow {
    id: String,
    convo_id: String,
    user_did: String,
    new_device_id: String,
    new_device_credential_did: String,
    device_name: Option<String>,
    status: String,
    claimed_by_did: Option<String>,
}

#[derive(Debug)]
struct KeyPackageRow {
    did: String,
    key_package: Option<String>,
    key_package_hash: Option<String>,
    cipher_suite: String,
}
