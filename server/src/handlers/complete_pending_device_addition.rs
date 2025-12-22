use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{auth::AuthUser, device_utils::parse_device_did, storage::DbPool};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletePendingDeviceAdditionInput {
    pending_addition_id: String,
    new_epoch: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletePendingDeviceAdditionOutput {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Mark a pending device addition as complete
/// POST /xrpc/blue.catbird.mls.completePendingDeviceAddition
#[tracing::instrument(skip(pool))]
pub async fn complete_pending_device_addition(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<CompletePendingDeviceAdditionInput>,
) -> Result<Json<CompletePendingDeviceAdditionOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(
        &auth_user.claims,
        "blue.catbird.mls.completePendingDeviceAddition",
    ) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Extract user DID from potentially device-qualified DID
    let (user_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
        error!("Invalid DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let now = Utc::now();

    info!(
        user = %crate::crypto::redact_for_log(&user_did),
        pending_id = %crate::crypto::redact_for_log(&input.pending_addition_id),
        new_epoch = input.new_epoch,
        "Completing pending device addition"
    );

    // Update the pending addition to completed status
    // Only allow completion if the caller is the one who claimed it
    let result = sqlx::query!(
        r#"
        UPDATE pending_device_additions
        SET status = 'completed',
            completed_by_did = $2,
            completed_at = $3,
            new_epoch = $4,
            updated_at = $3
        WHERE id = $1
          AND status = 'in_progress'
          AND claimed_by_did = $2
        RETURNING id
        "#,
        input.pending_addition_id,
        user_did,
        now,
        input.new_epoch as i32
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to complete pending addition: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if result.is_none() {
        // Either not found, not in_progress, or claimed by someone else
        let pending: Option<(String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT status, claimed_by_did
            FROM pending_device_additions
            WHERE id = $1
            "#,
        )
        .bind(&input.pending_addition_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch pending addition status: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        match pending {
            None => {
                warn!("Pending addition not found: {}", input.pending_addition_id);
                // Return structured response instead of 404 for better ATProto proxy compatibility
                return Ok(Json(CompletePendingDeviceAdditionOutput {
                    success: false,
                    error: Some("PendingAdditionNotFound".to_string()),
                }));
            }
            Some((status, claimed_by)) => {
                if status != "in_progress" {
                    warn!(
                        "Pending addition {} is not in_progress (status: {})",
                        input.pending_addition_id, status
                    );
                    // Return structured response instead of CONFLICT for better ATProto proxy compatibility
                    return Ok(Json(CompletePendingDeviceAdditionOutput {
                        success: false,
                        error: Some(format!("InvalidStatus:{}", status)),
                    }));
                }
                if claimed_by.as_deref() != Some(&user_did) {
                    warn!(
                        "Pending addition {} claimed by {}, not {}",
                        input.pending_addition_id,
                        claimed_by.as_deref().unwrap_or("unknown"),
                        user_did
                    );
                    return Err(StatusCode::FORBIDDEN);
                }
            }
        }
    }

    info!(
        "Successfully completed pending addition {} at epoch {}",
        input.pending_addition_id, input.new_epoch
    );

    Ok(Json(CompletePendingDeviceAdditionOutput {
        success: true,
        error: None,
    }))
}
