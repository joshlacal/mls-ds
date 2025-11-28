use axum::{extract::State, http::StatusCode, Json};
use sqlx::Row;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue::catbird::mls::invalidate_welcome::{Input, Output, OutputData},
    storage::DbPool,
};

/// Invalidate a Welcome message that cannot be processed.
/// POST /xrpc/blue.catbird.mls.invalidateWelcome
///
/// Used when a client receives NoMatchingKeyPackage error during Welcome processing.
/// This marks the Welcome as consumed with an error reason, allowing the client to
/// fall back to External Commit or request re-addition.
pub async fn invalidate_welcome(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, StatusCode> {
    // Enforce authentication
    if let Err(_e) = crate::auth::enforce_standard(
        &auth_user.claims,
        "blue.catbird.mls.invalidateWelcome",
    ) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let device_did = &auth_user.did;
    let convo_id = &input.data.convo_id;
    let reason = &input.data.reason;

    // Extract user DID from device DID
    let (user_did, _device_id) = parse_device_did(device_did).map_err(|e| {
        error!("Invalid device DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    info!(
        convo = %crate::crypto::redact_for_log(convo_id),
        user = %crate::crypto::redact_for_log(&user_did),
        reason = %reason,
        "Processing Welcome invalidation request"
    );

    // Find and invalidate the Welcome message
    // Only allow invalidating Welcomes intended for this user
    let result: Option<String> = sqlx::query(
        r#"
        UPDATE welcome_messages
        SET consumed = true,
            consumed_at = NOW(),
            error_reason = $3
        WHERE convo_id = $1
          AND recipient_did = $2
          AND consumed = false
        RETURNING id
        "#,
    )
    .bind(convo_id)
    .bind(&user_did)
    .bind(reason)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to invalidate Welcome: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .map(|row| row.get("id"));

    match result {
        Some(welcome_id) => {
            info!(
                convo = %crate::crypto::redact_for_log(convo_id),
                user = %crate::crypto::redact_for_log(&user_did),
                welcome_id = %welcome_id,
                "Welcome invalidated successfully"
            );
            Ok(Json(Output::from(OutputData {
                invalidated: true,
                welcome_id: Some(welcome_id),
            })))
        }
        None => {
            warn!(
                convo = %crate::crypto::redact_for_log(convo_id),
                user = %crate::crypto::redact_for_log(&user_did),
                "No unconsumed Welcome found to invalidate"
            );
            // Return success with invalidated=false rather than an error
            // This is non-critical - the Welcome might have already been invalidated
            Ok(Json(Output::from(OutputData {
                invalidated: false,
                welcome_id: None,
            })))
        }
    }
}
