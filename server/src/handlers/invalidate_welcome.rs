use axum::{extract::State, http::StatusCode, Json};
use sqlx::Row;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue_catbird::mls::invalidate_welcome::{
        InvalidateWelcome, InvalidateWelcomeOutput,
    },
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
    body: String,
) -> Result<Json<InvalidateWelcomeOutput<'static>>, StatusCode> {
    let input = crate::jacquard_json::from_json_body::<InvalidateWelcome>(&body)?;
    // Auth already enforced by AuthUser extractor.
    // Skipping v1 NSID check here to allow v2 (mlsChat) delegation.

    let device_did = &auth_user.did;
    let convo_id = input.convo_id.as_str();
    let reason = input.reason.as_str();

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
            Ok(Json(InvalidateWelcomeOutput {
                invalidated: true,
                welcome_id: Some(welcome_id.into()),
                extra_data: Default::default(),
            }))
        }
        None => {
            warn!(
                convo = %crate::crypto::redact_for_log(convo_id),
                user = %crate::crypto::redact_for_log(&user_did),
                "No unconsumed Welcome found to invalidate"
            );
            // Return success with invalidated=false rather than an error
            // This is non-critical - the Welcome might have already been invalidated
            Ok(Json(InvalidateWelcomeOutput {
                invalidated: false,
                welcome_id: None,
                extra_data: Default::default(),
            }))
        }
    }
}
