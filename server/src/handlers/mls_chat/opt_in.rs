use axum::{extract::State, http::StatusCode, Json};
use tracing::{error, info, warn};

use jacquard_axum::ExtractXrpc;

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::opt_in::{OptInOutput, OptInRequest, OptInStatus},
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.optIn";

/// Consolidated opt-in endpoint (POST)
/// POST /xrpc/blue.catbird.mlsChat.optIn
///
/// Action-based dispatch:
///   - "optIn": Enable MLS chat
///   - "optOut": Disable MLS chat
///   - "getStatus": Check opt-in status for a list of DIDs
#[tracing::instrument(skip(pool, input))]
pub async fn opt_in_post(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<OptInRequest>,
) -> Result<Json<OptInOutput<'static>>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match input.action.as_ref() {
        "optIn" => {
            let user_did = &auth_user.did;
            let device_id = input.device_id.as_deref();

            // Ensure user exists in users table (for FK constraint)
            sqlx::query(
                "INSERT INTO users (did, created_at, last_seen_at)
                 VALUES ($1, NOW(), NOW())
                 ON CONFLICT (did) DO NOTHING",
            )
            .bind(user_did)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to create user record: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            // Insert or update opt-in record
            let result = sqlx::query_as::<_, (chrono::DateTime<chrono::Utc>,)>(
                "INSERT INTO opt_in (did, device_id, opted_in_at)
                 VALUES ($1, $2, NOW())
                 ON CONFLICT (did)
                 DO UPDATE SET
                    device_id = EXCLUDED.device_id,
                    opted_in_at = NOW()
                 RETURNING opted_in_at",
            )
            .bind(user_did)
            .bind(device_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("Failed to insert/update opt-in record: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            info!(did = %crate::crypto::redact_for_log(&user_did), device_id = ?device_id, "User opted in to MLS chat");

            Ok(Json(OptInOutput {
                opted_in: Some(true),
                opted_in_at: Some(chrono_to_datetime(result.0)),
                statuses: None,
                success: Some(true),
                allow_followers_bypass: None,
                allow_following_bypass: None,
                auto_expire_days: None,
                extra_data: Default::default(),
            }))
        }

        "optOut" => {
            let user_did = &auth_user.did;

            let result = sqlx::query("DELETE FROM opt_in WHERE did = $1")
                .bind(user_did)
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("Failed to delete opt-in record: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            let success = result.rows_affected() > 0;

            info!(did = %crate::crypto::redact_for_log(user_did), success = success, "User opted out of MLS chat");

            Ok(Json(OptInOutput {
                opted_in: Some(false),
                opted_in_at: None,
                statuses: None,
                success: Some(success),
                allow_followers_bypass: None,
                allow_following_bypass: None,
                auto_expire_days: None,
                extra_data: Default::default(),
            }))
        }

        "getStatus" => {
            let dids: Vec<String> = input
                .dids
                .as_ref()
                .map(|d| d.iter().map(|did| did.to_string()).collect())
                .unwrap_or_default();

            if dids.is_empty() {
                warn!("No DIDs provided for getStatus");
                return Err(StatusCode::BAD_REQUEST);
            }

            if dids.len() > 100 {
                warn!("Too many DIDs requested: {} (max 100)", dids.len());
                return Err(StatusCode::BAD_REQUEST);
            }

            info!("Checking opt-in status for {} DIDs", dids.len());

            let results = sqlx::query_as::<_, (String, chrono::DateTime<chrono::Utc>)>(
                "SELECT did, opted_in_at
                 FROM opt_in
                 WHERE did = ANY($1)",
            )
            .bind(&dids)
            .fetch_all(&pool)
            .await
            .map_err(|e| {
                error!("Failed to query opt-in status: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            let mut status_map: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>> =
                results.into_iter().collect();

            let statuses: Vec<OptInStatus<'static>> = dids
                .into_iter()
                .map(|did| {
                    if let Some(opted_in_at) = status_map.remove(&did) {
                        OptInStatus {
                            did: did.parse().expect("DID should be valid"),
                            opted_in: true,
                            opted_in_at: Some(chrono_to_datetime(opted_in_at)),
                            extra_data: Default::default(),
                        }
                    } else {
                        OptInStatus {
                            did: did.parse().expect("DID should be valid"),
                            opted_in: false,
                            opted_in_at: None,
                            extra_data: Default::default(),
                        }
                    }
                })
                .collect();

            Ok(Json(OptInOutput {
                opted_in: None,
                opted_in_at: None,
                statuses: Some(statuses),
                success: Some(true),
                allow_followers_bypass: None,
                allow_following_bypass: None,
                auto_expire_days: None,
                extra_data: Default::default(),
            }))
        }

        other => {
            warn!("Unknown optIn action: {}", other);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
