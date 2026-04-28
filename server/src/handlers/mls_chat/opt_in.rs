use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use jacquard_axum::ExtractXrpc;

use crate::{
    auth::AuthUser,
    federation::DeviceRecordClient,
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
#[tracing::instrument(skip(pool, device_client, input))]
pub async fn opt_in_post(
    State(pool): State<DbPool>,
    State(device_client): State<Arc<DeviceRecordClient>>,
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

            info!(did = %crate::crypto::redact_for_log(user_did), device_id = ?device_id, "User opted in to MLS chat");

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

            // Step 1: Check local opt_in table
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

            // Step 2: For DIDs not found locally, check their PDS for device records
            let missing_dids: Vec<&str> = dids
                .iter()
                .filter(|did| !status_map.contains_key(did.as_str()))
                .map(|s| s.as_str())
                .collect();

            if !missing_dids.is_empty() {
                debug!(
                    "Checking PDS device records for {} missing DIDs",
                    missing_dids.len()
                );

                for did in &missing_dids {
                    match device_client.fetch_device_records(did).await {
                        Ok(records) if !records.is_empty() => {
                            // User has device records on their PDS — they're opted in.
                            // Auto-populate the local opt_in table so future lookups are fast.
                            let now = chrono::Utc::now();

                            if let Err(e) = sqlx::query(
                                "INSERT INTO users (did, created_at, last_seen_at)
                                 VALUES ($1, NOW(), NOW())
                                 ON CONFLICT (did) DO NOTHING",
                            )
                            .bind(did)
                            .execute(&pool)
                            .await
                            {
                                debug!("Failed to upsert user for {}: {}", did, e);
                            }

                            if let Err(e) = sqlx::query(
                                "INSERT INTO opt_in (did, opted_in_at)
                                 VALUES ($1, NOW())
                                 ON CONFLICT (did) DO NOTHING",
                            )
                            .bind(did)
                            .execute(&pool)
                            .await
                            {
                                debug!("Failed to auto-insert opt_in for {}: {}", did, e);
                            }

                            info!(did = %crate::crypto::redact_for_log(did), "Auto-opted in user from PDS device records");
                            status_map.insert(did.to_string(), now);
                        }
                        Ok(_) => {
                            // No device records — user hasn't set up MLS
                            debug!(did = %crate::crypto::redact_for_log(did), "No device records on PDS");
                        }
                        Err(e) => {
                            // PDS unreachable or error — don't block, just log
                            debug!(did = %crate::crypto::redact_for_log(did), error = %e, "Failed to fetch device records from PDS");
                        }
                    }
                }
            }

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
