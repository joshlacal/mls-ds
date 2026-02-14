use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    Json,
};
use jacquard_axum::ExtractXrpc;
use tracing::warn;

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::get_key_package_status::GetKeyPackageStatusRequest,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getKeyPackageStatus";

/// Get key package status, stats, and history.
/// GET /xrpc/blue.catbird.mlsChat.getKeyPackageStatus
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_key_package_status(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<GetKeyPackageStatusRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = input.did.as_ref().map(|d| d.to_string());
    let cipher_suite = input.cipher_suite.as_ref().map(|s| s.to_string());
    let limit = input.limit;
    let cursor = input.cursor.as_ref().map(|s| s.to_string());

    // Parse which sections to include
    let sections: Vec<&str> = input
        .include
        .as_deref()
        .unwrap_or("stats")
        .split(',')
        .map(|s| s.trim())
        .collect();

    let mut result = serde_json::Map::new();

    for section in &sections {
        match *section {
            "stats" => {
                // Reconstruct query string for the v1 handler
                let mut parts = Vec::new();
                if let Some(ref d) = did {
                    parts.push(format!("did={}", d));
                }
                if let Some(ref cs) = cipher_suite {
                    parts.push(format!("cipherSuite={}", cs));
                }
                let raw = if parts.is_empty() {
                    None
                } else {
                    Some(parts.join("&"))
                };

                let stats_result = crate::handlers::get_key_package_stats::get_key_package_stats(
                    State(pool.clone()),
                    auth_user.clone(),
                    RawQuery(raw),
                )
                .await?;
                result.insert(
                    "stats".to_string(),
                    serde_json::to_value(stats_result.0).unwrap_or_default(),
                );
            }

            "status" => {
                // Build query params for the v1 handler
                let mut query_json = serde_json::Map::new();
                if let Some(l) = limit {
                    query_json.insert("limit".to_string(), serde_json::json!(l));
                }
                if let Some(ref c) = cursor {
                    query_json.insert("cursor".to_string(), serde_json::json!(c));
                }

                let params: crate::handlers::get_key_package_status::GetKeyPackageStatusParams =
                    serde_json::from_value(serde_json::Value::Object(query_json)).map_err(|e| {
                        warn!("Failed to construct status query: {}", e);
                        StatusCode::BAD_REQUEST
                    })?;

                let status_result =
                    crate::handlers::get_key_package_status::get_key_package_status(
                        State(pool.clone()),
                        auth_user.clone(),
                        axum::extract::Query(params),
                    )
                    .await?;
                result.insert(
                    "status".to_string(),
                    serde_json::to_value(status_result.0).unwrap_or_default(),
                );
            }

            "history" => {
                // Reconstruct query string for the v1 handler
                let mut parts = Vec::new();
                if let Some(l) = limit {
                    parts.push(format!("limit={}", l));
                }
                if let Some(ref c) = cursor {
                    parts.push(format!("cursor={}", c));
                }
                let raw = if parts.is_empty() {
                    None
                } else {
                    Some(parts.join("&"))
                };

                let history_result =
                    crate::handlers::get_key_package_history::get_key_package_history(
                        State(pool.clone()),
                        auth_user.clone(),
                        RawQuery(raw),
                    )
                    .await?;
                result.insert(
                    "history".to_string(),
                    serde_json::to_value(history_result.0).unwrap_or_default(),
                );
            }

            unknown => {
                warn!(
                    "Unknown include section for getKeyPackageStatus: {}",
                    unknown
                );
            }
        }
    }

    Ok(Json(serde_json::Value::Object(result)))
}
