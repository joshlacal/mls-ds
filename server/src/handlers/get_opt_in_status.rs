use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::{error, info, warn};

use crate::{auth::AuthUser, storage::DbPool};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OptInStatus {
    did: String,
    opted_in: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    opted_in_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetOptInStatusOutput {
    statuses: Vec<OptInStatus>,
}

/// Get opt-in status for a list of users
/// GET /xrpc/blue.catbird.mls.getOptInStatus?dids=did1&dids=did2 (ATProto array format)
/// Also supports legacy comma-separated format: ?dids=did1,did2
#[tracing::instrument(skip(pool))]
pub async fn get_opt_in_status(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    RawQuery(query): RawQuery,
) -> Result<Json<GetOptInStatusOutput>, StatusCode> {
    // Enforce authentication
    if let Err(_e) =
        crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.getOptInStatus")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Parse query string manually to handle ATProto array format (?dids=X&dids=Y)
    let query_str = query.unwrap_or_default();
    info!("getOptInStatus called with query: {}", query_str);

    let mut dids: Vec<String> = Vec::new();

    for pair in query_str.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == "dids" {
                let decoded_value = urlencoding::decode(value).unwrap_or_default().to_string();
                // Support both ATProto array format (?dids=X&dids=Y) and comma-separated (?dids=X,Y)
                if decoded_value.contains(',') {
                    // Comma-separated legacy format
                    dids.extend(
                        decoded_value
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                    );
                } else if !decoded_value.is_empty() {
                    // Single DID from ATProto array format
                    dids.push(decoded_value);
                }
            }
        }
    }

    // Validate DID count (max 100 per request)
    if dids.is_empty() {
        warn!("No DIDs provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    if dids.len() > 100 {
        warn!("Too many DIDs requested: {} (max 100)", dids.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    info!("Checking opt-in status for {} DIDs", dids.len());

    // Query opt-in status for all DIDs
    let results = sqlx::query_as::<_, (String, DateTime<Utc>)>(
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

    // Build status map from query results
    let mut status_map: std::collections::HashMap<String, DateTime<Utc>> =
        results.into_iter().collect();

    // Build response with all requested DIDs
    let statuses: Vec<OptInStatus> = dids
        .into_iter()
        .map(|did| {
            if let Some(opted_in_at) = status_map.remove(&did) {
                OptInStatus {
                    did,
                    opted_in: true,
                    opted_in_at: Some(opted_in_at),
                }
            } else {
                OptInStatus {
                    did,
                    opted_in: false,
                    opted_in_at: None,
                }
            }
        })
        .collect();

    Ok(Json(GetOptInStatusOutput { statuses }))
}
