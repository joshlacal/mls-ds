use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{auth::AuthUser, storage::DbPool};

// Database row struct for query results
#[derive(Debug, Clone)]
struct KeyPackageHistoryRow {
    key_package_hash: String,
    created_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    consumed_for_convo_id: Option<String>,
    consumed_by_device_id: Option<String>,
    device_id: Option<String>,
    cipher_suite: String,
    convo_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackageHistoryEntry {
    pub package_id: String,
    pub created_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub consumed_for_convo: Option<String>,
    pub consumed_for_convo_name: Option<String>,
    pub consumed_by_device: Option<String>,
    pub device_id: Option<String>,
    pub cipher_suite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeyPackageHistoryResponse {
    pub history: Vec<KeyPackageHistoryEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Get key package consumption history for authenticated user
/// GET /xrpc/blue.catbird.mls.getKeyPackageHistory
#[tracing::instrument(skip(pool))]
pub async fn get_key_package_history(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    RawQuery(query): RawQuery,
) -> Result<Json<GetKeyPackageHistoryResponse>, StatusCode> {
    // Auth already enforced by AuthUser extractor.
    // Skipping v1 NSID check here to allow v2 (mlsChat) delegation.

    // Parse query parameters
    let query_str = query.unwrap_or_default();
    let mut limit = 20i64;
    let mut cursor: Option<String> = None;

    for pair in query_str.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let decoded_value = match urlencoding::decode(value) {
                Ok(v) => v.to_string(),
                Err(e) => {
                    warn!(
                        "Invalid URL encoding for query parameter '{}': {}",
                        key, e
                    );
                    return Err(StatusCode::BAD_REQUEST);
                }
            };
            match key {
                "limit" => {
                    if let Ok(l) = decoded_value.parse::<i64>() {
                        limit = l.clamp(1, 100);
                    }
                }
                "cursor" => cursor = Some(decoded_value),
                _ => {}
            }
        }
    }

    let user_did = &auth_user.claims.iss;
    info!(
        "Fetching key package history for user: {} (limit: {})",
        user_did, limit
    );

    // Fetch history from database
    let rows: Vec<KeyPackageHistoryRow> = if let Some(cursor_id) = cursor {
        sqlx::query_as!(
            KeyPackageHistoryRow,
            r#"
            SELECT
                kp.key_package_hash,
                kp.created_at,
                kp.consumed_at,
                kp.consumed_for_convo_id,
                kp.consumed_by_device_id,
                kp.device_id,
                kp.cipher_suite,
                c.name as convo_name
            FROM key_packages kp
            LEFT JOIN conversations c ON kp.consumed_for_convo_id = c.id
            WHERE kp.owner_did = $1
              AND kp.consumed_at IS NOT NULL
              AND kp.key_package_hash < $2
            ORDER BY kp.consumed_at DESC, kp.key_package_hash DESC
            LIMIT $3
            "#,
            user_did,
            cursor_id,
            limit
        )
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            warn!("Failed to fetch key package history: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        sqlx::query_as!(
            KeyPackageHistoryRow,
            r#"
            SELECT
                kp.key_package_hash,
                kp.created_at,
                kp.consumed_at,
                kp.consumed_for_convo_id,
                kp.consumed_by_device_id,
                kp.device_id,
                kp.cipher_suite,
                c.name as convo_name
            FROM key_packages kp
            LEFT JOIN conversations c ON kp.consumed_for_convo_id = c.id
            WHERE kp.owner_did = $1
              AND kp.consumed_at IS NOT NULL
            ORDER BY kp.consumed_at DESC, kp.key_package_hash DESC
            LIMIT $2
            "#,
            user_did,
            limit
        )
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            warn!("Failed to fetch key package history: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    // Build response
    let history: Vec<KeyPackageHistoryEntry> = rows
        .iter()
        .map(|row| KeyPackageHistoryEntry {
            package_id: row.key_package_hash.clone(),
            created_at: row.created_at,
            consumed_at: row.consumed_at,
            consumed_for_convo: row.consumed_for_convo_id.clone(),
            consumed_for_convo_name: row.convo_name.clone(),
            consumed_by_device: row.consumed_by_device_id.clone(),
            device_id: row.device_id.clone(),
            cipher_suite: row.cipher_suite.clone(),
        })
        .collect();

    // Generate next cursor if we got a full page
    let next_cursor = if history.len() as i64 == limit {
        history.last().map(|h| h.package_id.clone())
    } else {
        None
    };

    info!("Returning {} history entries", history.len());

    Ok(Json(GetKeyPackageHistoryResponse {
        history,
        cursor: next_cursor,
    }))
}
