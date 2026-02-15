use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use sqlx::Row;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
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

    let did_raw = input
        .did
        .as_ref()
        .map(|d| d.to_string())
        .unwrap_or_else(|| auth_user.did.clone());
    let (did, _) = parse_device_did(&did_raw).map_err(|e| {
        error!("Invalid device DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let cipher_suite = input.cipher_suite.as_ref().map(|s| s.to_string());
    let limit = input.limit.unwrap_or(50).clamp(1, 100);
    let cursor = input.cursor.as_ref().map(|s| s.to_string());

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
                let available: i64 = if let Some(ref suite) = cipher_suite {
                    sqlx::query_scalar(
                        "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND cipher_suite = $2 AND consumed_at IS NULL AND expires_at > NOW()",
                    )
                    .bind(&did)
                    .bind(suite)
                    .fetch_one(&pool)
                    .await
                } else {
                    sqlx::query_scalar(
                        "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND consumed_at IS NULL AND expires_at > NOW()",
                    )
                    .bind(&did)
                    .fetch_one(&pool)
                    .await
                }
                .map_err(|e| {
                    error!("Failed to count available key packages: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                let total: i64 = if let Some(ref suite) = cipher_suite {
                    sqlx::query_scalar(
                        "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND cipher_suite = $2",
                    )
                    .bind(&did)
                    .bind(suite)
                    .fetch_one(&pool)
                    .await
                } else {
                    sqlx::query_scalar(
                        "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1",
                    )
                    .bind(&did)
                    .fetch_one(&pool)
                    .await
                }
                .map_err(|e| {
                    error!("Failed to count total key packages: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                let expired: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND consumed_at IS NULL AND expires_at <= NOW()",
                )
                .bind(&did)
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    error!("Failed to count expired key packages: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                let consumed = total - available - expired;
                let threshold = 5;
                let needs_replenish = available < threshold;

                info!("Key package stats: available={}, total={}, expired={}", available, total, expired);

                result.insert(
                    "stats".to_string(),
                    serde_json::json!({
                        "available": available,
                        "total": total,
                        "consumed": consumed,
                        "expired": expired,
                        "threshold": threshold,
                        "needsReplenish": needs_replenish,
                    }),
                );
            }

            "status" => {
                let rows = if let Some(ref c) = cursor {
                    sqlx::query(
                        r#"
                        SELECT id, cipher_suite, key_package_hash, created_at, expires_at,
                               consumed_at, device_id
                        FROM key_packages
                        WHERE owner_did = $1 AND consumed_at IS NOT NULL AND id < $2
                        ORDER BY consumed_at DESC
                        LIMIT $3
                        "#,
                    )
                    .bind(&did)
                    .bind(c)
                    .bind(limit)
                    .fetch_all(&pool)
                    .await
                } else {
                    sqlx::query(
                        r#"
                        SELECT id, cipher_suite, key_package_hash, created_at, expires_at,
                               consumed_at, device_id
                        FROM key_packages
                        WHERE owner_did = $1 AND consumed_at IS NOT NULL
                        ORDER BY consumed_at DESC
                        LIMIT $2
                        "#,
                    )
                    .bind(&did)
                    .bind(limit)
                    .fetch_all(&pool)
                    .await
                }
                .map_err(|e| {
                    error!("Failed to fetch consumed key packages: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                let next_cursor = if rows.len() as i64 == limit {
                    rows.last().map(|r| r.get::<String, _>("id"))
                } else {
                    None
                };

                let status_items: Vec<serde_json::Value> = rows
                    .into_iter()
                    .map(|r| {
                        serde_json::json!({
                            "keyPackageHash": r.get::<String, _>("key_package_hash"),
                            "cipherSuite": r.get::<String, _>("cipher_suite"),
                            "createdAt": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
                            "expiresAt": r.get::<chrono::DateTime<chrono::Utc>, _>("expires_at").to_rfc3339(),
                            "consumedAt": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("consumed_at").map(|d| d.to_rfc3339()),
                            "deviceId": r.get::<Option<String>, _>("device_id"),
                        })
                    })
                    .collect();

                let mut status_obj = serde_json::json!({ "consumedPackages": status_items });
                if let Some(c) = next_cursor {
                    status_obj["cursor"] = serde_json::json!(c);
                }
                result.insert("status".to_string(), status_obj);
            }

            "history" => {
                let rows = if let Some(ref c) = cursor {
                    sqlx::query(
                        r#"
                        SELECT
                            kp.key_package_hash,
                            kp.cipher_suite,
                            kp.created_at,
                            kp.consumed_at,
                            kp.device_id
                        FROM key_packages kp
                        WHERE kp.owner_did = $1
                          AND kp.consumed_at IS NOT NULL
                          AND kp.key_package_hash < $2
                        ORDER BY kp.consumed_at DESC, kp.key_package_hash DESC
                        LIMIT $3
                        "#,
                    )
                    .bind(&did)
                    .bind(c)
                    .bind(limit)
                    .fetch_all(&pool)
                    .await
                } else {
                    sqlx::query(
                        r#"
                        SELECT
                            kp.key_package_hash,
                            kp.cipher_suite,
                            kp.created_at,
                            kp.consumed_at,
                            kp.device_id
                        FROM key_packages kp
                        WHERE kp.owner_did = $1
                          AND kp.consumed_at IS NOT NULL
                        ORDER BY kp.consumed_at DESC, kp.key_package_hash DESC
                        LIMIT $2
                        "#,
                    )
                    .bind(&did)
                    .bind(limit)
                    .fetch_all(&pool)
                    .await
                }
                .map_err(|e| {
                    error!("Failed to fetch key package history: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                let next_cursor = if rows.len() as i64 == limit {
                    rows.last().map(|r| r.get::<String, _>("key_package_hash"))
                } else {
                    None
                };

                let history_items: Vec<serde_json::Value> = rows
                    .into_iter()
                    .map(|r| {
                        serde_json::json!({
                            "packageId": r.get::<String, _>("key_package_hash"),
                            "createdAt": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
                            "consumedAt": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("consumed_at").map(|d| d.to_rfc3339()),
                            "deviceId": r.get::<Option<String>, _>("device_id"),
                            "cipherSuite": r.get::<String, _>("cipher_suite"),
                        })
                    })
                    .collect();

                let mut history_obj = serde_json::json!({ "history": history_items });
                if let Some(c) = next_cursor {
                    history_obj["cursor"] = serde_json::json!(c);
                }
                result.insert("history".to_string(), history_obj);
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
