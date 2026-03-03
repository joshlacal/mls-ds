use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use sqlx::Row;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::get_key_package_status::{
        GetKeyPackageStatusOutput, GetKeyPackageStatusRequest, KeyPackageHistoryItem,
        KeyPackageStats, KeyPackageStatusItem,
    },
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
) -> Result<Json<GetKeyPackageStatusOutput<'static>>, StatusCode> {
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

    let mut output = GetKeyPackageStatusOutput::default();

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

                let consumed: i64 = if let Some(ref suite) = cipher_suite {
                    sqlx::query_scalar(
                        "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND cipher_suite = $2 AND consumed_at IS NOT NULL",
                    )
                    .bind(&did)
                    .bind(suite)
                    .fetch_one(&pool)
                    .await
                } else {
                    sqlx::query_scalar(
                        "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND consumed_at IS NOT NULL",
                    )
                    .bind(&did)
                    .fetch_one(&pool)
                    .await
                }
                .map_err(|e| {
                    error!("Failed to count consumed key packages: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                info!(
                    "Key package stats: available={}, consumed={}",
                    available, consumed
                );

                output.stats = Some(KeyPackageStats {
                    total_available: available,
                    total_consumed: consumed,
                    by_device: None,
                    extra_data: Default::default(),
                });
            }

            "status" => {
                let rows = if let Some(ref c) = cursor {
                    sqlx::query(
                        r#"
                        SELECT id, cipher_suite, created_at, expires_at,
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
                        SELECT id, cipher_suite, created_at, expires_at,
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

                if rows.len() as i64 == limit {
                    if let Some(last) = rows.last() {
                        output.cursor = Some(last.get::<String, _>("id").into());
                    }
                }

                let status_items: Vec<KeyPackageStatusItem<'static>> = rows
                    .into_iter()
                    .map(|r| KeyPackageStatusItem {
                        id: r.get::<String, _>("id").into(),
                        cipher_suite: r.get::<String, _>("cipher_suite").into(),
                        consumed: r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("consumed_at").is_some(),
                        created_at: crate::sqlx_jacquard::chrono_to_datetime(
                            r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                        ),
                        expires_at: r
                            .get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at")
                            .map(crate::sqlx_jacquard::chrono_to_datetime),
                        device_id: r
                            .get::<Option<String>, _>("device_id")
                            .unwrap_or_default()
                            .into(),
                        extra_data: Default::default(),
                    })
                    .collect();

                output.status = Some(status_items);
            }

            "history" => {
                let rows = if let Some(ref c) = cursor {
                    sqlx::query(
                        r#"
                        SELECT
                            kp.key_package_hash,
                            kp.created_at,
                            kp.consumed_at
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
                            kp.created_at,
                            kp.consumed_at
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

                if rows.len() as i64 == limit {
                    if let Some(last) = rows.last() {
                        output.cursor = Some(last.get::<String, _>("key_package_hash").into());
                    }
                }

                let history_items: Vec<KeyPackageHistoryItem<'static>> = rows
                    .into_iter()
                    .map(|r| KeyPackageHistoryItem {
                        id: r.get::<String, _>("key_package_hash").into(),
                        action: "consumed".into(),
                        created_at: crate::sqlx_jacquard::chrono_to_datetime(
                            r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                        ),
                        consumed_by_did: None,
                        extra_data: Default::default(),
                    })
                    .collect();

                output.history = Some(history_items);
            }

            unknown => {
                warn!(
                    "Unknown include section for getKeyPackageStatus: {}",
                    unknown
                );
            }
        }
    }

    Ok(Json(output))
}
