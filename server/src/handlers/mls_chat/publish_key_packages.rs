use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use jacquard_axum::ExtractXrpc;
use tracing::{error, warn};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::publish_key_packages::PublishKeyPackagesRequest,
    storage::DbPool,
};

// NSID for auth enforcement
const NSID: &str = "blue.catbird.mlsChat.publishKeyPackages";

/// Build the `stats` object matching the lexicon `#keyPackageStats` shape:
/// `{ published, available, expired }`
async fn build_stats(pool: &DbPool, did: &str) -> Result<serde_json::Value, StatusCode> {
    let (user_did, _) = parse_device_did(did).map_err(|e| {
        error!("Invalid DID format for stats: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let available: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND consumed_at IS NULL AND expires_at > NOW()",
    )
    .bind(&user_did)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!("Failed to count available key packages: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1",
    )
    .bind(&user_did)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!("Failed to count total key packages: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let expired: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND consumed_at IS NULL AND expires_at <= NOW()",
    )
    .bind(&user_did)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!("Failed to count expired key packages: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let published = total; // "total ever published" = total rows

    Ok(serde_json::json!({
        "published": published,
        "available": available,
        "expired": expired,
    }))
}

// ─── POST handler ───

/// Consolidated key package management endpoint (POST)
/// POST /xrpc/blue.catbird.mlsChat.publishKeyPackages
///
/// All actions return `{ stats: KeyPackageStats, syncResult?, publishResult? }`
/// per the lexicon output schema.
#[tracing::instrument(skip(pool, headers, auth_user, input))]
pub async fn publish_key_packages_post(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<PublishKeyPackagesRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let body = serde_json::to_string(&input).unwrap_or_default();
    let did = auth_user.did.clone();

    match input.action.as_ref() {
        "publish" => {
            let v1_input: crate::generated::blue_catbird::mls::publish_key_package::PublishKeyPackage<'static> = {
                use jacquard_common::IntoStatic;
                let parsed: crate::generated::blue_catbird::mls::publish_key_package::PublishKeyPackage =
                    serde_json::from_str(&body).map_err(|e| {
                        warn!("Failed to parse publish action body: {}", e);
                        StatusCode::BAD_REQUEST
                    })?;
                parsed.into_static()
            };
            let _result = crate::handlers::publish_key_package::publish_key_package(
                State(pool.clone()),
                auth_user,
                serde_json::to_string(&v1_input).unwrap(),
            )
            .await?;

            let stats = build_stats(&pool, &did).await?;
            Ok(Json(serde_json::json!({
                "stats": stats,
                "publishResult": { "succeeded": 1, "failed": 0 },
            })))
        }

        "publishBatch" => {
            let batch_input: crate::handlers::publish_key_packages::PublishKeyPackagesInput =
                serde_json::from_str(&body).map_err(|e| {
                    warn!("Failed to parse publishBatch action body: {}", e);
                    StatusCode::BAD_REQUEST
                })?;
            let result = crate::handlers::publish_key_packages::publish_key_packages(
                State(pool.clone()),
                headers,
                auth_user,
                Json(batch_input),
            )
            .await?;

            let publish_result = serde_json::to_value(result.0).unwrap_or_default();
            let stats = build_stats(&pool, &did).await?;
            Ok(Json(serde_json::json!({
                "stats": stats,
                "publishResult": publish_result,
            })))
        }

        "sync" => {
            let sync_input: crate::handlers::sync_key_packages::SyncKeyPackagesInput =
                serde_json::from_str(&body).map_err(|e| {
                    warn!("Failed to parse sync action body: {}", e);
                    StatusCode::BAD_REQUEST
                })?;
            let result = crate::handlers::sync_key_packages::sync_key_packages(
                State(pool.clone()),
                auth_user,
                Json(sync_input),
            )
            .await?;

            let sync_result = serde_json::to_value(result.0).unwrap_or_default();
            let stats = build_stats(&pool, &did).await?;
            Ok(Json(serde_json::json!({
                "stats": stats,
                "syncResult": sync_result,
            })))
        }

        "stats" => {
            let stats = build_stats(&pool, &did).await?;
            Ok(Json(serde_json::json!({
                "stats": stats,
            })))
        }

        unknown => {
            warn!("Unknown action for v2 publishKeyPackages POST: {}", unknown);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
