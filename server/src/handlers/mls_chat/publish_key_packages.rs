use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use jacquard_axum::ExtractXrpc;
use tracing::warn;

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::publish_key_packages::PublishKeyPackagesRequest,
    storage::DbPool,
};

// NSID for auth enforcement
const NSID: &str = "blue.catbird.mlsChat.publishKeyPackages";

// ─── POST handler ───

/// Consolidated key package management endpoint (POST)
/// POST /xrpc/blue.catbird.mlsChat.publishKeyPackages
///
/// Dispatches based on `action` field to the appropriate v1 handler.
///
/// Actions:
///   - publish: Publish a single key package (v1 publishKeyPackage fields)
///   - publishBatch: Publish multiple key packages (v1 publishKeyPackages fields)
///   - sync: Synchronize key packages between client and server (v1 syncKeyPackages fields)
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

    // Serialize parsed input back to body string for v1 delegation
    let body = serde_json::to_string(&input).unwrap_or_default();

    match input.action.as_ref() {
        "publish" => {
            // Delegate to existing publish_key_package handler (single key package)
            let v1_input: crate::generated::blue_catbird::mls::publish_key_package::PublishKeyPackage<'static> = {
                use jacquard_common::IntoStatic;
                let parsed: crate::generated::blue_catbird::mls::publish_key_package::PublishKeyPackage =
                    serde_json::from_str(&body).map_err(|e| {
                        warn!("Failed to parse publish action body: {}", e);
                        StatusCode::BAD_REQUEST
                    })?;
                parsed.into_static()
            };
            let result = crate::handlers::publish_key_package::publish_key_package(
                State(pool),
                auth_user,
                serde_json::to_string(&v1_input).unwrap(),
            )
            .await?;
            Ok(Json(serde_json::to_value(result.0).unwrap()))
        }

        "publishBatch" => {
            // Delegate to existing publish_key_packages handler (batch upload)
            let batch_input: crate::handlers::publish_key_packages::PublishKeyPackagesInput =
                serde_json::from_str(&body).map_err(|e| {
                    warn!("Failed to parse publishBatch action body: {}", e);
                    StatusCode::BAD_REQUEST
                })?;
            let result = crate::handlers::publish_key_packages::publish_key_packages(
                State(pool),
                headers,
                auth_user,
                Json(batch_input),
            )
            .await?;
            Ok(Json(serde_json::to_value(result.0).unwrap_or_default()))
        }

        "sync" => {
            // Delegate to existing sync_key_packages handler
            let sync_input: crate::handlers::sync_key_packages::SyncKeyPackagesInput =
                serde_json::from_str(&body).map_err(|e| {
                    warn!("Failed to parse sync action body: {}", e);
                    StatusCode::BAD_REQUEST
                })?;
            let result = crate::handlers::sync_key_packages::sync_key_packages(
                State(pool),
                auth_user,
                Json(sync_input),
            )
            .await?;
            Ok(Json(serde_json::to_value(result.0).unwrap_or_default()))
        }

        "stats" => {
            // Delegate to existing get_key_package_stats handler
            let result = crate::handlers::get_key_package_stats::get_key_package_stats(
                State(pool),
                auth_user,
                axum::extract::RawQuery(None),
            )
            .await?;
            Ok(Json(serde_json::to_value(result.0).unwrap_or_default()))
        }

        unknown => {
            warn!("Unknown action for v2 publishKeyPackages POST: {}", unknown);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
