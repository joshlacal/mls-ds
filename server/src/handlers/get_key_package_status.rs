use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::{auth::AuthUser, storage::DbPool};

#[derive(Debug, Deserialize)]
pub struct GetKeyPackageStatusParams {
    limit: Option<i64>,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumedPackageView {
    key_package_hash: String,
    used_in_group: Option<String>,
    consumed_at: String,
    cipher_suite: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeyPackageStatusOutput {
    total_uploaded: i64,
    available: i64,
    consumed: i64,
    reserved: i64,
    consumed_packages: Vec<ConsumedPackageView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
}

/// Get key package statistics and consumption history
/// GET /xrpc/blue.catbird.mls.getKeyPackageStatus
#[tracing::instrument(skip(pool))]
pub async fn get_key_package_status(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<GetKeyPackageStatusParams>,
) -> Result<Json<GetKeyPackageStatusOutput>, StatusCode> {
    if let Err(_e) =
        crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.getKeyPackageStatus")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = &auth_user.did;
    let limit = params.limit.unwrap_or(20).min(100);

    // Get stats
    let (total, available, consumed, reserved) =
        match crate::db::get_key_package_stats(&pool, did).await {
            Ok(stats) => stats,
            Err(e) => {
                error!("Failed to get key package stats: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

    // Get consumed packages with pagination
    let (consumed_pkgs, next_cursor) = match crate::db::get_consumed_key_packages_paginated(
        &pool,
        did,
        limit,
        params.cursor,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to get consumed key packages: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Convert to output format
    let consumed_packages: Vec<ConsumedPackageView> = consumed_pkgs
        .into_iter()
        .map(|pkg| ConsumedPackageView {
            key_package_hash: pkg.key_package_hash,
            used_in_group: pkg.consumed_by_convo,
            consumed_at: pkg
                .consumed_at
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default(),
            cipher_suite: Some(pkg.cipher_suite),
        })
        .collect();

    info!(
        "Key package status for {}: total={}, available={}, consumed={}, reserved={}",
        did, total, available, consumed, reserved
    );

    Ok(Json(GetKeyPackageStatusOutput {
        total_uploaded: total,
        available,
        consumed,
        reserved,
        consumed_packages,
        cursor: next_cursor,
    }))
}
