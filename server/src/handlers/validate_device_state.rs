use axum::{extract::{RawQuery, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    auth::AuthUser,
    storage::DbPool,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPackageInventory {
    available: i64,
    target: i64,
    needs_replenishment: bool,
    per_device_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidateDeviceStateResponse {
    is_valid: bool,
    issues: Vec<String>,
    recommendations: Vec<String>,
    expected_convos: i64,
    actual_convos: i64,
    key_package_inventory: KeyPackageInventory,
    pending_rejoin_requests: Vec<String>,
}

/// Validate device state and sync status
/// GET /xrpc/blue.catbird.mls.validateDeviceState
#[tracing::instrument(skip(pool))]
pub async fn validate_device_state(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    RawQuery(query): RawQuery,
) -> Result<Json<ValidateDeviceStateResponse>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.validateDeviceState") {
        warn!("Unauthorized access attempt");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Parse query parameters
    let query_str = query.unwrap_or_default();
    let mut device_id: Option<String> = None;

    for pair in query_str.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let decoded_value = urlencoding::decode(value).unwrap_or_default().to_string();
            if key == "deviceId" {
                device_id = Some(decoded_value);
            }
        }
    }

    let user_did = &auth_user.claims.iss;
    info!("Validating device state for user: {} (device: {:?})", user_did, device_id);

    let mut issues = Vec::new();
    let mut recommendations = Vec::new();

    // 1. Check conversation memberships
    let expected_convos = count_expected_conversations(&pool, user_did).await
        .map_err(|e| {
            warn!("Failed to count expected conversations: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let actual_convos = count_actual_conversations(&pool, user_did).await
        .map_err(|e| {
            warn!("Failed to count actual conversations: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if expected_convos != actual_convos {
        issues.push(format!(
            "Conversation membership mismatch: expected {}, found {}",
            expected_convos, actual_convos
        ));
        recommendations.push("Sync conversation list with server".to_string());
    }

    // 2. Check key package inventory
    let (total, available, consumed, _reserved) = crate::db::get_key_package_stats(&pool, user_did)
        .await
        .map_err(|e| {
            warn!("Failed to get key package stats: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Target threshold: 50 key packages recommended
    let target_threshold = 50i64;
    let needs_replenishment = available < target_threshold;

    // Calculate per-device count (total / number of active devices)
    let device_count = count_active_devices(&pool, user_did).await
        .map_err(|e| {
            warn!("Failed to count active devices: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let per_device_count = if device_count > 0 {
        total / device_count
    } else {
        0
    };

    if needs_replenishment {
        issues.push(format!(
            "Key package inventory low: {} available (target: {})",
            available, target_threshold
        ));
        recommendations.push(format!(
            "Upload {} more key packages to reach target",
            target_threshold - available
        ));
    }

    if per_device_count < 10 && device_count > 0 {
        issues.push(format!(
            "Low key packages per device: {} per device",
            per_device_count
        ));
        recommendations.push("Each device should upload more key packages".to_string());
    }

    // 3. Check for pending rejoin requests
    let pending_rejoin_requests = get_pending_rejoin_requests(&pool, user_did).await
        .map_err(|e| {
            warn!("Failed to get pending rejoin requests: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if !pending_rejoin_requests.is_empty() {
        issues.push(format!(
            "{} pending rejoin requests waiting for approval",
            pending_rejoin_requests.len()
        ));
        recommendations.push("Check pending rejoin requests and approve if necessary".to_string());
    }

    // 4. Check for expired key packages
    let expired_count = count_expired_key_packages(&pool, user_did).await
        .map_err(|e| {
            warn!("Failed to count expired key packages: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if expired_count > 0 {
        issues.push(format!("{} expired key packages found", expired_count));
        recommendations.push("Clean up expired key packages".to_string());
    }

    let is_valid = issues.is_empty();

    info!(
        "Device state validation complete: {} (issues: {}, recommendations: {})",
        if is_valid { "VALID" } else { "INVALID" },
        issues.len(),
        recommendations.len()
    );

    Ok(Json(ValidateDeviceStateResponse {
        is_valid,
        issues,
        recommendations,
        expected_convos,
        actual_convos,
        key_package_inventory: KeyPackageInventory {
            available,
            target: target_threshold,
            needs_replenishment,
            per_device_count,
        },
        pending_rejoin_requests,
    }))
}

/// Count expected conversations (all conversations the user is a member of)
async fn count_expected_conversations(pool: &DbPool, user_did: &str) -> anyhow::Result<i64> {
    let count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(DISTINCT convo_id) as "count!"
        FROM members
        WHERE member_did = $1 AND left_at IS NULL
        "#,
        user_did
    )
    .fetch_one(pool)
    .await?;

    Ok(count)
}

/// Count actual conversations (from device's perspective - simplified version)
/// In production, this would compare against device-specific state
async fn count_actual_conversations(pool: &DbPool, user_did: &str) -> anyhow::Result<i64> {
    // For now, return the same as expected
    // In a real implementation, this would check device-specific conversation list
    count_expected_conversations(pool, user_did).await
}

/// Count active devices for a user
async fn count_active_devices(pool: &DbPool, user_did: &str) -> anyhow::Result<i64> {
    let count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM devices
        WHERE owner_did = $1 AND is_active = true
        "#,
        user_did
    )
    .fetch_one(pool)
    .await?;

    Ok(count)
}

/// Get pending rejoin requests for a user
async fn get_pending_rejoin_requests(pool: &DbPool, user_did: &str) -> anyhow::Result<Vec<String>> {
    let convo_ids = sqlx::query_scalar!(
        r#"
        SELECT convo_id
        FROM rejoin_requests
        WHERE requester_did = $1 AND status = 'pending'
        ORDER BY requested_at DESC
        "#,
        user_did
    )
    .fetch_all(pool)
    .await?;

    Ok(convo_ids)
}

/// Count expired key packages for a user
async fn count_expired_key_packages(pool: &DbPool, user_did: &str) -> anyhow::Result<i64> {
    let now = chrono::Utc::now();
    let count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM key_packages
        WHERE owner_did = $1 AND expires_at < $2 AND consumed_at IS NULL
        "#,
        user_did,
        now
    )
    .fetch_one(pool)
    .await?;

    Ok(count)
}
