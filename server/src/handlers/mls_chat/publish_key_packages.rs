use std::collections::HashSet;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use jacquard_axum::ExtractXrpc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::publish_key_packages::PublishKeyPackagesRequest,
    storage::DbPool,
};

// NSID for auth enforcement
const NSID: &str = "blue.catbird.mlsChat.publishKeyPackages";

const MAX_BATCH_SIZE: usize = 100;
const MAX_UNCONSUMED_PER_USER: i64 = 100;
const MAX_UPLOADS_PER_HOUR: i64 = 200;
const RATE_LIMIT_WINDOW_HOURS: i64 = 1;

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

// ─── Inline action handlers ───

/// Handle "publish" action — store a single key package via `store_key_package_with_device`.
async fn handle_publish(
    pool: &DbPool,
    input: &crate::generated::blue_catbird::mlsChat::publish_key_packages::PublishKeyPackages<'_>,
    user_did: &str,
    device_id: &str,
) -> Result<serde_json::Value, StatusCode> {
    let items = input.key_packages.as_ref().ok_or_else(|| {
        warn!("publish action requires keyPackages");
        StatusCode::BAD_REQUEST
    })?;

    let item = items.first().ok_or_else(|| {
        warn!("publish action requires at least one key package");
        StatusCode::BAD_REQUEST
    })?;

    if item.key_package.is_empty() {
        warn!("Empty key_package provided");
        return Err(StatusCode::BAD_REQUEST);
    }
    if item.cipher_suite.is_empty() {
        warn!("Empty cipher_suite provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    let expires_dt = item.expires.as_ref();
    if *expires_dt <= Utc::now().fixed_offset() {
        warn!("Key package expiration is in the past");
        return Err(StatusCode::BAD_REQUEST);
    }

    let key_data = STANDARD.decode(item.key_package.as_ref()).map_err(|e| {
        warn!("Invalid base64 key_package: {}", e);
        StatusCode::BAD_REQUEST
    })?;
    if key_data.is_empty() {
        warn!("Decoded key package is empty");
        return Err(StatusCode::BAD_REQUEST);
    }

    info!(
        "Publishing key package, cipher_suite: {}",
        item.cipher_suite
    );

    let dev = if device_id.is_empty() {
        None
    } else {
        Some(device_id.to_string())
    };

    crate::db::store_key_package_with_device(
        pool,
        user_did,
        item.cipher_suite.as_ref(),
        key_data,
        expires_dt.with_timezone(&Utc),
        dev,
        None,
    )
    .await
    .map_err(|e| {
        error!("Failed to store key package: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Key package published successfully");

    Ok(serde_json::json!({ "succeeded": 1, "failed": 0 }))
}

/// Handle "publishBatch" action — validate and store multiple key packages.
async fn handle_publish_batch(
    pool: &DbPool,
    _headers: &HeaderMap,
    input: &crate::generated::blue_catbird::mlsChat::publish_key_packages::PublishKeyPackages<'_>,
    user_did: &str,
    device_id: &str,
) -> Result<serde_json::Value, StatusCode> {
    let items = input.key_packages.as_ref().ok_or_else(|| {
        warn!("publishBatch action requires keyPackages");
        StatusCode::BAD_REQUEST
    })?;

    if items.is_empty() {
        warn!("Empty key packages array");
        return Err(StatusCode::BAD_REQUEST);
    }
    if items.len() > MAX_BATCH_SIZE {
        warn!(
            "Batch size {} exceeds maximum {}",
            items.len(),
            MAX_BATCH_SIZE
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = Utc::now();

    // Rate limit: uploads in the last hour
    let rate_limit_window = now - chrono::Duration::hours(RATE_LIMIT_WINDOW_HOURS);
    let recent_uploads: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND created_at > $2",
    )
    .bind(user_did)
    .bind(rate_limit_window)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!("Failed to check rate limit: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if recent_uploads.0 >= MAX_UPLOADS_PER_HOUR {
        warn!(
            "User {} exceeded rate limit: {} uploads in last hour (limit: {})",
            user_did, recent_uploads.0, MAX_UPLOADS_PER_HOUR
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Unconsumed limit
    let unconsumed: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND consumed_at IS NULL AND expires_at > $2",
    )
    .bind(user_did)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!("Failed to count unconsumed key packages: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if unconsumed.0 >= MAX_UNCONSUMED_PER_USER {
        warn!(
            "User {} has {} unconsumed key packages (limit: {})",
            user_did, unconsumed.0, MAX_UNCONSUMED_PER_USER
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    if unconsumed.0 + items.len() as i64 > MAX_UNCONSUMED_PER_USER {
        warn!(
            "Batch would exceed unconsumed limit: {} + {} > {}",
            unconsumed.0,
            items.len(),
            MAX_UNCONSUMED_PER_USER
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    info!("Publishing batch of {} key packages", items.len());

    // Validate all packages first (fail fast)
    let mut errors: Vec<serde_json::Value> = Vec::new();
    let mut failed: i64 = 0;

    for (idx, item) in items.iter().enumerate() {
        if item.key_package.is_empty() {
            errors.push(serde_json::json!({ "index": idx, "error": "Empty key_package" }));
            failed += 1;
            continue;
        }
        if item.cipher_suite.is_empty() {
            errors.push(serde_json::json!({ "index": idx, "error": "Empty cipher_suite" }));
            failed += 1;
            continue;
        }
        if *item.expires.as_ref() <= now.fixed_offset() {
            errors.push(serde_json::json!({ "index": idx, "error": "Expiration is in the past" }));
            failed += 1;
            continue;
        }
        if STANDARD.decode(item.key_package.as_ref()).is_err() {
            errors.push(serde_json::json!({ "index": idx, "error": "Invalid base64 encoding" }));
            failed += 1;
        }
    }

    if !errors.is_empty() {
        warn!("Batch validation failed: {} errors", errors.len());
        return Ok(serde_json::json!({
            "succeeded": 0,
            "failed": failed,
            "errors": errors,
        }));
    }

    // Process all packages
    let mut succeeded: i64 = 0;
    let dev = if device_id.is_empty() {
        None
    } else {
        Some(device_id.to_string())
    };

    for (idx, item) in items.iter().enumerate() {
        let key_data = match STANDARD.decode(item.key_package.as_ref()) {
            Ok(data) if !data.is_empty() => data,
            Ok(_) => {
                errors.push(serde_json::json!({ "index": idx, "error": "Decoded key package is empty" }));
                failed += 1;
                continue;
            }
            Err(e) => {
                errors.push(serde_json::json!({ "index": idx, "error": format!("Failed to decode base64: {}", e) }));
                failed += 1;
                continue;
            }
        };

        // Compute hash for deduplication
        let key_package_hash = crate::crypto::sha256_hex(&key_data);

        // Check for duplicates (idempotent — skip silently)
        match sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM key_packages WHERE owner_did = $1 AND key_package_hash = $2)",
        )
        .bind(user_did)
        .bind(&key_package_hash)
        .fetch_one(pool)
        .await
        {
            Ok(true) => continue, // duplicate — skip
            Ok(false) => {}
            Err(e) => {
                error!("Failed to check key package duplicate {}: {}", idx, e);
                errors.push(serde_json::json!({ "index": idx, "error": format!("Database error: {}", e) }));
                failed += 1;
                continue;
            }
        }

        match crate::db::store_key_package_with_device(
            pool,
            user_did,
            item.cipher_suite.as_ref(),
            key_data,
            item.expires.as_ref().with_timezone(&Utc),
            dev.clone(),
            None,
        )
        .await
        {
            Ok(_) => succeeded += 1,
            Err(e) => {
                error!("Failed to store key package {}: {}", idx, e);
                errors.push(serde_json::json!({ "index": idx, "error": format!("Database error: {}", e) }));
                failed += 1;
            }
        }
    }

    info!(
        "Batch upload complete: {} succeeded, {} failed",
        succeeded, failed
    );

    let mut result = serde_json::json!({
        "succeeded": succeeded,
        "failed": failed,
    });
    if !errors.is_empty() {
        result["errors"] = serde_json::json!(errors);
    }
    Ok(result)
}

/// Handle "sync" action — reconcile local/server key package state for a device.
async fn handle_sync(
    pool: &DbPool,
    input: &crate::generated::blue_catbird::mlsChat::publish_key_packages::PublishKeyPackages<'_>,
    user_did: &str,
) -> Result<serde_json::Value, StatusCode> {
    let local_hashes_cow = input.local_hashes.as_ref().ok_or_else(|| {
        warn!("sync action requires localHashes");
        StatusCode::BAD_REQUEST
    })?;
    let local_hashes: Vec<String> = local_hashes_cow.iter().map(|s| s.to_string()).collect();

    let device_id = input.device_id.as_ref().ok_or_else(|| {
        warn!("sync action requires deviceId");
        StatusCode::BAD_REQUEST
    })?;
    let device_id = device_id.as_ref();
    if device_id.trim().is_empty() {
        warn!("Empty device_id provided for sync");
        return Err(StatusCode::BAD_REQUEST);
    }

    info!(
        "🔄 [sync] START - user has {} local hashes, device_id: {}",
        local_hashes.len(),
        device_id
    );

    // Get available server hashes for this device
    let now = Utc::now();
    let reservation_timeout = now - chrono::Duration::minutes(5);
    let server_hashes: Vec<String> = sqlx::query_scalar::<_, String>(
        r#"
        SELECT key_package_hash FROM key_packages
        WHERE owner_did = $1 AND device_id = $2
          AND consumed_at IS NULL AND expires_at > $3
          AND (reserved_at IS NULL OR reserved_at < $4)
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_did)
    .bind(device_id)
    .bind(now)
    .bind(reservation_timeout)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!("Failed to get server key package hashes: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        "📊 [sync] Server has {} available key packages for device {}",
        server_hashes.len(),
        device_id
    );

    // Find orphaned: on server but not in local
    let local_set: HashSet<&str> = local_hashes.iter().map(|s| s.as_str()).collect();
    let orphaned_hashes: Vec<String> = server_hashes
        .iter()
        .filter(|h| !local_set.contains(h.as_str()))
        .cloned()
        .collect();
    let orphaned_count = orphaned_hashes.len() as i64;

    if orphaned_count == 0 {
        info!(
            "✅ [sync] No orphaned key packages found for device {}",
            device_id
        );
        return Ok(serde_json::json!({
            "serverHashes": server_hashes,
            "orphanedCount": 0,
            "deletedCount": 0,
            "remainingAvailable": server_hashes.len() as i64,
            "deviceId": device_id,
        }));
    }

    warn!(
        "⚠️ [sync] Found {} orphaned key packages for device {}",
        orphaned_count, device_id
    );

    // Delete orphaned packages (scoped to this device)
    let deleted_count = if !orphaned_hashes.is_empty() {
        let result = sqlx::query(
            r#"
            DELETE FROM key_packages
            WHERE owner_did = $1 AND device_id = $2
              AND key_package_hash = ANY($3) AND consumed_at IS NULL
            "#,
        )
        .bind(user_did)
        .bind(device_id)
        .bind(&orphaned_hashes)
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Failed to delete orphaned key packages: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        result.rows_affected() as i64
    } else {
        0
    };

    info!(
        "🗑️ [sync] Deleted {} orphaned key packages for device {}",
        deleted_count, device_id
    );

    // Invalidate pending welcomes referencing deleted key packages
    if deleted_count > 0 {
        let invalidated = sqlx::query(
            r#"
            UPDATE welcome_messages
            SET consumed = true, consumed_at = NOW(),
                error_reason = 'Key package orphaned during sync'
            WHERE recipient_did = $1 AND consumed = false
              AND key_package_hash IS NOT NULL
              AND encode(key_package_hash, 'hex') = ANY($2)
            "#,
        )
        .bind(user_did)
        .bind(&orphaned_hashes)
        .execute(pool)
        .await;

        match invalidated {
            Ok(r) if r.rows_affected() > 0 => {
                info!(
                    "🗑️ [sync] Invalidated {} Welcome(s) for deleted key packages",
                    r.rows_affected()
                );
            }
            Err(e) => warn!("Failed to invalidate stale Welcome messages: {}", e),
            _ => {}
        }
    }

    // Get remaining count
    let remaining: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM key_packages
        WHERE owner_did = $1 AND device_id = $2
          AND consumed_at IS NULL AND expires_at > NOW()
        "#,
    )
    .bind(user_did)
    .bind(device_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!("Failed to count remaining key packages: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Get updated server hashes after cleanup
    let remaining_hashes: Vec<String> = sqlx::query_scalar::<_, String>(
        r#"
        SELECT key_package_hash FROM key_packages
        WHERE owner_did = $1 AND device_id = $2
          AND consumed_at IS NULL AND expires_at > $3
          AND (reserved_at IS NULL OR reserved_at < $4)
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_did)
    .bind(device_id)
    .bind(now)
    .bind(reservation_timeout)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| {
        warn!("Failed to get updated hashes after cleanup: {}", e);
        server_hashes
            .iter()
            .filter(|h| !orphaned_hashes.contains(h))
            .cloned()
            .collect()
    });

    info!(
        "✅ [sync] COMPLETE for device {} - deleted {}, {} remaining",
        device_id, deleted_count, remaining.0
    );

    Ok(serde_json::json!({
        "serverHashes": remaining_hashes,
        "orphanedCount": orphaned_count,
        "deletedCount": deleted_count,
        "remainingAvailable": remaining.0,
        "deviceId": device_id,
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

    let did = auth_user.did.clone();

    let (user_did, device_id) = parse_device_did(&did).map_err(|e| {
        error!("Invalid DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    match input.action.as_ref() {
        "publish" => {
            let publish_result = handle_publish(&pool, &input, &user_did, &device_id).await?;
            let stats = build_stats(&pool, &did).await?;
            Ok(Json(serde_json::json!({
                "stats": stats,
                "publishResult": publish_result,
            })))
        }

        "publishBatch" => {
            let publish_result =
                handle_publish_batch(&pool, &headers, &input, &user_did, &device_id).await?;
            let stats = build_stats(&pool, &did).await?;
            Ok(Json(serde_json::json!({
                "stats": stats,
                "publishResult": publish_result,
            })))
        }

        "sync" => {
            let sync_result = handle_sync(&pool, &input, &user_did).await?;
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
