use std::{collections::HashSet, sync::Arc};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
// base64 no longer needed — key_package arrives as bytes::Bytes (already decoded)
use chrono::Utc;
use jacquard_axum::ExtractXrpc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::publish_key_packages::{
        BatchError, KeyPackageStats, PublishKeyPackages, PublishKeyPackagesOutput,
        PublishKeyPackagesRequest, PublishResult, ReplenishResult, SyncResult,
    },
    notifications::NotificationService,
    storage::DbPool,
};

// NSID for auth enforcement
const NSID: &str = "blue.catbird.mlsChat.publishKeyPackages";

const MAX_BATCH_SIZE: usize = 100;
const MAX_UNCONSUMED_PER_USER: i64 = 100;
const MAX_UPLOADS_PER_HOUR: i64 = 200;
const RATE_LIMIT_WINDOW_HOURS: i64 = 1;

#[derive(Debug, Clone)]
struct DeviceScope {
    raw_device_id: String,
    storage_device_id: String,
    storage_candidates: Vec<String>,
    signature_public_key: Option<Vec<u8>>,
}

async fn resolve_device_scope(
    pool: &DbPool,
    user_did: &str,
    raw_device_id: &str,
) -> Result<DeviceScope, StatusCode> {
    let raw_device_id = raw_device_id.trim();
    if raw_device_id.is_empty() {
        return Ok(DeviceScope {
            raw_device_id: String::new(),
            storage_device_id: String::new(),
            storage_candidates: Vec::new(),
            signature_public_key: None,
        });
    }

    let credential_did = format!("{}#{}", user_did, raw_device_id);
    let canonical: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT device_id, signature_public_key FROM devices \
         WHERE user_did = $1 \
           AND (device_id = $2 OR device_uuid = $2 OR credential_did = $3) \
         ORDER BY registered_at DESC \
         LIMIT 1",
    )
    .bind(user_did)
    .bind(raw_device_id)
    .bind(&credential_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(
            "Failed to resolve device id for key package operation: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let legacy_bucket = crate::device_utils::bucket_device_id(user_did, raw_device_id);
    let (storage_device_id, signature_public_key) =
        if let Some((device_id, signature_public_key_hex)) = canonical {
            let signature_public_key = match signature_public_key_hex
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                Some(value) => Some(hex::decode(value).map_err(|e| {
                    error!(
                        "Registered device signature_public_key is not valid hex for {}: {}",
                        crate::crypto::hash_for_log(user_did),
                        e
                    );
                    StatusCode::INTERNAL_SERVER_ERROR
                })?),
                None => None,
            };
            (device_id, signature_public_key)
        } else {
            (raw_device_id.to_string(), None)
        };
    let mut storage_candidates = vec![storage_device_id.clone(), raw_device_id.to_string()];
    if !legacy_bucket.is_empty() {
        storage_candidates.push(legacy_bucket);
    }
    storage_candidates.sort();
    storage_candidates.dedup();

    Ok(DeviceScope {
        raw_device_id: raw_device_id.to_string(),
        storage_device_id,
        storage_candidates,
        signature_public_key,
    })
}

fn map_key_package_store_error(e: anyhow::Error) -> StatusCode {
    let detail = format!("{e:#}");
    if detail.contains("Failed to store key package")
        || detail.contains("Failed to ensure user exists")
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    }
}

/// Build the `stats` object matching the lexicon `#keyPackageStats` shape:
/// `{ published, available, expired }`
async fn build_stats(
    pool: &DbPool,
    user_did: &str,
    device_scope: Option<&DeviceScope>,
) -> Result<KeyPackageStats<'static>, StatusCode> {
    let candidates = device_scope
        .map(|scope| scope.storage_candidates.as_slice())
        .unwrap_or(&[]);

    let available: i64 = if candidates.is_empty() {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND consumed_at IS NULL AND expires_at > NOW()",
        )
        .bind(user_did)
        .fetch_one(pool)
        .await
    } else {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND device_id = ANY($2::text[]) AND consumed_at IS NULL AND expires_at > NOW()",
        )
        .bind(user_did)
        .bind(candidates)
        .fetch_one(pool)
        .await
    }
    .map_err(|e| {
        error!("Failed to count available key packages: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let total: i64 = if candidates.is_empty() {
        sqlx::query_scalar("SELECT COUNT(*) FROM key_packages WHERE owner_did = $1")
            .bind(user_did)
            .fetch_one(pool)
            .await
    } else {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND device_id = ANY($2::text[])",
        )
        .bind(user_did)
        .bind(candidates)
        .fetch_one(pool)
        .await
    }
    .map_err(|e| {
        error!("Failed to count total key packages: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let expired: i64 = if candidates.is_empty() {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND consumed_at IS NULL AND expires_at <= NOW()",
        )
        .bind(user_did)
        .fetch_one(pool)
        .await
    } else {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND device_id = ANY($2::text[]) AND consumed_at IS NULL AND expires_at <= NOW()",
        )
        .bind(user_did)
        .bind(candidates)
        .fetch_one(pool)
        .await
    }
    .map_err(|e| {
        error!("Failed to count expired key packages: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let published = total; // "total ever published" = total rows

    Ok(KeyPackageStats {
        published,
        available,
        expired,
        extra_data: Default::default(),
    })
}

// ─── Inline action handlers ───

/// Handle "publish" action — store a single key package via `store_key_package_with_device`.
async fn handle_publish(
    pool: &DbPool,
    input: &crate::generated::blue_catbird::mlsChat::publish_key_packages::PublishKeyPackages<'_>,
    user_did: &str,
    device_id: &str,
    expected_signature_public_key: &[u8],
) -> Result<PublishResult<'static>, StatusCode> {
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

    let key_data = item.key_package.to_vec();
    if key_data.is_empty() {
        warn!("Key package is empty");
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

    crate::db::store_key_package_with_device_bound_to_signature(
        pool,
        user_did,
        item.cipher_suite.as_ref(),
        key_data,
        expires_dt.with_timezone(&Utc),
        dev,
        None,
        Some(expected_signature_public_key),
    )
    .await
    .map_err(|e| {
        let status = map_key_package_store_error(e);
        error!("Failed to store key package: status={}", status);
        status
    })?;

    info!("Key package published successfully");

    Ok(PublishResult {
        succeeded: 1,
        failed: 0,
        errors: None,
        extra_data: Default::default(),
    })
}

/// Handle "publishBatch" action — validate and store multiple key packages.
async fn handle_publish_batch(
    pool: &DbPool,
    headers: &HeaderMap,
    input: &crate::generated::blue_catbird::mlsChat::publish_key_packages::PublishKeyPackages<'_>,
    user_did: &str,
    device_scope: &DeviceScope,
    expected_signature_public_key: &[u8],
) -> Result<PublishResult<'static>, StatusCode> {
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
    let device_id = device_scope.storage_device_id.as_str();
    let device_candidates = &device_scope.storage_candidates;
    let recovery_mode_requested = headers
        .get(crate::middleware::rate_limit::RECOVERY_MODE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let recovery_mode_verified = if recovery_mode_requested && !device_candidates.is_empty() {
        let available_for_device: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM key_packages
             WHERE owner_did = $1
               AND device_id = ANY($2::text[])
               AND consumed_at IS NULL
               AND expires_at > $3",
        )
        .bind(user_did)
        .bind(device_candidates)
        .bind(now)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!("Failed to verify recovery mode eligibility: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if available_for_device.0 == 0 {
            info!(
                "Recovery mode verified for user {} on device {}",
                user_did, device_scope.raw_device_id
            );
            true
        } else {
            warn!(
                "Recovery mode requested but denied for user {} on device {} (available: {})",
                user_did, device_scope.raw_device_id, available_for_device.0
            );
            false
        }
    } else {
        if recovery_mode_requested && device_candidates.is_empty() {
            warn!("Recovery mode requested without device_id, applying normal limits");
        }
        false
    };

    // Rate limit: uploads in the last hour
    let rate_limit_window = now - chrono::Duration::hours(RATE_LIMIT_WINDOW_HOURS);
    let recent_uploads: (i64,) = if recovery_mode_verified {
        sqlx::query_as(
            "SELECT COUNT(*) FROM key_packages
             WHERE owner_did = $1
               AND device_id = ANY($2::text[])
               AND created_at > $3",
        )
        .bind(user_did)
        .bind(device_candidates)
        .bind(rate_limit_window)
        .fetch_one(pool)
        .await
    } else {
        sqlx::query_as("SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND created_at > $2")
            .bind(user_did)
            .bind(rate_limit_window)
            .fetch_one(pool)
            .await
    }
    .map_err(|e| {
        error!("Failed to check rate limit: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if recent_uploads.0 >= MAX_UPLOADS_PER_HOUR {
        warn!(
            "User {} exceeded {} upload rate limit: {} in last hour (limit: {})",
            user_did,
            if recovery_mode_verified {
                "device-scoped recovery"
            } else {
                "user-scoped"
            },
            recent_uploads.0,
            MAX_UPLOADS_PER_HOUR
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Unconsumed limit
    let unconsumed: (i64,) = if recovery_mode_verified {
        sqlx::query_as(
            "SELECT COUNT(*) FROM key_packages
             WHERE owner_did = $1
               AND device_id = ANY($2::text[])
               AND consumed_at IS NULL
               AND expires_at > $3",
        )
        .bind(user_did)
        .bind(device_candidates)
        .bind(now)
        .fetch_one(pool)
        .await
    } else {
        sqlx::query_as(
            "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND consumed_at IS NULL AND expires_at > $2",
        )
        .bind(user_did)
        .bind(now)
        .fetch_one(pool)
        .await
    }
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
    let mut errors: Vec<BatchError<'static>> = Vec::new();
    let mut failed: i64 = 0;

    for (idx, item) in items.iter().enumerate() {
        if item.key_package.is_empty() {
            errors.push(BatchError {
                index: idx as i64,
                error: "Empty key_package".into(),
                extra_data: Default::default(),
            });
            failed += 1;
            continue;
        }
        if item.cipher_suite.is_empty() {
            errors.push(BatchError {
                index: idx as i64,
                error: "Empty cipher_suite".into(),
                extra_data: Default::default(),
            });
            failed += 1;
            continue;
        }
        if *item.expires.as_ref() <= now.fixed_offset() {
            errors.push(BatchError {
                index: idx as i64,
                error: "Expiration is in the past".into(),
                extra_data: Default::default(),
            });
            failed += 1;
            continue;
        }
        // key_package is already decoded bytes — no base64 validation needed
    }

    if !errors.is_empty() {
        warn!("Batch validation failed: {} errors", errors.len());
        return Ok(PublishResult {
            succeeded: 0,
            failed,
            errors: Some(errors),
            extra_data: Default::default(),
        });
    }

    // Process all packages
    let mut succeeded: i64 = 0;
    let dev = if device_id.is_empty() {
        None
    } else {
        Some(device_id.to_string())
    };

    for (idx, item) in items.iter().enumerate() {
        let key_data = item.key_package.to_vec();
        if key_data.is_empty() {
            errors.push(BatchError {
                index: idx as i64,
                error: "Key package is empty".into(),
                extra_data: Default::default(),
            });
            failed += 1;
            continue;
        }

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
                errors.push(BatchError {
                    index: idx as i64,
                    error: format!("Database error: {}", e).into(),
                    extra_data: Default::default(),
                });
                failed += 1;
                continue;
            }
        }

        match crate::db::store_key_package_with_device_bound_to_signature(
            pool,
            user_did,
            item.cipher_suite.as_ref(),
            key_data,
            item.expires.as_ref().with_timezone(&Utc),
            dev.clone(),
            None,
            Some(expected_signature_public_key),
        )
        .await
        {
            Ok(_) => succeeded += 1,
            Err(e) => {
                let status = map_key_package_store_error(e);
                error!(
                    "Failed to store key package {} during batch: status={}",
                    idx, status
                );
                errors.push(BatchError {
                    index: idx as i64,
                    error: if status == StatusCode::BAD_REQUEST {
                        "Key package credential binding failed".to_string().into()
                    } else {
                        "Database error".to_string().into()
                    },
                    extra_data: Default::default(),
                });
                failed += 1;
            }
        }
    }

    info!(
        "Batch upload complete: {} succeeded, {} failed",
        succeeded, failed
    );

    Ok(PublishResult {
        succeeded,
        failed,
        errors: if errors.is_empty() {
            None
        } else {
            Some(errors)
        },
        extra_data: Default::default(),
    })
}

/// Handle "sync" action — reconcile local/server key package state for a device.
async fn handle_sync(
    pool: &DbPool,
    input: &crate::generated::blue_catbird::mlsChat::publish_key_packages::PublishKeyPackages<'_>,
    user_did: &str,
    device_scope: &DeviceScope,
) -> Result<SyncResult<'static>, StatusCode> {
    let local_hashes_cow = input.local_hashes.as_ref().ok_or_else(|| {
        warn!("sync action requires localHashes");
        StatusCode::BAD_REQUEST
    })?;
    let local_hashes: Vec<String> = local_hashes_cow.iter().map(|s| s.to_string()).collect();

    if device_scope.raw_device_id.is_empty() || device_scope.storage_candidates.is_empty() {
        warn!("sync action requires deviceId");
        return Err(StatusCode::BAD_REQUEST);
    }

    info!(
        "🔄 [sync] START - user has {} local hashes, device_id: {}",
        local_hashes.len(),
        device_scope.raw_device_id
    );

    // Get available server hashes for this device
    let now = Utc::now();
    let reservation_timeout = now - chrono::Duration::minutes(5);
    let server_hashes: Vec<String> = sqlx::query_scalar::<_, String>(
        r#"
        SELECT key_package_hash FROM key_packages
        WHERE owner_did = $1 AND device_id = ANY($2::text[])
          AND consumed_at IS NULL AND expires_at > $3
          AND (reserved_at IS NULL OR reserved_at < $4)
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_did)
    .bind(&device_scope.storage_candidates)
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
        device_scope.raw_device_id
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
            device_scope.raw_device_id
        );
        let count = server_hashes.len() as i64;
        return Ok(SyncResult {
            server_hashes: server_hashes.into_iter().map(|s| s.into()).collect(),
            orphaned_count: 0,
            orphaned_hashes: None,
            deleted_count: 0,
            remaining_available: Some(count),
            device_id: device_scope.raw_device_id.clone().into(),
            extra_data: Default::default(),
        });
    }

    warn!(
        "⚠️ [sync] Found {} orphaned key packages for device {}",
        orphaned_count, device_scope.raw_device_id
    );

    // Delete orphaned packages (scoped to this device)
    let deleted_count = if !orphaned_hashes.is_empty() {
        let result = sqlx::query(
            r#"
            DELETE FROM key_packages
            WHERE owner_did = $1 AND device_id = ANY($2::text[])
              AND key_package_hash = ANY($3::text[]) AND consumed_at IS NULL
            "#,
        )
        .bind(user_did)
        .bind(&device_scope.storage_candidates)
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
        deleted_count, device_scope.raw_device_id
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
        WHERE owner_did = $1 AND device_id = ANY($2::text[])
          AND consumed_at IS NULL AND expires_at > NOW()
        "#,
    )
    .bind(user_did)
    .bind(&device_scope.storage_candidates)
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
        WHERE owner_did = $1 AND device_id = ANY($2::text[])
          AND consumed_at IS NULL AND expires_at > $3
          AND (reserved_at IS NULL OR reserved_at < $4)
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_did)
    .bind(&device_scope.storage_candidates)
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
        device_scope.raw_device_id, deleted_count, remaining.0
    );

    Ok(SyncResult {
        server_hashes: remaining_hashes.into_iter().map(|s| s.into()).collect(),
        orphaned_count,
        orphaned_hashes: Some(orphaned_hashes.into_iter().map(|s| s.into()).collect()),
        deleted_count,
        remaining_available: Some(remaining.0),
        device_id: device_scope.raw_device_id.clone().into(),
        extra_data: Default::default(),
    })
}

/// Handle "requestReplenish" action — ask target peer devices to upload fresh key packages.
async fn handle_request_replenish(
    pool: &DbPool,
    notification_service: Option<Arc<NotificationService>>,
    input: &PublishKeyPackages<'_>,
    requester_did: &str,
) -> Result<ReplenishResult<'static>, StatusCode> {
    let Some(target_dids) = input.target_dids.as_ref() else {
        warn!("requestReplenish action requires targetDids");
        return Err(StatusCode::BAD_REQUEST);
    };

    if target_dids.is_empty() || target_dids.len() > 100 {
        warn!(
            "requestReplenish targetDids length out of range: {}",
            target_dids.len()
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut seen = HashSet::new();
    let mut targets: Vec<String> = target_dids
        .iter()
        .map(|did| did.to_string())
        .filter(|did| seen.insert(did.clone()))
        .collect();
    let requested_target_count = targets.len();

    let convo_id = input
        .convo_id
        .as_ref()
        .map(|value| value.as_ref().trim())
        .filter(|value| !value.is_empty());

    if let Some(convo_id) = convo_id {
        let requester_is_member: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM members
                WHERE convo_id = $1
                  AND (user_did = $2 OR member_did = $2)
                  AND left_at IS NULL
            )",
        )
        .bind(convo_id)
        .bind(requester_did)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!(
                "requestReplenish: failed to verify requester membership for {}: {}",
                convo_id, e
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if !requester_is_member {
            warn!(
                "requestReplenish: requester {} is not an active member of {}",
                requester_did, convo_id
            );
            return Err(StatusCode::FORBIDDEN);
        }

        let active_targets: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT COALESCE(user_did, member_did)
             FROM members
             WHERE convo_id = $1
               AND COALESCE(user_did, member_did) = ANY($2)
               AND left_at IS NULL",
        )
        .bind(convo_id)
        .bind(&targets)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            error!(
                "requestReplenish: failed to filter target membership for {}: {}",
                convo_id, e
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let active_set: HashSet<String> = active_targets.into_iter().collect();
        let before_filter = targets.len();
        targets.retain(|did| active_set.contains(did));
        if targets.len() != before_filter {
            warn!(
                "requestReplenish: filtered {} non-member target(s) for {}",
                before_filter - targets.len(),
                convo_id
            );
        }
    }

    if targets.is_empty() {
        return Ok(ReplenishResult {
            requested: true,
            target_count: requested_target_count as i64,
            device_count: 0,
            delivered_count: 0,
            extra_data: Default::default(),
        });
    }

    let devices: Vec<(String, String)> = sqlx::query_as(
        "SELECT user_did, push_token
         FROM devices
         WHERE user_did = ANY($1)
           AND push_token IS NOT NULL
           AND push_token <> ''
         ORDER BY user_did, last_seen_at DESC",
    )
    .bind(&targets)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!("requestReplenish: failed to query target devices: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let device_count = devices.len();
    let mut delivered_count = 0i64;
    let requested_at = Utc::now().to_rfc3339();
    let reason = input
        .reason
        .as_ref()
        .map(|value| value.as_ref())
        .filter(|value| !value.is_empty());

    if let Some(notification_service) = notification_service {
        if notification_service.can_send_pushes() {
            for (target_did, push_token) in devices {
                match notification_service
                    .notify_key_package_replenish_request(
                        &push_token,
                        &target_did,
                        requester_did,
                        &requested_at,
                        reason,
                        convo_id,
                    )
                    .await
                {
                    Ok(()) => delivered_count += 1,
                    Err(e) => warn!(
                        "requestReplenish: failed to notify {} device: {}",
                        target_did, e
                    ),
                }
            }
        } else {
            info!("requestReplenish: push notification service disabled");
        }
    } else {
        info!("requestReplenish: notification service unavailable");
    }

    Ok(ReplenishResult {
        requested: true,
        target_count: requested_target_count as i64,
        device_count: device_count as i64,
        delivered_count,
        extra_data: Default::default(),
    })
}

// ─── POST handler ───

/// Consolidated key package management endpoint (POST)
/// POST /xrpc/blue.catbird.mlsChat.publishKeyPackages
///
/// All actions return `{ stats: KeyPackageStats, syncResult?, publishResult?, replenishResult? }`
/// per the lexicon output schema.
#[tracing::instrument(skip(pool, notification_service, resolver, headers, auth_user, input))]
pub async fn publish_key_packages_post(
    State(pool): State<DbPool>,
    State(notification_service): State<Option<Arc<NotificationService>>>,
    State(resolver): State<Arc<crate::federation::DsResolver>>,
    headers: HeaderMap,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<PublishKeyPackagesRequest>,
) -> Result<Json<PublishKeyPackagesOutput<'static>>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = auth_user.did.clone();

    let (user_did, mut raw_device_id) = parse_device_did(&did).map_err(|e| {
        error!("Invalid DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    // If the auth DID doesn't include a #device fragment, use device_id from the request body
    if raw_device_id.is_empty() {
        if let Some(ref req_device_id) = input.device_id {
            let req_dev = req_device_id.as_ref().trim();
            if !req_dev.is_empty() {
                raw_device_id = req_dev.to_string();
            }
        }
    }

    let device_scope = resolve_device_scope(&pool, &user_did, &raw_device_id).await?;
    let storage_device_id = device_scope.storage_device_id.as_str();

    // N44 Device Record Authorization (Rollout Mode)
    let enforce_auth = std::env::var("AUTHORIZATION_ROLLOUT_MODE")
        .map(|s| s.eq_ignore_ascii_case("enforce"))
        .unwrap_or(false);

    if input.action.as_ref() == "publish" || input.action.as_ref() == "publishBatch" {
        if let Some(expected_sig_key) = device_scope.signature_public_key.as_deref() {
            match resolver.resolve_authorized_device_keys(&user_did).await {
                Ok(keys) => {
                    let is_authorized = keys.iter().any(|k| k.as_slice() == expected_sig_key);
                    if !is_authorized {
                        if enforce_auth {
                            error!("N44 Enforcement: signature key for {} not found in device records (resolved {} keys). Rejecting.", user_did, keys.len());
                            return Err(StatusCode::FORBIDDEN);
                        } else {
                            warn!("N44 Warn-only: signature key for {} not found in device records (resolved {} keys)", user_did, keys.len());
                        }
                    }
                }
                Err(e) => {
                    // PDS resolution failure. In both warn and enforce, we allow to prevent PDS outages from breaking MLS publishing.
                    warn!("N44 device records resolution failed for {}: {}", user_did, e);
                }
            }
        }
    }

    match input.action.as_ref() {
        "publish" => {
            let Some(expected_signature_public_key) = device_scope.signature_public_key.as_deref()
            else {
                warn!(
                    "publishKeyPackages: publish rejected because device {} is not registered with a signature key",
                    device_scope.raw_device_id
                );
                return Err(StatusCode::FORBIDDEN);
            };
            let publish_result = if input
                .key_packages
                .as_ref()
                .map(|items| items.len() > 1)
                .unwrap_or(false)
            {
                warn!("publish action received multiple key packages; handling as publishBatch");
                handle_publish_batch(
                    &pool,
                    &headers,
                    &input,
                    &user_did,
                    &device_scope,
                    expected_signature_public_key,
                )
                .await?
            } else {
                handle_publish(
                    &pool,
                    &input,
                    &user_did,
                    storage_device_id,
                    expected_signature_public_key,
                )
                .await?
            };
            let stats = build_stats(&pool, &user_did, Some(&device_scope)).await?;
            Ok(Json(PublishKeyPackagesOutput {
                stats,
                publish_result: Some(publish_result),
                sync_result: None,
                replenish_result: None,
                extra_data: Default::default(),
            }))
        }

        "publishBatch" => {
            let Some(expected_signature_public_key) = device_scope.signature_public_key.as_deref()
            else {
                warn!(
                    "publishKeyPackages: publishBatch rejected because device {} is not registered with a signature key",
                    device_scope.raw_device_id
                );
                return Err(StatusCode::FORBIDDEN);
            };
            let publish_result = handle_publish_batch(
                &pool,
                &headers,
                &input,
                &user_did,
                &device_scope,
                expected_signature_public_key,
            )
            .await?;
            let stats = build_stats(&pool, &user_did, Some(&device_scope)).await?;
            Ok(Json(PublishKeyPackagesOutput {
                stats,
                publish_result: Some(publish_result),
                sync_result: None,
                replenish_result: None,
                extra_data: Default::default(),
            }))
        }

        "sync" => {
            let sync_result = handle_sync(&pool, &input, &user_did, &device_scope).await?;
            let stats = build_stats(&pool, &user_did, Some(&device_scope)).await?;
            Ok(Json(PublishKeyPackagesOutput {
                stats,
                publish_result: None,
                sync_result: Some(sync_result),
                replenish_result: None,
                extra_data: Default::default(),
            }))
        }

        "stats" => {
            let stats = build_stats(&pool, &user_did, Some(&device_scope)).await?;
            Ok(Json(PublishKeyPackagesOutput {
                stats,
                publish_result: None,
                sync_result: None,
                replenish_result: None,
                extra_data: Default::default(),
            }))
        }

        "requestReplenish" => {
            let replenish_result =
                handle_request_replenish(&pool, notification_service, &input, &user_did).await?;
            let stats = build_stats(&pool, &user_did, Some(&device_scope)).await?;
            Ok(Json(PublishKeyPackagesOutput {
                stats,
                publish_result: None,
                sync_result: None,
                replenish_result: Some(replenish_result),
                extra_data: Default::default(),
            }))
        }

        unknown => {
            warn!("Unknown action for v2 publishKeyPackages POST: {}", unknown);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
