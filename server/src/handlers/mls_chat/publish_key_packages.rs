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

    // "available" must mean "ready to be handed out by getKeyPackages right
    // now" — i.e. genuinely `state='available'`, not dead, not expired, not
    // consumed. The previous predicate (`consumed_at IS NULL AND expires_at >
    // NOW()`) also counted `reserved` rows stuck in a never-consumed Welcome
    // and `dead` rows, inflating the count. The client's replenish loop reads
    // this number; when it is inflated the loop sees a healthy pool, never
    // republishes, and the true available pool bleeds to zero while
    // getKeyPackages finds nothing to serve. Count exactly what is servable.
    let available: i64 = if candidates.is_empty() {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND state = 'available' AND dead_at IS NULL AND consumed_at IS NULL AND expires_at > NOW()",
        )
        .bind(user_did)
        .fetch_one(pool)
        .await
    } else {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND device_id = ANY($2::text[]) AND state = 'available' AND dead_at IS NULL AND consumed_at IS NULL AND expires_at > NOW()",
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
    let last_resort = item.last_resort.unwrap_or(false);

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
        last_resort,
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
               AND is_last_resort = false
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

    let regular_uploads = items
        .iter()
        .filter(|item| !item.last_resort.unwrap_or(false))
        .count() as i64;

    // Unconsumed regular-key-package limit. Reusable last-resort rows are
    // bounded separately to one active row per device and must not block
    // normal replenishment.
    let unconsumed: (i64,) = if recovery_mode_verified {
        sqlx::query_as(
            "SELECT COUNT(*) FROM key_packages
             WHERE owner_did = $1
               AND device_id = ANY($2::text[])
               AND consumed_at IS NULL
               AND is_last_resort = false
               AND expires_at > $3",
        )
        .bind(user_did)
        .bind(device_candidates)
        .bind(now)
        .fetch_one(pool)
        .await
    } else {
        sqlx::query_as(
            "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND consumed_at IS NULL AND is_last_resort = false AND expires_at > $2",
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

    if regular_uploads > 0 && unconsumed.0 >= MAX_UNCONSUMED_PER_USER {
        warn!(
            "User {} has {} unconsumed key packages (limit: {})",
            user_did, unconsumed.0, MAX_UNCONSUMED_PER_USER
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    if unconsumed.0 + regular_uploads > MAX_UNCONSUMED_PER_USER {
        warn!(
            "Batch would exceed unconsumed limit: {} + {} > {}",
            unconsumed.0, regular_uploads, MAX_UNCONSUMED_PER_USER
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
        let last_resort = item.last_resort.unwrap_or(false);
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
            last_resort,
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

    // Preserve pending welcomes referencing deleted key packages.
    //
    // A claimed key package may be deleted during device sync after createConvo
    // has already stored the matching Welcome. At that point the Welcome row is
    // the durable receipt the recipient needs to join; consuming it here strands
    // the member in the "server lists me, Welcome unavailable" state.
    if deleted_count > 0 {
        info!(
            "🛡️ [sync] Preserved pending Welcome(s) for {} deleted key package hash(es)",
            orphaned_hashes.len()
        );
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
                            error!(
                                "N44 Enforcement: signature key for {} not found in device records (resolved {} keys). Rejecting.",
                                user_did,
                                keys.len()
                            );
                            return Err(StatusCode::FORBIDDEN);
                        } else {
                            warn!(
                                "N44 Warn-only: signature key for {} not found in device records (resolved {} keys)",
                                user_did,
                                keys.len()
                            );
                        }
                    }
                }
                Err(e) => {
                    // PDS resolution failure. In both warn and enforce, we allow to prevent PDS outages from breaking MLS publishing.
                    warn!(
                        "N44 device records resolution failed for {}: {}",
                        user_did, e
                    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{init_db, DbConfig};
    use std::time::Duration;
    use uuid::Uuid;

    const CIPHER_SUITE: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";

    async fn setup_test_db() -> DbPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/catbird_test".to_string());

        init_db(DbConfig {
            database_url,
            max_connections: 4,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        })
        .await
        .expect("initialize test database")
    }

    async fn cleanup(pool: &DbPool, convo_id: &str, user_did: &str) {
        let _ = sqlx::query("DELETE FROM welcome_messages WHERE convo_id = $1")
            .bind(convo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM key_packages WHERE owner_did = $1")
            .bind(user_did)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM members WHERE convo_id = $1")
            .bind(convo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
            .bind(convo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(user_did)
            .execute(pool)
            .await;
    }

    async fn seed_user(pool: &DbPool, did: &str) {
        sqlx::query("INSERT INTO users (did) VALUES ($1) ON CONFLICT (did) DO NOTHING")
            .bind(did)
            .execute(pool)
            .await
            .expect("seed user");
    }

    async fn seed_convo(pool: &DbPool, convo_id: &str, creator_did: &str) {
        sqlx::query(
            "INSERT INTO conversations \
                (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, group_id) \
             VALUES ($1, $2, 1, NOW(), NOW(), $3, false, $1)",
        )
        .bind(convo_id)
        .bind(creator_did)
        .bind(CIPHER_SUITE)
        .execute(pool)
        .await
        .expect("seed conversation");
    }

    async fn seed_key_package(pool: &DbPool, owner_did: &str, device_id: &str, hash_hex: &str) {
        sqlx::query(
            "INSERT INTO key_packages \
                (id, owner_did, device_id, cipher_suite, key_package, key_package_hash, created_at, expires_at, state) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW() + INTERVAL '30 days', 'available')",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(owner_did)
        .bind(device_id)
        .bind(CIPHER_SUITE)
        .bind::<&[u8]>(&[0xA5])
        .bind(hash_hex)
        .execute(pool)
        .await
        .expect("seed key package");
    }

    async fn seed_pending_welcome(
        pool: &DbPool,
        convo_id: &str,
        recipient_did: &str,
        device_id: &str,
        hash_hex: &str,
    ) {
        let hash_bytes = hex::decode(hash_hex).expect("hash hex");
        sqlx::query(
            "INSERT INTO welcome_messages \
                (id, convo_id, recipient_did, recipient_device_id, welcome_data, key_package_hash, created_by_did, created_at, consumed) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), false)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(convo_id)
        .bind(recipient_did)
        .bind(device_id)
        .bind::<&[u8]>(&[0x57, 0x45, 0x4c])
        .bind(hash_bytes)
        .bind("did:plc:syncsender000000")
        .execute(pool)
        .await
        .expect("seed pending welcome");
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn sync_cleanup_preserves_unconsumed_welcome_for_orphaned_key_package() {
        let pool = setup_test_db().await;
        let user_did = format!("did:plc:syncwelcome{}", Uuid::new_v4().simple());
        let convo_id = format!("convo-sync-welcome-{}", Uuid::new_v4());
        let device_id = "device-sync-a";
        let hash_hex = "d138a0f7a772bac5db5a96748f01bad7d7a71c641b4ba87bdaf1431c1a6dde83";

        cleanup(&pool, &convo_id, &user_did).await;
        seed_user(&pool, &user_did).await;
        seed_convo(&pool, &convo_id, &user_did).await;
        seed_key_package(&pool, &user_did, device_id, hash_hex).await;
        seed_pending_welcome(&pool, &convo_id, &user_did, device_id, hash_hex).await;

        let input = PublishKeyPackages {
            action: "sync".into(),
            convo_id: None,
            device_id: Some(device_id.into()),
            key_packages: None,
            local_hashes: Some(Vec::new()),
            reason: None,
            target_dids: None,
            extra_data: Default::default(),
        };
        let device_scope = DeviceScope {
            raw_device_id: device_id.to_string(),
            storage_device_id: device_id.to_string(),
            storage_candidates: vec![device_id.to_string()],
            signature_public_key: None,
        };

        let result = handle_sync(&pool, &input, &user_did, &device_scope)
            .await
            .expect("sync succeeds");
        assert_eq!(result.orphaned_count, 1);
        assert_eq!(result.deleted_count, 1);

        let welcome: (bool, Option<String>) = sqlx::query_as(
            "SELECT consumed, error_reason \
             FROM welcome_messages \
             WHERE convo_id = $1 AND recipient_did = $2 AND encode(key_package_hash, 'hex') = $3",
        )
        .bind(&convo_id)
        .bind(&user_did)
        .bind(hash_hex)
        .fetch_one(&pool)
        .await
        .expect("fetch welcome");

        assert!(!welcome.0, "sync cleanup must not consume pending Welcome");
        assert!(
            welcome.1.is_none(),
            "sync cleanup must not mark pending Welcome as orphaned"
        );

        cleanup(&pool, &convo_id, &user_did).await;
    }
}
