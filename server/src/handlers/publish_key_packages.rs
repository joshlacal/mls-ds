use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    middleware::rate_limit::RECOVERY_MODE_HEADER,
    storage::DbPool,
};

const MAX_BATCH_SIZE: usize = 100;
const MAX_UNCONSUMED_PER_USER: i64 = 100;
const MAX_UPLOADS_PER_HOUR: i64 = 200;
const RATE_LIMIT_WINDOW_HOURS: i64 = 1;
/// Maximum key packages allowed in recovery mode (prevents abuse)
const MAX_RECOVERY_BATCH: usize = 50;

#[derive(Debug, Deserialize)]
pub struct KeyPackageItem {
    #[serde(rename = "keyPackage")]
    key_package: String,
    #[serde(rename = "cipherSuite")]
    cipher_suite: String,
    expires: DateTime<Utc>,
    #[serde(rename = "idempotencyKey")]
    idempotency_key: Option<String>,
    #[serde(rename = "deviceId")]
    device_id: Option<String>,
    #[serde(rename = "credentialDid")]
    credential_did: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PublishKeyPackagesInput {
    #[serde(rename = "keyPackages")]
    key_packages: Vec<KeyPackageItem>,
}

#[derive(Debug, Serialize)]
pub struct BatchError {
    index: usize,
    error: String,
}

#[derive(Debug, Serialize)]
pub struct PublishKeyPackagesOutput {
    succeeded: usize,
    failed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    skipped: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<Vec<BatchError>>,
}

/// Publish multiple key packages in a single request (batch upload)
/// POST /xrpc/blue.catbird.mls.publishKeyPackages
///
/// Supports recovery mode via `X-MLS-Recovery-Mode: true` header.
/// When in recovery mode and device genuinely has 0 key packages,
/// rate limits are bypassed to allow emergency key package upload.
#[tracing::instrument(skip(pool, input, headers))]
pub async fn publish_key_packages(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    auth_user: AuthUser,
    Json(input): Json<PublishKeyPackagesInput>,
) -> Result<Json<PublishKeyPackagesOutput>, StatusCode> {
    if let Err(_e) =
        crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.publishKeyPackages")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = &auth_user.did;

    // Extract user DID and device ID from device DID (handles both single and multi-device mode)
    let (user_did, device_id) = parse_device_did(did).map_err(|e| {
        error!("Invalid device DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    // Check for recovery mode request
    let is_recovery_mode = headers
        .get(RECOVERY_MODE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // Validate batch size
    if input.key_packages.is_empty() {
        warn!("Empty key packages array");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Recovery mode has a smaller max batch (prevents abuse)
    let max_batch = if is_recovery_mode {
        MAX_RECOVERY_BATCH
    } else {
        MAX_BATCH_SIZE
    };

    if input.key_packages.len() > max_batch {
        warn!(
            "Batch size {} exceeds maximum {} (recovery_mode: {})",
            input.key_packages.len(),
            max_batch,
            is_recovery_mode
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    info!(
        "Publishing batch of {} key packages (recovery_mode: {})",
        input.key_packages.len(),
        is_recovery_mode
    );

    let now = Utc::now();

    // For recovery mode, check if this device actually has 0 key packages
    // This verification prevents abuse of recovery mode bypass
    let recovery_verified = if is_recovery_mode {
        let device_key_count: (i64,) = if device_id.is_empty() {
            // Single-device mode: check all user key packages
            sqlx::query_as(
                r#"
                SELECT COUNT(*) as count
                FROM key_packages
                WHERE owner_did = $1
                  AND consumed_at IS NULL
                  AND expires_at > $2
                "#,
            )
            .bind(&user_did)
            .bind(now)
            .fetch_one(&pool)
            .await
        } else {
            // Multi-device mode: check key packages for THIS device only
            sqlx::query_as(
                r#"
                SELECT COUNT(*) as count
                FROM key_packages
                WHERE owner_did = $1
                  AND device_id = $2
                  AND consumed_at IS NULL
                  AND expires_at > $2
                "#,
            )
            .bind(&user_did)
            .bind(&device_id)
            .bind(now)
            .fetch_one(&pool)
            .await
        }
        .map_err(|e| {
            error!("Failed to verify recovery mode: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if device_key_count.0 == 0 {
            info!(
                "🚨 Recovery mode VERIFIED for {} (device: {}) - device has 0 key packages",
                user_did,
                if device_id.is_empty() { "single" } else { &device_id }
            );
            true
        } else {
            warn!(
                "⚠️ Recovery mode DENIED for {} (device: {}) - device has {} key packages (not 0)",
                user_did,
                if device_id.is_empty() { "single" } else { &device_id },
                device_key_count.0
            );
            false
        }
    } else {
        false
    };

    // Check 1: Total unconsumed key packages limit (skip in verified recovery mode)
    let unconsumed_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) as count
        FROM key_packages
        WHERE owner_did = $1
          AND consumed_at IS NULL
          AND expires_at > $2
        "#,
    )
    .bind(&user_did)
    .bind(now)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to count unconsumed key packages: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Skip limit check in verified recovery mode
    if !recovery_verified && unconsumed_count.0 >= MAX_UNCONSUMED_PER_USER {
        warn!(
            "User {} has {} unconsumed key packages (limit: {})",
            did, unconsumed_count.0, MAX_UNCONSUMED_PER_USER
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Check 2: Rate limiting - count uploads in the last hour (skip in verified recovery mode)
    if !recovery_verified {
        let rate_limit_window = now - chrono::Duration::hours(RATE_LIMIT_WINDOW_HOURS);
        let recent_uploads: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) as count
            FROM key_packages
            WHERE owner_did = $1
              AND created_at > $2
            "#,
        )
        .bind(&user_did)
        .bind(rate_limit_window)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!("Failed to check rate limit: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if recent_uploads.0 >= MAX_UPLOADS_PER_HOUR {
            warn!(
                "User {} exceeded rate limit: {} uploads in last hour (limit: {})",
                did, recent_uploads.0, MAX_UPLOADS_PER_HOUR
            );
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // Check if this batch would exceed limits (still apply in recovery mode)
    if unconsumed_count.0 + input.key_packages.len() as i64 > MAX_UNCONSUMED_PER_USER {
        warn!(
            "Batch would exceed unconsumed limit for user {}: {} + {} > {}",
            did,
            unconsumed_count.0,
            input.key_packages.len(),
            MAX_UNCONSUMED_PER_USER
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let mut succeeded = 0;
    let mut failed = 0;
    let mut skipped = 0;
    let mut errors = Vec::new();

    // Validate all packages first (fail fast)
    for (idx, item) in input.key_packages.iter().enumerate() {
        if item.key_package.is_empty() {
            errors.push(BatchError {
                index: idx,
                error: "Empty key_package".to_string(),
            });
            failed += 1;
            continue;
        }

        if item.cipher_suite.is_empty() {
            errors.push(BatchError {
                index: idx,
                error: "Empty cipher_suite".to_string(),
            });
            failed += 1;
            continue;
        }

        if item.expires <= now {
            errors.push(BatchError {
                index: idx,
                error: "Expiration is in the past".to_string(),
            });
            failed += 1;
            continue;
        }

        // Validate base64 encoding
        if base64::engine::general_purpose::STANDARD
            .decode(&item.key_package)
            .is_err()
        {
            errors.push(BatchError {
                index: idx,
                error: "Invalid base64 encoding".to_string(),
            });
            failed += 1;
        }
    }

    // If any validation failed, return early
    if !errors.is_empty() {
        warn!("Batch validation failed: {} errors", errors.len());
        return Ok(Json(PublishKeyPackagesOutput {
            succeeded: 0,
            failed: errors.len(),
            skipped: None,
            errors: Some(errors),
        }));
    }

    // Process all packages
    for (idx, item) in input.key_packages.iter().enumerate() {
        // Decode key package (we already validated, so this should succeed)
        let key_data = match base64::engine::general_purpose::STANDARD.decode(&item.key_package) {
            Ok(data) => data,
            Err(e) => {
                errors.push(BatchError {
                    index: idx,
                    error: format!("Failed to decode base64: {}", e),
                });
                failed += 1;
                continue;
            }
        };

        if key_data.is_empty() {
            errors.push(BatchError {
                index: idx,
                error: "Decoded key package is empty".to_string(),
            });
            failed += 1;
            continue;
        }

        // Compute hash for deduplication
        let key_package_hash = crate::crypto::sha256_hex(&key_data);

        // Check for duplicates (idempotent behavior)
        match crate::db::check_key_package_duplicate(&pool, &user_did, &key_package_hash).await {
            Ok(true) => {
                // Duplicate found - skip silently (idempotent)
                skipped += 1;
                continue;
            }
            Ok(false) => {
                // Not a duplicate - proceed with storage
            }
            Err(e) => {
                error!("Failed to check key package duplicate {}: {}", idx, e);
                errors.push(BatchError {
                    index: idx,
                    error: format!("Database error: {}", e),
                });
                failed += 1;
                continue;
            }
        }

        // Store key package with device information
        // NOTE: Use user_did (not device_did) as owner_did so getKeyPackages can find
        // all key packages for a user regardless of which device published them
        // The server will parse the KeyPackage and extract + validate the credential identity
        match crate::db::store_key_package_with_device(
            &pool,
            &user_did,
            &item.cipher_suite,
            key_data,
            item.expires,
            item.device_id.clone(),
            None, // credential_did is now extracted from KeyPackage and validated
        )
        .await
        {
            Ok(_) => {
                succeeded += 1;
            }
            Err(e) => {
                error!("Failed to store key package {}: {}", idx, e);
                errors.push(BatchError {
                    index: idx,
                    error: format!("Database error: {}", e),
                });
                failed += 1;
            }
        }
    }

    info!(
        "Batch upload complete: {} succeeded, {} failed, {} skipped",
        succeeded, failed, skipped
    );

    Ok(Json(PublishKeyPackagesOutput {
        succeeded,
        failed,
        skipped: if skipped > 0 { Some(skipped) } else { None },
        errors: if errors.is_empty() {
            None
        } else {
            Some(errors)
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn test_batch_upload_success() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let pool = crate::db::init_db(crate::db::DbConfig {
            database_url: db_url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap();

        let auth_user = AuthUser {
            did: "did:plc:test_batch".to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: "did:plc:test_batch".to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let expires = Utc::now() + Duration::days(30);

        let input = PublishKeyPackagesInput {
            key_packages: vec![
                KeyPackageItem {
                    key_package: base64::engine::general_purpose::STANDARD.encode(b"test_key_1"),
                    cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
                    expires,
                    idempotency_key: None,
                },
                KeyPackageItem {
                    key_package: base64::engine::general_purpose::STANDARD.encode(b"test_key_2"),
                    cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
                    expires,
                    idempotency_key: None,
                },
            ],
        };

        let result = publish_key_packages(State(pool), auth_user, Json(input)).await;
        assert!(result.is_ok());

        let output = result.unwrap().0;
        assert_eq!(output.succeeded, 2);
        assert_eq!(output.failed, 0);
        assert!(output.errors.is_none());
    }

    #[tokio::test]
    async fn test_batch_upload_with_validation_errors() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let pool = crate::db::init_db(crate::db::DbConfig {
            database_url: db_url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap();

        let auth_user = AuthUser {
            did: "did:plc:test_batch_err".to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: "did:plc:test_batch_err".to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let expires_past = Utc::now() - Duration::days(1);

        let input = PublishKeyPackagesInput {
            key_packages: vec![
                KeyPackageItem {
                    key_package: "".to_string(), // Empty - should fail
                    cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
                    expires: Utc::now() + Duration::days(30),
                    idempotency_key: None,
                },
                KeyPackageItem {
                    key_package: base64::engine::general_purpose::STANDARD.encode(b"test_key"),
                    cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
                    expires: expires_past, // Past expiration - should fail
                    idempotency_key: None,
                },
            ],
        };

        let result = publish_key_packages(State(pool), auth_user, Json(input)).await;
        assert!(result.is_ok());

        let output = result.unwrap().0;
        assert_eq!(output.succeeded, 0);
        assert_eq!(output.failed, 2);
        assert!(output.errors.is_some());
        assert_eq!(output.errors.unwrap().len(), 2);
    }
}
