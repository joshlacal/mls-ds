use base64::Engine;
use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    storage::DbPool,
};

const MAX_BATCH_SIZE: usize = 100;

#[derive(Debug, Deserialize)]
pub struct KeyPackageItem {
    #[serde(rename = "keyPackage")]
    key_package: String,
    #[serde(rename = "cipherSuite")]
    cipher_suite: String,
    expires: DateTime<Utc>,
    #[serde(rename = "idempotencyKey")]
    idempotency_key: Option<String>,
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
    errors: Option<Vec<BatchError>>,
}

/// Publish multiple key packages in a single request (batch upload)
/// POST /xrpc/blue.catbird.mls.publishKeyPackages
#[tracing::instrument(skip(pool, input))]
pub async fn publish_key_packages(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<PublishKeyPackagesInput>,
) -> Result<Json<PublishKeyPackagesOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.publishKeyPackages") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = &auth_user.did;

    // Validate batch size
    if input.key_packages.is_empty() {
        warn!("Empty key packages array");
        return Err(StatusCode::BAD_REQUEST);
    }

    if input.key_packages.len() > MAX_BATCH_SIZE {
        warn!("Batch size {} exceeds maximum {}", input.key_packages.len(), MAX_BATCH_SIZE);
        return Err(StatusCode::BAD_REQUEST);
    }

    info!("Publishing batch of {} key packages", input.key_packages.len());

    let now = Utc::now();
    let mut succeeded = 0;
    let mut failed = 0;
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
        if base64::engine::general_purpose::STANDARD.decode(&item.key_package).is_err() {
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

        // Store key package
        match crate::db::store_key_package(&pool, did, &item.cipher_suite, key_data, item.expires).await {
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
        "Batch upload complete: {} succeeded, {} failed",
        succeeded, failed
    );

    Ok(Json(PublishKeyPackagesOutput {
        succeeded,
        failed,
        errors: if errors.is_empty() { None } else { Some(errors) },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn test_batch_upload_success() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
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
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
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
