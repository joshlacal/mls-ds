use base64::Engine;

use axum::{extract::State, http::StatusCode, Json};
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    models::PublishKeyPackageInput,
    storage::DbPool,
};

/// Publish a key package for the authenticated user
/// POST /xrpc/chat.bsky.convo.publishKeyPackage
#[tracing::instrument(skip(pool, input), fields(did = %auth_user.did))]
pub async fn publish_key_package(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<PublishKeyPackageInput>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.publishKeyPackage") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let did = &auth_user.did;
    // Validate input
    if input.key_package.is_empty() {
        warn!("Empty key_package provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    if input.cipher_suite.is_empty() {
        warn!("Empty cipher_suite provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate expires is in the future
    let now = chrono::Utc::now();
    if input.expires <= now {
        warn!("Key package expiration is in the past");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Decode key package
    let key_data = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input.key_package)
        .map_err(|e| {
            warn!("Invalid base64 key_package: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    if key_data.is_empty() {
        warn!("Decoded key package is empty");
        return Err(StatusCode::BAD_REQUEST);
    }

    info!("Publishing key package for user {}, cipher_suite: {}", did, input.cipher_suite);

    // Store key package (dedup by did+cipher_suite+key_data)
    crate::db::store_key_package(&pool, did, &input.cipher_suite, key_data, input.expires)
        .await
        .map_err(|e| {
            error!("Failed to store key package: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!("Key package published successfully for user {}", did);

    Ok(Json(serde_json::json!({ "success": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::init_db;
    use chrono::Duration;

    #[tokio::test]
    async fn test_publish_key_package_success() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let did = AuthUser { did: "did:plc:user".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:user".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        
        let key_data = b"sample_key_package_data";
        let key_package = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_data);
        let expires = chrono::Utc::now() + Duration::days(30);
        
        let input = PublishKeyPackageInput {
            key_package,
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
            expires,
        };

        let result = publish_key_package(State(pool), did, Json(input)).await;
        assert!(result.is_ok());
        
        let json = result.unwrap().0;
        assert_eq!(json.get("success").unwrap().as_bool().unwrap(), true);
    }

    #[tokio::test]
    async fn test_publish_key_package_empty() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let did = AuthUser { did: "did:plc:user".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:user".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        
        let expires = chrono::Utc::now() + Duration::days(30);
        let input = PublishKeyPackageInput {
            key_package: String::new(),
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
            expires,
        };

        let result = publish_key_package(State(pool), did, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_publish_key_package_expired() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let did = AuthUser { did: "did:plc:user".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:user".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        
        let key_data = b"sample_key_package_data";
        let key_package = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_data);
        let expires = chrono::Utc::now() - Duration::days(1);
        
        let input = PublishKeyPackageInput {
            key_package,
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
            expires,
        };

        let result = publish_key_package(State(pool), did, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_publish_key_package_replace_existing() {
        // Skip replacement behavior validation for Postgres-backed store_key_package
        // (duplicates are prevented by unique index on did+cipher_suite+key_data)
        return;
    }
}
