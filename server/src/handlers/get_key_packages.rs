use base64::Engine;

use axum::{extract::{Query, State}, http::StatusCode, Json};
use serde::Deserialize;
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    models::{KeyPackage, KeyPackageInfo},
    storage::DbPool,
};

#[derive(Debug, Deserialize)]
pub struct GetKeyPackagesParams {
    pub dids: String, // comma-separated DIDs
}

/// Get key packages for specified users
/// GET /xrpc/chat.bsky.convo.getKeyPackages
#[tracing::instrument(skip(pool), fields(did = %auth_user.did))]
pub async fn get_key_packages(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<GetKeyPackagesParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.getKeyPackages") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // Validate input
    if params.dids.is_empty() {
        warn!("Empty dids parameter provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    let dids: Vec<&str> = params.dids.split(',').filter(|s| !s.is_empty()).collect();

    if dids.is_empty() {
        warn!("No valid DIDs provided after parsing");
        return Err(StatusCode::BAD_REQUEST);
    }

    if dids.len() > 100 {
        warn!("Too many DIDs requested: {}", dids.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate DID format
    for did in &dids {
        if !did.starts_with("did:") {
            warn!("Invalid DID format: {}", did);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    info!("Fetching key packages for {} DIDs", dids.len());

    let mut results = Vec::new();

    for did in dids {
        match crate::db::get_key_package(&pool, did, "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519").await {
            Ok(Some(kp)) => {
                results.push(KeyPackageInfo {
                    did: kp.did,
                    key_package: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kp.key_data),
                    cipher_suite: kp.cipher_suite,
                });
            }
            Ok(None) => {
                info!("No valid key package found for DID: {}", did);
            }
            Err(e) => {
                error!("Failed to get key package for {}: {}", did, e);
            }
        }
    }

    info!("Found {} key packages", results.len());

    Ok(Json(serde_json::json!({ "keyPackages": results })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::init_db;
    use chrono::Duration;

    async fn publish_key_package(pool: &DbPool, did: &str, cipher_suite: &str) {
        let now = chrono::Utc::now();
        let expires = now + Duration::days(30);
        let key_data = format!("key_package_for_{}", did).into_bytes();

        let _ = crate::db::store_key_package(pool, did, cipher_suite, key_data, expires).await;
    }

    #[tokio::test]
    async fn test_get_key_packages_success() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        
        let did1 = "did:plc:user1";
        let did2 = "did:plc:user2";
        let cipher_suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

        publish_key_package(&pool, did1, cipher_suite).await;
        publish_key_package(&pool, did2, cipher_suite).await;

        let auth_user = AuthUser { did: "did:plc:requester".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:requester".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        let params = GetKeyPackagesParams {
            dids: format!("{},{}", did1, did2),
        };

        let result = get_key_packages(State(pool), auth_user, Query(params)).await;
        assert!(result.is_ok());
        
        let json = result.unwrap().0;
        let key_packages = json.get("keyPackages").unwrap().as_array().unwrap();
        assert_eq!(key_packages.len(), 2);
    }

    #[tokio::test]
    async fn test_get_key_packages_not_found() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        
        let auth_user = AuthUser { did: "did:plc:requester".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:requester".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        let params = GetKeyPackagesParams {
            dids: "did:plc:nonexistent".to_string(),
        };

        let result = get_key_packages(State(pool), auth_user, Query(params)).await;
        assert!(result.is_ok());
        
        let json = result.unwrap().0;
        let key_packages = json.get("keyPackages").unwrap().as_array().unwrap();
        assert_eq!(key_packages.len(), 0);
    }

    #[tokio::test]
    async fn test_get_key_packages_empty_dids() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        
        let auth_user = AuthUser { did: "did:plc:requester".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:requester".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        let params = GetKeyPackagesParams {
            dids: String::new(),
        };

        let result = get_key_packages(State(pool), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_key_packages_invalid_did() {
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: ":memory:".to_string(), max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        
        let auth_user = AuthUser { did: "did:plc:requester".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:requester".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        let params = GetKeyPackagesParams {
            dids: "invalid_did".to_string(),
        };

        let result = get_key_packages(State(pool), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_key_packages_expired() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        
        let did = "did:plc:user1";
        let cipher_suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
        let now = chrono::Utc::now();
        let expires = now - Duration::days(1); // Expired
        let key_data = b"expired_key_package".to_vec();

        let _ = crate::db::store_key_package(&pool, did, cipher_suite, key_data, expires).await;

        let auth_user = AuthUser { did: "did:plc:requester".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:requester".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        let params = GetKeyPackagesParams {
            dids: did.to_string(),
        };

        let result = get_key_packages(State(pool), auth_user, Query(params)).await;
        assert!(result.is_ok());
        
        let json = result.unwrap().0;
        let key_packages = json.get("keyPackages").unwrap().as_array().unwrap();
        assert_eq!(key_packages.len(), 0); // Expired key package should not be returned
    }

    #[tokio::test]
    async fn test_get_key_packages_consumed() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        
        let did = "did:plc:user1";
        let cipher_suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
        let now = chrono::Utc::now();
        let expires = now + Duration::days(30);
        let key_data = b"consumed_key_package".to_vec();

        // Insert then mark consumed
        let _ = crate::db::store_key_package(&pool, did, cipher_suite, key_data.clone(), expires).await;
        let _ = crate::db::consume_key_package(&pool, did, cipher_suite, &key_data).await;

        let auth_user = AuthUser { did: "did:plc:requester".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:requester".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None } };
        let params = GetKeyPackagesParams {
            dids: did.to_string(),
        };

        let result = get_key_packages(State(pool), auth_user, Query(params)).await;
        assert!(result.is_ok());
        
        let json = result.unwrap().0;
        let key_packages = json.get("keyPackages").unwrap().as_array().unwrap();
        assert_eq!(key_packages.len(), 0); // Consumed key package should not be returned
    }
}
