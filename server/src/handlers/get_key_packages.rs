use base64::Engine;

use axum::{extract::{RawQuery, State}, http::StatusCode, Json};
use serde::Deserialize;
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    models::KeyPackageInfo,
    storage::DbPool,
};

/// Get key packages for specified users
/// GET /xrpc/chat.bsky.convo.getKeyPackages
#[tracing::instrument(skip(pool), fields(did = %auth_user.did))]
pub async fn get_key_packages(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    RawQuery(query): RawQuery,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.getKeyPackages") {
        warn!("Unauthorized access attempt");
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    // Parse query string manually to handle ATProto array format (?dids=X&dids=Y)
    let query_str = query.unwrap_or_default();
    info!("getKeyPackages called with query: {}", query_str);
    
    let mut dids = Vec::new();
    let mut cipher_suite = None;
    
    for pair in query_str.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let decoded_value = urlencoding::decode(value).unwrap_or_default().to_string();
            match key {
                "dids" => dids.push(decoded_value),
                "cipherSuite" => cipher_suite = Some(decoded_value),
                _ => {}
            }
        }
    }
    
    // Validate input
    if dids.is_empty() {
        warn!("Empty dids parameter provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    let dids_refs: Vec<&str> = dids.iter().map(|s| s.as_str()).collect();

    if dids_refs.len() > 100 {
        warn!("Too many DIDs requested: {}", dids_refs.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate DID format
    for did in &dids_refs {
        if !did.starts_with("did:") {
            warn!("Invalid DID format: {}", did);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    info!("Fetching key packages for {} DIDs", dids_refs.len());

    let mut results = Vec::new();
    let default_cipher_suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
    let suite = cipher_suite.as_deref().unwrap_or(default_cipher_suite);

    for did in dids_refs {
        // Get ALL available key packages for this DID (multi-device support)
        match crate::db::get_all_key_packages(&pool, did, suite).await {
            Ok(kps) if !kps.is_empty() => {
                info!("Found {} key package(s) for DID: {}", kps.len(), did);
                for kp in kps {
                    results.push(KeyPackageInfo {
                        did: kp.did,
                        key_package: base64::engine::general_purpose::STANDARD.encode(kp.key_data),
                        cipher_suite: kp.cipher_suite,
                        key_package_hash: kp.key_package_hash,
                    });
                }
            }
            Ok(_) => {
                info!("No valid key package found for DID: {}", did);
            }
            Err(e) => {
                error!("Failed to get key packages for {}: {}", did, e);
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

        let auth_user = AuthUser { did: "did:plc:requester".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:requester".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let params = GetKeyPackagesParams {
            dids: vec![did1.to_string(), did2.to_string()],
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
        
        let auth_user = AuthUser { did: "did:plc:requester".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:requester".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let params = GetKeyPackagesParams {
            dids: vec!["did:plc:nonexistent".to_string()],
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
        
        let auth_user = AuthUser { did: "did:plc:requester".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:requester".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let params = GetKeyPackagesParams {
            dids: vec![],
        };

        let result = get_key_packages(State(pool), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_key_packages_invalid_did() {
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: ":memory:".to_string(), max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        
        let auth_user = AuthUser { did: "did:plc:requester".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:requester".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let params = GetKeyPackagesParams {
            dids: vec!["invalid_did".to_string()],
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

        let auth_user = AuthUser { did: "did:plc:requester".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:requester".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let params = GetKeyPackagesParams {
            dids: vec![did.to_string()],
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

        let auth_user = AuthUser { did: "did:plc:requester".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:requester".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let params = GetKeyPackagesParams {
            dids: vec![did.to_string()],
        };

        let result = get_key_packages(State(pool), auth_user, Query(params)).await;
        assert!(result.is_ok());

        let json = result.unwrap().0;
        let key_packages = json.get("keyPackages").unwrap().as_array().unwrap();
        assert_eq!(key_packages.len(), 0); // Consumed key package should not be returned
    }
}
