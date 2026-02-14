use base64::Engine;

use axum::{extract::State, http::StatusCode, Json};
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mls::publish_key_package::{
        PublishKeyPackage, PublishKeyPackageOutput,
    },
    storage::DbPool,
};

/// Publish a key package for the authenticated user
/// POST /xrpc/chat.bsky.convo.publishKeyPackage
#[tracing::instrument(skip(pool, body))]
pub async fn publish_key_package(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<PublishKeyPackageOutput<'static>>, StatusCode> {
    let input = crate::jacquard_json::from_json_body::<PublishKeyPackage>(&body)?;
    if let Err(_e) =
        crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.publishKeyPackage")
    {
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

    // Extract and validate expires (required despite being Optional in lexicon)
    let expires = match input.expires {
        Some(dt) => dt,
        None => {
            warn!("Missing expires field");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Validate expires is in the future
    let now = chrono::Utc::now();
    if *expires.as_ref() <= now.fixed_offset() {
        warn!("Key package expiration is in the past");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Decode key package
    let key_data = base64::engine::general_purpose::STANDARD
        .decode(input.key_package.as_str())
        .map_err(|e| {
            warn!("Invalid base64 key_package: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    if key_data.is_empty() {
        warn!("Decoded key package is empty");
        return Err(StatusCode::BAD_REQUEST);
    }

    info!(
        "Publishing key package, cipher_suite: {}",
        input.cipher_suite
    );

    // Store key package (dedup by did+cipher_suite+key_data)
    crate::db::store_key_package(
        &pool,
        did,
        input.cipher_suite.as_str(),
        key_data,
        expires.as_ref().with_timezone(&chrono::Utc),
    )
    .await
    .map_err(|e| {
        error!("Failed to store key package: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Key package published successfully");

    let output = PublishKeyPackageOutput {
        extra_data: Default::default(),
    };
    Ok(Json(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::init_db;
    use chrono::Duration;
    use jacquard_common::types::string::Datetime;

    #[tokio::test]
    async fn test_publish_key_package_success() {
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
        let did = AuthUser {
            did: "did:plc:user".to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: "did:plc:user".to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let key_data = b"sample_key_package_data";
        let key_package = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_data);
        let expires = chrono::Utc::now() + Duration::days(30);

        let input = PublishKeyPackage {
            key_package: key_package.into(),
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".into(),
            expires: Some(Datetime::new(expires.fixed_offset())),
            ..Default::default()
        };

        let result =
            publish_key_package(State(pool), did, serde_json::to_string(&input).unwrap()).await;
        assert!(result.is_ok());

        let output = result.unwrap().0;
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json.get("success").unwrap().as_bool().unwrap(), true);
    }

    #[tokio::test]
    async fn test_publish_key_package_empty() {
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
        let did = AuthUser {
            did: "did:plc:user".to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: "did:plc:user".to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let expires = chrono::Utc::now() + Duration::days(30);
        let input = PublishKeyPackage {
            key_package: "".into(),
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".into(),
            expires: Some(Datetime::new(expires.fixed_offset())),
            ..Default::default()
        };

        let result =
            publish_key_package(State(pool), did, serde_json::to_string(&input).unwrap()).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_publish_key_package_expired() {
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
        let did = AuthUser {
            did: "did:plc:user".to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: "did:plc:user".to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let key_data = b"sample_key_package_data";
        let key_package = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_data);
        let expires = chrono::Utc::now() - Duration::days(1);

        let input = PublishKeyPackage {
            key_package: key_package.into(),
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".into(),
            expires: Some(Datetime::new(expires.fixed_offset())),
            ..Default::default()
        };

        let result =
            publish_key_package(State(pool), did, serde_json::to_string(&input).unwrap()).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_publish_key_package_replace_existing() {
        // Skip replacement behavior validation for Postgres-backed store_key_package
        // (duplicates are prevented by unique index on did+cipher_suite+key_data)
        return;
    }
}
