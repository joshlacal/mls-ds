use axum::{extract::State, http::StatusCode, Json};
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    models::BlobRef,
    storage::DbPool,
};

/// Upload a blob (e.g., media attachment)
/// POST /xrpc/chat.bsky.convo.uploadBlob
#[tracing::instrument(skip(pool, body), fields(did = %auth_user.did, size = body.len()))]
pub async fn upload_blob(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    body: axum::body::Bytes,
) -> Result<Json<BlobRef>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.uploadBlob") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let did = &auth_user.did;
    // Validate size
    const MAX_BLOB_SIZE: usize = 10 * 1024 * 1024; // 10MB
    
    if body.is_empty() {
        warn!("Empty blob provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    if body.len() > MAX_BLOB_SIZE {
        warn!("Blob size {} exceeds maximum {}", body.len(), MAX_BLOB_SIZE);
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let data = body.to_vec();
    let size = data.len() as i64;

    info!("Uploading blob of size {} bytes", size);

    // Generate CID using SHA256
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let cid = format!("sha256-{:x}", hasher.finalize());

    let now = chrono::Utc::now();

    // Insert blob (ignore if already exists)
    sqlx::query(
        "INSERT INTO blobs (cid, data, size, uploaded_by_did, uploaded_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (cid) DO NOTHING"
    )
    .bind(&cid)
    .bind(&data)
    .bind(size)
    .bind(did)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to insert blob: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Blob uploaded successfully with CID: {}", cid);

    Ok(Json(BlobRef { cid, size }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::init_db;
    use axum::body::Bytes;

    #[tokio::test]
    async fn test_upload_blob_success() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let did = AuthUser { did: "did:plc:uploader".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:uploader".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let data = b"test blob data content";
        let body = Bytes::from(data.to_vec());

        let result = upload_blob(State(pool), did, body).await;
        assert!(result.is_ok());
        
        let blob_ref = result.unwrap().0;
        assert!(!blob_ref.cid.is_empty());
        assert_eq!(blob_ref.size, data.len() as i64);
        assert!(blob_ref.cid.starts_with("sha256-"));
    }

    #[tokio::test]
    async fn test_upload_blob_empty() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let did = AuthUser { did: "did:plc:uploader".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:uploader".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let body = Bytes::new();

        let result = upload_blob(State(pool), did, body).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_upload_blob_too_large() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let did = AuthUser { did: "did:plc:uploader".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:uploader".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        
        // Create a blob larger than 10MB
        let data = vec![0u8; 11 * 1024 * 1024];
        let body = Bytes::from(data);

        let result = upload_blob(State(pool), did, body).await;
        assert_eq!(result.unwrap_err(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_upload_blob_duplicate() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let did = AuthUser { did: "did:plc:uploader".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:uploader".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let data = b"duplicate content";
        
        // Upload first time
        let body1 = Bytes::from(data.to_vec());
        let result1 = upload_blob(State(pool.clone()), did.clone(), body1).await;
        assert!(result1.is_ok());
        let blob_ref1 = result1.unwrap().0;

        // Upload same content again
        let body2 = Bytes::from(data.to_vec());
        let result2 = upload_blob(State(pool.clone()), did, body2).await;
        assert!(result2.is_ok());
        let blob_ref2 = result2.unwrap().0;

        // Should have same CID
        assert_eq!(blob_ref1.cid, blob_ref2.cid);

        // Verify only one blob exists in database
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM blobs WHERE cid = $1"
        )
        .bind(&blob_ref1.cid)
        .fetch_one(&pool)
        .await
        .unwrap();
        
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_upload_blob_different_content() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let did = AuthUser { did: "did:plc:uploader".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:uploader".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        
        let data1 = b"content one";
        let data2 = b"content two";
        
        let body1 = Bytes::from(data1.to_vec());
        let result1 = upload_blob(State(pool.clone()), did.clone(), body1).await;
        assert!(result1.is_ok());
        let blob_ref1 = result1.unwrap().0;

        let body2 = Bytes::from(data2.to_vec());
        let result2 = upload_blob(State(pool), did, body2).await;
        assert!(result2.is_ok());
        let blob_ref2 = result2.unwrap().0;

        // Should have different CIDs
        assert_ne!(blob_ref1.cid, blob_ref2.cid);
    }
}
