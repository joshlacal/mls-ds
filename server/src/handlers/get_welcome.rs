use axum::{extract::{Query, State}, http::StatusCode, Json};
use base64::Engine;
use serde::Deserialize;
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    models::GetWelcomeOutput,
    storage::{is_member, DbPool},
};

#[derive(Debug, Deserialize)]
pub struct GetWelcomeParams {
    #[serde(rename = "convoId")]
    pub convo_id: String,
}

/// Get Welcome message for joining a conversation
/// GET /xrpc/blue.catbird.mls.getWelcome
#[tracing::instrument(skip(pool), fields(did = %auth_user.did, convo_id = %params.convo_id))]
pub async fn get_welcome(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<GetWelcomeParams>,
) -> Result<Json<GetWelcomeOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.getWelcome") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = &auth_user.did;

    // Validate input
    if params.convo_id.is_empty() {
        warn!("Empty convo_id provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if user is a member
    if !is_member(&pool, did, &params.convo_id)
        .await
        .map_err(|e| {
            error!("Failed to check membership: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    {
        warn!("User {} is not a member of conversation {}", did, params.convo_id);
        return Err(StatusCode::FORBIDDEN);
    }

    // Fetch and consume Welcome message for this user (atomic operation)
    info!("Querying welcome message: convo_id={}, recipient_did={}", params.convo_id, did);
    
    // Use a transaction to atomically fetch and mark as consumed
    let mut tx = pool.begin().await.map_err(|e| {
        error!("Failed to begin transaction: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    // First, try to find a Welcome that matches one of the user's available key packages
    // This prevents the NoMatchingKeyPackage error when users publish new key packages
    let result: Option<(String, Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT wm.id, wm.welcome_data, wm.key_package_hash 
         FROM welcome_messages wm
         WHERE wm.convo_id = $1 AND wm.recipient_did = $2 AND wm.consumed = false
         AND (
           wm.key_package_hash IS NULL
           OR EXISTS (
             SELECT 1 FROM key_packages kp
             WHERE kp.did = $2
             AND kp.key_package_hash = encode(wm.key_package_hash, 'hex')
             AND kp.consumed = false
             AND kp.expires_at > NOW()
           )
         )
         ORDER BY wm.created_at ASC
         LIMIT 1
         FOR UPDATE"  // Lock row for update
    )
    .bind(&params.convo_id)
    .bind(did)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!("Failed to fetch welcome message: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (welcome_id, welcome_data, key_package_hash_opt) = match result {
        Some(data) => data,
        None => {
            // Check if already consumed (return 410 Gone) vs never existed (return 404)
            let consumed_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM welcome_messages 
                 WHERE convo_id = $1 AND recipient_did = $2 AND consumed = true"
            )
            .bind(&params.convo_id)
            .bind(did)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);
            
            if consumed_count > 0 {
                warn!("Welcome already consumed for user {} in conversation {}", did, params.convo_id);
                return Err(StatusCode::GONE);  // 410 Gone - already fetched
            }
            
            // Debug: Query all welcome messages for this conversation
            let all_messages: Vec<(String, bool)> = sqlx::query_as(
                "SELECT recipient_did, consumed FROM welcome_messages WHERE convo_id = $1"
            )
            .bind(&params.convo_id)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default();
            
            warn!(
                "No Welcome message found for user {} in conversation {}. All welcome messages in this convo: {:?}",
                did, params.convo_id, all_messages
            );
            return Err(StatusCode::NOT_FOUND);
        }
    };

    // Mark as consumed atomically
    let now = chrono::Utc::now();
    let rows_updated = sqlx::query(
        "UPDATE welcome_messages 
         SET consumed = true, consumed_at = $1 
         WHERE id = $2 AND consumed = false
         RETURNING 1"
    )
    .bind(&now)
    .bind(&welcome_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("Failed to mark welcome message as consumed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();
    
    if rows_updated == 0 {
        // Race condition: someone else consumed it between SELECT and UPDATE
        warn!("Welcome message {} was consumed by another request", welcome_id);
        return Err(StatusCode::GONE);
    }
    
    // Mark the corresponding key package as consumed (if hash is present)
    if let Some(ref hash_bytes) = key_package_hash_opt {
        let hash_hex = hex::encode(hash_bytes);
        info!("Marking key package as consumed: hash={}", hash_hex);
        
        let kp_rows = sqlx::query(
            "UPDATE key_packages
             SET consumed = true, consumed_at = $1
             WHERE did = $2 AND key_package_hash = $3 AND consumed = false"
        )
        .bind(&now)
        .bind(did)
        .bind(&hash_hex)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("Failed to mark key package as consumed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .rows_affected();
        
        if kp_rows > 0 {
            info!("Marked {} key package(s) as consumed", kp_rows);
        } else {
            warn!("Key package with hash {} not found or already consumed", hash_hex);
        }
    }
    
    // Commit transaction
    tx.commit().await.map_err(|e| {
        error!("Failed to commit transaction: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Encode welcome data as standard base64 (for Swift compatibility)
    let welcome_base64 = base64::engine::general_purpose::STANDARD.encode(&welcome_data);

    info!("Successfully fetched and consumed welcome message for {} in conversation {}", did, params.convo_id);

    Ok(Json(GetWelcomeOutput {
        convo_id: params.convo_id,
        welcome: welcome_base64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_convo_with_welcome(
        pool: &DbPool,
        creator: &str,
        member: &str,
        convo_id: &str,
    ) {
        let now = chrono::Utc::now();

        // Create conversation
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at)
             VALUES ($1, $2, 0, $3, $3)"
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();

        // Add members
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)"
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)"
        )
        .bind(convo_id)
        .bind(member)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();

        // Add welcome message
        let welcome_data = vec![1, 2, 3, 4, 5]; // Mock welcome data
        sqlx::query(
            "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, created_at)
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(convo_id)
        .bind(member)
        .bind(&welcome_data)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_get_welcome_success() {
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

        let convo_id = "test-welcome-convo-1";
        let creator = "did:plc:creator";
        let member = "did:plc:member";

        setup_test_convo_with_welcome(&pool, creator, member, convo_id).await;

        let auth_user = AuthUser {
            did: member.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: member.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let params = GetWelcomeParams {
            convo_id: convo_id.to_string(),
        };

        let result = get_welcome(State(pool.clone()), auth_user, Query(params)).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;
        assert_eq!(response.convo_id, convo_id);
        assert!(!response.welcome.is_empty());

        // Verify welcome was marked as consumed
        let consumed: bool = sqlx::query_scalar(
            "SELECT consumed FROM welcome_messages WHERE convo_id = $1 AND recipient_did = $2"
        )
        .bind(convo_id)
        .bind(member)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert!(consumed);
    }

    #[tokio::test]
    async fn test_get_welcome_not_member() {
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

        let convo_id = "test-welcome-convo-2";
        let creator = "did:plc:creator";
        let member = "did:plc:member";

        setup_test_convo_with_welcome(&pool, creator, member, convo_id).await;

        let auth_user = AuthUser {
            did: "did:plc:outsider".to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: "did:plc:outsider".to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let params = GetWelcomeParams {
            convo_id: convo_id.to_string(),
        };

        let result = get_welcome(State(pool), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_welcome_not_found() {
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

        let convo_id = "test-welcome-convo-3";
        let creator = "did:plc:creator";
        let member = "did:plc:member";

        // Setup convo but without welcome message
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at)
             VALUES ($1, $2, 0, $3, $3)"
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)"
        )
        .bind(convo_id)
        .bind(member)
        .bind(&now)
        .execute(&pool)
        .await
        .unwrap();

        let auth_user = AuthUser {
            did: member.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: member.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let params = GetWelcomeParams {
            convo_id: convo_id.to_string(),
        };

        let result = get_welcome(State(pool), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::NOT_FOUND);
    }
}
