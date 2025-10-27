use axum::{extract::{Query, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    storage::{is_member, DbPool},
};

#[derive(Debug, Deserialize)]
pub struct GetEpochParams {
    #[serde(rename = "convoId")]
    pub convo_id: String,
}

#[derive(Debug, Serialize)]
pub struct EpochResponse {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    #[serde(rename = "currentEpoch")]
    pub current_epoch: i64,
}

/// Get the current epoch for a conversation
/// GET /xrpc/blue.catbird.mls.getEpoch
#[tracing::instrument(skip(pool), fields(did = %auth_user.did, convo_id = %params.convo_id))]
pub async fn get_epoch(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<GetEpochParams>,
) -> Result<Json<EpochResponse>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.getEpoch") {
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
    
    // Get current epoch from conversations table
    let current_epoch: i64 = sqlx::query_scalar(
        "SELECT current_epoch FROM conversations WHERE id = $1"
    )
    .bind(&params.convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch current epoch: {}", e);
        match e {
            sqlx::Error::RowNotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    })?;
    
    info!("Fetched epoch {} for conversation {}", current_epoch, params.convo_id);
    
    Ok(Json(EpochResponse {
        convo_id: params.convo_id,
        current_epoch,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_convo(pool: &DbPool, creator: &str, convo_id: &str, epoch: i64) {
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $4)"
        )
        .bind(convo_id)
        .bind(creator)
        .bind(epoch as i32)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();
        
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, joined_at) 
             VALUES ($1, $2, $3)"
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_get_epoch_success() {
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
        
        let convo_id = "test-epoch-convo-1";
        let user = "did:plc:user";
        
        setup_test_convo(&pool, user, convo_id, 42).await;

        let auth_user = AuthUser {
            did: user.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: user.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };
        
        let params = GetEpochParams {
            convo_id: convo_id.to_string(),
        };

        let result = get_epoch(State(pool), auth_user, Query(params)).await;
        assert!(result.is_ok());
        
        let response = result.unwrap().0;
        assert_eq!(response.current_epoch, 42);
        assert_eq!(response.convo_id, convo_id);
    }

    #[tokio::test]
    async fn test_get_epoch_not_member() {
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
        
        let convo_id = "test-epoch-convo-2";
        let creator = "did:plc:creator";
        
        setup_test_convo(&pool, creator, convo_id, 10).await;

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
        
        let params = GetEpochParams {
            convo_id: convo_id.to_string(),
        };

        let result = get_epoch(State(pool), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_epoch_not_found() {
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
        
        let user = "did:plc:user";
        let auth_user = AuthUser {
            did: user.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: user.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };
        
        let params = GetEpochParams {
            convo_id: "nonexistent-convo".to_string(),
        };

        let result = get_epoch(State(pool), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::NOT_FOUND);
    }
}
