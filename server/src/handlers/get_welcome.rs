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

    // Fetch unconsumed Welcome message for this user
    info!("Querying welcome message: convo_id={}, recipient_did={}", params.convo_id, did);
    
    let result: Option<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, welcome_data FROM welcome_messages
         WHERE convo_id = $1 AND recipient_did = $2 AND consumed = false
         ORDER BY created_at ASC
         LIMIT 1"
    )
    .bind(&params.convo_id)
    .bind(did)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch welcome message: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (welcome_id, welcome_data) = match result {
        Some(data) => data,
        None => {
            warn!("No Welcome message found for user {} in conversation {}", did, params.convo_id);
            return Err(StatusCode::NOT_FOUND);
        }
    };

    // Mark as consumed
    let now = chrono::Utc::now();
    sqlx::query(
        "UPDATE welcome_messages SET consumed = true, consumed_at = $1 WHERE id = $2"
    )
    .bind(&now)
    .bind(&welcome_id)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to mark welcome message as consumed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Encode welcome data as base64url
    let welcome_base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&welcome_data);

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
