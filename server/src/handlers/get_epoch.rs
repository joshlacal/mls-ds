use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use crate::{
    actors::{ActorRegistry, ConvoMessage},
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
    pub current_epoch: i32,
}

/// Get the current epoch for a conversation
/// GET /xrpc/blue.catbird.mls.getEpoch
#[tracing::instrument(skip(pool, actor_registry))]
pub async fn get_epoch(
    State(pool): State<DbPool>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    auth_user: AuthUser,
    Query(params): Query<GetEpochParams>,
) -> Result<Json<EpochResponse>, StatusCode> {
    let did = &auth_user.did;

    // Validate input
    if params.convo_id.is_empty() {
        warn!("Empty convo_id provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if user is a member
    if !is_member(&pool, did, &params.convo_id).await.map_err(|e| {
        error!("Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })? {
        warn!("User is not a member of conversation");
        return Err(StatusCode::FORBIDDEN);
    }

    // Check if actor system is enabled
    let use_actors = std::env::var("ENABLE_ACTOR_SYSTEM")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let current_epoch = if use_actors {
        info!("Using actor system for get_epoch");

        // Get or spawn conversation actor
        let actor_ref = actor_registry
            .get_or_spawn(&params.convo_id)
            .await
            .map_err(|e| {
                error!("Failed to get conversation actor: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Get epoch from actor (fast in-memory read)
        let (tx, rx) = oneshot::channel();
        actor_ref
            .send_message(ConvoMessage::GetEpoch { reply: tx })
            .map_err(|_| {
                error!("Failed to send message to actor");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Await response
        let epoch = rx.await.map_err(|_| {
            error!("Actor channel closed unexpectedly");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        epoch as i32
    } else {
        info!("Using legacy database approach for get_epoch");

        // Get current epoch from conversations table
        sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
            .bind(&params.convo_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("Failed to fetch current epoch: {}", e);
                match e {
                    sqlx::Error::RowNotFound => StatusCode::NOT_FOUND,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                }
            })?
    };

    info!("Fetched epoch: {}", current_epoch);

    Ok(Json(EpochResponse {
        convo_id: params.convo_id,
        current_epoch,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realtime::SseState;

    async fn setup_test_convo(pool: &DbPool, creator: &str, convo_id: &str, epoch: i64) {
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $4)",
        )
        .bind(convo_id)
        .bind(creator)
        .bind(epoch as i32)
        .bind(&now)
        .execute(pool)
        .await
        .expect("test setup");

        sqlx::query(
            "INSERT INTO members (convo_id, member_did, joined_at) 
             VALUES ($1, $2, $3)",
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(pool)
        .await
        .expect("test setup");
    }

    #[tokio::test]
    async fn test_get_epoch_success() {
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
        .expect("test setup");

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

        let actor_registry = Arc::new(crate::actors::ActorRegistry::new(
            pool.clone(),
            Arc::new(SseState::new(1000)),
            None,
        ));
        let result = get_epoch(State(pool), State(actor_registry), auth_user, Query(params)).await;
        assert!(result.is_ok());

        let response = result.expect("handler should return Ok").0;
        assert_eq!(response.current_epoch, 42);
        assert_eq!(response.convo_id, convo_id);
    }

    #[tokio::test]
    async fn test_get_epoch_not_member() {
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
        .expect("test setup");

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

        let actor_registry = Arc::new(crate::actors::ActorRegistry::new(
            pool.clone(),
            Arc::new(SseState::new(1000)),
            None,
        ));
        let result = get_epoch(State(pool), State(actor_registry), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_epoch_not_found() {
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
        .expect("test setup");

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

        let actor_registry = Arc::new(crate::actors::ActorRegistry::new(
            pool.clone(),
            Arc::new(SseState::new(1000)),
            None,
        ));
        let result = get_epoch(State(pool), State(actor_registry), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::NOT_FOUND);
    }
}
