use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use crate::{
    actors::{ActorRegistry, ConvoMessage},
    auth::AuthUser,
    db,
    generated::blue_catbird::mls::get_messages::{GapInfo as GeneratedGapInfo, GetMessagesOutput},
    generated::blue_catbird::mls::MessageView as GeneratedMessageView,
    sqlx_jacquard::chrono_to_datetime,
    storage::{is_member, DbPool},
};

#[derive(Debug, Deserialize)]
pub struct GetMessagesParams {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    #[serde(rename = "sinceSeq")]
    pub since_seq: Option<i64>,
    pub limit: Option<i32>,
}

/// Get messages from a conversation
/// GET /xrpc/chat.bsky.convo.getMessages
#[tracing::instrument(skip(pool, actor_registry))]
pub async fn get_messages(
    State(pool): State<DbPool>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    auth_user: AuthUser,
    Query(params): Query<GetMessagesParams>,
) -> Result<Json<GetMessagesOutput<'static>>, StatusCode> {
    // Auth already enforced by AuthUser extractor (lxm/jti checked against URI path).
    // Skipping v1 NSID check here to allow v2 (mlsChat) delegation.
    let did = &auth_user.did;
    // Validate input
    if params.convo_id.is_empty() {
        warn!("Empty convo_id provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    let limit = params.limit.unwrap_or(50).min(100).max(1);

    // Check if user is a member
    if !is_member(&pool, did, &params.convo_id).await.map_err(|e| {
        error!("Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })? {
        warn!("User is not a member of conversation");
        return Err(StatusCode::FORBIDDEN);
    }

    // Note: Reduced logging per security hardening - no convo IDs at info level
    tracing::debug!(
        "Fetching messages from convo {}",
        crate::crypto::redact_for_log(&params.convo_id)
    );

    // Fetch messages using seq-based pagination if sinceSeq is provided
    let messages = if let Some(since_seq) = params.since_seq {
        // Get messages after a specific sequence number
        db::list_messages_since_seq(&pool, &params.convo_id, since_seq, limit as i64)
            .await
            .map_err(|e| {
                error!("Failed to fetch messages since seq {}: {}", since_seq, e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
    } else {
        // Get latest messages (ordered by epoch, seq)
        db::list_messages(&pool, &params.convo_id, None, limit as i64)
            .await
            .map_err(|e| {
                error!("Failed to list messages: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
    };

    // Detect gaps in message sequence
    let gap_info = db::detect_message_gaps(&pool, &params.convo_id)
        .await
        .map_err(|e| {
            error!("Failed to detect message gaps: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Convert to generated MessageView types
    // Note: sender field removed per security hardening - clients derive sender from decrypted MLS content
    // message_type is included so clients can distinguish 'app' messages from 'commit' messages
    let message_views: Vec<GeneratedMessageView<'static>> = messages
        .into_iter()
        .map(|m| GeneratedMessageView {
            id: m.id.into(),
            convo_id: m.convo_id.into(),
            ciphertext: bytes::Bytes::from(m.ciphertext),
            epoch: m.epoch,
            seq: m.seq,
            created_at: chrono_to_datetime(m.created_at),
            message_type: Some(m.message_type.into()),
            extra_data: Default::default(),
        })
        .collect();

    // Reset unread count for this user
    let use_actors = std::env::var("ENABLE_ACTOR_SYSTEM")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if use_actors {
        tracing::debug!("Using actor system for reset unread count");

        let actor_ref = actor_registry
            .get_or_spawn(&params.convo_id)
            .await
            .map_err(|e| {
                error!("Failed to get conversation actor: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let (tx, rx) = oneshot::channel();
        actor_ref
            .send_message(ConvoMessage::ResetUnread {
                member_did: did.clone(),
                reply: tx,
            })
            .map_err(|_| {
                error!("Failed to send message to actor");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        rx.await
            .map_err(|_| {
                error!("Actor channel closed unexpectedly");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .map_err(|e| {
                error!("Actor failed to reset unread count: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    } else {
        tracing::debug!("Using legacy database approach for reset unread count");

        sqlx::query(
            "UPDATE members SET unread_count = 0 WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL"
        )
        .bind(&params.convo_id)
        .bind(did)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to reset unread count: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    info!("Fetched {} messages", message_views.len());

    // Calculate lastSeq from the last message in the result
    let last_seq = message_views.last().map(|m| m.seq);

    // Build gapInfo if there are gaps
    let gap_info_output = if gap_info.has_gaps {
        Some(GeneratedGapInfo {
            has_gaps: gap_info.has_gaps,
            missing_seqs: gap_info.missing_seqs,
            total_messages: gap_info.total_messages,
            extra_data: Default::default(),
        })
    } else {
        None
    };

    let output = GetMessagesOutput {
        messages: message_views,
        last_seq,
        gap_info: gap_info_output,
        extra_data: Default::default(),
    };

    Ok(Json(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realtime::SseState;
    use crate::storage::init_db;

    async fn setup_test_convo_with_messages(pool: &DbPool, creator: &str, convo_id: &str) {
        let now = chrono::Utc::now();
        sqlx::query("INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at) VALUES ($1, $2, 0, $3, $3)")
            .bind(convo_id)
            .bind(creator)
            .bind(&now)
            .execute(pool)
            .await
            .expect("test setup");

        sqlx::query("INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)")
            .bind(convo_id)
            .bind(creator)
            .bind(&now)
            .execute(pool)
            .await
            .expect("test setup");

        // Add some messages
        for i in 0..3 {
            let msg_id = format!("msg-{}", i);
            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, ciphertext, created_at) VALUES ($1, $2, $3, 'app', 0, $4, $5)"
            )
            .bind(&msg_id)
            .bind(convo_id)
            .bind(creator)
            .bind(format!("ciphertext-{}", i).as_bytes())
            .bind(&now)
            .execute(pool)
            .await
            .expect("test setup");
        }
    }

    #[tokio::test]
    async fn test_get_messages_success() {
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
        let actor_registry = Arc::new(crate::actors::ActorRegistry::new(
            pool.clone(),
            Arc::new(SseState::new(1000)),
            None,
        ));
        let convo_id = "test-convo-1";
        let user = "did:plc:user";

        setup_test_convo_with_messages(&pool, user, convo_id).await;

        let did = AuthUser {
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
        let params = GetMessagesParams {
            convo_id: convo_id.to_string(),
            since_seq: None,
            limit: None,
        };

        let result = get_messages(State(pool), State(actor_registry), did, Query(params)).await;
        assert!(result.is_ok());

        let output = result.expect("handler should return Ok").0;
        let json = serde_json::to_value(&output).unwrap();
        let messages = json
            .get("messages")
            .expect("response should have 'messages' field")
            .as_array()
            .expect("should be array");
        assert_eq!(messages.len(), 3);
    }

    #[tokio::test]
    async fn test_get_messages_not_member() {
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
        let actor_registry = Arc::new(crate::actors::ActorRegistry::new(
            pool.clone(),
            Arc::new(SseState::new(1000)),
            None,
        ));
        let convo_id = "test-convo-2";
        let creator = "did:plc:creator";

        setup_test_convo_with_messages(&pool, creator, convo_id).await;

        let did = AuthUser {
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
        let params = GetMessagesParams {
            convo_id: convo_id.to_string(),
            since_seq: None,
            limit: None,
        };

        let result = get_messages(State(pool), State(actor_registry), did, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_messages_with_limit() {
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
        let actor_registry = Arc::new(crate::actors::ActorRegistry::new(
            pool.clone(),
            Arc::new(SseState::new(1000)),
            None,
        ));
        let convo_id = "test-convo-3";
        let user = "did:plc:user";

        setup_test_convo_with_messages(&pool, user, convo_id).await;

        let did = AuthUser {
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
        let params = GetMessagesParams {
            convo_id: convo_id.to_string(),
            since_seq: None,
            limit: Some(2),
        };

        let result = get_messages(State(pool), State(actor_registry), did, Query(params)).await;
        assert!(result.is_ok());

        let output = result.expect("handler should return Ok").0;
        let json = serde_json::to_value(&output).unwrap();
        let messages = json
            .get("messages")
            .expect("response should have 'messages' field")
            .as_array()
            .expect("should be array");
        assert_eq!(messages.len(), 2);
    }
}
