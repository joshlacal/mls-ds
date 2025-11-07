use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use crate::{
    actors::{ActorRegistry, ConvoMessage},
    auth::AuthUser,
    models::{SendMessageInput, SendMessageOutput},
    realtime::{SseState, StreamEvent},
    db,
    storage::{is_member, DbPool},
    util::json_extractor::LoggedJson,
};

/// Send a message to a conversation
/// POST /xrpc/chat.bsky.convo.sendMessage
#[tracing::instrument(skip(pool, sse_state, actor_registry, input), fields(did = %auth_user.did, convo_id = %input.convo_id))]
pub async fn send_message(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    auth_user: AuthUser,
    LoggedJson(input): LoggedJson<SendMessageInput>,
) -> Result<Json<SendMessageOutput>, StatusCode> {
    info!("🔷 [send_message] START - did: {}, convo: {}, epoch: {}, ciphertext: {} bytes", 
          auth_user.did, input.convo_id, input.epoch, input.ciphertext.len());
    
    if let Err(_e) =
        crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.sendMessage")
    {
        error!("❌ [send_message] Unauthorized - failed auth check");
        return Err(StatusCode::UNAUTHORIZED);
    }
    let did = &auth_user.did;

    // Validate msg_id format (ULID is 26 characters)
    if input.msg_id.len() != 26 || !input.msg_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        warn!("❌ [send_message] Invalid msg_id format: {}", input.msg_id);
        return Err(StatusCode::BAD_REQUEST);
    }

    if input.epoch < 0 {
        warn!("❌ [send_message] Invalid epoch: {}", input.epoch);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate ciphertext is present and not too large (10MB limit)
    if input.ciphertext.is_empty() {
        warn!("❌ [send_message] Empty ciphertext provided");
        return Err(StatusCode::BAD_REQUEST);
    }
    if input.ciphertext.len() > 10 * 1024 * 1024 {
        warn!("❌ [send_message] Ciphertext too large: {} bytes", input.ciphertext.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate padding: ciphertext length must match padded_size
    if input.ciphertext.len() as i64 != input.padded_size {
        warn!(
            "❌ [send_message] Ciphertext length ({}) does not match paddedSize ({})",
            input.ciphertext.len(),
            input.padded_size
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate declared_size is not larger than padded_size
    if input.declared_size > input.padded_size {
        warn!(
            "❌ [send_message] declaredSize ({}) > paddedSize ({})",
            input.declared_size, input.padded_size
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate padded_size is a valid bucket size
    let valid_buckets = [512, 1024, 2048, 4096, 8192];
    let is_valid_bucket = valid_buckets.contains(&input.padded_size)
        || (input.padded_size > 8192
            && input.padded_size <= 10 * 1024 * 1024
            && input.padded_size % 8192 == 0);

    if !is_valid_bucket {
        warn!(
            "❌ [send_message] Invalid paddedSize: {} (must be 512, 1024, 2048, 4096, 8192, or multiples of 8192 up to 10MB)",
            input.padded_size
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    info!("📍 [send_message] Checking membership...");
    // Check if sender is a member
    if !is_member(&pool, did, &input.convo_id).await.map_err(|e| {
        error!("❌ [send_message] Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })? {
        warn!(
            "❌ [send_message] User {} is not a member of conversation {}",
            did, input.convo_id
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Check if actor system is enabled
    let use_actors = std::env::var("ENABLE_ACTOR_SYSTEM")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let (msg_id, now) = if use_actors {
        info!("Using actor system for send_message");

        // Get or spawn conversation actor
        let actor_ref = actor_registry.get_or_spawn(&input.convo_id).await
            .map_err(|e| {
                error!("Failed to get conversation actor: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Send message via actor
        let (tx, rx) = oneshot::channel();
        actor_ref.send_message(ConvoMessage::SendMessage {
            sender_did: did.clone(),
            ciphertext: input.ciphertext.clone(),
            reply: tx,
        }).map_err(|_| {
            error!("Failed to send message to actor");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        // Await response
        rx.await
            .map_err(|_| {
                error!("Actor channel closed unexpectedly");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .map_err(|e| {
                error!("Actor failed to send message: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Increment unread counts via actor (fire-and-forget)
        let _ = actor_ref.cast(ConvoMessage::IncrementUnread {
            sender_did: did.clone(),
        });

        // For now, still create the message in DB directly for compatibility
        // TODO: Move this into the actor's SendMessage handler
        info!("📍 [send_message] Creating message in database...");
        let message = db::create_message_v2(
            &pool,
            &input.convo_id,
            &input.msg_id,
            input.ciphertext.clone(),
            input.epoch,
            input.declared_size,
            input.padded_size,
            input.idempotency_key.clone(),
        )
        .await
        .map_err(|e| {
            error!("❌ [send_message] Failed to create message: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        (message.id.clone(), message.created_at)
    } else {
        info!("Using legacy database approach for send_message");

        info!("📍 [send_message] Creating message in database...");

        // Create message with privacy-enhancing fields
        let message = db::create_message_v2(
            &pool,
            &input.convo_id,
            &input.msg_id,
            input.ciphertext,
            input.epoch,
            input.declared_size,
            input.padded_size,
            input.idempotency_key.clone(),
        )
        .await
        .map_err(|e| {
            error!("❌ [send_message] Failed to create message: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let msg_id = message.id.clone();
        let now = message.created_at;

        info!("✅ [send_message] Message created - id: {}", msg_id);

        info!("📍 [send_message] Updating unread counts...");
        // Update unread counts for other members
        sqlx::query(
            "UPDATE members SET unread_count = unread_count + 1 WHERE convo_id = $1 AND member_did != $2 AND left_at IS NULL"
        )
        .bind(&input.convo_id)
        .bind(did)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("❌ [send_message] Failed to update unread counts: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        (msg_id, now)
    };

    info!("✅ [send_message] Message created - id: {}", msg_id);

    info!("📍 [send_message] Spawning fan-out task...");
    // Spawn async task for fan-out and realtime emission
    let pool_clone = pool.clone();
    let convo_id = input.convo_id.clone();
    let msg_id_clone = msg_id.clone();
    let sender_did = did.clone();
    let epoch = input.epoch;
    let sse_state_clone = sse_state.clone();

    tokio::spawn(async move {
        let fanout_start = std::time::Instant::now();
        info!("📍 [send_message:fanout] Starting fan-out for convo: {}", convo_id);

        // Get all active members
        let members_result = sqlx::query!(
            r#"
            SELECT member_did
            FROM members
            WHERE convo_id = $1 AND left_at IS NULL
            "#,
            &convo_id
        )
        .fetch_all(&pool_clone)
        .await;

        match members_result {
            Ok(members) => {
                info!("📍 [send_message:fanout] Fan-out to {} members", members.len());

                // Write envelopes for message tracking
                for member in &members {
                    let envelope_id = uuid::Uuid::new_v4().to_string();

                    // Insert envelope
                    let envelope_result = sqlx::query!(
                        r#"
                        INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at)
                        VALUES ($1, $2, $3, $4, NOW())
                        ON CONFLICT (recipient_did, message_id) DO NOTHING
                        "#,
                        &envelope_id,
                        &convo_id,
                        &member.member_did,
                        &msg_id_clone,
                    )
                    .execute(&pool_clone)
                    .await;

                    if let Err(e) = envelope_result {
                        error!(
                            "❌ [send_message:fanout] Failed to insert envelope for {}: {:?}",
                            member.member_did, e
                        );
                    }
                }

                let fanout_duration = fanout_start.elapsed();
                crate::metrics::record_envelope_write_duration(&convo_id, fanout_duration);

                info!(
                    "✅ [send_message:fanout] Completed in {}ms",
                    fanout_duration.as_millis()
                );
            }
            Err(e) => {
                error!(
                    "❌ [send_message:fanout] Failed to get members: {:?}",
                    e
                );
            }
        }

        info!("📍 [send_message:fanout] Emitting SSE event...");
        // Emit realtime event with full message view including ciphertext
        let cursor = sse_state_clone
            .cursor_gen
            .next(&convo_id, "messageEvent")
            .await;

        // Fetch the full message from database to get seq and created_at
        let message_result = sqlx::query!(
            r#"
            SELECT id, sender_did, ciphertext, epoch, seq, created_at
            FROM messages
            WHERE id = $1
            "#,
            &msg_id_clone
        )
        .fetch_one(&pool_clone)
        .await;

        match message_result {
            Ok(msg) => {
                let message_view = crate::models::MessageView {
                    id: msg.id,
                    convo_id: convo_id.clone(),
                    sender: msg.sender_did,
                    ciphertext: msg.ciphertext.unwrap_or_default(),
                    epoch: msg.epoch,
                    seq: msg.seq,
                    created_at: msg.created_at,
                    embed_type: None,
                    embed_uri: None,
                };

                let event = StreamEvent::MessageEvent {
                    cursor: cursor.clone(),
                    message: message_view.clone(),
                };

                // Store event for backfill with full message data
                let event_payload = serde_json::to_value(&message_view)
                    .unwrap_or_else(|_| serde_json::json!({}));

                if let Err(e) = crate::db::store_event(
                    &pool_clone,
                    &cursor,
                    &convo_id,
                    "messageEvent",
                    event_payload,
                )
                .await
                {
                    error!("❌ [send_message:fanout] Failed to store event: {:?}", e);
                }

                // Emit to SSE subscribers
                if let Err(e) = sse_state_clone.emit(&convo_id, event).await {
                    error!(
                        "❌ [send_message:fanout] Failed to emit SSE event: {}",
                        e
                    );
                } else {
                    info!("✅ [send_message:fanout] SSE event emitted");
                }
            }
            Err(e) => {
                error!(
                    "❌ [send_message:fanout] Failed to fetch message for SSE event: {:?}",
                    e
                );
            }
        }
    });

    info!("✅ [send_message] COMPLETE - msgId: {} (async fan-out initiated)", msg_id);

    Ok(Json(SendMessageOutput {
        message_id: msg_id,
        received_at: now,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::init_db;

    async fn setup_test_convo(pool: &DbPool, creator: &str, convo_id: &str) {
        let now = chrono::Utc::now();
        sqlx::query("INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at) VALUES ($1, $2, 0, $3, $3)")
            .bind(convo_id)
            .bind(creator)
            .bind(&now)
            .execute(pool)
            .await
            .unwrap();

        sqlx::query("INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)")
            .bind(convo_id)
            .bind(creator)
            .bind(&now)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_send_message_success() {
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
        let sse_state = Arc::new(SseState::new(1000));
        let convo_id = "test-convo-1";
        let sender = "did:plc:sender";

        setup_test_convo(&pool, sender, convo_id).await;

        let auth_user = AuthUser {
            did: sender.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: sender.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None, jti: Some("test-jti".to_string()), lxm: None,
                sub: None,
            },
        };
        
        let input = SendMessageInput {
            convo_id: convo_id.to_string(),
            ciphertext: b"encrypted message data".to_vec(),
            epoch: 0,
            sender_did: sender.to_string(),
            embed_type: None,
            embed_uri: None,
        };

        let result = send_message(
            State(pool), 
            State(sse_state), 
            auth_user, 
            Json(input)
        ).await;
        assert!(result.is_ok());

        let output = result.unwrap().0;
        assert!(!output.message_id.is_empty());
    }

    #[tokio::test]
    async fn test_send_message_not_member() {
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
        let sse_state = Arc::new(SseState::new(1000));
        let convo_id = "test-convo-2";
        let creator = "did:plc:creator";

        setup_test_convo(&pool, creator, convo_id).await;

        let auth_user = AuthUser {
            did: "did:plc:outsider".to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: "did:plc:outsider".to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None, jti: Some("test-jti".to_string()), lxm: None,
                sub: None,
            },
        };
        
        let input = SendMessageInput {
            convo_id: convo_id.to_string(),
            ciphertext: b"encrypted message data".to_vec(),
            epoch: 0,
            sender_did: "did:plc:outsider".to_string(),
            embed_type: None,
            embed_uri: None,
        };

        let result = send_message(
            State(pool), 
            State(sse_state), 
            auth_user, 
            Json(input)
        ).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_send_message_invalid_provider() {
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
        let sse_state = Arc::new(SseState::new(1000));
        let convo_id = "test-convo-3";
        let sender = "did:plc:sender";

        setup_test_convo(&pool, sender, convo_id).await;

        let auth_user = AuthUser {
            did: sender.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: sender.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None, jti: Some("test-jti".to_string()), lxm: None,
                sub: None,
            },
        };
        
        let input = SendMessageInput {
            convo_id: convo_id.to_string(),
            ciphertext: b"".to_vec(), // Empty ciphertext should fail
            epoch: 0,
            sender_did: sender.to_string(),
            embed_type: None,
            embed_uri: None,
        };

        let result = send_message(
            State(pool), 
            State(sse_state), 
            auth_user, 
            Json(input)
        ).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_send_message_sender_mismatch() {
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
        let sse_state = Arc::new(SseState::new(1000));
        let convo_id = "test-convo-4";
        let sender = "did:plc:sender";

        setup_test_convo(&pool, sender, convo_id).await;

        let auth_user = AuthUser {
            did: sender.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: sender.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None, jti: Some("test-jti".to_string()), lxm: None,
                sub: None,
            },
        };
        
        let input = SendMessageInput {
            convo_id: convo_id.to_string(),
            ciphertext: b"encrypted message data".to_vec(),
            epoch: 0,
            sender_did: "did:plc:impostor".to_string(),
            embed_type: None,
            embed_uri: None,
        };

        let result = send_message(
            State(pool), 
            State(sse_state), 
            auth_user, 
            Json(input)
        ).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }
}
