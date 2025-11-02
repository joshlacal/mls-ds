use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    models::{SendMessageInput, SendMessageOutput},
    realtime::{SseState, StreamEvent},
    db,
    storage::{is_member, DbPool},
    util::json_extractor::LoggedJson,
};

/// Send a message to a conversation
/// POST /xrpc/chat.bsky.convo.sendMessage
#[tracing::instrument(skip(pool, sse_state, input), fields(did = %auth_user.did, convo_id = %input.convo_id))]
pub async fn send_message(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
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

    if &input.sender_did != did {
        warn!(
            "❌ [send_message] Sender DID mismatch: expected {}, got {}",
            did, input.sender_did
        );
        return Err(StatusCode::FORBIDDEN);
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

    info!("📍 [send_message] Creating message in database...");

    // Create message with direct ciphertext storage
    let message = db::create_message(
        &pool,
        &input.convo_id,
        did,
        input.ciphertext,
        input.epoch,
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
        // Emit realtime event
        let cursor = sse_state_clone
            .cursor_gen
            .next(&convo_id, "messageEvent")
            .await;
        let event = StreamEvent::MessageEvent {
            cursor: cursor.clone(),
            convo_id: convo_id.clone(),
            emitted_at: chrono::Utc::now().to_rfc3339(),
            payload: crate::realtime::sse::MessageEventPayload {
                message_id: msg_id_clone.clone(),
                sender_did: sender_did.clone(),
                epoch: epoch as i32,
            },
        };

        // Store event for backfill
        let event_payload = serde_json::json!({
            "messageId": msg_id_clone,
            "senderDid": sender_did,
            "epoch": epoch as i32,
        });

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
