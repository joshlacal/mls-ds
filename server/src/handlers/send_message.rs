use axum::{
    extract::{rejection::JsonRejection, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info};

use crate::{
    actors::{ActorRegistry, ConvoMessage},
    auth::AuthUser,
    db,
    generated::blue::catbird::mls::send_message::{Input, NSID},
    notifications::NotificationService,
    realtime::{SseState, StreamEvent},
    sqlx_atrium::chrono_to_datetime,
    storage::{is_member, DbPool},
};

/// Send a message to a conversation
/// POST /xrpc/blue.catbird.mls.sendMessage
#[tracing::instrument(skip(pool, sse_state, actor_registry, notification_service, auth_user))]
pub async fn send_message(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    State(notification_service): State<Option<Arc<NotificationService>>>,
    auth_user: AuthUser,
    input: Result<Json<Input>, JsonRejection>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let Json(input) = input.map_err(|rejection| {
        error!(
            "❌ [send_message] Failed to deserialize request body: {}",
            rejection
        );
        StatusCode::BAD_REQUEST
    })?;
    let input = input.data; // Unwrap Object<InputData>

    // Extract padded_size from bounded type
    let padded_size: u32 = input.padded_size.into();

    // Note: Reduced logging per security hardening - no identity-bearing fields at info level
    tracing::debug!(
        "send_message start: msgId={}, convoId={}, epoch={}",
        crate::crypto::redact_for_log(&input.msg_id),
        crate::crypto::redact_for_log(&input.convo_id),
        input.epoch
    );

    // Enforce authorization
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [send_message] Unauthorized - failed auth check");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Note: Sender verification from JWT - server no longer exposes sender in responses per security hardening
    // Clients derive sender from decrypted MLS content

    // Validate msgId format (accept ULID 26 chars or UUID 36 chars with hyphens)
    let is_ulid =
        input.msg_id.len() == 26 && input.msg_id.chars().all(|c| c.is_ascii_alphanumeric());
    let is_uuid = input.msg_id.len() == 36
        && input
            .msg_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !is_ulid && !is_uuid {
        error!("❌ [send_message] Invalid msgId format (expected ULID or UUID)");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate ciphertext is present and not too large (10MB limit)
    if input.ciphertext.is_empty() {
        error!("❌ [send_message] Empty ciphertext provided");
        return Err(StatusCode::BAD_REQUEST);
    }
    if input.ciphertext.len() > 10 * 1024 * 1024 {
        error!(
            "❌ [send_message] Ciphertext too large: {} bytes",
            input.ciphertext.len()
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate padding: ciphertext length must match padded_size
    if input.ciphertext.len() as u32 != padded_size {
        error!(
            "❌ [send_message] Ciphertext length ({}) does not match paddedSize ({})",
            input.ciphertext.len(),
            padded_size
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate padded_size is a valid bucket size
    let valid_buckets = [512, 1024, 2048, 4096, 8192];
    let is_valid_bucket = valid_buckets.contains(&padded_size)
        || (padded_size > 8192 && padded_size <= 10 * 1024 * 1024 && padded_size % 8192 == 0);

    if !is_valid_bucket {
        error!(
            "❌ [send_message] Invalid paddedSize: {} (must be 512, 1024, 2048, 4096, 8192, or multiples of 8192 up to 10MB)",
            padded_size
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    tracing::debug!("📍 [send_message] checking membership");
    // Check if sender is a member
    if !is_member(&pool, &auth_user.did, &input.convo_id)
        .await
        .map_err(|e| {
            error!("❌ [send_message] Failed to check membership: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    {
        error!(
            "❌ [send_message] User {} is not a member of conversation {}",
            auth_user.did, input.convo_id
        );
        return Err(StatusCode::FORBIDDEN);
    }

    tracing::debug!("📍 [send_message] checking epoch telemetry");
    // Fetch conversation for epoch telemetry (non-blocking)
    // Note: Server does NOT enforce epoch - clients are authoritative for MLS state
    let convo = sqlx::query_as::<_, crate::models::Conversation>(
        "SELECT id, creator_did, current_epoch, created_at, updated_at, name, cipher_suite FROM conversations WHERE id = $1"
    )
    .bind(&input.convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [send_message] Failed to fetch conversation: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Epoch telemetry (mailbox-only, not authoritative)
    let client_epoch = input.epoch as i64;
    let server_epoch = convo.current_epoch as i64;

    if client_epoch != server_epoch {
        // Log suspicious patterns
        if client_epoch < server_epoch {
            tracing::warn!(
                target: "mls_epoch",
                convo_id = %crate::crypto::redact_for_log(&input.convo_id),
                server_last_seen = server_epoch,
                client_reports = client_epoch,
                "client reported epoch behind last_reported_epoch; device may be out-of-date or restored"
            );
        } else if client_epoch > server_epoch + 50 {
            tracing::warn!(
                target: "mls_epoch",
                convo_id = %crate::crypto::redact_for_log(&input.convo_id),
                server_last_seen = server_epoch,
                client_reports = client_epoch,
                jump = client_epoch - server_epoch,
                "client reported large epoch jump; investigate MLS client state"
            );
        } else {
            // Normal mismatch (client ahead by small amount)
            tracing::info!(
                target: "mls_epoch",
                convo_id = %crate::crypto::redact_for_log(&input.convo_id),
                server_last_seen = server_epoch,
                client_reports = client_epoch,
                "send_message epoch telemetry mismatch (server is mailbox-only, not authoritative)"
            );
        }
    }

    // Update server's last-seen epoch for telemetry (best-effort, non-blocking)
    if client_epoch as i32 > convo.current_epoch {
        let _ = sqlx::query(
            "UPDATE conversations SET current_epoch = GREATEST(current_epoch, $1) WHERE id = $2",
        )
        .bind(client_epoch as i32)
        .bind(&input.convo_id)
        .execute(&pool)
        .await; // Ignore errors - this is telemetry only
    }

    // Check if actor system is enabled
    let use_actors = std::env::var("ENABLE_ACTOR_SYSTEM")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    // Clone ciphertext early for push notifications
    let ciphertext_clone = input.ciphertext.clone();

    let (msg_id, now, seq, epoch) = if use_actors {
        tracing::debug!("Using actor system for send_message");

        // Get or spawn conversation actor
        let actor_ref = actor_registry
            .get_or_spawn(&input.convo_id)
            .await
            .map_err(|e| {
                error!("Failed to get conversation actor: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Send message via actor with all privacy fields
        let (tx, rx) = oneshot::channel();
        actor_ref
            .send_message(ConvoMessage::SendMessage {
                sender_did: auth_user.did.clone(),
                ciphertext: input.ciphertext.clone(),
                msg_id: input.msg_id.clone(),
                epoch: input.epoch as i64,
                padded_size: padded_size as i64,
                idempotency_key: input.idempotency_key.clone(),
                reply: tx,
            })
            .map_err(|_| {
                error!("Failed to send message to actor");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Await response - actor already stored message and returns (msg_id, timestamp)
        let (msg_id, created_at) = rx
            .await
            .map_err(|_| {
                error!("Actor channel closed unexpectedly");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .map_err(|e| {
                error!("Actor failed to send message: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Fetch seq and epoch from the created message
        let message = sqlx::query_as::<_, crate::models::Message>(
            "SELECT id, convo_id, sender_did, message_type, CAST(epoch AS BIGINT), CAST(seq AS BIGINT), ciphertext, created_at, expires_at FROM messages WHERE id = $1"
        )
        .bind(&msg_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch message for seq/epoch: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        // Increment unread counts via actor (fire-and-forget)
        let _ = actor_ref.cast(ConvoMessage::IncrementUnread {
            sender_did: auth_user.did.clone(),
        });

        (msg_id, created_at, message.seq, message.epoch)
    } else {
        tracing::debug!("Using legacy database approach for send_message");

        info!("📍 [send_message] Creating message in database...");

        // Clone ciphertext before moving it
        let ciphertext_for_db = input.ciphertext.clone();

        // Create message with privacy-enhancing fields
        let message = db::create_message(
            &pool,
            &input.convo_id,
            &input.msg_id,
            ciphertext_for_db,
            input.epoch as i64,
            padded_size as i64,
            input.idempotency_key.clone(),
        )
        .await
        .map_err(|e| {
            error!("❌ [send_message] Failed to create message: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let msg_id = message.id.clone();
        let now = message.created_at;
        let seq = message.seq;
        let epoch = message.epoch;

        tracing::debug!(
            "send_message message created: msgId={}, seq={}, epoch={}",
            crate::crypto::redact_for_log(&msg_id),
            seq,
            epoch
        );

        tracing::debug!("📍 [send_message] updating unread counts");
        // Update unread counts for all members except sender's devices
        // In multi-device mode, user_did is the base DID, so this excludes all sender's devices
        sqlx::query(
            "UPDATE members SET unread_count = unread_count + 1 WHERE convo_id = $1 AND user_did != $2 AND left_at IS NULL"
        )
        .bind(&input.convo_id)
        .bind(&auth_user.did)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("❌ [send_message] Failed to update unread counts: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        (msg_id, now, seq, epoch)
    };

    tracing::debug!(
        "send_message message created: msgId={}",
        crate::crypto::redact_for_log(&msg_id)
    );

    tracing::debug!("📍 [send_message] spawning fan-out task");
    // Spawn async task for fan-out, push notifications, and realtime emission
    let pool_clone = pool.clone();
    let convo_id = input.convo_id.clone();
    let msg_id_clone = msg_id.clone();
    let sse_state_clone = sse_state.clone();
    let sender_did_clone = auth_user.did.clone();
    let notification_service_clone = notification_service.clone();

    tokio::spawn(async move {
        let fanout_start = std::time::Instant::now();
        tracing::debug!("📍 [send_message:fanout] starting fan-out");

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
                tracing::debug!("📍 [send_message:fanout] fan-out to members");

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

                tracing::debug!(
                    "send_message:fanout completed in {}ms",
                    fanout_duration.as_millis()
                );
            }
            Err(e) => {
                error!("❌ [send_message:fanout] Failed to get members: {:?}", e);
            }
        }

        tracing::debug!("📍 [send_message:fanout] emitting SSE event");
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
                // Note: sender field removed per security hardening - clients derive sender from decrypted MLS content
                let message_view =
                    crate::models::MessageView::from(crate::models::MessageViewData {
                        id: msg.id,
                        convo_id: convo_id.clone(),
                        ciphertext: msg.ciphertext.unwrap_or_default(),
                        epoch: msg.epoch as usize,
                        seq: msg.seq as usize,
                        created_at: crate::sqlx_atrium::chrono_to_datetime(msg.created_at),
                        message_type: None,
                    });

                let event = StreamEvent::MessageEvent {
                    cursor: cursor.clone(),
                    message: message_view.clone(),
                };

                // Store minimal event envelope (no ciphertext)
                // Clients will fetch full message via getMessages
                if let Err(e) = crate::db::store_event(
                    &pool_clone,
                    &cursor,
                    &convo_id,
                    "messageEvent",
                    Some(&msg_id_clone),
                )
                .await
                {
                    error!("❌ [send_message:fanout] Failed to store event: {:?}", e);
                }

                // Emit to SSE subscribers
                if let Err(e) = sse_state_clone.emit(&convo_id, event).await {
                    error!("❌ [send_message:fanout] Failed to emit SSE event: {}", e);
                } else {
                    tracing::debug!("✅ [send_message:fanout] SSE event emitted");
                }
            }
            Err(e) => {
                error!(
                    "❌ [send_message:fanout] Failed to fetch message for SSE event: {:?}",
                    e
                );
            }
        }

        // Send push notifications with ciphertext
        if let Some(notification_service) = notification_service_clone.as_ref() {
            info!(
                "🔔 [send_message:fanout] Starting push notification delivery for convo={}, message={}, sender={}",
                convo_id, msg_id_clone, sender_did_clone
            );

            let push_start = std::time::Instant::now();

            match notification_service
                .notify_new_message(
                    &pool_clone,
                    &convo_id,
                    &msg_id_clone,
                    &ciphertext_clone,
                    &sender_did_clone,
                )
                .await
            {
                Ok(_) => {
                    let push_duration = push_start.elapsed();
                    info!(
                        "✅ [send_message:fanout] Push notifications completed successfully in {}ms",
                        push_duration.as_millis()
                    );
                }
                Err(e) => {
                    let push_duration = push_start.elapsed();
                    error!(
                        "❌ [send_message:fanout] Failed to send push notifications after {}ms: {}",
                        push_duration.as_millis(),
                        e
                    );
                }
            }
        } else {
            info!("🔔 [send_message:fanout] No notification service available, skipping push notifications");
        }
    });

    info!("✅ [send_message] COMPLETE - async fan-out initiated");

    // Note: sender field removed from output per security hardening - client already knows sender from JWT
    // Manually construct response with new seq and epoch fields (lexicon has been updated)
    Ok(Json(serde_json::json!({
        "messageId": msg_id,
        "receivedAt": chrono_to_datetime(now),
        "seq": seq,
        "epoch": epoch,
    })))
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
                iat: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
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

        let result = send_message(State(pool), State(sse_state), auth_user, Json(input)).await;
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
                iat: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
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

        let result = send_message(State(pool), State(sse_state), auth_user, Json(input)).await;
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
                iat: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
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

        let result = send_message(State(pool), State(sse_state), auth_user, Json(input)).await;
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
                iat: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
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

        let result = send_message(State(pool), State(sse_state), auth_user, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }
}
