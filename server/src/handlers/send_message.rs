use base64::Engine;

use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    fanout::{Envelope, MailboxConfig, MailboxFactory},
    models::{SendMessageInput, SendMessageOutput},
    realtime::{SseState, StreamEvent},
    storage::{is_member, DbPool},
};

/// Send a message to a conversation
/// POST /xrpc/chat.bsky.convo.sendMessage
#[tracing::instrument(skip(pool, sse_state, input), fields(did = %auth_user.did, convo_id = %input.convo_id))]
pub async fn send_message(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    Json(input): Json<SendMessageInput>,
) -> Result<Json<SendMessageOutput>, StatusCode> {
    if let Err(_e) =
        crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.sendMessage")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let did = &auth_user.did;

    // Validate ExternalAsset payload
    let config = crate::util::asset_validate::AssetValidationConfig::default();
    if let Err(e) = crate::util::asset_validate::validate_asset(&input.payload, &config) {
        warn!("Invalid ExternalAsset: {}", e);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate attachments if present
    if let Some(ref attachments) = input.attachments {
        if let Err(e) = crate::util::asset_validate::validate_assets(attachments, &config, 10) {
            warn!("Invalid attachments: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    if &input.sender_did != did {
        warn!(
            "Sender DID mismatch: expected {}, got {}",
            did, input.sender_did
        );
        return Err(StatusCode::FORBIDDEN);
    }

    if input.epoch < 0 {
        warn!("Invalid epoch: {}", input.epoch);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if sender is a member
    if !is_member(&pool, did, &input.convo_id).await.map_err(|e| {
        error!("Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })? {
        warn!(
            "User {} is not a member of conversation {}",
            did, input.convo_id
        );
        return Err(StatusCode::FORBIDDEN);
    }

    let msg_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    info!(
        "Sending message {} to conversation {} (payload provider: {})",
        msg_id, input.convo_id, input.payload.provider
    );

    // Insert message with ExternalAsset payload
    sqlx::query(
        r#"
        INSERT INTO messages (
            id, convo_id, sender_did, message_type, epoch,
            payload_provider, payload_uri, payload_mime_type, payload_size, payload_sha256,
            content_type, reply_to, sent_at
        ) VALUES ($1, $2, $3, 'app', $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#
    )
    .bind(&msg_id)
    .bind(&input.convo_id)
    .bind(did)
    .bind(input.epoch)
    .bind(&input.payload.provider)
    .bind(&input.payload.uri)
    .bind(&input.payload.mime_type)
    .bind(input.payload.size)
    .bind(&input.payload.sha256)
    .bind(&input.content_type)
    .bind(&input.reply_to)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to insert message: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Insert attachments if present
    if let Some(attachments) = &input.attachments {
        for (idx, attachment) in attachments.iter().enumerate() {
            let attachment_id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO message_attachments (
                    id, message_id, attachment_index,
                    provider, uri, mime_type, size, sha256
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                "#
            )
            .bind(&attachment_id)
            .bind(&msg_id)
            .bind(idx as i32)
            .bind(&attachment.provider)
            .bind(&attachment.uri)
            .bind(&attachment.mime_type)
            .bind(attachment.size)
            .bind(&attachment.sha256)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to insert attachment {}: {}", idx, e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        }
    }

    // Update unread counts for other members
    sqlx::query(
        "UPDATE members SET unread_count = unread_count + 1 WHERE convo_id = $1 AND member_did != $2 AND left_at IS NULL"
    )
    .bind(&input.convo_id)
    .bind(did)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to update unread counts: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Spawn async task for fan-out and realtime emission
    // Clone variables needed for async task
    let pool_clone = pool.clone();
    let convo_id = input.convo_id.clone();
    let msg_id_clone = msg_id.clone();
    let sender_did = did.clone();
    let epoch = input.epoch;
    let sse_state_clone = sse_state.clone();

    tokio::spawn(async move {
        let fanout_start = std::time::Instant::now();

        // Get all active members
        let members_result = sqlx::query!(
            r#"
            SELECT member_did, mailbox_provider, mailbox_zone
            FROM members
            WHERE convo_id = $1 AND left_at IS NULL
            "#,
            &convo_id
        )
        .fetch_all(&pool_clone)
        .await;

        match members_result {
            Ok(members) => {
                info!(convo_id = %convo_id, member_count = members.len(), "Fan-out to members");

                let mailbox_config = MailboxConfig::default();

                // Write envelopes and notify mailboxes
                for member in &members {
                    let envelope_id = uuid::Uuid::new_v4().to_string();
                    let provider = &member.mailbox_provider;
                    let zone = member.mailbox_zone.as_deref();

                    // Insert envelope
                    let envelope_result = sqlx::query!(
                        r#"
                        INSERT INTO envelopes (id, convo_id, recipient_did, message_id, mailbox_provider, cloudkit_zone, created_at)
                        VALUES ($1, $2, $3, $4, $5, $6, NOW())
                        ON CONFLICT (recipient_did, message_id) DO NOTHING
                        "#,
                        &envelope_id,
                        &convo_id,
                        &member.member_did,
                        &msg_id_clone,
                        provider,
                        zone,
                    )
                    .execute(&pool_clone)
                    .await;

                    if let Err(e) = envelope_result {
                        error!(
                            convo_id = %convo_id,
                            recipient = %member.member_did,
                            error = ?e,
                            "Failed to insert envelope"
                        );
                        continue;
                    }

                    // Notify mailbox backend
                    let backend = MailboxFactory::create(provider, &mailbox_config);
                    let envelope = Envelope {
                        id: envelope_id,
                        convo_id: convo_id.clone(),
                        recipient_did: member.member_did.clone(),
                        message_id: msg_id_clone.clone(),
                        mailbox_provider: provider.clone(),
                        cloudkit_zone: zone.map(String::from),
                    };

                    if let Err(e) = backend.notify(&envelope).await {
                        error!(
                            recipient = %member.member_did,
                            provider = provider,
                            error = ?e,
                            "Mailbox notification failed"
                        );
                        crate::metrics::record_fanout_operation(provider, false);
                    } else {
                        crate::metrics::record_fanout_operation(provider, true);
                    }
                }

                let fanout_duration = fanout_start.elapsed();
                crate::metrics::record_envelope_write_duration(&convo_id, fanout_duration);

                info!(
                    convo_id = %convo_id,
                    duration_ms = fanout_duration.as_millis(),
                    "Fan-out completed"
                );
            }
            Err(e) => {
                error!(
                    convo_id = %convo_id,
                    error = ?e,
                    "Failed to get members for fan-out"
                );
            }
        }

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
                epoch,
            },
        };

        // Store event for backfill
        let event_payload = serde_json::json!({
            "messageId": msg_id_clone,
            "senderDid": sender_did,
            "epoch": epoch,
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
            error!(error = ?e, "Failed to store event for backfill");
        }

        // Emit to SSE subscribers
        if let Err(e) = sse_state_clone.emit(&convo_id, event).await {
            error!(
                convo_id = %convo_id,
                error = %e,
                "Failed to emit realtime event"
            );
        }
    });

    info!(
        "Message {} sent successfully (async fan-out initiated)",
        msg_id
    );

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
        let sse_state = Arc::new(SseState::new());
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
                sub: None,
            },
        };
        
        let input = SendMessageInput {
            convo_id: convo_id.to_string(),
            payload: ExternalAsset {
                provider: "cloudkit".to_string(),
                uri: "cloudkit://iCloud.com.example.app/Messages/msg-123".to_string(),
                mime_type: "application/octet-stream".to_string(),
                size: 1024,
                sha256: vec![0u8; 32],
            },
            epoch: 0,
            sender_did: sender.to_string(),
            content_type: Some("text/plain".to_string()),
            attachments: None,
            reply_to: None,
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
        let sse_state = Arc::new(SseState::new());
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
                sub: None,
            },
        };
        
        let input = SendMessageInput {
            convo_id: convo_id.to_string(),
            payload: ExternalAsset {
                provider: "cloudkit".to_string(),
                uri: "cloudkit://iCloud.com.example.app/Messages/msg-123".to_string(),
                mime_type: "application/octet-stream".to_string(),
                size: 1024,
                sha256: vec![0u8; 32],
            },
            epoch: 0,
            sender_did: "did:plc:outsider".to_string(),
            content_type: None,
            attachments: None,
            reply_to: None,
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
        let sse_state = Arc::new(SseState::new());
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
                sub: None,
            },
        };
        
        let input = SendMessageInput {
            convo_id: convo_id.to_string(),
            payload: ExternalAsset {
                provider: "invalid-provider".to_string(),
                uri: "invalid://uri".to_string(),
                mime_type: "application/octet-stream".to_string(),
                size: 1024,
                sha256: vec![0u8; 32],
            },
            epoch: 0,
            sender_did: sender.to_string(),
            content_type: None,
            attachments: None,
            reply_to: None,
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
        let sse_state = Arc::new(SseState::new());
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
                sub: None,
            },
        };
        
        let input = SendMessageInput {
            convo_id: convo_id.to_string(),
            payload: ExternalAsset {
                provider: "cloudkit".to_string(),
                uri: "cloudkit://iCloud.com.example.app/Messages/msg-123".to_string(),
                mime_type: "application/octet-stream".to_string(),
                size: 1024,
                sha256: vec![0u8; 32],
            },
            epoch: 0,
            sender_did: "did:plc:impostor".to_string(),
            content_type: None,
            attachments: None,
            reply_to: None,
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
