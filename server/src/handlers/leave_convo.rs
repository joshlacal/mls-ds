use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use crate::{
    actors::{ActorRegistry, ConvoMessage},
    auth::AuthUser,
    federation::SequencerTransfer,
    generated_types::{LeaveConvoInput, LeaveConvoOutput},
    realtime::SseState,
    storage::{get_current_epoch, is_member, DbPool},
};

/// Leave a conversation
/// POST /xrpc/chat.bsky.convo.leaveConvo
#[tracing::instrument(skip(pool, actor_registry, sse_state, sequencer_transfer))]
pub async fn leave_convo(
    State(pool): State<DbPool>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    State(sse_state): State<Arc<SseState>>,
    State(sequencer_transfer): State<Arc<SequencerTransfer>>,
    auth_user: AuthUser,
    Json(input): Json<LeaveConvoInput>,
) -> Result<Json<LeaveConvoOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.leaveConvo")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let did = &auth_user.did;
    // Validate input
    if input.convo_id.is_empty() {
        warn!("Empty convo_id provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    let target_did = input.target_did.unwrap_or_else(|| did.clone());

    // Validate target DID format
    if !target_did.starts_with("did:") {
        warn!(
            "Invalid target DID format: {}",
            crate::crypto::redact_for_log(&target_did)
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if requester is a member
    if !is_member(&pool, did, &input.convo_id).await.map_err(|e| {
        error!("Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })? {
        warn!("User is not a member of conversation");
        return Err(StatusCode::FORBIDDEN);
    }

    // Users can only remove themselves unless they're the creator
    if &target_did != did {
        let creator_did: String =
            sqlx::query_scalar("SELECT creator_did FROM conversations WHERE id = $1")
                .bind(&input.convo_id)
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    error!("Failed to fetch conversation creator: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

        if creator_did != *did {
            warn!("User is not the creator, cannot remove other members");
            return Err(StatusCode::FORBIDDEN);
        }
    }

    info!("User leaving conversation");

    // Check if actor system is enabled
    let use_actors = std::env::var("ENABLE_ACTOR_SYSTEM")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let new_epoch = if use_actors {
        info!("Using actor system for leave_convo");

        // Decode commit if provided
        let commit_bytes = if let Some(ref commit) = input.commit {
            Some(
                base64::engine::general_purpose::STANDARD
                    .decode(commit)
                    .map_err(|e| {
                        warn!("Invalid base64 commit: {}", e);
                        StatusCode::BAD_REQUEST
                    })?,
            )
        } else {
            None
        };

        // Get or spawn conversation actor
        let actor_ref = actor_registry
            .get_or_spawn(&input.convo_id)
            .await
            .map_err(|e| {
                error!("Failed to get conversation actor: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Send RemoveMember message
        let (tx, rx) = oneshot::channel();
        actor_ref
            .send_message(ConvoMessage::RemoveMember {
                member_did: target_did.clone(),
                commit: commit_bytes,
                reply: tx,
            })
            .map_err(|_| {
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
                error!("Actor failed to remove member: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
    } else {
        info!("Using legacy database approach for leave_convo");

        let current_epoch = get_current_epoch(&pool, &input.convo_id)
            .await
            .map_err(|e| {
                error!("Failed to get current epoch: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let mut new_epoch = current_epoch;
        let now = chrono::Utc::now();

        // Process commit if provided
        if let Some(commit) = input.commit {
            use base64::Engine;
            let commit_bytes = base64::engine::general_purpose::STANDARD
                .decode(commit)
                .map_err(|e| {
                    warn!("Invalid base64 commit: {}", e);
                    StatusCode::BAD_REQUEST
                })?;

            let msg_id = uuid::Uuid::new_v4().to_string();

            // Start transaction
            let mut tx = pool.begin().await.map_err(|e| {
                error!("Failed to begin transaction: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            let advanced_epoch = crate::db::try_advance_conversation_epoch_tx(
                &mut tx,
                &input.convo_id,
                current_epoch,
            )
            .await
            .map_err(|e| {
                error!("Failed to advance conversation epoch: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .ok_or_else(|| {
                warn!(
                    "❌ [leave_convo] Epoch conflict for convo {}: expected {}",
                    crate::crypto::redact_for_log(&input.convo_id),
                    current_epoch
                );
                StatusCode::CONFLICT
            })?;

            // Calculate sequence number
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1"
            )
            .bind(&input.convo_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                error!("Failed to calculate sequence number: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            // Insert commit message with sequence number
            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7)"
            )
            .bind(&msg_id)
            .bind(&input.convo_id)
            .bind(Option::<&str>::None) // sender_did intentionally NULL — PRIV-001 (docs/PRIVACY.md)
            .bind(advanced_epoch)
            .bind(seq)
            .bind(&commit_bytes)
            .bind(&now)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("Failed to insert commit message: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            // Commit transaction
            tx.commit().await.map_err(|e| {
                error!("Failed to commit transaction: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            new_epoch = advanced_epoch;

            info!(
                "✅ [leave_convo] Commit message stored with seq={}, epoch={}",
                seq, new_epoch
            );

            // Fan out commit message to all members (async)
            let pool_clone = pool.clone();
            let convo_id_clone = input.convo_id.clone();
            let msg_id_clone = msg_id.clone();
            let sse_state_clone = sse_state.clone();

            tokio::spawn(async move {
                tracing::debug!("📍 [leave_convo:fanout] starting commit fan-out");

                // Get all active members (including the one leaving, so they get the commit)
                let members_result = sqlx::query_as::<_, (String,)>(
                    r#"
                    SELECT member_did
                    FROM members
                    WHERE convo_id = $1 AND left_at IS NULL
                    "#,
                )
                .bind(&convo_id_clone)
                .fetch_all(&pool_clone)
                .await;

                match members_result {
                    Ok(members) => {
                        tracing::debug!(
                            "📍 [leave_convo:fanout] fan-out commit to {} members",
                            members.len()
                        );

                        // Create envelopes for each member
                        for (member_did,) in &members {
                            let envelope_id = uuid::Uuid::new_v4().to_string();

                            let envelope_result = sqlx::query(
                                r#"
                                INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at)
                                VALUES ($1, $2, $3, $4, NOW())
                                ON CONFLICT (recipient_did, message_id) DO NOTHING
                                "#,
                            )
                            .bind(&envelope_id)
                            .bind(&convo_id_clone)
                            .bind(member_did)
                            .bind(&msg_id_clone)
                            .execute(&pool_clone)
                            .await;

                            if let Err(e) = envelope_result {
                                error!(
                                    "❌ [leave_convo:fanout] Failed to insert envelope for {}: {:?}",
                                    member_did, e
                                );
                            }
                        }

                        tracing::debug!("✅ [leave_convo:fanout] envelopes created");
                    }
                    Err(e) => {
                        error!("❌ [leave_convo:fanout] Failed to get members: {:?}", e);
                    }
                }

                tracing::debug!("📍 [leave_convo:fanout] emitting SSE event for commit");
                // Emit SSE event for commit message
                let cursor = sse_state_clone
                    .cursor_gen
                    .next(&convo_id_clone, "messageEvent")
                    .await;

                // Fetch the full message from database to get all fields
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
                        let message_view = crate::generated_types::MessageView {
                            id: msg.id,
                            convo_id: convo_id_clone.clone(),
                            ciphertext: msg.ciphertext.unwrap_or_default(),
                            epoch: msg.epoch as i64,
                            seq: msg.seq as i64,
                            created_at: msg.created_at,
                            message_type: "app".to_string(),
                            reactions: None,
                        };

                        let event = crate::realtime::StreamEvent::MessageEvent {
                            cursor: cursor.clone(),
                            message: message_view.clone(),
                            ephemeral: false,
                        };

                        // Store event for cursor-based SSE replay
                        if let Err(e) = crate::db::store_event(
                            &pool_clone,
                            &cursor,
                            &convo_id_clone,
                            "messageEvent",
                            Some(&msg_id_clone),
                        )
                        .await
                        {
                            error!("❌ [leave_convo:fanout] Failed to store event: {:?}", e);
                        }

                        if let Err(e) = sse_state_clone.emit(&convo_id_clone, event).await {
                            error!("❌ [leave_convo:fanout] Failed to emit SSE event: {}", e);
                        } else {
                            tracing::debug!("✅ [leave_convo:fanout] SSE event emitted");
                        }
                    }
                    Err(e) => {
                        error!(
                            "❌ [leave_convo:fanout] Failed to fetch message for SSE: {:?}",
                            e
                        );
                    }
                }
            });
        }

        // Mark member as left and clear rejoin flags (natural idempotency: only update if not already left)
        // In multi-device mode, this marks ALL devices of the user as having left
        // FIX: Check both member_did and user_did since user_did may be NULL in single-device mode
        let rows_affected = sqlx::query(
            "UPDATE members SET left_at = $1, needs_rejoin = false, rejoin_requested_at = NULL WHERE convo_id = $2 AND (member_did = $3 OR user_did = $3) AND left_at IS NULL"
        )
            .bind(&now)
            .bind(&input.convo_id)
            .bind(&target_did)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to mark member as left: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .rows_affected();

        if rows_affected == 0 {
            // Member was already marked as left - this is idempotent
            info!("Member already left conversation, treating as idempotent success");
        } else {
            // Emit membershipChangeEvent for the member leaving
            let cursor = sse_state
                .cursor_gen
                .next(&input.convo_id, "membershipChangeEvent")
                .await;

            let membership_event = crate::realtime::StreamEvent::MembershipChangeEvent {
                cursor,
                convo_id: input.convo_id.clone(),
                did: target_did.clone(),
                action: "left".to_string(),
                actor: None, // self-leave has no actor
                reason: None,
                epoch: new_epoch as usize,
            };

            if let Err(e) = sse_state.emit(&input.convo_id, membership_event).await {
                error!("Failed to emit membershipChangeEvent: {}", e);
            } else {
                info!(
                    "✅ Emitted membershipChangeEvent for {} leaving",
                    crate::crypto::redact_for_log(&target_did)
                );
            }
        }

        // Federation: Check if leaving member is the conversation creator.
        // The creator's DS is typically the sequencer — if they leave, a sequencer
        // transfer to another participant's DS may be needed.
        let creator_did: Option<String> =
            sqlx::query_scalar("SELECT creator_did FROM conversations WHERE id = $1")
                .bind(&input.convo_id)
                .fetch_optional(&pool)
                .await
                .unwrap_or(None);

        if creator_did.as_deref() == Some(target_did.as_str()) {
            warn!(
                convo_id = %input.convo_id,
                creator_did = %crate::crypto::redact_for_log(&target_did),
                "Creator leaving conversation — sequencer transfer may be needed"
            );
            // Federation: if creator is leaving, initiate sequencer transfer
            match sequencer_transfer.pick_new_sequencer(&input.convo_id).await {
                Ok(Some(new_ds_did)) => {
                    if let Err(e) = sequencer_transfer
                        .initiate_transfer(&input.convo_id, &new_ds_did)
                        .await
                    {
                        tracing::warn!(
                            convo_id = %input.convo_id,
                            new_sequencer = %crate::crypto::redact_for_log(&new_ds_did),
                            error = %e,
                            "Sequencer transfer failed on leave (non-fatal)"
                        );
                    }
                }
                Ok(None) => {
                    tracing::warn!(
                        convo_id = %input.convo_id,
                        "No eligible new sequencer found after creator left"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        convo_id = %input.convo_id,
                        error = %e,
                        "Failed to pick new sequencer on leave (non-fatal)"
                    );
                }
            }
        }

        new_epoch as u32
    };

    info!(
        "User successfully left conversation, new epoch: {}",
        new_epoch
    );

    Ok(Json(LeaveConvoOutput {
        success: true,
        new_epoch: new_epoch as i32,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realtime::SseState;
    use crate::storage::init_db;

    async fn setup_test_convo(pool: &DbPool, creator: &str, convo_id: &str, members: Vec<&str>) {
        let now = chrono::Utc::now();
        sqlx::query("INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at) VALUES ($1, $2, 0, $3, $3)")
            .bind(convo_id)
            .bind(creator)
            .bind(&now)
            .execute(pool)
            .await
            .expect("test setup");

        for member in members {
            sqlx::query(
                "INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)",
            )
            .bind(convo_id)
            .bind(member)
            .bind(&now)
            .execute(pool)
            .await
            .expect("test setup");
        }
    }

    #[tokio::test]
    async fn test_leave_convo_success() {
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
        let convo_id = "test-convo-1";
        let creator = "did:plc:creator";
        let member = "did:plc:member";

        setup_test_convo(&pool, creator, convo_id, vec![creator, member]).await;

        let did = AuthUser {
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
        let input = LeaveConvoInput {
            convo_id: convo_id.to_string(),
            target_did: None,
            commit: None,
        };

        let sse_state = Arc::new(SseState::new(1000));
        let actor_registry = Arc::new(crate::actors::ActorRegistry::new(
            pool.clone(),
            sse_state.clone(),
            None,
        ));
        let sequencer_transfer = Arc::new(crate::federation::transfer::SequencerTransfer::new(
            pool.clone(),
            "did:web:test".to_string(),
        ));
        let result = leave_convo(
            State(pool.clone()),
            State(actor_registry),
            State(sse_state),
            State(sequencer_transfer),
            did,
            Json(input),
        )
        .await;
        assert!(result.is_ok());

        let output = result.expect("handler should return Ok").0;
        assert!(output.success);
        assert_eq!(output.new_epoch, 1);

        // Verify member is marked as left
        let is_active = is_member(&pool, member, convo_id)
            .await
            .expect("membership check should succeed");
        assert!(!is_active);
    }

    #[tokio::test]
    async fn test_leave_convo_not_member() {
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
        let convo_id = "test-convo-2";
        let creator = "did:plc:creator";

        setup_test_convo(&pool, creator, convo_id, vec![creator]).await;

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
        let input = LeaveConvoInput {
            convo_id: convo_id.to_string(),
            target_did: None,
            commit: None,
        };

        let sse_state = Arc::new(SseState::new(1000));
        let actor_registry = Arc::new(crate::actors::ActorRegistry::new(
            pool.clone(),
            sse_state.clone(),
            None,
        ));
        let sequencer_transfer = Arc::new(crate::federation::transfer::SequencerTransfer::new(
            pool.clone(),
            "did:web:test".to_string(),
        ));
        let result = leave_convo(
            State(pool),
            State(actor_registry),
            State(sse_state),
            State(sequencer_transfer),
            did,
            Json(input),
        )
        .await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_leave_convo_creator_removes_member() {
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
        let convo_id = "test-convo-3";
        let creator = "did:plc:creator";
        let member = "did:plc:member";

        setup_test_convo(&pool, creator, convo_id, vec![creator, member]).await;

        let did = AuthUser {
            did: creator.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: creator.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };
        let input = LeaveConvoInput {
            convo_id: convo_id.to_string(),
            target_did: Some(member.to_string()),
            commit: None,
        };

        let sse_state = Arc::new(SseState::new(1000));
        let actor_registry = Arc::new(crate::actors::ActorRegistry::new(
            pool.clone(),
            sse_state.clone(),
            None,
        ));
        let sequencer_transfer = Arc::new(crate::federation::transfer::SequencerTransfer::new(
            pool.clone(),
            "did:web:test".to_string(),
        ));
        let result = leave_convo(
            State(pool.clone()),
            State(actor_registry),
            State(sse_state),
            State(sequencer_transfer),
            did,
            Json(input),
        )
        .await;
        assert!(result.is_ok());

        let is_active = is_member(&pool, member, convo_id)
            .await
            .expect("membership check should succeed");
        assert!(!is_active);
    }

    #[tokio::test]
    async fn test_leave_convo_non_creator_cannot_remove_others() {
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
        let convo_id = "test-convo-4";
        let creator = "did:plc:creator";
        let member1 = "did:plc:member1";
        let member2 = "did:plc:member2";

        setup_test_convo(&pool, creator, convo_id, vec![creator, member1, member2]).await;

        let did = AuthUser {
            did: member1.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: member1.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };
        let input = LeaveConvoInput {
            convo_id: convo_id.to_string(),
            target_did: Some(member2.to_string()),
            commit: None,
        };

        let sse_state = Arc::new(SseState::new(1000));
        let actor_registry = Arc::new(crate::actors::ActorRegistry::new(
            pool.clone(),
            sse_state.clone(),
            None,
        ));
        let sequencer_transfer = Arc::new(crate::federation::transfer::SequencerTransfer::new(
            pool.clone(),
            "did:web:test".to_string(),
        ));
        let result = leave_convo(
            State(pool),
            State(actor_registry),
            State(sse_state),
            State(sequencer_transfer),
            did,
            Json(input),
        )
        .await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }
}
