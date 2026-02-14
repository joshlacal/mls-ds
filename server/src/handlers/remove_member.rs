use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use crate::{
    actors::{ActorRegistry, ConvoMessage},
    auth::{enforce_standard, verify_is_admin, verify_is_member, AuthUser},
    generated::blue_catbird::mls::remove_member::{RemoveMember, RemoveMemberOutput},
    realtime::SseState,
    storage::{get_current_epoch, DbPool},
};

/// Remove a member from conversation (admin-only)
/// POST /xrpc/blue.catbird.mls.removeMember
#[tracing::instrument(skip(pool, sse_state, actor_registry, auth_user))]
pub async fn remove_member(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<RemoveMemberOutput<'static>>, StatusCode> {
    let input = crate::jacquard_json::from_json_body::<RemoveMember>(&body)?;

    info!(
        "📍 [remove_member] START - actor: {}, convo: {}, target: {}",
        crate::crypto::redact_for_log(&auth_user.did),
        crate::crypto::redact_for_log(&input.convo_id),
        crate::crypto::redact_for_log(input.target_did.as_str())
    );

    // Enforce standard auth
    if let Err(_) = enforce_standard(&auth_user.claims, "blue.catbird.mls.removeMember") {
        error!("❌ [remove_member] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify actor is an admin
    verify_is_admin(&pool, &input.convo_id, &auth_user.did).await?;

    // Cannot remove self
    if auth_user.did == input.target_did.as_str() {
        error!("❌ [remove_member] Cannot remove self - use leaveConvo");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Verify target is member
    verify_is_member(&pool, &input.convo_id, input.target_did.as_str()).await?;

    let now = chrono::Utc::now();

    // Check if actor system is enabled
    let use_actors = std::env::var("ENABLE_ACTOR_SYSTEM")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let new_epoch = if use_actors {
        info!("📍 [remove_member] Using actor system");

        // Decode commit if provided
        let commit_bytes = if let Some(ref commit) = input.commit {
            Some(
                base64::engine::general_purpose::STANDARD
                    .decode(commit.as_str())
                    .map_err(|e| {
                        error!("Invalid base64 commit: {}", e);
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
                member_did: input.target_did.as_str().to_string(),
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
        info!("📍 [remove_member] Using legacy database approach");

        let current_epoch = get_current_epoch(&pool, &input.convo_id)
            .await
            .map_err(|e| {
                error!("Failed to get current epoch: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let mut new_epoch = current_epoch;

        // Process commit if provided
        if let Some(ref commit) = input.commit {
            let commit_bytes = base64::engine::general_purpose::STANDARD
                .decode(commit.as_str())
                .map_err(|e| {
                    error!("Invalid base64 commit: {}", e);
                    StatusCode::BAD_REQUEST
                })?;

            let msg_id = uuid::Uuid::new_v4().to_string();

            // Start transaction for atomic commit storage
            let mut tx = pool.begin().await.map_err(|e| {
                error!("Failed to start transaction: {}", e);
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
                    "❌ [remove_member] Epoch conflict for convo {}: expected {}",
                    crate::crypto::redact_for_log(&input.convo_id),
                    current_epoch
                );
                StatusCode::CONFLICT
            })?;

            // Calculate sequence number
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1"
            )
            .bind(input.convo_id.as_str())
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
            .bind(input.convo_id.as_str())
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
                "✅ [remove_member] Commit message stored with seq={}, epoch={}",
                seq, new_epoch
            );

            // Fan out commit message to all remaining members (async)
            let pool_clone = pool.clone();
            let convo_id_clone = input.convo_id.to_string();
            let msg_id_clone = msg_id.clone();
            let sse_state_clone = sse_state.clone();

            tokio::spawn(async move {
                tracing::debug!("📍 [remove_member:fanout] starting commit fan-out");

                // Get all active members (remaining after removal)
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
                            "📍 [remove_member:fanout] fan-out commit to {} members",
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
                                tracing::error!(
                                    "❌ [remove_member:fanout] Failed to insert envelope for {}: {:?}",
                                    member_did, e
                                );
                            }
                        }

                        tracing::debug!("✅ [remove_member:fanout] envelopes created");
                    }
                    Err(e) => {
                        tracing::error!("❌ [remove_member:fanout] Failed to get members: {:?}", e);
                    }
                }

                tracing::debug!("📍 [remove_member:fanout] emitting SSE event for commit");
                // Emit SSE event for commit message
                let cursor = sse_state_clone
                    .cursor_gen
                    .next(&convo_id_clone, "messageEvent")
                    .await;

                // Fetch the commit message from database
                let message_result = sqlx::query_as::<
                    _,
                    (
                        String,
                        Option<String>,
                        Option<Vec<u8>>,
                        i64,
                        i64,
                        chrono::DateTime<chrono::Utc>,
                    ),
                >(
                    r#"
                    SELECT id, sender_did, ciphertext, epoch, seq, created_at
                    FROM messages
                    WHERE id = $1
                    "#,
                )
                .bind(&msg_id_clone)
                .fetch_one(&pool_clone)
                .await;

                match message_result {
                    Ok((id, _sender_did, ciphertext, epoch, seq, created_at)) => {
                        let message_view = crate::generated_types::MessageView {
                            id,
                            convo_id: convo_id_clone.clone(),
                            ciphertext: ciphertext.unwrap_or_default(),
                            epoch: epoch as i64,
                            seq: seq as i64,
                            created_at,
                            message_type: "app".to_string(),
                            reactions: None,
                        };

                        let event = crate::realtime::StreamEvent::MessageEvent {
                            cursor: cursor.clone(),
                            message: message_view,
                            ephemeral: false,
                        };

                        // Store event
                        if let Err(e) = crate::db::store_event(
                            &pool_clone,
                            &cursor,
                            &convo_id_clone,
                            "messageEvent",
                            Some(&msg_id_clone),
                        )
                        .await
                        {
                            tracing::error!(
                                "❌ [remove_member:fanout] Failed to store event: {:?}",
                                e
                            );
                        }

                        // Emit to SSE subscribers
                        if let Err(e) = sse_state_clone.emit(&convo_id_clone, event).await {
                            tracing::error!(
                                "❌ [remove_member:fanout] Failed to emit SSE event: {}",
                                e
                            );
                        } else {
                            tracing::debug!(
                                "✅ [remove_member:fanout] SSE event emitted for commit"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!("❌ [remove_member:fanout] Failed to fetch commit message for SSE event: {:?}", e);
                    }
                }
            });
        }

        // Soft delete member (set left_at for ALL devices of this user)
        // In multi-device mode, this removes all devices belonging to the target user
        // Note: We check both user_did (for multi-device entries) and member_did (for legacy single-device entries)
        let affected_rows = sqlx::query(
            "UPDATE members SET left_at = $3
             WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL",
        )
        .bind(input.convo_id.as_str())
        .bind(input.target_did.as_str())
        .bind(&now)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("❌ [remove_member] Database update failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .rows_affected();

        if affected_rows == 0 {
            error!("❌ [remove_member] Member already removed or not found");
            return Err(StatusCode::NOT_FOUND);
        }

        new_epoch as u32
    };

    // Prepare membershipChangeEvent metadata for emission
    let event_cursor = sse_state
        .cursor_gen
        .next(&input.convo_id, "membershipChangeEvent")
        .await;

    // Determine action based on reason - use "kicked" if there's a reason suggesting disciplinary action
    let event_action = if input
        .reason
        .as_ref()
        .map(|r| {
            r.to_lowercase().contains("violat")
                || r.to_lowercase().contains("abuse")
                || r.to_lowercase().contains("spam")
        })
        .unwrap_or(false)
    {
        "kicked"
    } else {
        "removed"
    };

    // Log admin action
    let action_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO admin_actions (id, convo_id, actor_did, action, target_did, reason, created_at)
         VALUES ($1, $2, $3, 'remove', $4, $5, $6)"
    )
    .bind(&action_id)
    .bind(input.convo_id.as_str())
    .bind(&auth_user.did)
    .bind(input.target_did.as_str())
    .bind(input.reason.as_deref())
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [remove_member] Failed to log action: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Emit the membership event with the correct epoch
    let membership_event = crate::realtime::StreamEvent::MembershipChangeEvent {
        cursor: event_cursor,
        convo_id: input.convo_id.to_string(),
        did: input.target_did.as_str().to_string(),
        action: event_action.to_string(),
        actor: Some(auth_user.did.clone()),
        reason: input.reason.as_ref().map(|s| s.to_string()),
        epoch: new_epoch as usize,
    };

    if let Err(e) = sse_state.emit(&input.convo_id, membership_event).await {
        error!("Failed to emit membershipChangeEvent: {}", e);
    } else {
        info!(
            "✅ Emitted membershipChangeEvent for {} being {} by {}",
            crate::crypto::redact_for_log(input.target_did.as_str()),
            event_action,
            crate::crypto::redact_for_log(&auth_user.did)
        );
    }

    info!(
        "✅ [remove_member] SUCCESS - {} removed by {}, epoch_hint: {}",
        crate::crypto::redact_for_log(input.target_did.as_str()),
        crate::crypto::redact_for_log(&auth_user.did),
        new_epoch
    );

    Ok(Json(RemoveMemberOutput {
        ok: true,
        epoch_hint: Some(new_epoch as i64),
        extra_data: None,
    }))
}
