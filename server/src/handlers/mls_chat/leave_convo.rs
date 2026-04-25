use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use jacquard_axum::ExtractXrpc;

use crate::{
    actors::{ActorRegistry, ConvoMessage},
    auth::AuthUser,
    federation::SequencerTransfer,
    generated::blue_catbird::mlsChat::leave_convo::{LeaveConvoOutput, LeaveConvoRequest},
    realtime::{SseState, StreamMessageView},
    storage::{get_current_epoch, is_member, DbPool},
};

const NSID: &str = "blue.catbird.mlsChat.leaveConvo";

/// Consolidated leave/remove handler (v2, self-contained)
/// POST /xrpc/blue.catbird.mlsChat.leaveConvo
///
/// - No targetDid → self-leave
/// - With targetDid → admin removing member (requires admin/creator privileges)
#[tracing::instrument(skip(pool, sse_state, actor_registry, sequencer_transfer, auth_user, input))]
pub async fn leave_convo(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    State(sequencer_transfer): State<Arc<SequencerTransfer>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<LeaveConvoRequest>,
) -> Result<Json<LeaveConvoOutput<'static>>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = &auth_user.did;
    let convo_id = input.convo_id.to_string();

    if convo_id.is_empty() {
        warn!("Empty convo_id provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    let target_did = input
        .target_did
        .as_ref()
        .map(|d| d.to_string())
        .unwrap_or_else(|| did.clone());

    if !target_did.starts_with("did:") {
        warn!(
            "Invalid target DID format: {}",
            crate::crypto::redact_for_log(&target_did)
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if requester is a member
    if !is_member(&pool, did, &convo_id).await.map_err(|e| {
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
                .bind(&convo_id)
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

    let use_actors = std::env::var("ENABLE_ACTOR_SYSTEM")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let new_epoch = if use_actors {
        let commit_bytes = input.commit.as_ref().map(|c| c.to_vec());

        let actor_ref = actor_registry.get_or_spawn(&convo_id).await.map_err(|e| {
            error!("Failed to get conversation actor: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

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
        let current_epoch = get_current_epoch(&pool, &convo_id).await.map_err(|e| {
            error!("Failed to get current epoch: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let mut new_epoch = current_epoch;
        let now = chrono::Utc::now();

        if let Some(ref commit) = input.commit {
            let commit_bytes = commit.to_vec();
            let commit_shape =
                super::commit_inspect::inspect_commit_shape(&commit_bytes).map_err(|e| {
                    warn!("leave_convo: invalid commit framing: {}", e);
                    StatusCode::BAD_REQUEST
                })?;
            if commit_shape.epoch != current_epoch as u64 {
                warn!(
                    "leave_convo: stale commit wire_epoch={} current_epoch={} for convo {}",
                    commit_shape.epoch,
                    current_epoch,
                    crate::crypto::redact_for_log(&convo_id)
                );
                return Err(StatusCode::CONFLICT);
            }
            let commit_wire_epoch = commit_shape.epoch as i64;

            let msg_id = uuid::Uuid::new_v4().to_string();

            let mut db_tx = pool.begin().await.map_err(|e| {
                error!("Failed to begin transaction: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            let advanced_epoch =
                crate::db::try_advance_conversation_epoch_tx(&mut db_tx, &convo_id, current_epoch)
                    .await
                    .map_err(|e| {
                        error!("Failed to advance conversation epoch: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?
                    .ok_or_else(|| {
                        warn!(
                            "❌ [leave_convo] Epoch conflict: expected {}",
                            current_epoch
                        );
                        StatusCode::CONFLICT
                    })?;

            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
            )
            .bind(&convo_id)
            .fetch_one(&mut *db_tx)
            .await
            .map_err(|e| {
                error!("Failed to calculate sequence number: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, wire_epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7, $8)",
            )
            .bind(&msg_id)
            .bind(&convo_id)
            .bind(Option::<&str>::None) // sender_did intentionally NULL — PRIV-001
            .bind(advanced_epoch)
            .bind(commit_wire_epoch)
            .bind(seq)
            .bind(&commit_bytes)
            .bind(&now)
            .execute(&mut *db_tx)
            .await
            .map_err(|e| {
                error!("Failed to insert commit message: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            db_tx.commit().await.map_err(|e| {
                error!("Failed to commit transaction: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            new_epoch = advanced_epoch;

            info!(
                "✅ [leave_convo] Commit stored seq={}, epoch={}",
                seq, new_epoch
            );

            // ── Enqueue commit messageEvent on per-convo FIFO queue (task #39) ──
            // Synchronous enqueue so order matches the DB commit order above.
            let commit_cursor = sse_state.cursor_gen.next(&convo_id, "messageEvent").await;

            let commit_message_view: StreamMessageView =
                crate::generated::blue_catbird::mlsChat::MessageView {
                    id: msg_id.clone().into(),
                    convo_id: convo_id.clone().into(),
                    ciphertext: bytes::Bytes::from(commit_bytes.clone()),
                    epoch: new_epoch as i64,
                    seq,
                    created_at: crate::sqlx_jacquard::chrono_to_datetime(now),
                    // NOTE: legacy code emitted "app" here, but this is a
                    // commit; preserving original wire compatibility for now.
                    message_type: Some("app".into()),
                    extra_data: Default::default(),
                }
                .into();

            let commit_event = crate::realtime::StreamEvent::MessageEvent {
                cursor: commit_cursor.clone(),
                message: commit_message_view,
                ephemeral: false,
            };

            sse_state.enqueue_with_store(&convo_id, pool.clone(), commit_event);

            // ── Envelope fanout (non-order-sensitive, detached) ──
            {
                let pool_clone = pool.clone();
                let convo_id_clone = convo_id.clone();
                let msg_id_clone = msg_id.clone();

                tokio::spawn(async move {
                    let members_result = sqlx::query_as::<_, (String,)>(
                        "SELECT member_did FROM members WHERE convo_id = $1 AND left_at IS NULL",
                    )
                    .bind(&convo_id_clone)
                    .fetch_all(&pool_clone)
                    .await;

                    match members_result {
                        Ok(members) => {
                            for (member_did,) in &members {
                                let envelope_id = uuid::Uuid::new_v4().to_string();
                                if let Err(e) = sqlx::query(
                                    "INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at) VALUES ($1, $2, $3, $4, NOW()) ON CONFLICT (recipient_did, message_id) DO NOTHING",
                                )
                                .bind(&envelope_id)
                                .bind(&convo_id_clone)
                                .bind(member_did)
                                .bind(&msg_id_clone)
                                .execute(&pool_clone)
                                .await
                                {
                                    error!("❌ [leave_convo:fanout] envelope insert: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("❌ [leave_convo:fanout] Failed to get members: {:?}", e);
                        }
                    }
                });
            }
        }

        // Mark member as left
        let rows_affected = sqlx::query(
            "UPDATE members SET left_at = $1, needs_rejoin = false, rejoin_requested_at = NULL WHERE convo_id = $2 AND (member_did = $3 OR user_did = $3) AND left_at IS NULL",
        )
        .bind(&now)
        .bind(&convo_id)
        .bind(&target_did)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to mark member as left: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .rows_affected();

        if rows_affected == 0 {
            info!("Member already left, treating as idempotent success");
        } else {
            let cursor = sse_state
                .cursor_gen
                .next(&convo_id, "membershipChangeEvent")
                .await;

            let membership_event = crate::realtime::StreamEvent::MembershipChangeEvent {
                cursor,
                convo_id: convo_id.clone(),
                did: target_did.clone(),
                action: "left".to_string(),
                actor: None,
                reason: None,
                epoch: new_epoch as usize,
            };

            if let Err(e) = sse_state.emit(&convo_id, membership_event).await {
                error!("Failed to emit membershipChangeEvent: {}", e);
            }
        }

        // Federation: sequencer transfer if creator leaves
        let creator_did: Option<String> =
            sqlx::query_scalar("SELECT creator_did FROM conversations WHERE id = $1")
                .bind(&convo_id)
                .fetch_optional(&pool)
                .await
                .unwrap_or(None);

        if creator_did.as_deref() == Some(target_did.as_str()) {
            warn!("Creator leaving conversation — sequencer transfer may be needed");
            match sequencer_transfer.pick_new_sequencer(&convo_id).await {
                Ok(Some(new_ds_did)) => {
                    if let Err(e) = sequencer_transfer
                        .initiate_transfer(&convo_id, &new_ds_did)
                        .await
                    {
                        warn!("Sequencer transfer failed on leave (non-fatal): {}", e);
                    }
                }
                Ok(None) => {
                    warn!("No eligible new sequencer found after creator left");
                }
                Err(e) => {
                    warn!("Failed to pick new sequencer on leave (non-fatal): {}", e);
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
        new_epoch: new_epoch as i64,
        extra_data: Default::default(),
    }))
}
