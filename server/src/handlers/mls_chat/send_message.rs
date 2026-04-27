use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use jacquard_axum::ExtractXrpc;
use sqlx::{Postgres, QueryBuilder};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    actors::ActorRegistry,
    auth::AuthUser,
    federation::{self, FederatedBackend},
    generated::blue_catbird::mlsChat::send_message::{SendMessageOutput, SendMessageRequest},
    notifications::NotificationService,
    realtime::{SseState, StreamEvent, StreamMessageView},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.sendMessage";

/// Maximum allowed epoch drift (client behind server) before requiring sync.
const MAX_EPOCH_DRIFT: i64 = 5;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Consolidated message sending endpoint (v2 – inline SQL, no v1 delegation).
///
/// POST /xrpc/blue.catbird.mlsChat.sendMessage
///
/// Dispatches based on `delivery` field:
/// - `"persistent"` (default) → insert message + fan-out envelopes + SSE + push + federation
/// - `"ephemeral"` + `action`:
///   - default            → SSE typing indicator (no DB write)
#[tracing::instrument(skip(
    pool,
    sse_state,
    _actor_registry,
    notification_service,
    federated_backend,
    federation_config,
    outbound_queue,
    auth_user,
    input
))]
pub async fn send_message(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    State(_actor_registry): State<Arc<ActorRegistry>>,
    State(notification_service): State<Option<Arc<NotificationService>>>,
    State(federated_backend): State<Arc<FederatedBackend>>,
    State(federation_config): State<federation::FederationConfig>,
    State(outbound_queue): State<Arc<federation::queue::OutboundQueue>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<SendMessageRequest>,
) -> Result<Response, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [v2.sendMessage] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let delivery = input.delivery.as_deref().unwrap_or("persistent");

    match delivery {
        "persistent" => Ok(handle_persistent(
            pool,
            sse_state,
            notification_service,
            federated_backend,
            federation_config,
            outbound_queue,
            auth_user,
            &input,
        )
        .await?),

        "ephemeral" => {
            let action = input.action.as_deref().unwrap_or("typing");
            Ok(match action {
                "typingStop" | "stopTyping" => {
                    handle_typing(pool, sse_state, auth_user, &input, false).await?
                }
                "typing" | "typingStart" => {
                    handle_typing(pool, sse_state, auth_user, &input, true).await?
                }
                other => {
                    warn!(
                        "❌ [v2.sendMessage] Unknown ephemeral action '{}', defaulting to typing start",
                        other
                    );
                    handle_typing(pool, sse_state, auth_user, &input, true).await?
                }
            })
        }

        other => {
            warn!("❌ [v2.sendMessage] Unknown delivery mode: {}", other);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

// ---------------------------------------------------------------------------
// Persistent message
// ---------------------------------------------------------------------------

async fn handle_persistent(
    pool: DbPool,
    sse_state: Arc<SseState>,
    notification_service: Option<Arc<NotificationService>>,
    federated_backend: Arc<FederatedBackend>,
    federation_config: federation::FederationConfig,
    outbound_queue: Arc<federation::queue::OutboundQueue>,
    auth_user: AuthUser,
    input: &crate::generated::blue_catbird::mlsChat::send_message::SendMessage<'_>,
) -> Result<Response, StatusCode> {
    let convo_id = input.convo_id.to_string();
    let msg_id = input.msg_id.to_string();
    let padded_size = input.padded_size as u32;

    // --- Validate msgId format (ULID 26 chars or UUID 36 chars) ---
    let is_ulid = msg_id.len() == 26 && msg_id.chars().all(|c| c.is_ascii_alphanumeric());
    let is_uuid = msg_id.len() == 36
        && msg_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !is_ulid && !is_uuid {
        error!("❌ [v2.sendMessage] Invalid msgId format");
        return Err(StatusCode::BAD_REQUEST);
    }

    // --- Validate ciphertext ---
    if input.ciphertext.is_empty() {
        error!("❌ [v2.sendMessage] Empty ciphertext");
        return Err(StatusCode::BAD_REQUEST);
    }
    if input.ciphertext.len() > 10 * 1024 * 1024 {
        error!(
            "❌ [v2.sendMessage] Ciphertext too large: {} bytes",
            input.ciphertext.len()
        );
        return Err(StatusCode::BAD_REQUEST);
    }
    if input.ciphertext.len() as u32 != padded_size {
        error!(
            "❌ [v2.sendMessage] Ciphertext length ({}) != paddedSize ({})",
            input.ciphertext.len(),
            padded_size
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // --- Validate padded_size bucket ---
    let valid_buckets = [512, 1024, 2048, 4096, 8192];
    let is_valid_bucket = valid_buckets.contains(&padded_size)
        || (padded_size > 8192 && padded_size <= 10 * 1024 * 1024 && padded_size % 8192 == 0);
    if !is_valid_bucket {
        error!("❌ [v2.sendMessage] Invalid paddedSize: {}", padded_size);
        return Err(StatusCode::BAD_REQUEST);
    }

    // --- Check membership ---
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL)",
    )
    .bind(&convo_id)
    .bind(&auth_user.did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.sendMessage] membership check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        error!("❌ [v2.sendMessage] Not a member");
        return Err(StatusCode::FORBIDDEN);
    }

    // --- Fetch conversation epoch, sequencer term, confirmation tag, and reset_count ---
    let (server_epoch, server_sequencer_term, stored_confirmation_tag, reset_count): (i64, i64, Option<Vec<u8>>, i32) = sqlx::query_as(
        "SELECT CAST(current_epoch AS BIGINT), CAST(COALESCE(sequencer_term, 0) AS BIGINT), confirmation_tag, COALESCE(reset_count, 0) \
         FROM conversations WHERE id = $1",
    )
    .bind(&convo_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.sendMessage] Failed to fetch conversation: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or_else(|| {
        error!("❌ [v2.sendMessage] Conversation not found");
        StatusCode::NOT_FOUND
    })?;

    // --- Validate confirmation tag (if client sent one) ---
    if let Some(ref client_tag) = input.confirmation_tag {
        if let Some(ref server_tag) = stored_confirmation_tag {
            if client_tag.as_ref() != server_tag.as_slice() {
                warn!(
                    convo_id = %crate::crypto::redact_for_log(&convo_id),
                    "TREE DIVERGED — client confirmation_tag does not match server canonical tree"
                );
                use base64::Engine;
                let server_tag_b64 = base64::engine::general_purpose::STANDARD.encode(server_tag);
                return Ok((
                    StatusCode::CONFLICT,
                    axum::Json(serde_json::json!({
                        "error": "TreeStateDiverged",
                        "message": "Client MLS tree state does not match server canonical tree. Client must re-join via external commit.",
                        "serverConfirmationTag": server_tag_b64,
                        "serverEpoch": server_epoch
                    })),
                )
                    .into_response());
            }
        }
    }

    let client_epoch = input.epoch;

    // Reject if client claims to be ahead of server — indicates a bug
    if client_epoch > server_epoch {
        warn!(
            "❌ [v2.sendMessage] Client epoch {} is ahead of server epoch {} — rejecting",
            client_epoch, server_epoch
        );
        return Ok((
            StatusCode::CONFLICT,
            axum::Json(serde_json::json!({
                "error": "TreeStateDiverged",
                "message": format!(
                    "Client epoch {} is ahead of server epoch {}. This indicates a client bug.",
                    client_epoch, server_epoch
                ),
                "serverEpoch": server_epoch
            })),
        )
            .into_response());
    }

    // Reject if client is too far behind — needs to sync
    if server_epoch - client_epoch > MAX_EPOCH_DRIFT {
        warn!(
            "❌ [v2.sendMessage] Client epoch {} is {} behind server epoch {} — sync required",
            client_epoch,
            server_epoch - client_epoch,
            server_epoch
        );
        return Ok((
            StatusCode::CONFLICT,
            axum::Json(serde_json::json!({
                "error": "EpochMismatch",
                "message": format!(
                    "Client epoch {} is behind server epoch {}. Sync required.",
                    client_epoch, server_epoch
                ),
                "serverEpoch": server_epoch
            })),
        )
            .into_response());
    }

    if client_epoch != server_epoch {
        tracing::warn!(
            target: "mls_epoch",
            convo_id = %crate::crypto::redact_for_log(&convo_id),
            server_epoch, client_epoch,
            "accepting app message with stale epoch (server={}, client={})",
            server_epoch, client_epoch
        );
    }

    // Always store with server epoch, not client epoch
    let store_epoch = server_epoch;

    // --- Insert message in a transaction (seq via MAX+1) ---
    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(30);
    let received_bucket_ts = (now.timestamp() / 2) * 2;

    let mut tx = pool.begin().await.map_err(|e| {
        error!("❌ [v2.sendMessage] begin tx: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Lock the conversation row to serialize sequence number assignment.
    // This prevents two concurrent senders from reading the same MAX(seq).
    sqlx::query("SELECT 1 FROM conversations WHERE id = $1 FOR UPDATE")
        .bind(&convo_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("❌ [v2.sendMessage] conversation lock: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Dedup by msg_id
    let existing: Option<(String, i64, i64, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, CAST(seq AS BIGINT), CAST(epoch AS BIGINT), created_at FROM messages WHERE convo_id = $1 AND msg_id = $2",
    )
    .bind(&convo_id)
    .bind(&msg_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!("❌ [v2.sendMessage] dedup check: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Some((eid, eseq, eepoch, eat)) = existing {
        tx.rollback().await.ok();
        return Ok(Json(SendMessageOutput {
            message_id: eid.into(),
            received_at: crate::sqlx_jacquard::chrono_to_datetime(eat),
            seq: eseq,
            epoch: eepoch,
            extra_data: Default::default(),
        })
        .into_response());
    }

    let seq: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
    )
    .bind(&convo_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!("❌ [v2.sendMessage] seq calc: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let row_id = uuid::Uuid::new_v4().to_string();
    let ciphertext_vec = input.ciphertext.to_vec();

    sqlx::query(
        r#"INSERT INTO messages (
            id, convo_id, sender_did, message_type, epoch, seq,
            ciphertext, created_at, expires_at,
            msg_id, padded_size, received_bucket_ts, reset_generation
        ) VALUES ($1, $2, NULL, 'app', $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
    )
    .bind(&row_id)
    .bind(&convo_id)
    .bind(store_epoch)
    .bind(seq)
    .bind(&ciphertext_vec)
    .bind(&now)
    .bind(&expires_at)
    .bind(&msg_id)
    .bind(padded_size as i64)
    .bind(received_bucket_ts)
    .bind(reset_count)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("❌ [v2.sendMessage] insert message: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Query members and create envelopes inside the transaction
    let member_dids: Vec<String> = sqlx::query_scalar(
        "SELECT member_did FROM members WHERE convo_id = $1 AND left_at IS NULL",
    )
    .bind(&convo_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| {
        error!("❌ [v2.sendMessage] get members for envelopes: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !member_dids.is_empty() {
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
            "INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at) ",
        );
        let envelope_now = Utc::now();
        qb.push_values(member_dids.iter(), |mut b, did| {
            b.push_bind(uuid::Uuid::new_v4().to_string())
                .push_bind(&convo_id)
                .push_bind(did)
                .push_bind(&row_id)
                .push_bind(envelope_now);
        });
        qb.push(" ON CONFLICT (recipient_did, message_id) DO NOTHING");
        qb.build().execute(&mut *tx).await.map_err(|e| {
            error!("❌ [v2.sendMessage] envelope insert: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    tx.commit().await.map_err(|e| {
        error!("❌ [v2.sendMessage] commit: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!(
        "✅ [v2.sendMessage] message created: msgId={}, seq={}, epoch={}",
        crate::crypto::redact_for_log(&row_id),
        seq,
        store_epoch
    );

    // --- SSE: synchronously enqueue on the per-convo FIFO queue ---
    //
    // Task #39: the enqueue must be synchronous (no `tokio::spawn`) so the
    // hand-off order matches the DB commit order. The consumer task drains
    // per-convo in order, performing store_event + broadcast send atomically.
    let cursor = sse_state.cursor_gen.next(&convo_id, "messageEvent").await;

    let sse_message_view: StreamMessageView =
        crate::generated::blue_catbird::mlsChat::MessageView {
            id: row_id.clone().into(),
            convo_id: convo_id.clone().into(),
            ciphertext: bytes::Bytes::from(ciphertext_vec.clone()),
            epoch: store_epoch,
            seq,
            created_at: crate::sqlx_jacquard::chrono_to_datetime(now),
            message_type: Some("app".into()),
            extra_data: Default::default(),
        }
        .into();

    let sse_event = StreamEvent::MessageEvent {
        cursor: cursor.clone(),
        message: sse_message_view,
        ephemeral: false,
    };

    sse_state.enqueue_with_store(&convo_id, pool.clone(), sse_event);

    // --- Spawn async fan-out (push, federation) ---
    // Push/federation are NOT order-sensitive at the per-convo level, so
    // they remain in a detached spawn. Only the SSE store+emit path needs
    // the FIFO queue (task #39).
    let pool_clone = pool.clone();
    let convo_id_clone = convo_id.clone();
    let msg_id_clone = row_id.clone();
    let ciphertext_for_push = ciphertext_vec;
    let sender_did_clone = auth_user.did.clone();
    let epoch_for_sse = store_epoch;
    let sequencer_term_for_federation = server_sequencer_term.max(0) as u64;
    let federation_delivery_id = ulid::Ulid::new().to_string();

    tokio::spawn(async move {
        let fanout_start = std::time::Instant::now();

        // Push notifications
        if let Some(ns) = notification_service.as_ref() {
            if let Err(e) = ns
                .notify_new_message(
                    &pool_clone,
                    &convo_id_clone,
                    &msg_id_clone,
                    &ciphertext_for_push,
                    &sender_did_clone,
                    seq,
                    epoch_for_sse,
                )
                .await
            {
                error!("❌ [v2.sendMessage:push] {}", e);
                metrics::counter!("fanout_failures_total", 1, "stage" => "push_notification");
            }
        }

        // Federation
        if federation_config.enabled {
            if let Ok(true) = federated_backend.is_sequencer(&convo_id_clone).await {
                use base64::Engine;
                let ciphertext_b64 =
                    base64::engine::general_purpose::STANDARD.encode(&ciphertext_for_push);
                let deliver_payload = serde_json::json!({
                    "convoId": &convo_id_clone,
                    "msgId": &msg_id_clone,
                    "deliveryId": &federation_delivery_id,
                    "sequencerTerm": sequencer_term_for_federation,
                    "epoch": epoch_for_sse,
                    "senderDsDid": &federation_config.self_did,
                    "ciphertext": { "$bytes": ciphertext_b64 },
                    "paddedSize": padded_size as i64,
                    "messageType": "app"
                });
                let payload_bytes = match serde_json::to_vec(&deliver_payload) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(convo_id = %crate::crypto::redact_for_log(&convo_id_clone), error = %e, "federation serialize failed");
                        return;
                    }
                };

                match federated_backend
                    .get_participant_ds_dids(&convo_id_clone)
                    .await
                {
                    Ok(ds_dids) => {
                        for ds_did in ds_dids {
                            if crate::identity::dids_equivalent(
                                &ds_did,
                                &federation_config.self_did,
                            ) {
                                continue;
                            }
                            if let Err(e) = outbound_queue
                                .enqueue(
                                    &ds_did,
                                    "",
                                    "blue.catbird.mlsDS.deliverMessage",
                                    &payload_bytes,
                                    &convo_id_clone,
                                    "initial enqueue",
                                )
                                .await
                            {
                                tracing::warn!(
                                    convo_id = %crate::crypto::redact_for_log(&convo_id_clone),
                                    target_ds = %crate::crypto::redact_for_log(&ds_did),
                                    error = %e,
                                    "federation outbound enqueue failed (non-fatal)"
                                );
                                metrics::counter!("fanout_failures_total", 1, "stage" => "federation_outbound");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(convo_id = %crate::crypto::redact_for_log(&convo_id_clone), error = %e, "get participant DS DIDs failed (non-fatal)");
                        metrics::counter!("fanout_failures_total", 1, "stage" => "federation_outbound");
                    }
                }
            }
        }

        let fanout_duration = fanout_start.elapsed();
        crate::metrics::record_envelope_write_duration(&convo_id_clone, fanout_duration);
    });

    info!("✅ [v2.sendMessage] COMPLETE");

    Ok(Json(SendMessageOutput {
        message_id: row_id.into(),
        received_at: crate::sqlx_jacquard::chrono_to_datetime(now),
        seq,
        epoch: store_epoch,
        extra_data: Default::default(),
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// Typing indicator (ephemeral, no DB)
// ---------------------------------------------------------------------------

async fn handle_typing(
    pool: DbPool,
    sse_state: Arc<SseState>,
    auth_user: AuthUser,
    input: &crate::generated::blue_catbird::mlsChat::send_message::SendMessage<'_>,
    is_typing: bool,
) -> Result<Response, StatusCode> {
    let convo_id = input.convo_id.to_string();
    let user_did = auth_user.did.clone();

    // Check membership
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL)",
    )
    .bind(&convo_id)
    .bind(&user_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.sendMessage:typing] membership check: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        error!("❌ [v2.sendMessage:typing] Not a member");
        return Err(StatusCode::FORBIDDEN);
    }

    // SSE event (no DB persistence for typing indicators)
    let cursor = sse_state.cursor_gen.next(&convo_id, "typingEvent").await;
    let event = StreamEvent::TypingEvent {
        cursor: cursor.clone(),
        convo_id: convo_id.clone(),
        did: user_did,
        is_typing,
    };

    if let Err(e) = sse_state.emit(&convo_id, event).await {
        error!("❌ [v2.sendMessage:typing] SSE emit: {}", e);
    }

    let now = Utc::now();
    let msg_id = input.msg_id.to_string();
    let received_bucket_ts = (now.timestamp() / 2) * 2;
    let received_at = chrono::DateTime::from_timestamp(received_bucket_ts, 0).unwrap_or(now);
    Ok(Json(SendMessageOutput {
        message_id: msg_id.into(),
        received_at: crate::sqlx_jacquard::chrono_to_datetime(received_at),
        seq: 0,
        epoch: input.epoch,
        extra_data: Default::default(),
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::MAX_EPOCH_DRIFT;

    #[test]
    fn max_epoch_drift_is_reasonable() {
        assert!(MAX_EPOCH_DRIFT > 0);
        assert!(MAX_EPOCH_DRIFT <= 10_000);
    }
}
