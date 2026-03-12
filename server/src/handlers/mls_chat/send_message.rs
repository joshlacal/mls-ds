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

fn resolve_stored_epoch(client_epoch: i64, server_epoch: i64) -> i64 {
    if client_epoch != server_epoch {
        client_epoch
    } else {
        client_epoch
    }
}

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
///   - `"addReaction"`    → insert reaction + SSE
///   - `"removeReaction"` → delete reaction + SSE
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
                "addReaction" => handle_add_reaction(pool, sse_state, auth_user, &input)
                    .await?
                    .into_response(),
                "removeReaction" => handle_remove_reaction(pool, sse_state, auth_user, &input)
                    .await?
                    .into_response(),
                "typingStop" | "stopTyping" => {
                    handle_typing(pool, sse_state, auth_user, &input, false)
                        .await?
                        .into_response()
                }
                "typing" | "typingStart" => {
                    handle_typing(pool, sse_state, auth_user, &input, true)
                        .await?
                        .into_response()
                }
                other => {
                    warn!(
                        "❌ [v2.sendMessage] Unknown ephemeral action '{}', defaulting to typing start",
                        other
                    );
                    handle_typing(pool, sse_state, auth_user, &input, true)
                        .await?
                        .into_response()
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
    let idempotency_key: Option<String> = None; // msgId now serves as the idempotency key

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

    // --- Fetch conversation epoch and sequencer term ---
    let (server_epoch, server_sequencer_term): (i64, i64) = sqlx::query_as(
        "SELECT CAST(current_epoch AS BIGINT), CAST(COALESCE(sequencer_term, 0) AS BIGINT) \
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

    let client_epoch = input.epoch;
    let store_epoch = if client_epoch != server_epoch {
        // Log the mismatch but trust the client's epoch. The client knows what MLS epoch
        // it encrypted at. The server's current_epoch can be stale (e.g. after createConvo
        // + addMembers race, or if the client processed commits the server hasn't tracked).
        // Overriding with server_epoch caused EPOCH-SKIP on the receiver side.
        tracing::warn!(
            target: "mls_epoch",
            convo_id = %crate::crypto::redact_for_log(&convo_id),
            server_epoch, client_epoch,
            "accepting app message with {} epoch (server={}, client={})",
            if client_epoch < server_epoch { "stale" } else { "future" },
            server_epoch, client_epoch
        );
        resolve_stored_epoch(client_epoch, server_epoch)
    } else {
        resolve_stored_epoch(client_epoch, server_epoch)
    };

    // --- Insert message in a transaction (seq via MAX+1) ---
    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(30);
    let received_bucket_ts = (now.timestamp() / 2) * 2;

    let mut tx = pool.begin().await.map_err(|e| {
        error!("❌ [v2.sendMessage] begin tx: {}", e);
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

    // Dedup by idempotency_key
    if let Some(ref idem_key) = idempotency_key {
        let existing_idem: Option<(String, i64, i64, chrono::DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, CAST(seq AS BIGINT), CAST(epoch AS BIGINT), created_at FROM messages WHERE idempotency_key = $1",
        )
        .bind(idem_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            error!("❌ [v2.sendMessage] idempotency check: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if let Some((eid, eseq, eepoch, eat)) = existing_idem {
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
            msg_id, padded_size, received_bucket_ts, idempotency_key
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
    .bind(&idempotency_key)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("❌ [v2.sendMessage] insert message: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

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

    // --- Spawn async fan-out (envelopes, SSE, push, federation) ---
    let pool_clone = pool.clone();
    let convo_id_clone = convo_id.clone();
    let msg_id_clone = row_id.clone();
    let sse_state_clone = sse_state.clone();
    let ciphertext_for_sse = ciphertext_vec.clone();
    let ciphertext_for_push = ciphertext_vec;
    let sender_did_clone = auth_user.did.clone();
    let epoch_for_sse = store_epoch;
    let sequencer_term_for_federation = server_sequencer_term.max(0) as u64;
    let federation_delivery_id = ulid::Ulid::new().to_string();

    tokio::spawn(async move {
        let fanout_start = std::time::Instant::now();

        // Fan-out envelopes
        let members_result = sqlx::query_scalar::<_, String>(
            "SELECT member_did FROM members WHERE convo_id = $1 AND left_at IS NULL",
        )
        .bind(&convo_id_clone)
        .fetch_all(&pool_clone)
        .await;

        match members_result {
            Ok(member_dids) => {
                if !member_dids.is_empty() {
                    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
                        "INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at) ",
                    );
                    let envelope_now = Utc::now();
                    qb.push_values(member_dids.iter(), |mut b, did| {
                        b.push_bind(uuid::Uuid::new_v4().to_string())
                            .push_bind(&convo_id_clone)
                            .push_bind(did)
                            .push_bind(&msg_id_clone)
                            .push_bind(envelope_now);
                    });
                    qb.push(" ON CONFLICT (recipient_did, message_id) DO NOTHING");
                    if let Err(e) = qb.build().execute(&pool_clone).await {
                        error!("❌ [v2.sendMessage:fanout] envelope insert: {:?}", e);
                    }
                }

                let fanout_duration = fanout_start.elapsed();
                crate::metrics::record_envelope_write_duration(&convo_id_clone, fanout_duration);
            }
            Err(e) => {
                error!("❌ [v2.sendMessage:fanout] get members: {:?}", e);
            }
        }

        // SSE event
        let cursor = sse_state_clone
            .cursor_gen
            .next(&convo_id_clone, "messageEvent")
            .await;

        let message_view: StreamMessageView =
            crate::generated::blue_catbird::mlsChat::MessageView {
                id: msg_id_clone.clone().into(),
                convo_id: convo_id_clone.clone().into(),
                ciphertext: bytes::Bytes::from(ciphertext_for_sse),
                epoch: epoch_for_sse,
                seq,
                created_at: crate::sqlx_jacquard::chrono_to_datetime(now),
                message_type: Some("app".into()),
                extra_data: Default::default(),
            }
            .into();

        let event = StreamEvent::MessageEvent {
            cursor: cursor.clone(),
            message: message_view,
            ephemeral: false,
        };

        // Store event for cursor-based replay
        if let Err(e) = crate::db::store_event(
            &pool_clone,
            &cursor,
            &convo_id_clone,
            "messageEvent",
            Some(&msg_id_clone),
        )
        .await
        {
            error!("❌ [v2.sendMessage:fanout] store event: {:?}", e);
        }

        if let Err(e) = sse_state_clone.emit(&convo_id_clone, event).await {
            error!("❌ [v2.sendMessage:fanout] SSE emit: {}", e);
        }

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
                        tracing::warn!(convo_id = %convo_id_clone, error = %e, "federation serialize failed");
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
                                    convo_id = %convo_id_clone,
                                    target_ds = %crate::crypto::redact_for_log(&ds_did),
                                    error = %e,
                                    "federation outbound enqueue failed (non-fatal)"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(convo_id = %convo_id_clone, error = %e, "get participant DS DIDs failed (non-fatal)");
                    }
                }
            }
        }
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
// Add reaction (ephemeral)
// ---------------------------------------------------------------------------

async fn handle_add_reaction(
    pool: DbPool,
    sse_state: Arc<SseState>,
    auth_user: AuthUser,
    input: &crate::generated::blue_catbird::mlsChat::send_message::SendMessage<'_>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let convo_id = input.convo_id.to_string();
    let target_msg = input
        .target_message_id
        .as_deref()
        .unwrap_or_default()
        .to_string();
    let emoji = input
        .reaction_emoji
        .as_deref()
        .unwrap_or_default()
        .to_string();
    let user_did = auth_user.did.clone();

    if emoji.is_empty() || emoji.len() > 16 {
        error!("❌ [v2.sendMessage:addReaction] Invalid reaction length");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check membership
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL)",
    )
    .bind(&convo_id)
    .bind(&user_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.sendMessage:addReaction] membership check: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        error!("❌ [v2.sendMessage:addReaction] Not a member");
        return Err(StatusCode::FORBIDDEN);
    }

    // Check message exists
    let msg_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM messages WHERE convo_id = $1 AND id = $2)")
            .bind(&convo_id)
            .bind(&target_msg)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("❌ [v2.sendMessage:addReaction] msg existence: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    if !msg_exists {
        error!("❌ [v2.sendMessage:addReaction] Message not found");
        return Err(StatusCode::NOT_FOUND);
    }

    let now = Utc::now();

    // Insert reaction
    let result = sqlx::query(
        r#"INSERT INTO message_reactions (convo_id, message_id, user_did, reaction, created_at)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (convo_id, message_id, user_did, reaction) DO NOTHING"#,
    )
    .bind(&convo_id)
    .bind(&target_msg)
    .bind(&user_did)
    .bind(&emoji)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.sendMessage:addReaction] insert: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::CONFLICT);
    }

    // SSE event
    let cursor = sse_state.cursor_gen.next(&convo_id, "reactionEvent").await;
    let event = StreamEvent::ReactionEvent {
        cursor: cursor.clone(),
        convo_id: convo_id.clone(),
        message_id: target_msg.clone(),
        did: user_did.clone(),
        reaction: emoji.clone(),
        action: "add".to_string(),
    };

    if let Err(e) = crate::db::store_reaction_event(
        &pool,
        &cursor,
        &convo_id,
        &target_msg,
        &user_did,
        &emoji,
        "add",
    )
    .await
    {
        error!("❌ [v2.sendMessage:addReaction] store event: {:?}", e);
    }

    if let Err(e) = sse_state.emit(&convo_id, event).await {
        error!("❌ [v2.sendMessage:addReaction] SSE emit: {}", e);
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "reactedAt": now.to_rfc3339(),
    })))
}

// ---------------------------------------------------------------------------
// Remove reaction (ephemeral)
// ---------------------------------------------------------------------------

async fn handle_remove_reaction(
    pool: DbPool,
    sse_state: Arc<SseState>,
    auth_user: AuthUser,
    input: &crate::generated::blue_catbird::mlsChat::send_message::SendMessage<'_>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let convo_id = input.convo_id.to_string();
    let target_msg = input
        .target_message_id
        .as_deref()
        .unwrap_or_default()
        .to_string();
    let emoji = input
        .reaction_emoji
        .as_deref()
        .unwrap_or_default()
        .to_string();
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
        error!("❌ [v2.sendMessage:removeReaction] membership check: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        error!("❌ [v2.sendMessage:removeReaction] Not a member");
        return Err(StatusCode::FORBIDDEN);
    }

    // Delete reaction
    let result = sqlx::query(
        "DELETE FROM message_reactions WHERE convo_id = $1 AND message_id = $2 AND user_did = $3 AND reaction = $4",
    )
    .bind(&convo_id)
    .bind(&target_msg)
    .bind(&user_did)
    .bind(&emoji)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.sendMessage:removeReaction] delete: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if result.rows_affected() == 0 {
        error!("❌ [v2.sendMessage:removeReaction] Reaction not found");
        return Err(StatusCode::NOT_FOUND);
    }

    // SSE event
    let cursor = sse_state.cursor_gen.next(&convo_id, "reactionEvent").await;
    let event = StreamEvent::ReactionEvent {
        cursor: cursor.clone(),
        convo_id: convo_id.clone(),
        message_id: target_msg.clone(),
        did: user_did.clone(),
        reaction: emoji.clone(),
        action: "remove".to_string(),
    };

    if let Err(e) = crate::db::store_reaction_event(
        &pool,
        &cursor,
        &convo_id,
        &target_msg,
        &user_did,
        &emoji,
        "remove",
    )
    .await
    {
        error!("❌ [v2.sendMessage:removeReaction] store event: {:?}", e);
    }

    if let Err(e) = sse_state.emit(&convo_id, event).await {
        error!("❌ [v2.sendMessage:removeReaction] SSE emit: {}", e);
    }

    Ok(Json(serde_json::json!({"success": true})))
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
) -> Result<Json<serde_json::Value>, StatusCode> {
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

    Ok(Json(
        serde_json::json!({"success": true, "isTyping": is_typing}),
    ))
}

#[cfg(test)]
mod tests {
    use super::resolve_stored_epoch;

    #[test]
    fn resolve_stored_epoch_prefers_client_epoch_on_mismatch() {
        assert_eq!(resolve_stored_epoch(1, 0), 1);
    }

    #[test]
    fn resolve_stored_epoch_keeps_matching_epoch() {
        assert_eq!(resolve_stored_epoch(4, 4), 4);
    }
}
