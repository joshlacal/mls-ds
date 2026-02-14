use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tracing::{error, warn};

use crate::{
    actors::ActorRegistry, auth::AuthUser, federation,
    generated::blue_catbird::mlsChat::send_message::SendMessageRequest,
    notifications::NotificationService, realtime::SseState, storage::DbPool,
};
use base64::Engine;

const NSID: &str = "blue.catbird.mlsChat.sendMessage";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Consolidated message sending endpoint.
///
/// POST /xrpc/blue.catbird.mlsChat.sendMessage
///
/// Dispatches based on `delivery` field:
/// - `"persistent"` (default) → delegates to existing `send_message`
/// - `"ephemeral"` + `action` → further dispatches on action:
///   - `"addReaction"`   → delegates to existing `add_reaction`
///   - `"removeReaction"` → delegates to existing `remove_reaction`
///   - default           → delegates to existing `send_typing_indicator`
#[tracing::instrument(skip(
    pool,
    sse_state,
    actor_registry,
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
    State(actor_registry): State<Arc<ActorRegistry>>,
    State(notification_service): State<Option<Arc<NotificationService>>>,
    State(federated_backend): State<Arc<federation::FederatedBackend>>,
    State(federation_config): State<federation::FederationConfig>,
    State(outbound_queue): State<Arc<federation::queue::OutboundQueue>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<SendMessageRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [v2.sendMessage] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let delivery = input.delivery.as_deref().unwrap_or("persistent");

    match delivery {
        "persistent" => {
            let convo_id = input.convo_id.to_string();
            let msg_id = input.msg_id.to_string();
            let epoch = input.epoch as usize;
            let padded_size = input.padded_size as usize;
            let idempotency_key = input.idempotency_key.as_ref().map(|k| k.to_string());

            let v1_body = serde_json::json!({
                "convoId": convo_id,
                "ciphertext": { "$bytes": base64::engine::general_purpose::STANDARD.encode(&input.ciphertext) },
                "epoch": epoch,
                "paddedSize": padded_size,
                "msgId": msg_id,
                "idempotencyKey": idempotency_key,
            });

            let v1_body_str = v1_body.to_string();
            let v1_input: crate::generated::blue_catbird::mls::send_message::SendMessage<'static> = {
                use jacquard_common::IntoStatic;
                let parsed: crate::generated::blue_catbird::mls::send_message::SendMessage =
                    serde_json::from_str(&v1_body_str).map_err(|e| {
                        warn!("❌ [v2.sendMessage] Failed to construct v1 input: {}", e);
                        StatusCode::BAD_REQUEST
                    })?;
                parsed.into_static()
            };

            let result = crate::handlers::send_message(
                State(pool),
                State(sse_state),
                State(actor_registry),
                State(notification_service),
                State(federated_backend),
                State(federation_config),
                State(outbound_queue),
                auth_user,
                serde_json::to_string(&v1_input).unwrap(),
            )
            .await?;
            Ok(Json(serde_json::to_value(result.0).unwrap()))
        }

        "ephemeral" => {
            let convo_id = input.convo_id.to_string();
            let action = input.action.as_deref().unwrap_or("typing");

            match action {
                "addReaction" => {
                    let target_msg = input.target_message_id.as_deref().unwrap_or_default();
                    let emoji = input.reaction_emoji.as_deref().unwrap_or_default();

                    let v1_body = serde_json::json!({
                        "convoId": convo_id,
                        "messageId": target_msg,
                        "reaction": emoji,
                    });

                    let v1_input: crate::handlers::add_reaction::AddReactionInput =
                        serde_json::from_value(v1_body).map_err(|e| {
                            warn!(
                                "❌ [v2.sendMessage] Failed to construct addReaction input: {}",
                                e
                            );
                            StatusCode::BAD_REQUEST
                        })?;

                    let result = crate::handlers::add_reaction(
                        State(pool),
                        State(sse_state),
                        auth_user,
                        Json(v1_input),
                    )
                    .await?;

                    Ok(Json(
                        serde_json::to_value(result.0)
                            .unwrap_or(serde_json::json!({"success": true})),
                    ))
                }

                "removeReaction" => {
                    let target_msg = input.target_message_id.as_deref().unwrap_or_default();
                    let emoji = input.reaction_emoji.as_deref().unwrap_or_default();

                    let v1_body = serde_json::json!({
                        "convoId": convo_id,
                        "messageId": target_msg,
                        "reaction": emoji,
                    });

                    let v1_input: crate::handlers::remove_reaction::RemoveReactionInput =
                        serde_json::from_value(v1_body).map_err(|e| {
                            warn!(
                                "❌ [v2.sendMessage] Failed to construct removeReaction input: {}",
                                e
                            );
                            StatusCode::BAD_REQUEST
                        })?;

                    let result = crate::handlers::remove_reaction(
                        State(pool),
                        State(sse_state),
                        auth_user,
                        Json(v1_input),
                    )
                    .await?;

                    Ok(Json(
                        serde_json::to_value(result.0)
                            .unwrap_or(serde_json::json!({"success": true})),
                    ))
                }

                _ => {
                    // Default ephemeral: typing indicator
                    let v1_body = serde_json::json!({
                        "convoId": convo_id,
                        "isTyping": true,
                    });

                    let v1_input: crate::handlers::send_typing_indicator::SendTypingIndicatorInput =
                        serde_json::from_value(v1_body).map_err(|e| {
                            warn!(
                                "❌ [v2.sendMessage] Failed to construct typing input: {}",
                                e
                            );
                            StatusCode::BAD_REQUEST
                        })?;

                    let result = crate::handlers::send_typing_indicator(
                        State(pool),
                        State(sse_state),
                        auth_user,
                        Json(v1_input),
                    )
                    .await?;

                    Ok(Json(
                        serde_json::to_value(result.0)
                            .unwrap_or(serde_json::json!({"success": true})),
                    ))
                }
            }
        }

        other => {
            warn!("❌ [v2.sendMessage] Unknown delivery mode: {}", other);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
