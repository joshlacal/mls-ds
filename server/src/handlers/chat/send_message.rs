//! `blue.catbird.chat.sendMessage` clean procedure.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};
use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::{
            message_delivery::{self, MessageDeliveryError},
            prelude::{self, PreparedChatAdmission},
        },
    },
    storage::DbPool,
};

const ENDPOINT: ChatEndpoint = ChatEndpoint::SendMessage;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    send(&pool, &runtime, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn send(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_signed_operation_only(pool, runtime, ENDPOINT, headers, body).await?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let prepared = prelude::prepare_chat_admission(&mut tx, admission)
        .await
        .map_err(|e| context::operation_prelude_failure(ENDPOINT, e))?;
    match prepared {
        PreparedChatAdmission::Replay(replay) => {
            let response = context::replay_response(ENDPOINT, &replay)?;
            tx.commit()
                .await
                .map_err(|_| ChatFailure::storage(ENDPOINT))?;
            Ok(response)
        }
        PreparedChatAdmission::First(first) => {
            let (authority, scope, completion) = first.into_execution_parts();
            let (response_bytes, event_position) = message_delivery::send(
                &mut tx,
                &authority,
                &scope,
                runtime.relationship_authority().as_ref(),
            )
            .await
            .map_err(|e| {
                tracing::error!("message_delivery::send error: {:?}", e);
                map_failure(e)
            })?;
            prelude::complete_operation(
                &mut tx,
                &authority,
                scope,
                completion,
                200,
                &response_bytes,
                event_position,
            )
            .await
            .map_err(|e| {
                tracing::error!("complete_operation error: {:?}", e);
                context::operation_prelude_failure(ENDPOINT, e)
            })?;
            tx.commit().await.map_err(|e| {
                tracing::error!("tx.commit error: {:?}", e);
                ChatFailure::storage(ENDPOINT)
            })?;

            if let Ok(resp_val) = serde_json::from_slice::<serde_json::Value>(&response_bytes) {
                if let Some(entry_obj) = resp_val.get("entry") {
                    if let Some(convo_str) = entry_obj["conversationId"].as_str() {
                        if let Ok(convo_id) = uuid::Uuid::parse_str(convo_str) {
                            let participants: Vec<String> = sqlx::query_scalar("SELECT user_did FROM chat.participants WHERE conversation_id = $1 AND current_membership")
                                .bind(convo_id)
                                .fetch_all(pool)
                                .await
                                .unwrap_or_default();

                            for other_did in &participants {
                                if other_did != authority.subject().as_str() {
                                    if let Ok(coord) = crate::federation::canonical_relay::resolve_pair_coordinator(pool, authority.subject().as_str(), other_did).await {
                                        let target_endpoint = if coord.is_coordinator {
                                            &coord.recipient_home.endpoint
                                        } else {
                                            coord.coordinator_endpoint()
                                        };
                                        let target_did = if coord.is_coordinator {
                                            &coord.recipient_home.did
                                        } else {
                                            &coord.coordinator_did
                                        };
                                        let deliver_payload = crate::federation::canonical_relay::DeliverMessageEntryInput {
                                            conversation_id: convo_id,
                                            entry: entry_obj.clone(),
                                        };
                                        let _ = crate::federation::canonical_relay::deliver_message_entry_to_peer(
                                            target_endpoint,
                                            target_did,
                                            deliver_payload,
                                        ).await;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            context::canonical_json_response(ENDPOINT, 200, response_bytes)
        }
    }
}

fn map_failure(error: MessageDeliveryError) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    match &error {
        MessageDeliveryError::Database(e) => {
            tracing::error!("MessageDeliveryError::Database: {:?}", e);
            ChatFailure::storage(ENDPOINT)
        }
        MessageDeliveryError::InvalidApplicationMessage => {
            ChatFailure::protocol(ENDPOINT, C::InvalidApplicationMessage)
        }
        MessageDeliveryError::InvalidCoordinates => {
            ChatFailure::protocol(ENDPOINT, C::StaleCoordinates)
        }
        MessageDeliveryError::ConversationNotFound => {
            ChatFailure::protocol(ENDPOINT, C::ConversationNotFound)
        }
        MessageDeliveryError::ConversationNotAccepted => {
            ChatFailure::protocol(ENDPOINT, C::ConversationNotAccepted)
        }
        MessageDeliveryError::DeviceNotLeaf => ChatFailure::protocol(ENDPOINT, C::DeviceNotLeaf),
        MessageDeliveryError::RecipientNotReady => {
            ChatFailure::protocol(ENDPOINT, C::RecipientNotReady)
        }
        MessageDeliveryError::RelationshipPolicyUnavailable => {
            ChatFailure::protocol(ENDPOINT, C::RelationshipPolicyUnavailable)
        }
        MessageDeliveryError::BlockedRelationship => {
            ChatFailure::protocol(ENDPOINT, C::BlockedRelationship)
        }
        MessageDeliveryError::BlobNotFound => ChatFailure::protocol(ENDPOINT, C::BlobNotFound),
        MessageDeliveryError::BlobBindingConflict => {
            ChatFailure::protocol(ENDPOINT, C::BlobBindingConflict)
        }
        MessageDeliveryError::IdempotencyConflict => {
            ChatFailure::protocol(ENDPOINT, C::IdempotencyConflict)
        }
        MessageDeliveryError::RateLimited | MessageDeliveryError::Invariant => {
            ChatFailure::invariant(ENDPOINT)
        }
    }
}
