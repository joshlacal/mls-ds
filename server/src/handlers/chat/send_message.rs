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
    let body_json: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    let signed_req = body_json.as_ref()
        .and_then(|v| v.get("signedRequest"))
        .unwrap_or(body_json.as_ref().unwrap_or(&serde_json::Value::Null));

    let convo_id_from_body: Option<uuid::Uuid> = signed_req.pointer("/body/prior/conversationId")
        .or_else(|| signed_req.pointer("/body/conversationId"))
        .and_then(|v| {
            if let Some(s) = v.as_str() {
                uuid::Uuid::parse_str(s).ok()
                    .or_else(|| {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.decode(s).ok().and_then(|b| {
                            if b.len() == 16 {
                                Some(uuid::Uuid::from_bytes(b.try_into().unwrap()))
                            } else {
                                None
                            }
                        })
                    })
            } else if let Some(b64) = v.pointer("/$bytes").and_then(|b| b.as_str()) {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.decode(b64).ok().and_then(|b| {
                    if b.len() == 16 {
                        Some(uuid::Uuid::from_bytes(b.try_into().unwrap()))
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        })
        .or_else(|| {
            signed_req.pointer("/body/aad/conversationId").and_then(|v| {
                if let Some(s) = v.as_str() {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.decode(s).ok().and_then(|b| {
                        if b.len() == 16 {
                            Some(uuid::Uuid::from_bytes(b.try_into().unwrap()))
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
        });

    if let Some(convo_id) = convo_id_from_body {
        let is_local_convo: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id = $1)"
        )
        .bind(convo_id)
        .fetch_one(pool)
        .await
        .unwrap_or(false);

        if !is_local_convo {
            let any_inbox: Option<(String, String)> = sqlx::query_as(
                "SELECT sender_did, recipient_did \
                 FROM chat.direct_request_transport_inbox \
                 WHERE conversation_id = $1 \
                 LIMIT 1"
            )
            .bind(convo_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?;

            if any_inbox.is_none() {
                return Err(ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::ConversationNotFound));
            }

            // Actor-pair and device binding before relaying
            let authenticated_did = admission.subject();
            let actor_did = signed_req.pointer("/body/actorDid").and_then(|v| v.as_str()).unwrap_or_default();
            if actor_did != authenticated_did {
                return Err(ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::NotAuthorized));
            }

            let is_participant: bool = sqlx::query_scalar(
                "SELECT EXISTS( \
                    SELECT 1 FROM chat.direct_request_transport_inbox \
                    WHERE conversation_id = $1 AND (sender_did = $2 OR recipient_did = $2) \
                 )"
            )
            .bind(convo_id)
            .bind(actor_did)
            .fetch_one(pool)
            .await
            .unwrap_or(false);

            if !is_participant {
                return Err(ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::NotAuthorized));
            }

            let actor_device_str = signed_req.pointer("/body/actorDeviceId").and_then(|v| v.as_str()).unwrap_or_default();
            let actor_device_uuid = uuid::Uuid::parse_str(actor_device_str)
                .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;

            // Entitlement check by owner and device before LIMIT 1
            let inbox_info: Option<(String, String, Option<uuid::Uuid>, String, uuid::Uuid, String)> = sqlx::query_as(
                "SELECT coordinator_did, sender_did, sender_device_id, recipient_did, recipient_device_id, status \
                 FROM chat.direct_request_transport_inbox \
                 WHERE conversation_id = $1 \
                   AND ( \
                     (recipient_did = $2 AND recipient_device_id = $3) \
                     OR (sender_did = $2 AND (sender_device_id IS NULL OR sender_device_id = $3)) \
                   ) \
                 LIMIT 1"
            )
            .bind(convo_id)
            .bind(actor_did)
            .bind(actor_device_uuid)
            .fetch_optional(pool)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?;

            let Some((coord_did, sender_did, sender_device_id, recipient_did, recipient_device_id, status)) = inbox_info else {
                return Err(ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::NotEntitled));
            };

            // Durable acceptance check
            if status != "accepted" {
                return Err(ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::ConversationNotAccepted));
            }
            // Stable idempotent retry check: if message already committed, return cached entry
            let message_id_str = signed_req.pointer("/body/messageId").and_then(|v| v.as_str());
            if let Some(msg_id_str) = message_id_str {
                let existing_entries: Vec<Vec<u8>> = sqlx::query_scalar(
                    "SELECT entry_bytes FROM chat.direct_request_transport_entries \
                     WHERE conversation_id = $1 \
                     ORDER BY seq DESC"
                )
                .bind(convo_id)
                .fetch_all(pool)
                .await
                .map_err(|_| ChatFailure::storage(ENDPOINT))?;

                for e_bytes in existing_entries {
                    if let Ok(mut entry_val) = serde_json::from_slice::<serde_json::Value>(&e_bytes) {
                        if entry_val.pointer("/signedRequest/body/messageId").and_then(|v| v.as_str()) == Some(msg_id_str) {
                            if entry_val.get("signedRequest") != Some(signed_req) {
                                return Err(ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::IdempotencyConflict));
                            }
                            entry_val.as_object_mut().ok_or_else(|| ChatFailure::invariant(ENDPOINT))?.remove("$type");
                            let resp_val = serde_json::json!({ "entry": entry_val });
                            let response_bytes = serde_json::to_vec(&resp_val)
                                .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
                            return context::canonical_json_response(ENDPOINT, 200, response_bytes);
                        }
                    }
                }
            }

            // Resolve coordinator using the conversation participants (sender_did, recipient_did)
            let coord = crate::federation::canonical_relay::resolve_pair_coordinator(pool, &sender_did, &recipient_did)
                .await
                .map_err(|_| ChatFailure::storage(ENDPOINT))?;
            if crate::identity::canonical_did(&coord.coordinator_did) != crate::identity::canonical_did(&coord_did) {
                return Err(ChatFailure::invariant(ENDPOINT));
            }

            let relay_payload = crate::federation::canonical_relay::RelaySendMessageInput {
                conversation_id: convo_id,
                message: signed_req.clone(),
            };

            let result = crate::federation::canonical_relay::relay_message_to_coordinator(
                coord.coordinator_endpoint(),
                &coord_did,
                relay_payload,
            )
            .await
            .map_err(|e| {
                tracing::error!("relay_message_to_coordinator failed: {:?}", e);
                ChatFailure::storage(ENDPOINT)
            })?;

            let entry = result.get("entry").ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
            if entry.get("signedRequest") != Some(signed_req) {
                return Err(ChatFailure::invariant(ENDPOINT));
            }
            crate::federation::canonical_relay::ingest_remote_message_entry(
                pool, None, &coord_did, convo_id, entry,
            ).await.map_err(|error| {
                tracing::error!(?error, "Invalid coordinator application entry");
                ChatFailure::storage(ENDPOINT)
            })?;

            let mut result = result;
            result["entry"].as_object_mut().ok_or_else(|| ChatFailure::invariant(ENDPOINT))?.remove("$type");
            let response_bytes = serde_json::to_vec(&result)
                .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
            return context::canonical_json_response(ENDPOINT, 200, response_bytes);
        }
    }

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
            let actor_did = signed_req.pointer("/body/actorDid").and_then(|v| v.as_str()).unwrap_or_default();
            deliver_message_entry_to_remote_peers(pool, actor_did, replay.response_bytes()).await?;
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
            deliver_message_entry_to_remote_peers(pool, authority.subject().as_str(), &response_bytes).await?;

            context::canonical_json_response(ENDPOINT, 200, response_bytes)
        }
    }
}

async fn deliver_message_entry_to_remote_peers(
    pool: &DbPool,
    actor_did: &str,
    response_bytes: &[u8],
) -> Result<(), ChatFailure> {
    let response: serde_json::Value = serde_json::from_slice(response_bytes)
        .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let entry = response.get("entry").ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let convo_id = entry["conversationId"].as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let entry_id = entry["entryId"].as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let conversation_routing: Option<(String, bool)> =
        sqlx::query_as("SELECT kind, is_remote FROM chat.conversations WHERE conversation_id = $1")
            .bind(convo_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    match conversation_routing
        .as_ref()
        .map(|(kind, remote)| (kind.as_str(), *remote))
    {
        // Only the local sequencer enqueues ordinary group delivery. Apply the
        // same authority rule to completed replay before reporting success.
        Some(("group", false)) => return Ok(()),
        Some(("group", true)) => {
            return Err(ChatFailure::protocol(
                ENDPOINT,
                ChatProtocolErrorCode::NotAuthorized,
            ));
        }
        Some(("direct", _)) => {}
        _ => return Err(ChatFailure::invariant(ENDPOINT)),
    }
    let participants: Vec<String> = sqlx::query_scalar(
        "SELECT user_did FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(convo_id)
    .fetch_all(pool)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    for other_did in &participants {
        if crate::identity::canonical_did(other_did) == crate::identity::canonical_did(actor_did) {
            continue;
        }
        let coord = crate::federation::canonical_relay::resolve_pair_coordinator(
            pool, actor_did, other_did,
        ).await.map_err(|error| {
            tracing::error!(?error, "Failed to resolve application entry peer");
            ChatFailure::storage(ENDPOINT)
        })?;
        let (target_endpoint, target_did) = if coord.is_coordinator {
            (coord.recipient_home.endpoint.as_str(), coord.recipient_home.did.as_str())
        } else {
            (coord.coordinator_endpoint(), coord.coordinator_did.as_str())
        };
        if crate::identity::canonical_did(target_did) == crate::identity::canonical_did(&crate::identity::service_did()) {
            continue;
        }
        let mut typed_entry = entry.clone();
        typed_entry["$type"] = serde_json::json!("blue.catbird.chat.defs#applicationEntry");
        let delivery = crate::federation::canonical_relay::DeliverMessageEntryInput {
            conversation_id: convo_id,
            entry: typed_entry,
        };
        if let Err(error) = crate::federation::canonical_relay::deliver_message_entry_to_peer(
            target_endpoint, target_did, delivery.clone(),
        ).await {
            tracing::warn!(?error, "Failed to deliver application entry to peer, queueing for retry");
            sqlx::query(
                "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, last_error, next_retry_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() + INTERVAL '5 seconds') \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(format!("message-delivery-{entry_id}-{}", crate::identity::canonical_did(target_did)))
            .bind(target_did)
            .bind(target_endpoint)
            .bind("blue.catbird.mlsDS.deliverMessageEntry")
            .bind(serde_json::to_vec(&delivery).map_err(|_| ChatFailure::invariant(ENDPOINT))?)
            .bind(convo_id.to_string())
            .bind(error.to_string())
            .execute(pool)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?;
            return Err(ChatFailure::storage(ENDPOINT));
        }
    }
    Ok(())
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
        MessageDeliveryError::NotAuthorized => ChatFailure::protocol(ENDPOINT, C::NotAuthorized),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_failure_maps_conversation_not_accepted() {
        let failure = map_failure(MessageDeliveryError::ConversationNotAccepted);
        assert_eq!(
            failure.code(),
            Some(ChatProtocolErrorCode::ConversationNotAccepted)
        );
    }

    #[test]
    fn map_failure_maps_device_not_leaf() {
        let failure = map_failure(MessageDeliveryError::DeviceNotLeaf);
        assert_eq!(failure.code(), Some(ChatProtocolErrorCode::DeviceNotLeaf));
    }

    #[test]
    fn map_failure_maps_invalid_coordinates() {
        let failure = map_failure(MessageDeliveryError::InvalidCoordinates);
        assert_eq!(failure.code(), Some(ChatProtocolErrorCode::StaleCoordinates));
    }
}
