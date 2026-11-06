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
            delivery, entry_read,
            message_delivery::{self, MessageDeliveryError},
            prelude::{self, PreparedChatAdmission},
        },
    },
    federation::{group_relay::GroupRelayError, FederationError},
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

async fn is_transport_participant(
    pool: &DbPool,
    conversation_id: uuid::Uuid,
    actor_did: &str,
) -> Result<bool, ChatFailure> {
    sqlx::query_scalar(
        "SELECT EXISTS( \
            SELECT 1 FROM chat.direct_request_transport_inbox \
            WHERE conversation_id = $1 AND (sender_did = $2 OR recipient_did = $2) \
         )",
    )
    .bind(conversation_id)
    .bind(actor_did)
    .fetch_one(pool)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))
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
    let signed_req = body_json
        .as_ref()
        .and_then(|v| v.get("signedRequest"))
        .unwrap_or(body_json.as_ref().unwrap_or(&serde_json::Value::Null));

    let convo_id_from_body: Option<uuid::Uuid> = signed_req
        .pointer("/body/prior/conversationId")
        .or_else(|| signed_req.pointer("/body/conversationId"))
        .and_then(|v| {
            if let Some(s) = v.as_str() {
                uuid::Uuid::parse_str(s).ok().or_else(|| {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD
                        .decode(s)
                        .ok()
                        .and_then(|b| {
                            if b.len() == 16 {
                                Some(uuid::Uuid::from_bytes(b.try_into().unwrap()))
                            } else {
                                None
                            }
                        })
                })
            } else if let Some(b64) = v.pointer("/$bytes").and_then(|b| b.as_str()) {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .ok()
                    .and_then(|b| {
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
            signed_req
                .pointer("/body/aad/conversationId")
                .and_then(|v| {
                    if let Some(s) = v.as_str() {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD
                            .decode(s)
                            .ok()
                            .and_then(|b| {
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
        let local_convo: Option<(String, bool, Option<String>)> = sqlx::query_as(
            "SELECT kind, is_remote, sequencer_ds FROM chat.conversations WHERE conversation_id = $1"
        )
        .bind(convo_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
        let is_local_convo = local_convo.is_some();

        if let Some((kind, true, Some(seq_ds))) = &local_convo {
            // Only its sequencer sequences a remote group: a closed gate decided
            // nothing, and never falls through to the local path.
            if kind == "group" {
                crate::federation::peer_policy::ensure_federation_open()
                    .map_err(|error| GroupRelayError::from_local(error).into_failure(ENDPOINT))?;
            }
            if kind == "group" && runtime.resolver().is_some() {
                let secret = crate::federation::group_relay::configured_group_relay_hmac_secret();
                let can_authenticate_s2s = secret.is_some()
                    || crate::federation::canonical_relay::configured_s2s_signing_key_pem().is_ok();
                if can_authenticate_s2s {
                    let secret_bytes = secret.as_deref().map(str::as_bytes).unwrap_or(&[]);
                    let authenticated_did = admission.subject();
                    let actor_did = signed_req
                        .pointer("/body/actorDid")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    if actor_did != authenticated_did {
                        return Err(ChatFailure::protocol(
                            ENDPOINT,
                            ChatProtocolErrorCode::NotAuthorized,
                        ));
                    }
                    let actor_device_str = signed_req
                        .pointer("/body/actorDeviceId")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let actor_device_uuid =
                        uuid::Uuid::parse_str(actor_device_str).map_err(|_| {
                            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                        })?;
                    let resolver = runtime.resolver().unwrap();
                    let dest = resolver
                        .resolve_ds_destination_uncached(seq_ds)
                        .await
                        .map_err(|error| {
                            GroupRelayError::from_local(error).into_failure(ENDPOINT)
                        })?;
                    let out = crate::federation::group_relay::relay_group_mutation_to_sequencer(
                        dest.url.as_str(),
                        &crate::identity::service_did(),
                        seq_ds,
                        secret_bytes,
                        &crate::federation::group_relay::RelayGroupMutationRequest {
                            conversation_id: convo_id,
                            endpoint: "blue.catbird.chat.sendMessage".to_string(),
                            actor_did: actor_did.to_string(),
                            actor_device_id: actor_device_uuid,
                            signed_request: signed_req.clone(),
                        },
                    )
                    .await
                    .map_err(|error| {
                        tracing::warn!(?error, "relayed group sendMessage failed");
                        error.into_failure(ENDPOINT)
                    })?;
                    let mut entry = out.entry;
                    if let Some(obj) = entry.as_object_mut() {
                        obj.remove("$type");
                    }
                    let response_bytes =
                        serde_json::to_vec(&entry_read::accepted_send_outcome(entry))
                            .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
                    return context::canonical_json_response(ENDPOINT, 200, response_bytes);
                }
            }
        }

        if !is_local_convo {
            let any_inbox: Option<(String, String)> = sqlx::query_as(
                "SELECT sender_did, recipient_did \
                 FROM chat.direct_request_transport_inbox \
                 WHERE conversation_id = $1 \
                 LIMIT 1",
            )
            .bind(convo_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?;

            if any_inbox.is_none() {
                return Err(ChatFailure::protocol(
                    ENDPOINT,
                    ChatProtocolErrorCode::ConversationNotFound,
                ));
            }

            // Actor-pair and device binding before relaying
            let authenticated_did = admission.subject();
            let actor_did = signed_req
                .pointer("/body/actorDid")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if actor_did != authenticated_did {
                return Err(ChatFailure::protocol(
                    ENDPOINT,
                    ChatProtocolErrorCode::NotAuthorized,
                ));
            }

            let is_participant = is_transport_participant(pool, convo_id, actor_did).await?;

            if !is_participant {
                return Err(ChatFailure::protocol(
                    ENDPOINT,
                    ChatProtocolErrorCode::NotAuthorized,
                ));
            }

            let actor_device_str = signed_req
                .pointer("/body/actorDeviceId")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let actor_device_uuid = uuid::Uuid::parse_str(actor_device_str).map_err(|_| {
                ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
            })?;

            // Entitlement check by owner and device before LIMIT 1
            let inbox_info: Option<(String, String)> = sqlx::query_as(
                "SELECT coordinator_did, status \
                 FROM chat.direct_request_transport_inbox \
                 WHERE conversation_id = $1 \
                   AND ( \
                     (recipient_did = $2 AND recipient_device_id = $3) \
                     OR (sender_did = $2 AND sender_device_id = $3) \
                   ) \
                 LIMIT 1",
            )
            .bind(convo_id)
            .bind(actor_did)
            .bind(actor_device_uuid)
            .fetch_optional(pool)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?;

            let Some((coord_did, status)) = inbox_info else {
                return Err(ChatFailure::protocol(
                    ENDPOINT,
                    ChatProtocolErrorCode::NotEntitled,
                ));
            };

            // Durable acceptance check
            if status != "accepted" {
                return Err(ChatFailure::protocol(
                    ENDPOINT,
                    ChatProtocolErrorCode::ConversationNotAccepted,
                ));
            }
            // A stored send replays as the entry `getEntries` serves here: once
            // pruned (O7), its `payloadPruned` projection, with no ciphertext.
            let message_id = signed_req
                .pointer("/body/messageId")
                .and_then(|value| value.as_str())
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
                .ok_or_else(|| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
            // Signed requests carry NUL escapes PostgreSQL JSON rejects: compare the
            // insert-captured digest, and parse rows without evidence (stored before
            // migration 20261103000001, or older schemas) here instead.
            let has_replay_evidence: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_attribute \
                  WHERE attrelid = 'chat.direct_request_transport_entries'::regclass \
                    AND attname = 'application_message_id' AND NOT attisdropped)",
            )
            .fetch_one(pool)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?;
            let request_sha256 = delivery::signed_request_sha256(signed_req)
                .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
            let candidates: Vec<(Vec<u8>, Option<uuid::Uuid>, Option<Vec<u8>>)> =
                if has_replay_evidence {
                    sqlx::query_as(
                        "SELECT entry_bytes, application_message_id, application_request_sha256 \
                           FROM chat.direct_request_transport_entries \
                          WHERE conversation_id = $1 \
                            AND (application_message_id = $2 OR evidence_pending) \
                          ORDER BY seq DESC",
                    )
                    .bind(convo_id)
                    .bind(message_id)
                    .fetch_all(pool)
                    .await
                } else {
                    sqlx::query_as(
                        "SELECT entry_bytes, NULL::uuid, NULL::bytea \
                           FROM chat.direct_request_transport_entries \
                          WHERE conversation_id = $1 ORDER BY seq DESC",
                    )
                    .bind(convo_id)
                    .fetch_all(pool)
                    .await
                }
                .map_err(|_| ChatFailure::storage(ENDPOINT))?;
            for (entry_bytes, stored_message, stored_request) in candidates {
                let (stored_message, stored_request) = match (stored_message, stored_request) {
                    (Some(message), Some(request)) => (message, request),
                    _ => match delivery::transport_application_evidence(&entry_bytes) {
                        Ok(Some(evidence)) => (evidence.message_id, evidence.request_sha256),
                        _ => continue,
                    },
                };
                if stored_message != message_id {
                    continue;
                }
                if stored_request != request_sha256 {
                    return Err(ChatFailure::protocol(
                        ENDPOINT,
                        ChatProtocolErrorCode::IdempotencyConflict,
                    ));
                }
                let mut entry: serde_json::Value = serde_json::from_slice(&entry_bytes)
                    .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
                entry
                    .as_object_mut()
                    .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?
                    .remove("$type");
                let response_bytes = serde_json::to_vec(&entry_read::accepted_send_outcome(entry))
                    .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
                return context::canonical_json_response(ENDPOINT, 200, response_bytes);
            }

            // The coordinator this inbox recorded for the pair, never re-derived
            // from both parties' declarations: a deleted party's is typically gone.
            let coordinator =
                crate::federation::canonical_relay::resolve_recorded_coordinator(pool, &coord_did)
                    .await
                    .map_err(|error| {
                        c33_failure("Failed to resolve the pair's recorded coordinator", &error)
                    })?;

            let relay_payload = crate::federation::canonical_relay::RelaySendMessageInput {
                conversation_id: convo_id,
                message: signed_req.clone(),
            };

            let result = crate::federation::canonical_relay::relay_message_to_coordinator(
                &coordinator.endpoint,
                &coord_did,
                relay_payload,
            )
            .await
            .map_err(|error| c33_failure("relay_message_to_coordinator failed", &error))?;

            let entry = result
                .get("entry")
                .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
            // A pruned send's replay (O7) carries the coordinator's `payloadPruned`
            // projection: the accepted outcome, with no ciphertext to store here.
            if entry.get("payloadPruned") != Some(&serde_json::Value::Bool(true)) {
                if entry.get("signedRequest") != Some(signed_req) {
                    return Err(ChatFailure::invariant(ENDPOINT));
                }
                crate::federation::canonical_relay::ingest_remote_message_entry(
                    pool, None, &coord_did, convo_id, entry,
                )
                .await
                .map_err(|error| c33_failure("Invalid coordinator application entry", &error))?;
            }

            let mut result = result;
            result["entry"]
                .as_object_mut()
                .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?
                .remove("$type");
            let response_bytes =
                serde_json::to_vec(&result).map_err(|_| ChatFailure::invariant(ENDPOINT))?;
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
            let replay_bytes = replay.response_bytes().to_vec();
            let replayed = serde_json::from_slice::<serde_json::Value>(&replay_bytes).ok();
            // A pruned send (O7) replays its accepted entry without ciphertext:
            // nothing is left to fan out or redeliver. It was pruned only once
            // its audience acknowledged it, it expired, or its sender was deleted.
            let pruned = replayed
                .as_ref()
                .is_some_and(|value| value["entry"]["payloadPruned"] == true);
            let group_fanout = match replayed.as_ref().filter(|_| !pruned) {
                Some(val) => {
                    crate::federation::group_fanout::prepare_group_entry_fanout(&mut tx, val)
                        .await
                        .map_err(|_| ChatFailure::storage(ENDPOINT))?
                }
                None => None,
            };
            let response = context::replay_response(ENDPOINT, &replay)?;
            tx.commit()
                .await
                .map_err(|_| ChatFailure::storage(ENDPOINT))?;
            if let Some(fanout) = group_fanout {
                runtime.spawn_post_commit_group_entry_fanout(pool, fanout);
            }
            if !pruned {
                let actor_did = signed_req
                    .pointer("/body/actorDid")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                deliver_message_entry_to_remote_peers(pool, actor_did, &replay_bytes).await?;
            }
            Ok(response)
        }
        PreparedChatAdmission::First(first) => {
            let (authority, scope, completion) = first.into_execution_parts();
            let (response_bytes, event_position) = message_delivery::send_with_receipt_signer(
                &mut tx,
                &authority,
                &scope,
                runtime.relationship_authority().as_ref(),
                runtime.i13_receipt_signer(),
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
            let response_value = serde_json::from_slice::<serde_json::Value>(&response_bytes).ok();
            let group_fanout = match &response_value {
                Some(val) => {
                    crate::federation::group_fanout::prepare_group_entry_fanout(&mut tx, val)
                        .await
                        .map_err(|_| ChatFailure::storage(ENDPOINT))?
                }
                None => None,
            };
            let local_push = match &response_value {
                Some(val) if runtime.push_gateway_client().is_some() => {
                    crate::push_gateway::client::prepare_local_entry_wake(&mut tx, val)
                        .await
                        .map_err(|_| ChatFailure::storage(ENDPOINT))?
                }
                _ => None,
            };
            tx.commit().await.map_err(|e| {
                tracing::error!("tx.commit error: {:?}", e);
                ChatFailure::storage(ENDPOINT)
            })?;
            if let Some(fanout) = group_fanout {
                runtime.spawn_post_commit_group_entry_fanout(pool, fanout);
            }
            if let Some(wake) = local_push {
                runtime.spawn_post_commit_local_push(pool, wake);
            }
            runtime.notify_events();
            deliver_message_entry_to_remote_peers(
                pool,
                authority.subject().as_str(),
                &response_bytes,
            )
            .await?;

            context::canonical_json_response(ENDPOINT, 200, response_bytes)
        }
    }
}

async fn deliver_message_entry_to_remote_peers(
    pool: &DbPool,
    actor_did: &str,
    response_bytes: &[u8],
) -> Result<(), ChatFailure> {
    let response: serde_json::Value =
        serde_json::from_slice(response_bytes).map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let entry = response
        .get("entry")
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let convo_id = entry["conversationId"]
        .as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let entry_id = entry["entryId"]
        .as_str()
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
    // C33 transport homes receive `deliverMessageEntry`; ordinary Direct homes
    // already receive the signed clean envelope queued in the transaction.
    let has_c33_publication: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM chat.direct_request_publications
              WHERE conversation_id = $1
         )",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    if !has_c33_publication {
        return Ok(());
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
        // A deleted party's home gets none of this conversation's later entries.
        if crate::federation::canonical_relay::account_deleted_in(pool, convo_id, other_did)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?
        {
            continue;
        }
        let coord = crate::federation::canonical_relay::resolve_pair_coordinator(
            pool, actor_did, other_did,
        )
        .await
        .map_err(|error| match error {
            // The send is committed: a refusal cannot undo it, so a peer that
            // cannot be routed stays an internal failure (store and transient
            // failures keep their class).
            ref error if !error.is_retryable() && !matches!(error, FederationError::Storage(_)) => {
                tracing::error!(?error, "Failed to resolve application entry peer");
                ChatFailure::invariant(ENDPOINT)
            }
            error => c33_failure("Failed to resolve application entry peer", &error),
        })?;
        let (target_endpoint, target_did) = if coord.is_coordinator {
            (
                coord.recipient_home.endpoint.as_str(),
                coord.recipient_home.did.as_str(),
            )
        } else {
            (coord.coordinator_endpoint(), coord.coordinator_did.as_str())
        };
        if crate::identity::canonical_did(target_did)
            == crate::identity::canonical_did(&crate::identity::service_did())
        {
            continue;
        }
        let mut typed_entry = entry.clone();
        typed_entry["$type"] = serde_json::json!("blue.catbird.chat.defs#applicationEntry");
        let delivery = crate::federation::canonical_relay::DeliverMessageEntryInput {
            conversation_id: convo_id,
            entry: typed_entry,
        };
        if let Err(error) = crate::federation::canonical_relay::deliver_message_entry_to_peer(
            target_endpoint,
            target_did,
            delivery.clone(),
        )
        .await
        {
            // Committed: the send stands, and its durable queue row delivers
            // this entry once the peer answers.
            tracing::warn!(
                ?error,
                "Failed to deliver application entry to peer, queueing for retry"
            );
            sqlx::query(
                "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, last_error, next_retry_at) \
                 SELECT $1, $2, $3, $4, $5, $6, $7, $8 \
                  WHERE NOT EXISTS (SELECT 1 FROM outbound_queue WHERE id = $1) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(format!("message-delivery-{entry_id}-{}", crate::identity::canonical_did(target_did)))
            .bind(target_did)
            .bind(target_endpoint)
            .bind("blue.catbird.mlsDS.deliverMessageEntry")
            .bind(serde_json::to_vec(&delivery).map_err(|_| ChatFailure::invariant(ENDPOINT))?)
            .bind(convo_id.to_string())
            .bind(error.to_string())
            .bind(crate::sim_hooks::current_utc() + chrono::Duration::seconds(5))
            .execute(pool)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?;
        }
    }
    Ok(())
}

/// A C33 step of this send failed: resolving or relaying to the pair's
/// coordinator, ingesting its entry, or resolving a peer's home. This DS's
/// store failing is storage; a closed gate, or a coordinator, home or resolver
/// that could not answer now, decided nothing. A coordinator that refused, or
/// one that cannot be routed or verified, is a refusal.
fn c33_failure(stage: &'static str, error: &FederationError) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    tracing::error!(?error, "{stage}");
    match error {
        FederationError::Database(_) | FederationError::Storage(_) => {
            ChatFailure::storage(ENDPOINT)
        }
        error if error.is_retryable() => ChatFailure::unavailable(ENDPOINT),
        FederationError::BlockedRelationship => {
            ChatFailure::protocol(ENDPOINT, C::BlockedRelationship)
        }
        FederationError::RemoteError { status: 409, .. } => {
            ChatFailure::protocol(ENDPOINT, C::StaleCoordinates)
        }
        FederationError::RemoteError { status: 404, .. }
        | FederationError::ConversationNotFound { .. } => {
            ChatFailure::protocol(ENDPOINT, C::ConversationNotFound)
        }
        FederationError::RemoteError {
            status: 400 | 422, ..
        }
        | FederationError::InvalidRequest(_)
        | FederationError::InvalidEnvelope { .. } => {
            ChatFailure::protocol(ENDPOINT, C::InvalidRequest)
        }
        _ => ChatFailure::protocol(ENDPOINT, C::NotAuthorized),
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
        MessageDeliveryError::NotAuthorized => ChatFailure::protocol(ENDPOINT, C::NotAuthorized),
        MessageDeliveryError::DeviceNotLeaf => ChatFailure::protocol(ENDPOINT, C::DeviceNotLeaf),
        MessageDeliveryError::RecipientNotReady => {
            ChatFailure::protocol(ENDPOINT, C::RecipientNotReady)
        }
        MessageDeliveryError::RelationshipPolicyUnavailable => {
            ChatFailure::protocol(ENDPOINT, C::RelationshipPolicyUnavailable)
        }
        MessageDeliveryError::RelationshipSourceUnavailable => ChatFailure::unavailable(ENDPOINT),
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
        assert_eq!(
            failure.code(),
            Some(ChatProtocolErrorCode::StaleCoordinates)
        );
    }

    /// A C33 step of a send: this DS's store failing is storage, a source
    /// that could not answer now is retryable, and a definitive refusal is a
    /// declared 4xx without retry.
    #[test]
    fn c33_failures_keep_their_class() {
        use axum::http::{header::RETRY_AFTER, StatusCode};
        for (error, status, retry_after) in [
            (
                FederationError::Database(sqlx::Error::PoolTimedOut),
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
            ),
            (
                FederationError::DsUnreachable {
                    endpoint: "https://peer.example.com".into(),
                    reason: "unreachable".into(),
                },
                StatusCode::SERVICE_UNAVAILABLE,
                Some("5"),
            ),
            (
                FederationError::RemoteError {
                    status: 429,
                    body: String::new(),
                },
                StatusCode::SERVICE_UNAVAILABLE,
                Some("5"),
            ),
            (
                FederationError::Unsupported("no declaration".into()),
                StatusCode::UNAUTHORIZED,
                None,
            ),
            (
                FederationError::RemoteError {
                    status: 409,
                    body: String::new(),
                },
                StatusCode::BAD_REQUEST,
                None,
            ),
        ] {
            let response = c33_failure("test", &error).into_response();
            assert_eq!(response.status(), status, "{error:?}");
            assert_eq!(
                response
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()),
                retry_after,
                "{error:?}"
            );
        }
        assert_eq!(
            c33_failure("test", &FederationError::BlockedRelationship).code(),
            Some(ChatProtocolErrorCode::BlockedRelationship)
        );
    }

    #[tokio::test]
    async fn participant_store_failure_is_storage_not_a_refusal() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://127.0.0.1/c33_participant_store_failure")
            .unwrap();
        pool.close().await;
        let failure = is_transport_participant(&pool, uuid::Uuid::new_v4(), "did:plc:actor")
            .await
            .expect_err("closed pool must fail the participant lookup");
        assert_eq!(
            failure.into_response().status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
