//! `blue.catbird.chat.acknowledgeEntries` handler: monotonic per-device entry ACK
//! watermark and immediate ciphertext pruning once all active non-dormant devices
//! spanning an `applicationEntry` have acknowledged it (`I14`, `G6`). A home
//! queues a signed `relayEntryAck` of each ACK for a conversation sequenced
//! elsewhere, so the sequencer's prune also waits for the devices homed here.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::{header::CONTENT_TYPE, HeaderMap},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    chat_protocol::{
        dpop,
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::{
            auth, delivery,
            entry_read::{self, EntryReadFacadeError, RecoveryAck, RecoveryReadWindow},
        },
        validation::{
            CanonicalHttpMethod, CanonicalTimestamp, KeyThumbprint, TrustedRequestInstant,
        },
    },
    storage::DbPool,
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

const ENDPOINT: ChatEndpoint = ChatEndpoint::AcknowledgeEntries;
const ACK_DOMAIN: &[u8] = b"CATBIRD-CHAT-ACK-ENTRIES\0";
const MAX_ACK_SKEW_SECS: i64 = 300;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcknowledgeEntriesInput {
    conversation_id: Uuid,
    generation: i64,
    actor_device_id: Uuid,
    key_id: String,
    auth_generation: i64,
    up_to_seq: i64,
    signed_at: String,
    signature: Value,
}

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    match execute(&pool, &runtime, &headers, query.as_deref(), &body).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn execute(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    query: Option<&str>,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    context::require_cutover(runtime, ENDPOINT)?;
    if query.is_some_and(|q| !q.is_empty()) {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let media_type = content_type.split(';').next().unwrap_or("").trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }
    let principal = context::verify_service_principal(pool, ENDPOINT, headers).await?;
    execute_ack(pool, principal, body, runtime.resolver().map(Arc::as_ref)).await
}

#[cfg(test)]
pub(crate) async fn execute_for_principal(
    pool: &DbPool,
    principal: crate::auth::VerifiedServicePrincipal,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    execute_ack(pool, principal, body, None).await
}

async fn execute_ack(
    pool: &DbPool,
    principal: crate::auth::VerifiedServicePrincipal,
    body: &[u8],
    resolver: Option<&crate::federation::DsResolver>,
) -> Result<Response, ChatFailure> {
    let input: AcknowledgeEntriesInput = serde_json::from_slice(body)
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    if input.conversation_id.get_version_num() != 4
        || input.actor_device_id.get_version_num() != 4
        || input.generation < 0
        || input.auth_generation < 1
        || input.up_to_seq < 1
    {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }
    KeyThumbprint::parse(&input.key_id)
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    let signed_at_ts = CanonicalTimestamp::parse(&input.signed_at)
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    let signature_bytes = decode_signature_field(&input.signature)?;
    let signature = Signature::from_bytes(&signature_bytes);

    let actor_did = principal.did().to_owned();
    let actor_device_str = input.actor_device_id.to_string();
    let method =
        CanonicalHttpMethod::parse("POST").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let instant = TrustedRequestInstant::capture().map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let now = instant.datetime();
    let pre_replay =
        dpop::standard_service_auth_evidence(principal, &actor_device_str, method, instant, None)
            .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    auth::authorize_unsigned_request(pool, pre_replay)
        .await
        .map_err(|error| context::auth_repository_failure(ENDPOINT, error))?;

    let mut recovered: Option<(String, RecoveryReadWindow)> = None;
    let (mut tx, convo_head, sequencer) = loop {
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?;

        let skew = (crate::sim_hooks::current_utc() - signed_at_ts.datetime())
            .num_seconds()
            .abs();
        if skew > MAX_ACK_SKEW_SECS {
            return Err(ChatFailure::protocol(
                ENDPOINT,
                ChatProtocolErrorCode::InvalidRequest,
            ));
        }

        let convo_head: Option<(i64, bool, Option<String>)> = sqlx::query_as(
            "SELECT next_entry_seq, is_remote, sequencer_ds FROM chat.conversations \
          WHERE conversation_id = $1 FOR UPDATE",
        )
        .bind(input.conversation_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

        if convo_head.is_none() {
            // Serialize every C33 device ACK on the same inbox rows, before locking
            // the actor device. Otherwise simultaneous final ACKs can both miss the
            // other's uncommitted watermark and leave ciphertext behind.
            sqlx::query(
                "SELECT delivery_id FROM chat.direct_request_transport_inbox \
              WHERE conversation_id = $1 ORDER BY delivery_id FOR UPDATE",
            )
            .bind(input.conversation_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?;
        }

        type TransportInbox = (
            String,
            String,
            Option<Uuid>,
            String,
            Uuid,
            DateTime<Utc>,
            String,
        );
        let transport_inbox: Option<TransportInbox> = if convo_head.is_none() {
            sqlx::query_as(
                "SELECT status, sender_did, sender_device_id, recipient_did, recipient_device_id, \
                    import_until, coordinator_did \
               FROM chat.direct_request_transport_inbox \
              WHERE conversation_id = $1 \
                AND (recipient_did = $2 OR sender_did = $2) \
              ORDER BY CASE \
                WHEN (recipient_did = $2 AND recipient_device_id = $3) \
                  OR (sender_did = $2 AND sender_device_id = $3) THEN 0 \
                ELSE 1 \
              END \
              LIMIT 1 \
              FOR UPDATE",
            )
            .bind(input.conversation_id)
            .bind(&actor_did)
            .bind(input.actor_device_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?
        } else {
            None
        };

        if convo_head.is_none() && transport_inbox.is_none() {
            return Err(ChatFailure::protocol(
                ENDPOINT,
                ChatProtocolErrorCode::ConversationNotFound,
            ));
        }

        let dev_row: Option<(String, i64, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT d.status, d.auth_generation, dk.signing_public_key \
           FROM chat.devices d \
           LEFT JOIN chat.device_keys dk \
             ON dk.user_did = d.user_did AND dk.device_id = d.device_id AND dk.key_id = $3 \
            AND dk.revoked_at IS NULL \
            AND dk.enrollment_auth_generation <= d.auth_generation \
            AND NOT EXISTS ( \
                SELECT 1 FROM chat.device_keys newer \
                 WHERE newer.user_did = dk.user_did AND newer.device_id = dk.device_id \
                   AND newer.enrollment_auth_generation > dk.enrollment_auth_generation \
                   AND newer.enrollment_auth_generation <= d.auth_generation \
            ) \
          WHERE d.user_did = $1 AND d.device_id = $2 \
          FOR UPDATE OF d",
        )
        .bind(&actor_did)
        .bind(input.actor_device_id)
        .bind(&input.key_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

        let Some((dev_status, dev_auth_gen, pubkey_opt)) = dev_row else {
            return Err(ChatFailure::protocol(
                ENDPOINT,
                ChatProtocolErrorCode::DeviceNotRegistered,
            ));
        };
        if dev_status == "revoked" {
            return Err(ChatFailure::protocol(
                ENDPOINT,
                ChatProtocolErrorCode::DeviceRevoked,
            ));
        }
        if dev_status != "active" {
            return Err(ChatFailure::protocol(
                ENDPOINT,
                ChatProtocolErrorCode::DeviceNotRegistered,
            ));
        }
        if dev_auth_gen != input.auth_generation {
            return Err(ChatFailure::protocol(
                ENDPOINT,
                ChatProtocolErrorCode::NotAuthorized,
            ));
        }
        let pubkey_raw: [u8; 32] = pubkey_opt
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::NotAuthorized))?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_raw).map_err(|_| {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidSignature)
        })?;

        let transcript = build_ack_transcript(&input)?;
        verifying_key.verify(&transcript, &signature).map_err(|_| {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidSignature)
        })?;

        // The DS sequencing a conversation held here only as a C33 inbox or a
        // remote mirror; it waits for this ACK, so the ACK is relayed to it.
        let mut sequencer = None;
        if convo_head.is_none() {
            let (
                status,
                sender_did,
                sender_device_id,
                recipient_did,
                recipient_device_id,
                import_until,
                coordinator_did,
            ) = transport_inbox.ok_or_else(|| {
                ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::ConversationNotFound)
            })?;
            sequencer = Some(coordinator_did);
            if status == "pending" {
                if now > import_until {
                    return Err(ChatFailure::protocol(
                        ENDPOINT,
                        ChatProtocolErrorCode::ConversationNotFound,
                    ));
                }
            } else if status != "accepted" {
                return Err(ChatFailure::protocol(
                    ENDPOINT,
                    ChatProtocolErrorCode::ConversationNotFound,
                ));
            }
            let device_matches = (actor_did == recipient_did
                && input.actor_device_id == recipient_device_id)
                || (actor_did == sender_did && sender_device_id == Some(input.actor_device_id));
            if !device_matches {
                return Err(ChatFailure::protocol(
                    ENDPOINT,
                    ChatProtocolErrorCode::DeviceNotLeaf,
                ));
            }
        }

        let is_leaf: bool = if convo_head.is_some() {
            sqlx::query_scalar(
                "SELECT EXISTS( \
                 SELECT 1 FROM chat.application_intervals \
                  WHERE conversation_id = $1 AND generation = $2 \
                    AND recipient_did = $3 AND recipient_device_id = $4 \
                 UNION ALL \
                 SELECT 1 FROM chat.member_devices \
                  WHERE conversation_id = $1 AND generation = $2 \
                    AND user_did = $3 AND device_id = $4 \
             )",
            )
            .bind(input.conversation_id)
            .bind(input.generation)
            .bind(&actor_did)
            .bind(input.actor_device_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?
        } else {
            true // The exact C33 inbox device was authorized above.
        };
        if !is_leaf {
            let denied = || ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::DeviceNotLeaf);
            let current_ds = convo_head
                .as_ref()
                .filter(|(_, remote, _)| *remote)
                .and_then(|(_, _, ds)| ds.as_deref())
                .ok_or_else(denied)?;
            if let Some((window_ds, window)) = &recovered {
                if current_ds != window_ds {
                    return Err(denied());
                }
                let ack = RecoveryAck {
                    conversation: input.conversation_id,
                    did: &actor_did,
                    device: input.actor_device_id,
                    generation: input.generation,
                    key_id: &input.key_id,
                    auth_generation: input.auth_generation,
                    through: input.up_to_seq,
                };
                entry_read::verify_recovery_ack(&mut tx, window, current_ds, ack)
                    .await
                    .map_err(|error| match error {
                        EntryReadFacadeError::NotEntitled => denied(),
                        _ => ChatFailure::storage(ENDPOINT),
                    })?;
            } else {
                // Fetch the sequencer's current interval without holding either home
                // lock. Retry the normal device lock, signature and freshness checks
                // before using that interval to advance the authenticated watermark.
                tx.rollback()
                    .await
                    .map_err(|_| ChatFailure::storage(ENDPOINT))?;
                recovered = Some(
                    crate::federation::group_relay::recovery_window_for_home(
                        pool,
                        resolver,
                        ENDPOINT,
                        input.conversation_id,
                        &actor_did,
                        input.actor_device_id,
                    )
                    .await?
                    .ok_or_else(denied)?,
                );
                continue;
            }
        }
        break (tx, convo_head, sequencer);
    };
    let (next_entry_seq, is_remote, sequencer_ds) = convo_head.unwrap_or((1, true, None));
    let sequencer = sequencer
        .or(sequencer_ds.filter(|_| is_remote))
        .filter(|did| !crate::identity::dids_equivalent(did, &crate::identity::service_did_base()));

    sqlx::query(
        "UPDATE chat.devices \
            SET last_active_at = $3, dormant_at = NULL \
          WHERE user_did = $1 AND device_id = $2 \
            AND (last_active_at IS DISTINCT FROM $3 OR dormant_at IS NOT NULL)",
    )
    .bind(&actor_did)
    .bind(input.actor_device_id)
    .bind(crate::chat_protocol::device_activity::coarse_activity_day(
        now,
    ))
    .execute(&mut *tx)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let max_seq = if is_remote {
        let transport_max: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq), 0) FROM chat.direct_request_transport_entries WHERE conversation_id = $1",
        )
        .bind(input.conversation_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
        (next_entry_seq - 1).max(transport_max).max(0)
    } else {
        (next_entry_seq - 1).max(0)
    };
    if input.up_to_seq > max_seq {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }

    let acked_seq: i64 = sqlx::query_scalar(
        "INSERT INTO chat.device_entry_acks ( \
             conversation_id, user_did, device_id, acked_through_seq, updated_at \
         ) VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (conversation_id, user_did, device_id) DO UPDATE \
           SET acked_through_seq = GREATEST(chat.device_entry_acks.acked_through_seq, EXCLUDED.acked_through_seq), \
               updated_at = EXCLUDED.updated_at \
         RETURNING acked_through_seq",
    )
    .bind(input.conversation_id)
    .bind(&actor_did)
    .bind(input.actor_device_id)
    .bind(input.up_to_seq)
    .bind(crate::chat_protocol::device_activity::coarse_activity_day(now))
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let pruned = delivery::prune_acknowledged_application_payloads(
        &mut tx,
        input.conversation_id,
        input.generation,
        acked_seq,
        is_remote,
        now,
    )
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    if !is_remote {
        // Pruning here is authoritative: the group's mirrors follow it.
        crate::federation::group_relay::enqueue_entries_pruned_notices(
            &mut tx,
            input.conversation_id,
            input.generation,
            &pruned,
            now,
        )
        .await
        .map_err(signed_relay_failure)?;
    }
    if let Some(sequencer) = sequencer {
        crate::federation::group_relay::enqueue_entry_ack_relay(
            &mut tx,
            &sequencer,
            input.conversation_id,
            input.generation,
            &actor_did,
            input.actor_device_id,
            acked_seq,
            now,
        )
        .await
        .map_err(signed_relay_failure)?;
    }
    tx.commit()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let out = serde_json::to_vec(&json!({
        "acknowledgedSeq": acked_seq,
        "prunedCount": pruned.len(),
    }))
    .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    Ok(context::json_ok(out))
}

/// An ACK whose relay or prune notice this DS cannot sign commits nothing: the
/// declared `CutoverRequired` says the service is not ready for it.
fn signed_relay_failure(error: crate::federation::group_relay::SignedRelayError) -> ChatFailure {
    match error {
        crate::federation::group_relay::SignedRelayError::SignerUnavailable => {
            tracing::error!("acknowledgeEntries refused: no S2S signing key for its relay");
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::CutoverRequired)
        }
        crate::federation::group_relay::SignedRelayError::Storage(_) => {
            ChatFailure::storage(ENDPOINT)
        }
    }
}

fn decode_signature_field(value: &Value) -> Result<[u8; 64], ChatFailure> {
    let encoded = match value {
        Value::String(s) => s.as_str(),
        Value::Object(map) if map.len() == 1 => {
            map.get("$bytes").and_then(Value::as_str).ok_or_else(|| {
                ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
            })?
        }
        _ => {
            return Err(ChatFailure::protocol(
                ENDPOINT,
                ChatProtocolErrorCode::InvalidRequest,
            ));
        }
    };
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    if STANDARD.encode(&decoded) != encoded {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }
    decoded
        .try_into()
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))
}

#[derive(Serialize)]
struct AckTranscriptPayload<'a> {
    #[serde(rename = "keyId")]
    key_id: &'a str,
    #[serde(rename = "upToSeq")]
    up_to_seq: i64,
    #[serde(rename = "signedAt")]
    signed_at: &'a str,
    generation: i64,
    #[serde(rename = "actorDeviceId")]
    actor_device_id: String,
    #[serde(rename = "authGeneration")]
    auth_generation: i64,
    #[serde(rename = "conversationId")]
    conversation_id: String,
}

fn build_ack_transcript(input: &AcknowledgeEntriesInput) -> Result<Vec<u8>, ChatFailure> {
    let payload = AckTranscriptPayload {
        key_id: &input.key_id,
        up_to_seq: input.up_to_seq,
        signed_at: &input.signed_at,
        generation: input.generation,
        actor_device_id: input.actor_device_id.to_string(),
        auth_generation: input.auth_generation,
        conversation_id: input.conversation_id.to_string(),
    };
    let cbor =
        serde_ipld_dagcbor::to_vec(&payload).map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let mut transcript = Vec::with_capacity(ACK_DOMAIN.len() + cbor.len());
    transcript.extend_from_slice(ACK_DOMAIN);
    transcript.extend_from_slice(&cbor);
    Ok(transcript)
}
