//! `blue.catbird.chat.acknowledgeEntries` handler: monotonic per-device entry ACK
//! watermark and immediate ciphertext pruning once all active non-dormant devices
//! spanning an `applicationEntry` have acknowledged it (`I14`, `G6`).

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::{header::CONTENT_TYPE, HeaderMap},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    chat_protocol::{
        dpop,
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::{auth, delivery},
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

    let principal = context::verify_service_principal(pool, ENDPOINT, headers).await?;
    let actor_did = principal.did().to_owned();
    let actor_device_str = input.actor_device_id.to_string();
    let method =
        CanonicalHttpMethod::parse("POST").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let instant = TrustedRequestInstant::capture().map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let pre_replay = dpop::standard_service_auth_evidence(
        principal,
        &actor_device_str,
        method,
        instant,
        None,
    )
    .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    auth::authorize_unsigned_request(pool, pre_replay)
        .await
        .map_err(|error| context::auth_repository_failure(ENDPOINT, error))?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let skew = (now - signed_at_ts.datetime()).num_seconds().abs();
    if skew > MAX_ACK_SKEW_SECS {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }

    let convo_head: Option<i64> = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id = $1 FOR UPDATE",
    )
    .bind(input.conversation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let Some(next_entry_seq) = convo_head else {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::ConversationNotFound,
        ));
    };

    let dev_row: Option<(String, i64, Option<i64>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT d.status, d.auth_generation, dk.enrollment_auth_generation, dk.signing_public_key \
           FROM chat.devices d \
           LEFT JOIN chat.device_keys dk \
             ON dk.user_did = d.user_did AND dk.device_id = d.device_id AND dk.key_id = $3 \
          WHERE d.user_did = $1 AND d.device_id = $2 \
          FOR UPDATE OF d",
    )
    .bind(&actor_did)
    .bind(input.actor_device_id)
    .bind(&input.key_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let Some((dev_status, dev_auth_gen, key_auth_gen, pubkey_opt)) = dev_row else {
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
    if dev_auth_gen != input.auth_generation || key_auth_gen != Some(dev_auth_gen) {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    }
    let pubkey_raw: [u8; 32] = pubkey_opt
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::NotAuthorized))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_raw)
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidSignature))?;

    let transcript = build_ack_transcript(&input)?;
    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidSignature))?;

    let is_leaf: bool = sqlx::query_scalar(
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
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    if !is_leaf {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::DeviceNotLeaf,
        ));
    }

    sqlx::query(
        "UPDATE chat.devices \
            SET last_active_at = $3, dormant_at = NULL \
          WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&actor_did)
    .bind(input.actor_device_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let max_seq = (next_entry_seq - 1).max(0);
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
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let prunable_seqs: Vec<i64> = sqlx::query_scalar(
        "SELECT e.seq \
           FROM chat.entries e \
          WHERE e.conversation_id = $1 \
            AND e.generation = $2 \
            AND e.seq <= $3 \
            AND e.entry_kind = 'blue.catbird.chat.defs#applicationEntry' \
            AND e.payload_pruned_at IS NULL \
            AND EXISTS ( \
                SELECT 1 \
                  FROM chat.application_intervals ai \
                  JOIN chat.devices d \
                    ON d.user_did = ai.recipient_did \
                   AND d.device_id = ai.recipient_device_id \
                 WHERE ai.conversation_id = e.conversation_id \
                   AND ai.generation = e.generation \
                   AND ai.start_seq <= e.seq \
                   AND (ai.terminal_seq IS NULL OR e.seq <= ai.terminal_seq) \
                   AND d.status = 'active' \
                   AND d.dormant_at IS NULL \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                  FROM chat.application_intervals ai \
                  JOIN chat.devices d \
                    ON d.user_did = ai.recipient_did \
                   AND d.device_id = ai.recipient_device_id \
                  LEFT JOIN chat.device_entry_acks ack \
                    ON ack.conversation_id = ai.conversation_id \
                   AND ack.user_did = ai.recipient_did \
                   AND ack.device_id = ai.recipient_device_id \
                 WHERE ai.conversation_id = e.conversation_id \
                   AND ai.generation = e.generation \
                   AND ai.start_seq <= e.seq \
                   AND (ai.terminal_seq IS NULL OR e.seq <= ai.terminal_seq) \
                   AND d.status = 'active' \
                   AND d.dormant_at IS NULL \
                   AND COALESCE(ack.acked_through_seq, 0) < e.seq \
            ) \
          ORDER BY e.seq ASC",
    )
    .bind(input.conversation_id)
    .bind(input.generation)
    .bind(acked_seq)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let mut pruned_count: i64 = 0;
    for seq in prunable_seqs {
        let did_prune =
            delivery::prune_application_entry_payload(&mut tx, input.conversation_id, seq, now)
                .await
                .map_err(|_| ChatFailure::storage(ENDPOINT))?;
        if did_prune {
            pruned_count += 1;
        }
    }

    let _ = Duration::seconds(1);
    tx.commit()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let out = serde_json::to_vec(&json!({
        "acknowledgedSeq": acked_seq,
        "prunedCount": pruned_count,
    }))
    .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    Ok(context::json_ok(out))
}

fn decode_signature_field(value: &Value) -> Result<[u8; 64], ChatFailure> {
    let encoded = match value {
        Value::String(s) => s.as_str(),
        Value::Object(map) if map.len() == 1 => map
            .get("$bytes")
            .and_then(Value::as_str)
            .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?,
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
