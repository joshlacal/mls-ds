//! `blue.catbird.chat.getEntries` — exact-device visible entry paging.

use std::sync::Arc;

use axum::{
    extract::{RawQuery, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::chat_protocol::{
    error::{ChatEndpoint, ChatProtocolErrorCode},
    repository::entry_read::{get_entries_for_admission, EntryReadFacadeError},
    validation::{CanonicalHttpMethod, CanonicalUuidV4, MAX_SAFE_INTEGER},
};
use crate::storage::DbPool;

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

const ENDPOINT: ChatEndpoint = ChatEndpoint::GetEntries;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    match get_entries(&pool, &runtime, &headers, query.as_deref()).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn get_entries(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<Response, ChatFailure> {
    context::require_cutover(runtime, ENDPOINT)?;
    let (actor_device_id, conversation_id, after_seq, limit) = parse_query(query)?;
    let method = CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let admission =
        context::admit_unsigned_read(pool, runtime, ENDPOINT, method, headers, &actor_device_id)
            .await?;
    let actor_did = admission.locked_did().to_string();
    let is_local_convo: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id = $1)"
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    if !is_local_convo {
        let actor_device_uuid = Uuid::parse_str(&actor_device_id)
            .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;

        let inbox_opt: Option<(String, String, Option<Uuid>, String, Uuid, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT status, sender_did, sender_device_id, recipient_did, recipient_device_id, import_until \
             FROM chat.direct_request_transport_inbox \
             WHERE conversation_id = $1 \
               AND ((recipient_did = $2 AND recipient_device_id = $3) \
                    OR (sender_did = $2 AND sender_device_id = $3)) \
             LIMIT 1"
        )
        .bind(conversation_id)
        .bind(&actor_did)
        .bind(actor_device_uuid)
        .fetch_optional(pool)
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

        let Some((status, sender_did, sender_device_id, recipient_did, recipient_device_id, import_until)) = inbox_opt else {
            return Err(ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::ConversationNotFound));
        };

        let is_sender = actor_did == sender_did;
        let is_recipient = actor_did == recipient_did;
        if !is_sender && !is_recipient {
            return Err(ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::ConversationNotFound));
        }

        // Exact-device entitlement check:
        // On recipient side: only recipient_device_id is admitted.
        // On sender side: only sender_device_id is admitted.
        if is_recipient && actor_device_uuid != recipient_device_id {
            return Err(ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::NotEntitled));
        }
        if is_sender {
            if let Some(expected_sender_dev) = sender_device_id {
                if actor_device_uuid != expected_sender_dev {
                    return Err(ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::NotEntitled));
                }
            }
        }

        if status == "pending" {
            if chrono::Utc::now() > import_until {
                return Err(ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvitationNotPending));
            }
        } else if status != "accepted" {
            return Err(ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::ConversationNotFound));
        }

        let stored_entries: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT entry_bytes FROM chat.direct_request_transport_entries \
             WHERE conversation_id = $1 AND seq > $2 \
             ORDER BY seq ASC LIMIT $3"
        )
        .bind(conversation_id)
        .bind(after_seq as i64)
        .bind(limit + 1)
        .fetch_all(pool)
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

        let has_more = stored_entries.len() > limit as usize;
        let entries: Vec<serde_json::Value> = stored_entries
            .into_iter()
            .take(limit as usize)
            .map(|bytes| {
                let mut val: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|_| ChatFailure::invariant(ENDPOINT))?;
                if val.get("$type").is_none()
                    && val.pointer("/signedRequest/body/$type").and_then(|v| v.as_str())
                        == Some("blue.catbird.chat.defs#applicationSendBody")
                {
                    val["$type"] = serde_json::json!("blue.catbird.chat.defs#applicationEntry");
                }
                crate::chat_protocol::direct_request_transcript::present_read_presentation(
                    "conversationEntry", &mut val,
                ).map_err(|_| ChatFailure::invariant(ENDPOINT))?;
                Ok(val)
            })
            .collect::<Result<_, ChatFailure>>()?;


        let next_after_seq = entries
            .last()
            .and_then(|e| e.get("seq").and_then(|v| v.as_u64()))
            .unwrap_or(after_seq);

        let resp = serde_json::json!({
            "entries": entries,
            "nextAfterSeq": next_after_seq,
            "hasMore": has_more,
        });
        let bytes = serde_json::to_vec(&resp)
            .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
        return context::canonical_json_response(ENDPOINT, 200, bytes);
    }

    let response = get_entries_for_admission(pool, admission, conversation_id, after_seq, limit)
        .await
        .map_err(facade_failure)?;
    Ok(context::json_ok(response.into_response_bytes()))
}

fn parse_query(query: Option<&str>) -> Result<(String, Uuid, u64, i64), ChatFailure> {
    let mut actor_device_id = None;
    let mut conversation_id = None;
    let mut after_seq = None;
    let mut limit = None;
    for pair in query
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (raw_key, raw_value) = pair.split_once('=').ok_or_else(|| {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
        })?;
        let key = percent_decode(raw_key).ok_or_else(|| {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
        })?;
        let value = percent_decode(raw_value).ok_or_else(|| {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
        })?;
        match key.as_str() {
            "actorDeviceId" if actor_device_id.is_none() => {
                let canonical = CanonicalUuidV4::parse(&value).map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                actor_device_id = Some(canonical.as_str().to_string());
            }
            "conversationId" if conversation_id.is_none() => {
                let canonical = CanonicalUuidV4::parse(&value).map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                let uuid = Uuid::parse_str(canonical.as_str()).map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                conversation_id = Some(uuid);
            }
            "afterSeq" if after_seq.is_none() => {
                let parsed = value.parse::<i64>().map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                if !(0..=MAX_SAFE_INTEGER).contains(&parsed) {
                    return Err(ChatFailure::protocol(
                        ENDPOINT,
                        ChatProtocolErrorCode::InvalidRequest,
                    ));
                }
                let seq = u64::try_from(parsed).map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                after_seq = Some(seq);
            }
            "limit" if limit.is_none() => {
                let parsed = value.parse::<i64>().map_err(|_| {
                    ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
                })?;
                if !(1..=100).contains(&parsed) {
                    return Err(ChatFailure::protocol(
                        ENDPOINT,
                        ChatProtocolErrorCode::InvalidRequest,
                    ));
                }
                limit = Some(parsed);
            }
            _ => {
                return Err(ChatFailure::protocol(
                    ENDPOINT,
                    ChatProtocolErrorCode::InvalidRequest,
                ));
            }
        }
    }
    let actor_device_id = actor_device_id
        .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    let conversation_id = conversation_id
        .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    let after_seq = after_seq
        .ok_or_else(|| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;
    let limit = limit.unwrap_or(100);
    Ok((actor_device_id, conversation_id, after_seq, limit))
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hi = (bytes[index + 1] as char).to_digit(16)?;
                let lo = (bytes[index + 2] as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                index += 3;
            }
            byte if byte.is_ascii() => {
                out.push(byte);
                index += 1;
            }
            _ => return None,
        }
    }
    String::from_utf8(out).ok()
}

fn facade_failure(error: EntryReadFacadeError) -> ChatFailure {
    tracing::error!("get_entries facade_failure: {:?}", error);
    match error {
        EntryReadFacadeError::AccessOutsideMembershipInterval => ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::AccessOutsideMembershipInterval,
        ),
        EntryReadFacadeError::ConversationNotFound => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::ConversationNotFound)
        }
        EntryReadFacadeError::DeviceRevoked => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::DeviceRevoked)
        }
        EntryReadFacadeError::NotEntitled => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::NotEntitled)
        }
        EntryReadFacadeError::InvalidRequest => {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest)
        }
        EntryReadFacadeError::Storage | EntryReadFacadeError::Invariant => {
            ChatFailure::invariant(ENDPOINT)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_failure_maps_not_entitled_to_declared_protocol_error() {
        let failure = facade_failure(EntryReadFacadeError::NotEntitled);
        assert_eq!(failure.code(), Some(ChatProtocolErrorCode::NotEntitled));
    }

    #[test]
    fn facade_failure_maps_access_outside_membership_interval() {
        let failure = facade_failure(EntryReadFacadeError::AccessOutsideMembershipInterval);
        assert_eq!(
            failure.code(),
            Some(ChatProtocolErrorCode::AccessOutsideMembershipInterval)
        );
    }

    #[test]
    fn parse_query_validates_mandatory_parameters() {
        let convo = Uuid::new_v4();
        let device = Uuid::new_v4();
        let query = format!(
            "actorDeviceId={}&conversationId={}&afterSeq=0&limit=10",
            device, convo
        );
        let parsed = parse_query(Some(&query)).expect("valid query");
        assert_eq!(parsed.0, device.to_string());
        assert_eq!(parsed.1, convo);
        assert_eq!(parsed.2, 0);
        assert_eq!(parsed.3, 10);
    }

    #[test]
    fn parse_query_rejects_missing_actor_device() {
        let convo = Uuid::new_v4();
        let query = format!("conversationId={}&afterSeq=0", convo);
        assert!(parse_query(Some(&query)).is_err());
    }
}
