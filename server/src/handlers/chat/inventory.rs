//! The three authenticated clean-chat inventory reads.
//!
//! These handlers are intentionally thin: parsing owns only public query
//! syntax, while admission, session identity, cursor replay, projection, and
//! receipt CAS semantics remain in the inventory repository.

use std::sync::Arc;

use axum::{
    extract::{RawQuery, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::chat_protocol::{
    error::{ChatEndpoint, ChatProtocolErrorCode},
    repository::inventory::{
        continue_inventory_page_for_admission, create_inventory_snapshot_and_first_page,
        InventoryDomain, InventoryPublicRequestBinding, InventoryRepositoryError,
    },
    validation::{CanonicalHttpMethod, CanonicalUuidV4},
    OsSecureRandom,
};
use crate::storage::DbPool;

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

pub(super) async fn conversations(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    handle(
        &pool,
        &runtime,
        &headers,
        query.as_deref(),
        ChatEndpoint::GetConversations,
        InventoryDomain::Conversations,
    )
    .await
}

pub(super) async fn welcomes(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    handle(
        &pool,
        &runtime,
        &headers,
        query.as_deref(),
        ChatEndpoint::GetPendingWelcomes,
        InventoryDomain::Welcomes,
    )
    .await
}

pub(super) async fn recovery(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    handle(
        &pool,
        &runtime,
        &headers,
        query.as_deref(),
        ChatEndpoint::GetLeafRecoveryInbox,
        InventoryDomain::Recovery,
    )
    .await
}

async fn handle(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    query: Option<&str>,
    endpoint: ChatEndpoint,
    domain: InventoryDomain,
) -> Response {
    serve(pool, runtime, headers, query, endpoint, domain)
        .await
        .unwrap_or_else(ChatFailure::into_response)
}

async fn serve(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    query: Option<&str>,
    endpoint: ChatEndpoint,
    domain: InventoryDomain,
) -> Result<Response, ChatFailure> {
    context::require_cutover(runtime, endpoint)?;
    let parsed = QueryParams::parse(query, domain)
        .map_err(|error| ChatFailure::protocol(endpoint, error))?;
    let method = CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(endpoint))?;
    let admission = context::admit_unsigned_read(
        pool,
        runtime,
        endpoint,
        method,
        headers,
        &parsed.actor_device_id,
    )
    .await?;
    let sealer = runtime
        .cursor_sealer()
        .ok_or_else(|| ChatFailure::invariant(endpoint))?;
    let request = InventoryPublicRequestBinding::new(
        endpoint.nsid(),
        1,
        domain,
        parsed.limit,
        Sha256::digest([]).into(),
    )
    .map_err(|_| ChatFailure::invariant(endpoint))?;

    let response = if let Some(cursor) = parsed.page_cursor.as_deref() {
        continue_inventory_page_for_admission(
            pool,
            admission,
            cursor,
            request,
            parsed.inventory_session_id.as_deref(),
            sealer,
        )
        .await
    } else {
        let mut random = OsSecureRandom::new();
        create_inventory_snapshot_and_first_page(
            pool,
            admission,
            request,
            parsed.inventory_session_id.as_deref(),
            sealer,
            &mut random,
        )
        .await
    }
    .map_err(|error| {
        tracing::error!(
            "create_inventory_snapshot_and_first_page error: {:?}",
            error
        );
        map_repository_error(endpoint, error)
    })?;
    Ok(context::json_ok(response.into_bytes()))
}

struct QueryParams {
    actor_device_id: String,
    limit: u16,
    page_cursor: Option<String>,
    inventory_session_id: Option<String>,
}

impl QueryParams {
    fn parse(query: Option<&str>, domain: InventoryDomain) -> Result<Self, ChatProtocolErrorCode> {
        let mut actor_device_id = None;
        let mut limit = None;
        let mut page_cursor = None;
        let mut inventory_session_id = None;
        for pair in query
            .unwrap_or_default()
            .split('&')
            .filter(|pair| !pair.is_empty())
        {
            let (raw_key, raw_value) = pair
                .split_once('=')
                .ok_or(ChatProtocolErrorCode::InvalidRequest)?;
            let key = percent_decode(raw_key).ok_or(ChatProtocolErrorCode::InvalidRequest)?;
            let value = percent_decode(raw_value).ok_or(ChatProtocolErrorCode::InvalidRequest)?;
            match key.as_str() {
                "actorDeviceId" if actor_device_id.is_none() => {
                    let canonical = CanonicalUuidV4::parse(&value)
                        .map_err(|_| ChatProtocolErrorCode::InvalidRequest)?;
                    actor_device_id = Some(canonical.as_str().to_string());
                }
                "limit" if limit.is_none() => {
                    let parsed = value
                        .parse::<u16>()
                        .map_err(|_| ChatProtocolErrorCode::InvalidRequest)?;
                    if !(1..=100).contains(&parsed) {
                        return Err(ChatProtocolErrorCode::InvalidRequest);
                    }
                    limit = Some(parsed);
                }
                "pageCursor" if page_cursor.is_none() => {
                    if value.is_empty() || value.len() > 512 {
                        return Err(ChatProtocolErrorCode::InvalidRequest);
                    }
                    page_cursor = Some(value);
                }
                "inventorySessionId" if inventory_session_id.is_none() => {
                    inventory_session_id = Some(parse_canonical_capability(&value)?);
                }
                _ => return Err(ChatProtocolErrorCode::InvalidRequest),
            }
        }
        let actor_device_id = actor_device_id.ok_or(ChatProtocolErrorCode::InvalidRequest)?;
        let limit = limit.unwrap_or(50);
        let inventory_session_id = match domain {
            InventoryDomain::Conversations => {
                if inventory_session_id.is_some() {
                    return Err(ChatProtocolErrorCode::InvalidRequest);
                }
                None
            }
            InventoryDomain::Welcomes | InventoryDomain::Recovery => {
                Some(inventory_session_id.ok_or(ChatProtocolErrorCode::InvalidRequest)?)
            }
        };
        Ok(Self {
            actor_device_id,
            limit,
            page_cursor,
            inventory_session_id,
        })
    }
}

fn parse_canonical_capability(value: &str) -> Result<String, ChatProtocolErrorCode> {
    if value.len() != 43 {
        return Err(ChatProtocolErrorCode::InvalidRequest);
    }
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ChatProtocolErrorCode::InvalidRequest)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(ChatProtocolErrorCode::InvalidRequest);
    }
    Ok(value.to_owned())
}

fn percent_decode(value: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let raw = value.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'+' => bytes.push(b' '),
            b'%' if index + 2 < raw.len() => {
                let hi = (raw[index + 1] as char).to_digit(16)?;
                let lo = (raw[index + 2] as char).to_digit(16)?;
                bytes.push((hi * 16 + lo) as u8);
                index += 2;
            }
            byte if byte.is_ascii() => bytes.push(byte),
            _ => return None,
        }
        index += 1;
    }
    String::from_utf8(bytes).ok()
}

fn map_repository_error(endpoint: ChatEndpoint, error: InventoryRepositoryError) -> ChatFailure {
    use InventoryRepositoryError as E;
    match error {
        E::SessionNotFound | E::SessionPresentationMismatch => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InventorySessionMismatch)
        }
        E::DeviceAuthorityMismatch => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::DeviceRevoked)
        }
        E::ReadAuthority(error) => match error {
            crate::chat_protocol::read_authority::ReadAuthorityError::DeviceRevoked => {
                ChatFailure::protocol(endpoint, ChatProtocolErrorCode::DeviceRevoked)
            }
            crate::chat_protocol::read_authority::ReadAuthorityError::Storage => {
                ChatFailure::storage(endpoint)
            }
            crate::chat_protocol::read_authority::ReadAuthorityError::ConversationNotFound
            | crate::chat_protocol::read_authority::ReadAuthorityError::NotEntitled
            | crate::chat_protocol::read_authority::ReadAuthorityError::AccessOutsideMembershipInterval
            | crate::chat_protocol::read_authority::ReadAuthorityError::Invariant => {
                ChatFailure::invariant(endpoint)
            }
        },
        E::ReadAdmission(_) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::DeviceBindingMismatch)
        }
        E::Cursor(crate::chat_protocol::CursorCodecError::Expired)
        | E::Cursor(crate::chat_protocol::CursorCodecError::BelowRetentionFloor) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::CursorExpired)
        }
        E::Cursor(_) => ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest),
        E::Database(_) => ChatFailure::storage(endpoint),
        E::SecureRandom(_)
        | E::Sealer(_)
        | E::DurableRowInvalid
        | E::ProtocolFenceMismatch
        | E::DomainAlreadyComplete
        | E::BoundaryItemMismatch
        | E::TransactionMismatch
        | E::RaceOrReuse
        | E::InvalidMaterialization
        | E::InconsistentConversationSelection
        | E::InconsistentWelcomeSelection
        | E::InconsistentRecoverySelection
        | E::SnapshotConflict
        | E::RetryCeiling
        | E::RequestTooBroad => ChatFailure::invariant(endpoint),
        #[allow(unreachable_patterns)]
        _ => ChatFailure::invariant(endpoint),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTOR: &str = "018f0c4e-7a2b-4b15-8c21-4e6ad3d6a901";
    const SESSION: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";

    #[test]
    fn defaults_limit_and_rejects_session_for_conversations() {
        let query = format!("actorDeviceId={ACTOR}");
        let parsed = QueryParams::parse(Some(&query), InventoryDomain::Conversations).unwrap();
        assert_eq!(parsed.limit, 50);
        assert_eq!(parsed.actor_device_id, ACTOR);
        assert!(parsed.inventory_session_id.is_none());
        assert!(QueryParams::parse(
            Some(&format!(
                "actorDeviceId={ACTOR}&limit=50&inventorySessionId={SESSION}"
            )),
            InventoryDomain::Conversations
        )
        .is_err());
    }

    #[test]
    fn requires_canonical_session_for_domain_pages() {
        let query = format!("actorDeviceId={ACTOR}&inventorySessionId={SESSION}&limit=1");
        let parsed = QueryParams::parse(Some(&query), InventoryDomain::Welcomes).unwrap();
        assert_eq!(parsed.limit, 1);
        assert_eq!(parsed.inventory_session_id.as_deref(), Some(SESSION));
        assert!(QueryParams::parse(
            Some(&format!(
                "actorDeviceId={ACTOR}&inventorySessionId=not-a-valid-capability&limit=1"
            )),
            InventoryDomain::Recovery,
        )
        .is_err());
    }

    #[test]
    fn rejects_duplicate_unknown_and_oversized_query_values() {
        let oversized = format!(
            "actorDeviceId={ACTOR}&inventorySessionId={SESSION}&limit=1&pageCursor={}",
            "a".repeat(513)
        );
        for query in [
            format!("actorDeviceId={ACTOR}&inventorySessionId={SESSION}&limit=1&limit=2"),
            format!("actorDeviceId={ACTOR}&inventorySessionId={SESSION}&limit=1&unexpected=x"),
            format!("actorDeviceId={ACTOR}&inventorySessionId={SESSION}&limit=1&pageCursor="),
        ] {
            assert!(QueryParams::parse(Some(&query), InventoryDomain::Recovery).is_err());
        }
        assert!(QueryParams::parse(Some(&oversized), InventoryDomain::Recovery).is_err());
    }
}
