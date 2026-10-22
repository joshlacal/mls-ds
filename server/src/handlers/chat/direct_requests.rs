//! Thin transport adapters. The repository owns signed admission, ordered locks,
//! attempt claims and commit-before-response behavior; feature activation is off
//! until the dedicated receipt authority has passed its durable startup check.
use super::{context, errors::ChatFailure, runtime::ChatRuntime};
use base64::Engine;
use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::direct_request_preparation::{
            self as requests, DirectRequestResult, DirectRequestStoreError,
        },
    },
    storage::DbPool,
};
use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

fn failure(endpoint: ChatEndpoint, error: DirectRequestStoreError) -> ChatFailure {
    tracing::warn!(%error, endpoint = endpoint.nsid(), "direct request repository failure");
    let code = match error {
        DirectRequestStoreError::Database(_) => return ChatFailure::storage(endpoint),
        DirectRequestStoreError::ForeignTransaction | DirectRequestStoreError::InvalidReceipt => {
            return ChatFailure::invariant(endpoint)
        }
        DirectRequestStoreError::IdentityConflict => ChatProtocolErrorCode::PreparationConflict,
        DirectRequestStoreError::InvalidSignature => ChatProtocolErrorCode::InvalidSignature,
        DirectRequestStoreError::Expired => ChatProtocolErrorCode::PreparationExpired,
        DirectRequestStoreError::QuotaExceeded => ChatProtocolErrorCode::CapacityUnavailable,
        DirectRequestStoreError::RecipientKeysUnavailable => {
            ChatProtocolErrorCode::RecipientKeysUnavailable
        }
        DirectRequestStoreError::RecipientAuthorityUnsupported
        | DirectRequestStoreError::CoordinatorMoved => {
            ChatProtocolErrorCode::RecipientAuthorityUnsupported
        }
        DirectRequestStoreError::IncludedAuthorityChanged => {
            ChatProtocolErrorCode::PreparationRevoked
        }
        DirectRequestStoreError::PolicyDenied => ChatProtocolErrorCode::RequestPolicyDenied,
    };
    ChatFailure::protocol(endpoint, code)
}
fn pair_failure(endpoint: ChatEndpoint, error: crate::federation::FederationError) -> ChatFailure {
    use crate::federation::FederationError;
    match error {
        FederationError::Unsupported(_)
        | FederationError::AuthFailed { .. }
        | FederationError::EndpointNotFound { .. } => failure(
            endpoint,
            DirectRequestStoreError::RecipientAuthorityUnsupported,
        ),
        _ => failure(endpoint, DirectRequestStoreError::PolicyDenied),
    }
}
/// Whether a prepare answered by this DS alone ended in a refusal that holds
/// wherever the recipient is homed: its authority is not admitted, policy
/// refused, or the sender's own request is stale, conflicting or over quota.
fn confirms_local_refusal(result: &DirectRequestResult) -> bool {
    let DirectRequestResult::Terminal(bytes) = result else {
        return false;
    };
    serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|receipt| {
        let receipt = &receipt["body"]["receipt"];
        receipt["$type"] == "blue.catbird.chat.defs#directRequestExpiredReceipt"
            || matches!(
                receipt["code"].as_str(),
                Some(
                    "RecipientAuthorityUnsupported"
                        | "RequestPolicyDenied"
                        | "PreparationExpired"
                        | "PreparationConflict"
                        | "CapacityUnavailable"
                )
            )
    })
}
fn output(result: DirectRequestResult, endpoint: ChatEndpoint) -> Result<Vec<u8>, ChatFailure> {
    let mut payload = match result {
        DirectRequestResult::Keys(bytes) => return Ok(bytes),
        DirectRequestResult::Unknown(id) => {
            serde_json::json!({"$type":"blue.catbird.chat.defs#directRequestUnknownOutcome","requestId":id.to_string()})
        }
        DirectRequestResult::Prepared(bytes) => {
            serde_json::json!({"$type":"blue.catbird.chat.defs#directRequestPreparedOutcome","preparation":serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|_|ChatFailure::invariant(endpoint))?})
        }
        DirectRequestResult::Terminal(bytes) => {
            let mut value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| ChatFailure::invariant(endpoint))?;
            value["$type"] = serde_json::json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
            value
        }
    };
    // Outcomes and mutation receipts echo retained bare-base64 signed bytes;
    // present them as lexicon `{"$bytes":…}` at response time only.
    crate::chat_protocol::direct_request_transcript::present_read_presentation(
        "directRequestOutcome",
        &mut payload,
    )
    .map_err(|_| ChatFailure::invariant(endpoint))?;
    let bytes = serde_json::to_vec(&serde_json::json!({"outcome":payload}))
        .map_err(|_| ChatFailure::invariant(endpoint))?;
    if bytes.len() > 8_388_608 {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::ArtifactTooLarge,
        ));
    }
    Ok(bytes)
}
/// The active, unrevoked signing key of a sender's device at the generation
/// its request names.
async fn active_device_key(
    pool: &DbPool,
    endpoint: ChatEndpoint,
    actor_did: &str,
    actor_device_id: uuid::Uuid,
    key_id: &str,
    auth_generation: i64,
) -> Result<(Vec<u8>, i64), ChatFailure> {
    let sender_key_row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT k.signing_public_key, d.auth_generation \
         FROM chat.device_keys k \
         JOIN chat.devices d ON d.user_did = k.user_did AND d.device_id = k.device_id \
         WHERE k.user_did = $1 \
           AND k.device_id = $2 \
           AND k.key_id = $3 \
           AND d.auth_generation = $4 \
           AND d.status = 'active' \
           AND d.revoked_at IS NULL \
           AND k.revoked_at IS NULL",
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(key_id)
    .bind(auth_generation)
    .fetch_optional(pool)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;

    sender_key_row.ok_or_else(|| {
        tracing::warn!(
            actor_did,
            %actor_device_id,
            key_id,
            auth_generation,
            "sender active non-revoked device/key not found or generation mismatch"
        );
        failure(endpoint, DirectRequestStoreError::IdentityConflict)
    })
}

/// A request this DS relays to the pair's coordinator.
struct OutboundRoute<'a> {
    request_id: uuid::Uuid,
    actor_did: &'a str,
    actor_device_id: uuid::Uuid,
    recipient_did: &'a str,
    coordinator_did: &'a str,
}

/// The coordinator this DS relayed a request to when it first saw it, which
/// stays the request's receipt authority whatever the declarations say now.
pub(super) struct RecordedRoute {
    pub(super) actor_did: String,
    pub(super) actor_device_id: uuid::Uuid,
    pub(super) recipient_did: String,
    pub(super) coordinator_did: String,
}

impl RecordedRoute {
    pub(super) async fn load(
        pool: &DbPool,
        endpoint: ChatEndpoint,
        request_id: uuid::Uuid,
    ) -> Result<Option<Self>, ChatFailure> {
        let route: Option<(String, uuid::Uuid, String, String)> = sqlx::query_as(
            "SELECT actor_did, actor_device_id, recipient_did, coordinator_did \
             FROM chat.direct_request_outbound_routes WHERE request_id=$1",
        )
        .bind(request_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
        Ok(route.map(
            |(actor_did, actor_device_id, recipient_did, coordinator_did)| Self {
                actor_did,
                actor_device_id,
                recipient_did,
                coordinator_did,
            },
        ))
    }

    /// Whether the route was recorded for this sender's device and, when the
    /// caller names one, this recipient.
    pub(super) fn belongs_to(
        &self,
        actor_did: &str,
        actor_device_id: uuid::Uuid,
        recipient_did: Option<&str>,
    ) -> bool {
        self.actor_did == actor_did
            && self.actor_device_id == actor_device_id
            && recipient_did.is_none_or(|recipient| self.recipient_did == recipient)
    }
}

/// Whether this DS has relayed `request_id` to another coordinator, read
/// under the pair lock by a writer that would otherwise answer it here.
async fn request_routed(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    endpoint: ChatEndpoint,
    request_id: uuid::Uuid,
) -> Result<bool, ChatFailure> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.direct_request_outbound_routes WHERE request_id=$1)",
    )
    .bind(request_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))
}

/// Record, before the first relay, which coordinator a request goes to, so
/// every later prepare, cancel or outcome read of it reaches the same one.
/// `fenced` also refuses a pair that another coordinator already holds.
async fn record_outbound_route(
    pool: &DbPool,
    endpoint: ChatEndpoint,
    route: OutboundRoute<'_>,
    fenced: bool,
) -> Result<(), ChatFailure> {
    let OutboundRoute {
        request_id,
        actor_did,
        actor_device_id,
        recipient_did,
        coordinator_did,
    } = route;
    let mut route_tx = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let (p1, p2) = if actor_did <= recipient_did {
        (actor_did, recipient_did)
    } else {
        (recipient_did, actor_did)
    };
    let pair_lock_key = format!("chat-direct-request-pair:{p1}:{p2}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&pair_lock_key)
        .execute(&mut *route_tx)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    // A request this DS prepared or cancelled as the sender's home while the
    // caller was resolving the pair is never routed elsewhere. The caller
    // gets an unsigned conflict, and its retry replays the home attempt.
    if crate::federation::canonical_relay::held_attempt_origin(&mut *route_tx, request_id)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?
        == Some(crate::federation::canonical_relay::AttemptOrigin::Home)
    {
        return Err(failure(endpoint, DirectRequestStoreError::IdentityConflict));
    }

    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("chat-direct-request-outbound:{actor_did}"))
        .execute(&mut *route_tx)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let (recent, existing): (i64, bool) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM chat.direct_request_outbound_routes WHERE actor_did=$1 AND created_at>clock_timestamp()-INTERVAL '1 hour'), \
                EXISTS(SELECT 1 FROM chat.direct_request_outbound_routes WHERE request_id=$2 AND actor_did=$1)",
    )
    .bind(actor_did)
    .bind(request_id)
    .fetch_one(&mut *route_tx)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;
    if recent >= 20 && !existing {
        return Err(failure(endpoint, DirectRequestStoreError::QuotaExceeded));
    }
    if fenced {
        if let Some(crate::federation::canonical_relay::PairFenceConflict::ForeignCoordinator {
            ..
        }) = crate::federation::canonical_relay::check_pair_owner_fence(
            &mut route_tx,
            actor_did,
            recipient_did,
            request_id,
            Some(coordinator_did),
        )
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?
        {
            return Err(failure(endpoint, DirectRequestStoreError::IdentityConflict));
        }
    }
    let route: Option<uuid::Uuid> = sqlx::query_scalar(
        "INSERT INTO chat.direct_request_outbound_routes \
            (request_id, actor_did, actor_device_id, recipient_did, coordinator_did) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (request_id) DO UPDATE SET request_id=EXCLUDED.request_id \
         WHERE chat.direct_request_outbound_routes.actor_did=EXCLUDED.actor_did \
           AND chat.direct_request_outbound_routes.actor_device_id=EXCLUDED.actor_device_id \
           AND chat.direct_request_outbound_routes.recipient_did=EXCLUDED.recipient_did \
           AND chat.direct_request_outbound_routes.coordinator_did=EXCLUDED.coordinator_did \
         RETURNING request_id",
    )
    .bind(request_id)
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(recipient_did)
    .bind(coordinator_did)
    .fetch_optional(&mut *route_tx)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;
    if route.is_none() {
        return Err(failure(endpoint, DirectRequestStoreError::IdentityConflict));
    }
    route_tx
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    Ok(())
}

/// What a cancel names, read before verification only to find where it goes.
struct CancelTarget {
    request_id: uuid::Uuid,
    actor_device_id: uuid::Uuid,
    key_id: String,
    auth_generation: i64,
    recipient_did: String,
}

impl CancelTarget {
    fn parse(raw: &str, actor_did: &str) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_str(raw).ok()?;
        let body = &value["body"];
        let recipient_did = body["recipientDid"].as_str()?;
        if body["actorDid"].as_str()? != actor_did
            || !crate::chat_protocol::is_bare_did(recipient_did)
            || recipient_did == actor_did
        {
            return None;
        }
        Some(Self {
            request_id: uuid::Uuid::parse_str(body["requestId"].as_str()?).ok()?,
            actor_device_id: uuid::Uuid::parse_str(body["actorDeviceId"].as_str()?).ok()?,
            key_id: body["keyId"].as_str()?.to_owned(),
            auth_generation: body["authGeneration"].as_i64()?,
            recipient_did: recipient_did.to_owned(),
        })
    }
}

/// How a sender's home answers a coordinator's refusal of a relayed cancel.
/// Only the status survives the relay, so it is the whole contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancelRelayDisposition {
    /// 404, 405, 501: the coordinator predates the cancel procedure.
    Unsupported,
    /// 410: the cancel is too old to sign and nothing ended the request yet.
    Stale,
    Conflict,
    BadSignature,
    NotAuthorized,
    RateLimited,
    Capacity,
    Invalid,
    Transient,
}

impl CancelRelayDisposition {
    fn of(status: u16) -> Self {
        match status {
            404 | 405 | 501 => Self::Unsupported,
            410 => Self::Stale,
            409 => Self::Conflict,
            422 => Self::BadSignature,
            401 | 403 => Self::NotAuthorized,
            429 => Self::RateLimited,
            507 => Self::Capacity,
            400 => Self::Invalid,
            _ => Self::Transient,
        }
    }

    /// Whether the coordinator's stored outcome may still answer the cancel.
    fn reads_outcome(self) -> bool {
        matches!(self, Self::Unsupported | Self::Stale)
    }

    fn failure(self, endpoint: ChatEndpoint) -> ChatFailure {
        let code = match self {
            Self::Unsupported | Self::Transient => return ChatFailure::storage(endpoint),
            Self::Stale => ChatProtocolErrorCode::PreparationExpired,
            Self::Conflict => ChatProtocolErrorCode::PreparationConflict,
            Self::BadSignature => ChatProtocolErrorCode::InvalidSignature,
            Self::NotAuthorized => ChatProtocolErrorCode::NotAuthorized,
            Self::RateLimited => ChatProtocolErrorCode::RateLimited,
            Self::Capacity => ChatProtocolErrorCode::CapacityUnavailable,
            Self::Invalid => ChatProtocolErrorCode::InvalidRequest,
        };
        ChatFailure::protocol(endpoint, code)
    }
}

const SIGNED_RECEIPT: &str = "blue.catbird.chat.defs#signedDirectRequestReceipt";

/// A cancel is answered by the coordinator that holds the request. The client
/// checks the receipt against the coordinator it pinned when it minted the
/// request, so a request this DS routed elsewhere is cancelled there, never
/// here. A cancel this DS cannot read is left to the repository to refuse.
async fn cancel_routed(
    pool: &DbPool,
    principal: &crate::auth::VerifiedServicePrincipal,
    signed_request: &serde_json::value::RawValue,
    signer: &crate::chat_protocol::repository::direct_request_receipts::DirectRequestReceiptSigner,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Response, ChatFailure> {
    use crate::federation::canonical_relay::{self, AttemptOrigin};
    let endpoint = ChatEndpoint::CancelDirectRequestPreparation;
    let Some(target) = CancelTarget::parse(signed_request.get(), principal.did()) else {
        return cancel_locally(pool, principal, signed_request, signer, now, None).await;
    };
    // A request this DS prepared as the sender's home is cancelled here: the
    // client pinned this DS, which signed what it holds, even if a later retry
    // was relayed elsewhere after a declaration move. A refusal this DS signed
    // alone, or an attempt it holds for a sender homed elsewhere, does not
    // decide where the cancel goes.
    let origin = canonical_relay::held_attempt_origin(pool, target.request_id)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    if origin == Some(AttemptOrigin::Home) {
        return cancel_locally(
            pool,
            principal,
            signed_request,
            signer,
            now,
            Some((&target, AttemptOrigin::Home)),
        )
        .await;
    }
    let route = RecordedRoute::load(pool, endpoint, target.request_id).await?;
    let routed = route.is_some();

    // This DS vouches for the sender's key to the coordinator, so it checks
    // the cancel under that key before it resolves or contacts anyone, in the
    // order a local cancel would: the device's key, the signature under it,
    // then that it is the device's active key at the signed generation.
    let registered: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT signing_public_key FROM chat.device_keys WHERE user_did=$1 AND device_id=$2",
    )
    .bind(principal.did())
    .bind(target.actor_device_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;
    let registered =
        registered.ok_or_else(|| failure(endpoint, DirectRequestStoreError::IdentityConflict))?;
    crate::chat_protocol::direct_request_transcript::verify_signed_request(
        crate::chat_protocol::direct_request_transcript::DirectRequestKind::Cancel,
        signed_request.get().as_bytes(),
        &registered,
    )
    .map_err(|_| failure(endpoint, DirectRequestStoreError::InvalidSignature))?;
    let (signing_public_key, auth_generation) = active_device_key(
        pool,
        endpoint,
        principal.did(),
        target.actor_device_id,
        &target.key_id,
        target.auth_generation,
    )
    .await?;
    if signing_public_key != registered {
        return Err(failure(endpoint, DirectRequestStoreError::IdentityConflict));
    }

    let (coordinator_did, coordinator_endpoint) = match route {
        Some(route) => {
            if !route.belongs_to(
                principal.did(),
                target.actor_device_id,
                Some(&target.recipient_did),
            ) {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::NotAuthorized,
                ));
            }
            // The recorded coordinator, not the live one: the declaration
            // may have moved since the request was minted.
            let home = canonical_relay::admit_recorded_coordinator(pool, &route.coordinator_did)
                .await
                .map_err(|error| pair_failure(endpoint, error))?;
            (route.coordinator_did, home.endpoint)
        }
        None => {
            match canonical_relay::resolve_pair_coordinator_by_side(
                pool,
                principal.did(),
                &target.recipient_did,
            )
            .await
            {
                Ok(coord) if !coord.is_sender_home => {
                    return Err(ChatFailure::protocol(
                        endpoint,
                        ChatProtocolErrorCode::NotAuthorized,
                    ))
                }
                Ok(coord) if !coord.is_coordinator => {
                    let coordinator_endpoint = coord.coordinator_endpoint().to_owned();
                    (coord.coordinator_did, coordinator_endpoint)
                }
                Ok(_) => {
                    return cancel_locally(
                        pool,
                        principal,
                        signed_request,
                        signer,
                        now,
                        Some((&target, AttemptOrigin::Home)),
                    )
                    .await
                }
                Err(error) => {
                    let self_did = crate::identity::service_did();
                    // The pair has no federated coordinator: the recipient
                    // has no authority this DS could join, or the sender has
                    // none and the client pinned the canonical authority,
                    // which is this DS. The cancel is answered here, as it
                    // was before relaying existed. Anything else, a
                    // resolution that failed in transit included, could
                    // name another coordinator, so this DS signs nothing.
                    let origin = if error.local_refusal_coordinator(&self_did).is_some() {
                        AttemptOrigin::LocalRefusal
                    } else if error.sender_has_no_authority()
                        && crate::identity::canonical_did(&self_did)
                            == canonical_relay::CANONICAL_DIRECT_REQUEST_AUTHORITY
                    {
                        AttemptOrigin::Home
                    } else {
                        return Err(pair_failure(endpoint, error.into_federation_error()));
                    };
                    return cancel_locally(
                        pool,
                        principal,
                        signed_request,
                        signer,
                        now,
                        Some((&target, origin)),
                    )
                    .await;
                }
            }
        }
    };

    if !routed {
        // A cancel can be the first this DS hears of a request, and a later
        // prepare or outcome read must still reach the same coordinator.
        record_outbound_route(
            pool,
            endpoint,
            OutboundRoute {
                request_id: target.request_id,
                actor_did: principal.did(),
                actor_device_id: target.actor_device_id,
                recipient_did: &target.recipient_did,
                coordinator_did: &coordinator_did,
            },
            false,
        )
        .await?;
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct RelayedCancel<'a> {
        signed_request: &'a serde_json::value::RawValue,
        sender_device_key: canonical_relay::SenderDeviceKey,
    }
    let payload = RelayedCancel {
        signed_request,
        sender_device_key: canonical_relay::SenderDeviceKey {
            device_id: target.actor_device_id,
            key_id: target.key_id.clone(),
            signing_public_key: base64::engine::general_purpose::STANDARD
                .encode(&signing_public_key),
            auth_generation,
        },
    };
    let response = match canonical_relay::relay_cancel_direct_request(
        &coordinator_endpoint,
        &coordinator_did,
        &payload,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            let status = match &error {
                crate::federation::FederationError::RemoteError { status, .. } => *status,
                _ => 502,
            };
            let disposition = CancelRelayDisposition::of(status);
            tracing::warn!(
                ?error,
                ?disposition,
                "coordinator refused the relayed cancel"
            );
            // A coordinator without the procedure, or one that will not sign a
            // stale cancel, may still have ended the request: its own expiry,
            // rejection or publication answers the cancel.
            let stored = match disposition.reads_outcome() {
                true => canonical_relay::relay_get_outcome(
                    &coordinator_endpoint,
                    &coordinator_did,
                    target.request_id,
                    target.actor_device_id,
                )
                .await
                .ok()
                .filter(|response| response["outcome"]["$type"] == SIGNED_RECEIPT),
                false => None,
            };
            stored.ok_or_else(|| disposition.failure(endpoint))?
        }
    };

    let outcome = response
        .get("outcome")
        .filter(|outcome| outcome["$type"] == SIGNED_RECEIPT)
        .ok_or_else(|| ChatFailure::storage(endpoint))?;
    let published = outcome
        .pointer("/body/receipt/$type")
        .and_then(|t| t.as_str())
        == Some("blue.catbird.chat.defs#directRequestPublishedReceipt");
    let mut outcome = if published {
        // A cancel that lost the race to publish gets the publication, and
        // this DS mirrors it as a relayed publish would.
        crate::handlers::chat::publish_direct_request::materialize_sender_home_published_mirror(
            pool,
            &coordinator_did,
            principal.did(),
            target.actor_device_id,
            &target.recipient_did,
            target.request_id,
            outcome,
            response.get("entry"),
            None,
            now,
            endpoint,
        )
        .await?
    } else {
        outcome.clone()
    };
    crate::chat_protocol::direct_request_transcript::present_read_presentation(
        "directRequestOutcome",
        &mut outcome,
    )
    .map_err(|_| ChatFailure::storage(endpoint))?;
    let bytes = serde_json::to_vec(&serde_json::json!({ "outcome": outcome }))
        .map_err(|_| ChatFailure::invariant(endpoint))?;
    Ok(context::json_ok(bytes))
}

/// A cancel this DS answers itself, as the pair's coordinator. A cancel that
/// is the first this DS hears of a request records `origin` for the attempt
/// it ends. A request it had reserved recipient packages for on another DS
/// gives them back.
async fn cancel_locally(
    pool: &DbPool,
    principal: &crate::auth::VerifiedServicePrincipal,
    signed_request: &serde_json::value::RawValue,
    signer: &crate::chat_protocol::repository::direct_request_receipts::DirectRequestReceiptSigner,
    now: chrono::DateTime<chrono::Utc>,
    target: Option<(&CancelTarget, crate::federation::canonical_relay::AttemptOrigin)>,
) -> Result<Response, ChatFailure> {
    let endpoint = ChatEndpoint::CancelDirectRequestPreparation;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    // The pair lock orders the cancel against a prepare, as on the
    // coordinator, so whether it creates the attempt is read reliably.
    let created = match target {
        Some((target, _)) => {
            let actor_did = principal.did();
            let recipient_did = target.recipient_did.as_str();
            let (p1, p2) = if actor_did <= recipient_did {
                (actor_did, recipient_did)
            } else {
                (recipient_did, actor_did)
            };
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(format!("chat-direct-request-pair:{p1}:{p2}"))
                .execute(&mut *tx)
                .await
                .map_err(|_| ChatFailure::storage(endpoint))?;
            let held: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM chat.direct_request_attempts WHERE request_id=$1)",
            )
            .bind(target.request_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
            // A request relayed elsewhere while this cancel resolved the pair
            // is the coordinator's to end; its retry follows the route.
            if !held && request_routed(&mut tx, endpoint, target.request_id).await? {
                return Err(failure(endpoint, DirectRequestStoreError::IdentityConflict));
            }
            !held
        }
        None => false,
    };
    let result = requests::cancel_direct_request(
        &mut tx,
        principal,
        signed_request.get().as_bytes(),
        signer,
        now,
    )
    .await
    .map_err(|e| failure(endpoint, e))?;
    let bytes = output(result, endpoint)?;
    if let Some((target, origin)) = target.filter(|_| created) {
        crate::federation::canonical_relay::record_attempt_origin(
            &mut tx,
            target.request_id,
            origin,
            &crate::identity::service_did(),
        )
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    }
    tx.commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    if let Some((target, _)) = target {
        crate::federation::canonical_relay::release_remote_reservation_if_unpublished(
            pool,
            target.request_id,
        )
        .await;
    }
    Ok(context::json_ok(bytes))
}

/// A prepare this DS relays to the coordinator that holds its pair.
struct RelayedPrepare<'a> {
    route: OutboundRoute<'a>,
    coordinator_endpoint: &'a str,
    signed_request: &'a serde_json::Value,
    key_id: &'a str,
    signing_public_key: &'a [u8],
    auth_generation: i64,
}

/// Relay a prepare, after recording (and fencing) its route.
async fn relay_prepare(pool: &DbPool, relay: RelayedPrepare<'_>) -> Result<Response, ChatFailure> {
    let endpoint = ChatEndpoint::PrepareDirectRequest;
    let RelayedPrepare {
        route,
        coordinator_endpoint,
        signed_request,
        key_id,
        signing_public_key,
        auth_generation,
    } = relay;
    let actor_device_id = route.actor_device_id;
    let coordinator_did = route.coordinator_did;
    record_outbound_route(pool, endpoint, route, true).await?;
    let relay_payload = serde_json::json!({
        "signedRequest": signed_request,
        "senderDeviceKey": {
            "deviceId": actor_device_id.to_string(),
            "keyId": key_id,
            "signingPublicKey": base64::engine::general_purpose::STANDARD.encode(signing_public_key),
            "authGeneration": auth_generation,
        }
    });

    let outcome = crate::federation::canonical_relay::relay_prepare_direct_request(
        coordinator_endpoint,
        coordinator_did,
        &relay_payload,
    )
    .await
    .map_err(|e| match e {
        crate::federation::FederationError::RemoteError { status: 409, .. } => {
            failure(endpoint, DirectRequestStoreError::IdentityConflict)
        }
        _ => failure(endpoint, DirectRequestStoreError::PolicyDenied),
    })?;
    let bytes = serde_json::to_vec(&outcome).map_err(|_| ChatFailure::invariant(endpoint))?;
    Ok(context::json_ok(bytes))
}

/// Replay a prepare of a request this DS prepared as the sender's home. The
/// repository returns what the attempt recorded, or signs its expiry, so the
/// pair need not be read.
#[allow(clippy::too_many_arguments)]
async fn replay_prepare(
    pool: &DbPool,
    runtime: &ChatRuntime,
    principal: &crate::auth::VerifiedServicePrincipal,
    signed_request: &serde_json::value::RawValue,
    signer: &crate::chat_protocol::repository::direct_request_receipts::DirectRequestReceiptSigner,
    now: chrono::DateTime<chrono::Utc>,
    recipient_did: &str,
    request_id: uuid::Uuid,
) -> Result<Response, ChatFailure> {
    let endpoint = ChatEndpoint::PrepareDirectRequest;
    let actor_did = principal.did();
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let (p1, p2) = if actor_did <= recipient_did {
        (actor_did, recipient_did)
    } else {
        (recipient_did, actor_did)
    };
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("chat-direct-request-pair:{p1}:{p2}"))
        .execute(&mut *tx)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let result = requests::prepare_direct_request(
        &mut tx,
        principal,
        signed_request.get().as_bytes(),
        signer,
        runtime.relationship_authority().as_ref(),
        &crate::identity::service_did(),
        now,
    )
    .await
    .map_err(|e| failure(endpoint, e))?;
    let ended = !matches!(result, DirectRequestResult::Prepared(_));
    let bytes = output(result, endpoint)?;
    tx.commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    if ended {
        crate::federation::canonical_relay::release_remote_reservation_if_unpublished(
            pool, request_id,
        )
        .await;
    }
    Ok(context::json_ok(bytes))
}

async fn mutate(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
    endpoint: ChatEndpoint,
) -> Result<Response, ChatFailure> {
    let signer = runtime
        .request_receipt_signer()
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::CutoverRequired))?;
    if !runtime.request_producers_enabled()
        && matches!(
            endpoint,
            ChatEndpoint::PrepareDirectRequest | ChatEndpoint::PublishDirectRequestKeys
        )
    {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::CutoverRequired,
        ));
    }
    let principal = context::verify_service_principal(pool, endpoint, headers).await?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope<'a> {
        #[serde(rename = "signedRequest", borrow)]
        signed_request: &'a serde_json::value::RawValue,
    }
    let envelope: Envelope = serde_json::from_slice(body)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let now = crate::chat_protocol::validation::TrustedRequestInstant::capture()
        .map_err(|_| ChatFailure::invariant(endpoint))?
        .datetime();

    if endpoint == ChatEndpoint::PrepareDirectRequest {
        let parsed_req: serde_json::Value = serde_json::from_str(envelope.signed_request.get())
            .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
        let body = parsed_req.get("body").ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;

        let req_actor_did = body.get("actorDid").and_then(|v| v.as_str()).ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
        if req_actor_did != principal.did() {
            tracing::warn!(
                claimed_actor = %req_actor_did,
                principal = %principal.did(),
                "signed prepare actorDid does not match authenticated principal"
            );
            return Err(failure(endpoint, DirectRequestStoreError::IdentityConflict));
        }
        let actor_did = principal.did();

        let recipient_did = body.get("recipientDid").and_then(|v| v.as_str()).ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
        if !crate::chat_protocol::is_bare_did(recipient_did) || recipient_did == actor_did {
            return Err(failure(endpoint, DirectRequestStoreError::IdentityConflict));
        }

        let actor_device_id_str = body.get("actorDeviceId").and_then(|v| v.as_str()).ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
        let actor_device_id = uuid::Uuid::parse_str(actor_device_id_str)
            .map_err(|_| failure(endpoint, DirectRequestStoreError::IdentityConflict))?;

        let key_id = body.get("keyId").and_then(|v| v.as_str()).ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;

        let auth_generation = body.get("authGeneration").and_then(|v| v.as_i64()).ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;

        let request_id_str = body.get("requestId").and_then(|v| v.as_str()).ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
        let request_id = uuid::Uuid::parse_str(request_id_str)
            .map_err(|_| failure(endpoint, DirectRequestStoreError::InvalidReceipt))?;

        let (signing_public_key, verified_auth_gen) = active_device_key(
            pool,
            endpoint,
            actor_did,
            actor_device_id,
            key_id,
            auth_generation,
        )
        .await?;

        crate::chat_protocol::direct_request_transcript::verify_signed_request(
            crate::chat_protocol::direct_request_transcript::DirectRequestKind::Prepare,
            envelope.signed_request.get().as_bytes(),
            &signing_public_key,
        )
        .map_err(|_| failure(endpoint, DirectRequestStoreError::InvalidSignature))?;

        // The client checks every receipt against the coordinator it pinned
        // when it minted the request, so a retry goes where the request
        // first went: this DS when it prepared the request as the sender's
        // home, or the coordinator it was first relayed to. Only a request
        // this DS has neither, a refusal it signed alone, or one it holds for
        // another DS reads the pair again.
        let origin = crate::federation::canonical_relay::held_attempt_origin(pool, request_id)
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
        if origin == Some(crate::federation::canonical_relay::AttemptOrigin::Home) {
            return replay_prepare(
                pool,
                runtime,
                &principal,
                envelope.signed_request,
                signer,
                now,
                recipient_did,
                request_id,
            )
            .await;
        }
        if let Some(route) = RecordedRoute::load(pool, endpoint, request_id).await? {
            if !route.belongs_to(actor_did, actor_device_id, Some(recipient_did)) {
                return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized));
            }
            let home = crate::federation::canonical_relay::admit_recorded_coordinator(
                pool,
                &route.coordinator_did,
            )
            .await
            .map_err(|error| pair_failure(endpoint, error))?;
            return relay_prepare(
                pool,
                RelayedPrepare {
                    route: OutboundRoute {
                        request_id,
                        actor_did,
                        actor_device_id,
                        recipient_did,
                        coordinator_did: &route.coordinator_did,
                    },
                    coordinator_endpoint: &home.endpoint,
                    signed_request: &parsed_req,
                    key_id,
                    signing_public_key: &signing_public_key,
                    auth_generation: verified_auth_gen,
                },
            )
            .await;
        }

        // A recipient with no chat authority this DS can join still gets a
        // signed terminal refusal when the sender is homed here: the repository
        // claims the attempt and signs it, and never prepares one (C33).
        let (coord, refusal) =
            match crate::federation::canonical_relay::resolve_pair_coordinator_by_side(
                pool,
                actor_did,
                recipient_did,
            )
            .await
            {
                Ok(coord) => (coord, None),
                Err(error) => {
                    match error.local_refusal_coordinator(&crate::identity::service_did()) {
                        Some(coord) => (coord, Some(error)),
                        None => return Err(pair_failure(endpoint, error.into_federation_error())),
                    }
                }
            };
        if !coord.is_sender_home {
            return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized));
        }


        if !coord.is_coordinator {
            return relay_prepare(
                pool,
                RelayedPrepare {
                    route: OutboundRoute {
                        request_id,
                        actor_did,
                        actor_device_id,
                        recipient_did,
                        coordinator_did: &coord.coordinator_did,
                    },
                    coordinator_endpoint: coord.coordinator_endpoint(),
                    signed_request: &parsed_req,
                    key_id,
                    signing_public_key: &signing_public_key,
                    auth_generation: verified_auth_gen,
                },
            )
            .await;
        } else {
            let mut tx = pool
                .begin()
                .await
                .map_err(|_| ChatFailure::storage(endpoint))?;

            let (p1, p2) = if actor_did <= recipient_did {
                (actor_did, recipient_did)
            } else {
                (recipient_did, actor_did)
            };
            let pair_lock_key = format!("chat-direct-request-pair:{p1}:{p2}");
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(&pair_lock_key)
                .execute(&mut *tx)
                .await
                .map_err(|_| ChatFailure::storage(endpoint))?;

            // A retry that raced the relay of this request to another
            // coordinator does not prepare it here too. It gets an unsigned
            // conflict, and the next retry follows the route.
            if request_routed(&mut tx, endpoint, request_id).await? {
                return Err(failure(endpoint, DirectRequestStoreError::IdentityConflict));
            }

            // Repository replay must not reserve another peer package for the
            // same attempt. A replay only returns what the attempt already
            // recorded, so it answers before the pair fence: a late prepare of
            // a cancelled request gets its tombstone even while another
            // request holds the pair (C12).
            let existing: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM chat.direct_request_attempts WHERE request_id=$1)"
            )
            .bind(request_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
            if existing {
                let result = requests::prepare_direct_request(
                    &mut tx, &principal, envelope.signed_request.get().as_bytes(), signer,
                    runtime.relationship_authority().as_ref(), &coord.sender_home.did, now,
                )
                .await
                .map_err(|e| failure(endpoint, e))?;
                let bytes = output(result, endpoint)?;
                tx.commit().await.map_err(|_| ChatFailure::storage(endpoint))?;
                return Ok(context::json_ok(bytes));
            }
            if let Some(_conflict) = crate::federation::canonical_relay::check_pair_owner_fence(
                &mut tx,
                actor_did,
                recipient_did,
                request_id,
                Some(&coord.coordinator_did),
            )
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?
            {
                return Err(failure(endpoint, DirectRequestStoreError::IdentityConflict));
            }


            if !coord.is_recipient_home {
                let remote_devices = crate::federation::canonical_relay::reserve_remote_recipient_bootstrap(
                    pool,
                    &coord.recipient_home.endpoint,
                    &coord.recipient_home.did,
                    request_id,
                    actor_did,
                    recipient_did,
                    Some(parsed_req.clone()),
                )
                .await
                .map_err(|e| {
                    tracing::error!("reserve_remote_recipient_bootstrap failed: {:?}", e);
                    failure(endpoint, DirectRequestStoreError::RecipientKeysUnavailable)
                })?;

                if let Err(error) = crate::federation::canonical_relay::stage_remote_recipient_devices(
                    pool, &mut tx, request_id, &remote_devices, now,
                ).await {
                    crate::federation::canonical_relay::release_remote_recipient_bootstrap(
                        pool,
                        &coord.recipient_home.endpoint, &coord.recipient_home.did,
                        request_id, recipient_did,
                    ).await.map_err(|_| ChatFailure::storage(endpoint))?;
                    tracing::error!("stage_remote_recipient_devices failed: {error:?}");
                    return Err(failure(endpoint, DirectRequestStoreError::RecipientKeysUnavailable));
                }
            }

            let result = requests::prepare_direct_request(
                &mut tx,
                &principal,
                envelope.signed_request.get().as_bytes(),
                signer,
                runtime.relationship_authority().as_ref(),
                &coord.sender_home.did,
                now,
            )
            .await;

            let result = match result {
                Ok(r) => r,
                Err(error) => {
                    if !coord.is_recipient_home {
                        crate::federation::canonical_relay::release_remote_recipient_bootstrap(
                            pool,
                            &coord.recipient_home.endpoint, &coord.recipient_home.did,
                            request_id, recipient_did,
                        ).await.map_err(|_| ChatFailure::storage(endpoint))?;
                    }
                    return Err(failure(endpoint, error));
                }
            };
            if let Some(refused) = refusal {
                // Nothing was staged for a remote recipient, so only a refusal
                // the repository reached itself may be signed. Anything else
                // (a preparation, or keys missing because the recipient's
                // authority changed meanwhile) is rolled back with the
                // transaction and answered unsigned.
                if !confirms_local_refusal(&result) {
                    return Err(pair_failure(endpoint, refused.into_federation_error()));
                }
                // The repository read the recipient's declaration again, so
                // its refusal can rest on an authority other than the one
                // that made this DS the signer. Before committing, read it
                // once more: the refusal stays signed only while no declared
                // authority sorts below this DS, the authority the client
                // checks the receipt against.
                match crate::federation::canonical_relay::resolve_pair_coordinator_by_side(
                    pool,
                    actor_did,
                    recipient_did,
                )
                .await
                {
                    Err(error)
                        if error
                            .local_refusal_coordinator(&crate::identity::service_did())
                            .is_some() => {}
                    Err(error) => {
                        return Err(pair_failure(endpoint, error.into_federation_error()))
                    }
                    Ok(_) => return Err(pair_failure(endpoint, refused.into_federation_error())),
                }
                // A retry reads the pair again rather than replaying this
                // refusal, in case the client pinned a lower authority this
                // DS could not read.
                crate::federation::canonical_relay::record_attempt_origin(
                    &mut tx,
                    request_id,
                    crate::federation::canonical_relay::AttemptOrigin::LocalRefusal,
                    &coord.sender_home.did,
                )
                .await
                .map_err(|_| ChatFailure::storage(endpoint))?;
            }

            // C33-LEASE-004: Release remote leases for non-Prepared outcomes (e.g. Terminal receipts)
            if !coord.is_recipient_home
                && !matches!(&result, crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Prepared(_))
            {
                crate::federation::canonical_relay::release_remote_recipient_bootstrap(
                    pool,
                    &coord.recipient_home.endpoint, &coord.recipient_home.did,
                    request_id, recipient_did,
                ).await.map_err(|_| ChatFailure::storage(endpoint))?;
            }

            let bytes = output(result, endpoint)?;
            if bytes.len() > 8_388_608 {
                return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::ArtifactTooLarge));
            }
            tx.commit().await.map_err(|_| ChatFailure::storage(endpoint))?;
            return Ok(context::json_ok(bytes));
        }
    }

    if endpoint == ChatEndpoint::CancelDirectRequestPreparation {
        return cancel_routed(pool, &principal, envelope.signed_request, signer, now).await;
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let result = match endpoint {
        ChatEndpoint::PublishDirectRequestKeys => {
            requests::publish_direct_request_keys(
                &mut tx,
                &principal,
                envelope.signed_request.get().as_bytes(),
                now,
            )
            .await
        }
        _ => return Err(ChatFailure::invariant(endpoint)),
    }
    .map_err(|e| failure(endpoint, e))?;
    let bytes = output(result, endpoint)?;
    if bytes.len() > 8_388_608 {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::ArtifactTooLarge,
        ));
    }
    tx.commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    Ok(context::json_ok(bytes))
}
macro_rules! handler {
    ($name:ident,$endpoint:ident) => {
        pub(super) async fn $name(
            State(pool): State<DbPool>,
            State(runtime): State<Arc<ChatRuntime>>,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            match mutate(&pool, &runtime, &headers, &body, ChatEndpoint::$endpoint).await {
                Ok(response) => response,
                Err(error) => error.into_response(),
            }
        }
    };
}
handler!(publish_keys, PublishDirectRequestKeys);
handler!(prepare, PrepareDirectRequest);
handler!(cancel, CancelDirectRequestPreparation);
pub(super) async fn outcome(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    async fn run(
        pool: &DbPool,
        runtime: &ChatRuntime,
        headers: &HeaderMap,
        query: Option<&str>,
    ) -> Result<Response, ChatFailure> {
        let endpoint = ChatEndpoint::GetDirectRequestOutcome;
        let signer = runtime.request_receipt_signer().ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::CutoverRequired)
        })?;
        let principal = context::verify_service_principal(pool, endpoint, headers).await?;
        let mut device = None;
        let mut request = None;
        for (k, v) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            let value =
                crate::chat_protocol::validation::CanonicalUuidV4::parse(&v).map_err(|_| {
                    ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
                })?;
            let id = uuid::Uuid::from_bytes(*value.as_bytes());
            match k.as_ref() {
                "actorDeviceId" if device.is_none() => device = Some(id),
                "requestId" if request.is_none() => request = Some(id),
                _ => {
                    return Err(ChatFailure::protocol(
                        endpoint,
                        ChatProtocolErrorCode::InvalidRequest,
                    ))
                }
            }
        }
        let device = device.ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
        let request = request.ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
        let now = crate::chat_protocol::validation::TrustedRequestInstant::capture()
            .map_err(|_| ChatFailure::invariant(endpoint))?
            .datetime();
        // A request this DS prepared as the sender's home is answered here,
        // and one it relayed by the coordinator it was first sent to,
        // whatever the declarations say now.
        let home_held = crate::federation::canonical_relay::held_attempt_origin(pool, request)
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?
            == Some(crate::federation::canonical_relay::AttemptOrigin::Home);
        let route = match home_held {
            true => None,
            false => RecordedRoute::load(pool, endpoint, request).await?,
        };
        if let Some(RecordedRoute {
            actor_did,
            actor_device_id,
            recipient_did,
            coordinator_did,
        }) = route
        {
            if actor_did != principal.did() || actor_device_id != device {
                return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized));
            }

            // Fast local idempotent replay check: if mirror already exists on sender home
            let existing: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT publication_receipt FROM chat.direct_request_transport_inbox \
                 WHERE request_id=$1 AND sender_did=$2 AND sender_device_id=$3 LIMIT 1"
            )
            .bind(request)
            .bind(&actor_did)
            .bind(actor_device_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
            if let Some(receipt_bytes) = existing {
                let receipt: serde_json::Value = serde_json::from_slice(&receipt_bytes)
                    .map_err(|_| ChatFailure::invariant(endpoint))?;
                let bytes = serde_json::to_vec(&serde_json::json!({"outcome": receipt}))
                    .map_err(|_| ChatFailure::invariant(endpoint))?;
                return Ok(context::json_ok(bytes));
            }

            let home = crate::federation::canonical_relay::admit_recorded_coordinator(
                pool,
                &coordinator_did,
            )
            .await
            .map_err(|error| {
                tracing::warn!(?error, "recorded coordinator unavailable");
                ChatFailure::storage(endpoint)
            })?;
            let result = crate::federation::canonical_relay::relay_get_outcome(
                &home.endpoint, &coordinator_did, request, device,
            ).await.map_err(|error| {
                tracing::warn!(?error, "Coordinator outcome unavailable");
                ChatFailure::storage(endpoint)
            })?;

            let outcome_val = result.get("outcome").unwrap_or(&result);
            let receipt_type = outcome_val.pointer("/receipt/$type")
                .or_else(|| outcome_val.pointer("/body/receipt/$type"))
                .or_else(|| outcome_val.get("$type"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let is_published = receipt_type == "blue.catbird.chat.defs#directRequestPublishedReceipt"
                || (receipt_type == "blue.catbird.chat.defs#signedDirectRequestReceipt"
                    && outcome_val.pointer("/receipt/$type").and_then(|v| v.as_str()) == Some("blue.catbird.chat.defs#directRequestPublishedReceipt"));

            if is_published {
                let receipt = crate::handlers::chat::publish_direct_request::materialize_sender_home_published_mirror(
                    pool,
                    &coordinator_did,
                    &actor_did,
                    actor_device_id,
                    &recipient_did,
                    request,
                    outcome_val,
                    result.get("entry"),
                    None,
                    now,
                    endpoint,
                ).await?;
                let bytes = serde_json::to_vec(&serde_json::json!({"outcome": receipt}))
                    .map_err(|_| ChatFailure::invariant(endpoint))?;
                return Ok(context::json_ok(bytes));
            }

            let bytes = serde_json::to_vec(&result).map_err(|_| ChatFailure::invariant(endpoint))?;
            return Ok(context::json_ok(bytes));
        }
        let recipient_receipt: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT publication_receipt FROM chat.direct_request_transport_inbox \
             WHERE request_id=$1 AND recipient_did=$2 AND recipient_device_id=$3",
        )
        .bind(request)
        .bind(principal.did())
        .bind(device)
        .fetch_optional(pool)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
        if let Some(receipt) = recipient_receipt {
            let receipt: serde_json::Value = serde_json::from_slice(&receipt)
                .map_err(|_| ChatFailure::invariant(endpoint))?;
            return Ok(context::json_ok(serde_json::to_vec(&serde_json::json!({"outcome":receipt}))
                .map_err(|_| ChatFailure::invariant(endpoint))?));
        }
        let mut tx = pool
            .begin()
            .await
            .map_err(|error| {
                tracing::error!(%error, "get_direct_request_outcome pool.begin failed");
                ChatFailure::storage(endpoint)
            })?;
        let result =
            requests::get_direct_request_outcome(&mut tx, &principal, device, request, signer, now)
                .await
                .map_err(|e| failure(endpoint, e))?;
        let bytes = output(result, endpoint)?;
        tx.commit()
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
        Ok(context::json_ok(bytes))
    }
    match run(&pool, &runtime, &headers, query.as_deref()).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod local_refusal_tests {
    use super::*;

    fn terminal(code: &str) -> DirectRequestResult {
        DirectRequestResult::Terminal(
            serde_json::to_vec(&serde_json::json!({
                "body": {"receipt": {
                    "$type": "blue.catbird.chat.defs#directRequestRejectedReceipt",
                    "code": code
                }},
                "signature": "AA=="
            }))
            .unwrap(),
        )
    }

    #[test]
    fn only_refusals_that_hold_anywhere_are_kept() {
        for code in [
            "RecipientAuthorityUnsupported",
            "RequestPolicyDenied",
            "PreparationExpired",
            "PreparationConflict",
            "CapacityUnavailable",
        ] {
            assert!(confirms_local_refusal(&terminal(code)), "{code}");
        }
        let expired = DirectRequestResult::Terminal(
            serde_json::to_vec(&serde_json::json!({
                "body": {"receipt": {
                    "$type": "blue.catbird.chat.defs#directRequestExpiredReceipt",
                    "requestKind": "expiry"
                }},
                "signature": "AA=="
            }))
            .unwrap(),
        );
        assert!(confirms_local_refusal(&expired));
        // Keys may live on the recipient's peer, which was never asked.
        assert!(!confirms_local_refusal(&terminal(
            "RecipientKeysUnavailable"
        )));
        assert!(!confirms_local_refusal(&DirectRequestResult::Prepared(
            b"{}".to_vec()
        )));
    }
}
