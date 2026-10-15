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
        DirectRequestStoreError::RecipientAuthorityUnsupported => {
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
        matches!(
            receipt["body"]["receipt"]["code"].as_str(),
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

        let (signing_public_key, verified_auth_gen) = sender_key_row.ok_or_else(|| {
            tracing::warn!(
                actor_did,
                %actor_device_id,
                key_id,
                auth_generation,
                "sender active non-revoked device/key not found or generation mismatch"
            );
            failure(endpoint, DirectRequestStoreError::IdentityConflict)
        })?;

        crate::chat_protocol::direct_request_transcript::verify_signed_request(
            crate::chat_protocol::direct_request_transcript::DirectRequestKind::Prepare,
            envelope.signed_request.get().as_bytes(),
            &signing_public_key,
        )
        .map_err(|_| failure(endpoint, DirectRequestStoreError::InvalidSignature))?;


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
            let mut route_tx = pool.begin().await.map_err(|_| ChatFailure::storage(endpoint))?;
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
            if let Some(crate::federation::canonical_relay::PairFenceConflict::ForeignCoordinator { .. }) =
                crate::federation::canonical_relay::check_pair_owner_fence(
                &mut route_tx,
                actor_did,
                recipient_did,
                request_id,
                Some(&coord.coordinator_did),
            )
            .await
            .map_err(|_| ChatFailure::storage(endpoint))? {
                return Err(failure(endpoint, DirectRequestStoreError::IdentityConflict));
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
            .bind(&coord.coordinator_did)
            .fetch_optional(&mut *route_tx)
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
            if route.is_none() {
                return Err(failure(endpoint, DirectRequestStoreError::IdentityConflict));
            }
            route_tx.commit().await.map_err(|_| ChatFailure::storage(endpoint))?;
            let relay_payload = serde_json::json!({
                "signedRequest": parsed_req,
                "senderDeviceKey": {
                    "deviceId": actor_device_id.to_string(),
                    "keyId": key_id,
                    "signingPublicKey": base64::engine::general_purpose::STANDARD.encode(&signing_public_key),
                    "authGeneration": verified_auth_gen,
                }
            });

            let outcome = crate::federation::canonical_relay::relay_prepare_direct_request(
                coord.coordinator_endpoint(),
                &coord.coordinator_did,
                &relay_payload,
            )
            .await
            .map_err(|e| match e {
                crate::federation::FederationError::RemoteError { status: 409, .. } => {
                    failure(endpoint, DirectRequestStoreError::IdentityConflict)
                }
                _ => failure(endpoint, DirectRequestStoreError::PolicyDenied),
            })?;
            let bytes = serde_json::to_vec(&outcome)
                .map_err(|_| ChatFailure::invariant(endpoint))?;
            return Ok(context::json_ok(bytes));
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

            if let Some(_conflict) = crate::federation::canonical_relay::check_pair_owner_fence(
                &mut tx,
                actor_did,
                recipient_did,
                request_id,
                Some(&coord.coordinator_did),
            )
            .await
            .map_err(|_| ChatFailure::storage(endpoint))? {
                return Err(failure(endpoint, DirectRequestStoreError::IdentityConflict));
            }
            // Repository replay must not reserve another peer package for the same attempt.
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
                    runtime.relationship_authority().as_ref(), now,
                )
                .await
                .map_err(|e| failure(endpoint, e))?;
                let bytes = output(result, endpoint)?;
                tx.commit().await.map_err(|_| ChatFailure::storage(endpoint))?;
                return Ok(context::json_ok(bytes));
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
        ChatEndpoint::CancelDirectRequestPreparation => {
            requests::cancel_direct_request(
                &mut tx,
                &principal,
                envelope.signed_request.get().as_bytes(),
                signer,
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
        let route: Option<(String, uuid::Uuid, String, String)> = sqlx::query_as(
            "SELECT actor_did, actor_device_id, recipient_did, coordinator_did \
             FROM chat.direct_request_outbound_routes WHERE request_id=$1",
        )
        .bind(request)
        .fetch_optional(pool)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
        if let Some((actor_did, actor_device_id, recipient_did, coordinator_did)) = route {
            if actor_did != principal.did() || actor_device_id != device {
                return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized));
            }
            let coord = crate::federation::canonical_relay::resolve_pair_coordinator(
                pool, &actor_did, &recipient_did,
            ).await.map_err(|_| ChatFailure::storage(endpoint))?;
            if !coord.is_sender_home || coord.is_coordinator {
                return Err(ChatFailure::invariant(endpoint));
            }
            if crate::identity::canonical_did(&coord.coordinator_did)
                != crate::identity::canonical_did(&coordinator_did)
            {
                tracing::warn!(
                    "Declaration rotation observed for request {request}: recorded coordinator {coordinator_did} vs live {}",
                    coord.coordinator_did
                );
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

            let result = crate::federation::canonical_relay::relay_get_outcome(
                coord.coordinator_endpoint(), &coordinator_did, request, device,
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
                    &coord,
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
        // Keys may live on the recipient's peer, which was never asked.
        assert!(!confirms_local_refusal(&terminal(
            "RecipientKeysUnavailable"
        )));
        assert!(!confirms_local_refusal(&DirectRequestResult::Prepared(
            b"{}".to_vec()
        )));
    }
}
