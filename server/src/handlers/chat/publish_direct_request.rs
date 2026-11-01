//! Single-transaction request publication transport. A success response is only
//! constructed after commit; no separate creation, Add or send endpoint runs.
use super::{context, errors::ChatFailure, runtime::ChatRuntime};
use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::direct_request_publication::{self, PublicationError, PublicationPreparation},
        validation::TrustedRequestInstant,
    },
    storage::DbPool,
};
use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    inner(&pool, &runtime, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}
async fn inner(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let endpoint = ChatEndpoint::PublishDirectRequest;
    context::require_cutover(runtime, endpoint)?;
    let signer = runtime
        .request_receipt_signer()
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::CutoverRequired))?;
    let principal = context::verify_service_principal(pool, endpoint, headers).await?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope<'a> {
        #[serde(rename = "signedRequest", borrow)]
        signed_request: &'a serde_json::value::RawValue,
    }
    let envelope: Envelope = serde_json::from_slice(body)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let now = TrustedRequestInstant::capture()
        .map_err(|_| ChatFailure::invariant(endpoint))?
        .datetime();
    let parsed_req: serde_json::Value = serde_json::from_str(envelope.signed_request.get())
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let recipient_did = parsed_req["body"]["recipientDid"]
        .as_str()
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let actor_did = principal.did();
    let actor_device_id = parsed_req["body"]["actorDeviceId"]
        .as_str()
        .and_then(|id| uuid::Uuid::parse_str(id).ok())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let key_id = parsed_req["body"]["keyId"]
        .as_str()
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let signer_key: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT k.signing_public_key, d.auth_generation FROM chat.device_keys k \
         JOIN chat.devices d ON d.user_did=k.user_did AND d.device_id=k.device_id \
         WHERE k.user_did=$1 AND k.device_id=$2 AND k.key_id=$3 \
           AND k.revoked_at IS NULL AND d.revoked_at IS NULL AND d.status='active' \
           AND k.enrollment_auth_generation=d.auth_generation",
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(key_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;
    let (signer_key, auth_generation) = signer_key
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized))?;
    let verified = crate::chat_protocol::direct_request_transcript::verify_signed_request(
        crate::chat_protocol::direct_request_transcript::DirectRequestKind::Publish,
        envelope.signed_request.get().as_bytes(),
        &signer_key,
    )
    .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidSignature))?;
    if verified.actor_did() != Some(actor_did)
        || verified.actor_device_id() != Some(actor_device_id.to_string().as_str())
        || verified.auth_generation() != Some(auth_generation as u64)
    {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    }

    let coord = crate::federation::canonical_relay::resolve_pair_coordinator(pool, actor_did, recipient_did)
        .await
        .map_err(|_| failure(PublicationError::Store(crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError::PolicyDenied)))?;
    if !coord.is_sender_home {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    }
    if !coord.is_coordinator {
        let request_id = parsed_req["body"]["requestId"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| {
                ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
            })?;

        // Fast local idempotent replay check
        let existing: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT publication_receipt, signed_publication \
             FROM chat.direct_request_transport_inbox \
             WHERE request_id=$1 AND sender_did=$2 AND sender_device_id=$3 \
             LIMIT 1",
        )
        .bind(request_id)
        .bind(actor_did)
        .bind(actor_device_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
        if let Some((receipt_bytes, signed_bytes)) = existing {
            let signed: serde_json::Value = serde_json::from_slice(&signed_bytes)
                .map_err(|_| ChatFailure::invariant(endpoint))?;
            if signed != parsed_req {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::IdempotencyConflict,
                ));
            }
            let receipt: serde_json::Value = serde_json::from_slice(&receipt_bytes)
                .map_err(|_| ChatFailure::invariant(endpoint))?;
            let resp_bytes = serde_json::to_vec(&serde_json::json!({ "outcome": receipt }))
                .map_err(|_| ChatFailure::invariant(endpoint))?;
            return Ok(context::json_ok(resp_bytes));
        }

        let _ = sqlx::query(
            "INSERT INTO chat.direct_request_outbound_routes \
                (request_id, actor_did, actor_device_id, recipient_did, coordinator_did) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (request_id) DO UPDATE SET request_id=EXCLUDED.request_id \
             WHERE chat.direct_request_outbound_routes.actor_did=EXCLUDED.actor_did \
               AND chat.direct_request_outbound_routes.actor_device_id=EXCLUDED.actor_device_id \
               AND chat.direct_request_outbound_routes.recipient_did=EXCLUDED.recipient_did \
               AND chat.direct_request_outbound_routes.coordinator_did=EXCLUDED.coordinator_did",
        )
        .bind(request_id)
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(recipient_did)
        .bind(&coord.coordinator_did)
        .execute(pool)
        .await;

        let relayed = crate::federation::canonical_relay::relay_publish_direct_request(
            &coord.coordinator_endpoint(),
            &coord.coordinator_did,
            &parsed_req,
        ).await.map_err(|e| {
            tracing::error!("relay_publish_direct_request failed: {e:?}");
            failure(PublicationError::Store(crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError::PolicyDenied))
        })?;

        let receipt_val = relayed.get("outcome").unwrap_or(&relayed);
        let receipt_type = receipt_val
            .pointer("/receipt/$type")
            .or_else(|| receipt_val.pointer("/body/receipt/$type"))
            .or_else(|| receipt_val.get("$type"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let is_published = receipt_type == "blue.catbird.chat.defs#directRequestPublishedReceipt"
            || (receipt_type == "blue.catbird.chat.defs#signedDirectRequestReceipt"
                && receipt_val
                    .pointer("/receipt/$type")
                    .and_then(|v| v.as_str())
                    == Some("blue.catbird.chat.defs#directRequestPublishedReceipt"));

        if !is_published {
            // A non-published outcome (e.g. rejection) has no published conversation.
            // Return the relayed receipt without writing phantom transport rows.
            let bytes =
                serde_json::to_vec(&relayed).map_err(|_| ChatFailure::invariant(endpoint))?;
            return Ok(context::json_ok(bytes));
        }

        let receipt = materialize_sender_home_published_mirror(
            pool,
            &coord,
            actor_did,
            actor_device_id,
            recipient_did,
            request_id,
            receipt_val,
            relayed.get("entry"),
            Some(&parsed_req),
            now,
            endpoint,
        )
        .await?;

        let resp_bytes = serde_json::to_vec(&serde_json::json!({ "outcome": receipt }))
            .map_err(|_| ChatFailure::invariant(endpoint))?;
        return Ok(context::json_ok(resp_bytes));
    }

    // M-F04 + C33-AUTH-002: Resolve actor and recipient PDS device keys BEFORE opening PostgreSQL transaction
    let http = crate::federation::resolver::build_resolver_http_client();
    let resolver = crate::federation::resolver::DsResolver::with_default_endpoint(
        pool.clone(),
        http,
        crate::identity::service_did(),
        crate::identity::self_endpoint(),
        std::env::var("DEFAULT_DS_ENDPOINT").ok(),
        3600,
    );
    let actor_authorized_keys = resolver.resolve_authorized_device_keys(actor_did).await.map_err(|_| failure(PublicationError::Store(crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError::PolicyDenied)))?;
    let actor_key_id = parsed_req
        .pointer("/body/keyId")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let actor_key_authorized = actor_authorized_keys.iter().any(|k| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(k))
            == actor_key_id
            || base64::engine::general_purpose::STANDARD.encode(k) == actor_key_id
            || crate::chat_protocol::validation::ed25519_key_id(k)
                .map(|id| id.as_str() == actor_key_id)
                .unwrap_or(false)
    });
    if !actor_key_authorized {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    }

    let recipient_authorized_keys = if coord.is_coordinator && !coord.is_recipient_home {
        let keys = resolver.resolve_authorized_device_keys(recipient_did).await.map_err(|_| failure(PublicationError::Store(crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError::RecipientKeysUnavailable)))?;
        if keys.is_empty() {
            return Err(failure(PublicationError::Store(crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError::RecipientKeysUnavailable)));
        }
        Some(keys)
    } else {
        None
    };

    let mut tx = pool.begin().await.map_err(|error| {
        tracing::error!(%error, "publish_direct_request pool.begin failed");
        ChatFailure::storage(endpoint)
    })?;

    let request_id =
        uuid::Uuid::parse_str(parsed_req["body"]["requestId"].as_str().unwrap_or_default())
            .unwrap_or_default();
    let conversation_id = uuid::Uuid::parse_str(
        parsed_req["body"]["conversationId"]
            .as_str()
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    let first_message_id = uuid::Uuid::parse_str(
        parsed_req["body"]["firstMessageId"]
            .as_str()
            .unwrap_or_default(),
    )
    .unwrap_or_default();
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
    .map_err(|_| ChatFailure::storage(endpoint))?
    {
        return Err(failure(PublicationError::Store(crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError::IdentityConflict)));
    }

    if let Some(recipient_authorized_keys) = recipient_authorized_keys.as_ref() {
        let selected_recipient_keys: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT k.signing_public_key \
             FROM chat.direct_request_selected_devices s \
             JOIN chat.device_keys k ON k.user_did = s.owner_did AND k.device_id = s.owner_device_id AND k.key_id = s.owner_key_id \
             WHERE s.request_id = $1 AND s.owner_did = $2"
        )
        .bind(request_id)
        .bind(recipient_did)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;

        for pk in &selected_recipient_keys {
            if !recipient_authorized_keys.iter().any(|k| k == pk) {
                return Err(failure(PublicationError::Store(crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError::RecipientKeysUnavailable)));
            }
        }
    }

    let prepared = direct_request_publication::prepare_publication(
        &mut tx,
        &principal,
        envelope.signed_request.get().as_bytes(),
        signer,
        runtime.relationship_authority().as_ref(),
        now,
        runtime.request_producers_enabled(),
    )
    .await
    .map_err(failure)?;
    let bytes = match prepared {
        PublicationPreparation::Terminal(bytes) => bytes,
        PublicationPreparation::Ready(prepared) => direct_request_publication::execute_publication(
            &mut tx,
            *prepared,
            signer,
            runtime.relationship_authority().as_ref(),
        )
        .await
        .map_err(failure)?,
    };
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ChatFailure::invariant(endpoint))?;
    receipt["$type"] = serde_json::json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
    crate::chat_protocol::direct_request_transcript::present_read_presentation(
        "directRequestOutcome",
        &mut receipt,
    )
    .map_err(|_| ChatFailure::invariant(endpoint))?;
    let response = serde_json::to_vec(&serde_json::json!({"outcome":receipt}))
        .map_err(|_| ChatFailure::invariant(endpoint))?;

    let mut deliver_input_opt = None;
    let mut queue_id_opt = None;

    if coord.is_coordinator && !coord.is_recipient_home {
        let entry_row: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT accepted_payload_bytes FROM chat.entries WHERE transition_id = $1",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;

        let pub_row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT full_welcome, signed_publication FROM chat.direct_request_publications WHERE request_id = $1"
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;

        if let (Some(entry_bytes), Some((welcome, signed_pub))) = (entry_row, pub_row) {
            let entry_val: serde_json::Value = serde_json::from_slice(&entry_bytes)
                .map_err(|_| ChatFailure::invariant(endpoint))?;
            let full_welcome_b64 = Some(base64::engine::general_purpose::STANDARD.encode(&welcome));
            let signed_pub_val = Some(
                serde_json::from_slice(&signed_pub)
                    .map_err(|_| ChatFailure::invariant(endpoint))?,
            );
            let deliveries = parsed_req
                .pointer("/body/artifacts/welcome/deliveries")
                .or_else(|| parsed_req.pointer("/artifacts/welcome/deliveries"))
                .or_else(|| receipt.pointer("/receipt/artifacts/welcome/deliveries"))
                .or_else(|| receipt.pointer("/artifacts/welcome/deliveries"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            let deliver_input = crate::federation::canonical_relay::DeliverDirectRequestInput {
                request_id,
                conversation_id,
                first_message_id,
                entry: entry_val,
                deliveries,
                publication_receipt: receipt.clone(),
                coordinator_did: coord.coordinator_did.clone(),
                full_welcome_bytes: full_welcome_b64,
                signed_publication: signed_pub_val,
            };

            let queue_id = format!("direct-request-delivery-{request_id}");
            let payload_bytes =
                serde_json::to_vec(&deliver_input).map_err(|_| ChatFailure::invariant(endpoint))?;

            crate::federation::queue::enqueue_c33_in_tx(
                pool,
                &mut tx,
                &queue_id,
                &coord.recipient_home.did,
                &coord.recipient_home.endpoint,
                "blue.catbird.mlsDS.deliverDirectRequest",
                &payload_bytes,
                &conversation_id.to_string(),
                "",
            )
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;

            deliver_input_opt = Some(deliver_input);
            queue_id_opt = Some(queue_id);
        }
    }

    tx.commit().await.map_err(|error| {
        trace_database_failure("commit", &error);
        ChatFailure::storage(endpoint)
    })?;

    if let (Some(deliver_input), Some(queue_id)) = (deliver_input_opt, queue_id_opt) {
        if let Ok(()) = crate::federation::canonical_relay::deliver_direct_request_to_peer(
            &coord.recipient_home.endpoint,
            &coord.recipient_home.did,
            deliver_input,
        )
        .await
        {
            let _ = crate::federation::queue::mark_delivered_by_id(pool, &queue_id).await;
        }
    }

    Ok(context::json_ok(response))
}
#[path = "publish_direct_request_mirror.rs"]
mod sender_mirror;
pub(super) use sender_mirror::materialize_sender_home_published_mirror;
fn failure(error: PublicationError) -> ChatFailure {
    tracing::warn!(?error, "publish_direct_request failure");
    use crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError as E;
    let endpoint = ChatEndpoint::PublishDirectRequest;
    match error {
        PublicationError::Disabled => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::CutoverRequired)
        }
        PublicationError::Database(error) | PublicationError::Store(E::Database(error)) => {
            trace_database_failure("prepare_or_execute", &error);
            ChatFailure::storage(endpoint)
        }
        PublicationError::Store(E::InvalidSignature) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidSignature)
        }
        PublicationError::Store(E::IdentityConflict) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::PreparationConflict)
        }
        PublicationError::Store(E::Expired) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::PreparationExpired)
        }
        PublicationError::Store(E::IncludedAuthorityChanged) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::PreparationRevoked)
        }
        PublicationError::Store(E::PolicyDenied) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::RequestPolicyDenied)
        }
        PublicationError::Store(E::QuotaExceeded) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::CapacityUnavailable)
        }
        PublicationError::Store(E::RecipientKeysUnavailable) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::RecipientKeysUnavailable)
        }
        _ => ChatFailure::invariant(endpoint),
    }
}

fn trace_database_failure(stage: &'static str, error: &sqlx::Error) {
    use sha2::{Digest, Sha256};
    // Database messages/details can interpolate a rejected row's contents.
    // A fingerprint identifies static migration exceptions without logging
    // signed envelopes, ciphertext, registration tokens, or SQL parameters.
    let database = error.as_database_error();
    tracing::error!(
        stage,
        code = database
            .and_then(|error| error.code())
            .as_deref()
            .unwrap_or("non_database"),
        constraint = database
            .and_then(|error| error.constraint())
            .unwrap_or("none"),
        message_fingerprint = database
            .map(|error| format!("{:x}", Sha256::digest(error.message().as_bytes())))
            .as_deref()
            .unwrap_or("none"),
        "encrypted request publication transaction failed"
    );
}

#[cfg(test)]
mod signature_error_tests {
    use super::*;
    use crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError;

    #[tokio::test]
    async fn invalid_publication_signature_uses_declared_public_error() {
        let failure = failure(PublicationError::Store(
            DirectRequestStoreError::InvalidSignature,
        ));
        assert_eq!(
            failure.code(),
            Some(ChatProtocolErrorCode::InvalidSignature)
        );
        let response = failure.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"error":"InvalidSignature", "message":"InvalidSignature"})
        );
    }
}
