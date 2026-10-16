//! Single-transaction request publication transport. A success response is only
//! constructed after commit; no separate creation, Add or send endpoint runs.
use super::{context, errors::ChatFailure, runtime::ChatRuntime};
use base64::Engine;
use sha2::{Digest, Sha256};
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
    let recipient_did = parsed_req["body"]["recipientDid"].as_str().ok_or_else(|| {
        ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
    })?;
    let actor_did = principal.did();
    let actor_device_id = parsed_req["body"]["actorDeviceId"].as_str()
        .and_then(|id| uuid::Uuid::parse_str(id).ok())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let key_id = parsed_req["body"]["keyId"].as_str()
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
        return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized));
    }


    let coord = crate::federation::canonical_relay::resolve_pair_coordinator(pool, actor_did, recipient_did)
        .await
        .map_err(|_| failure(PublicationError::Store(crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError::PolicyDenied)))?;
    if !coord.is_sender_home {
        return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized));
    }
    if !coord.is_coordinator {
        let request_id = parsed_req["body"]["requestId"].as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;

        // Fast local idempotent replay check
        let existing: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT publication_receipt, signed_publication \
             FROM chat.direct_request_transport_inbox \
             WHERE request_id=$1 AND sender_did=$2 AND sender_device_id=$3 \
             LIMIT 1"
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
                return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::IdempotencyConflict));
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
               AND chat.direct_request_outbound_routes.coordinator_did=EXCLUDED.coordinator_did"
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
        let receipt_type = receipt_val.pointer("/receipt/$type")
            .or_else(|| receipt_val.pointer("/body/receipt/$type"))
            .or_else(|| receipt_val.get("$type"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let is_published = receipt_type == "blue.catbird.chat.defs#directRequestPublishedReceipt"
            || (receipt_type == "blue.catbird.chat.defs#signedDirectRequestReceipt"
                && receipt_val.pointer("/receipt/$type").and_then(|v| v.as_str()) == Some("blue.catbird.chat.defs#directRequestPublishedReceipt"));

        if !is_published {
            // A non-published outcome (e.g. rejection) has no published conversation.
            // Return the relayed receipt without writing phantom transport rows.
            let bytes = serde_json::to_vec(&relayed)
                .map_err(|_| ChatFailure::invariant(endpoint))?;
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
        ).await?;

        let resp_bytes = serde_json::to_vec(&serde_json::json!({ "outcome": receipt }))
            .map_err(|_| ChatFailure::invariant(endpoint))?;
        return Ok(context::json_ok(resp_bytes));
    }

    let mut tx = pool.begin().await.map_err(|error| {
        tracing::error!(%error, "publish_direct_request pool.begin failed");
        ChatFailure::storage(endpoint)
    })?;

    let request_id = uuid::Uuid::parse_str(parsed_req["body"]["requestId"].as_str().unwrap_or_default())
        .unwrap_or_default();
    let conversation_id = uuid::Uuid::parse_str(parsed_req["body"]["conversationId"].as_str().unwrap_or_default())
        .unwrap_or_default();
    let first_message_id = uuid::Uuid::parse_str(parsed_req["body"]["firstMessageId"].as_str().unwrap_or_default())
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

    // A request that already ended without a publication only replays that
    // receipt, so the pair fence does not apply: a late publish of a cancelled
    // request gets its tombstone even while another request holds the pair
    // (C12), and an existing-direct one its stored receipt (C14). A published
    // request still passes the fence, because its replay can queue delivery
    // again.
    let ended_unpublished: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.direct_request_attempts \
         WHERE request_id=$1 AND actor_did=$2 AND recipient_did=$3 \
           AND status IN ('cancelled','expired','rejected','existing-direct'))",
    )
    .bind(request_id)
    .bind(actor_did)
    .bind(recipient_did)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;
    if !ended_unpublished {
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
    }

    // C33-AUTH-002: Revalidate actor and every selected recipient key against fresh PDS snapshot at commit boundary
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
    let actor_key_id = parsed_req.pointer("/body/keyId").and_then(|v| v.as_str()).unwrap_or_default();
    let actor_key_authorized = actor_authorized_keys.iter().any(|k| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(k)) == actor_key_id
            || base64::engine::general_purpose::STANDARD.encode(k) == actor_key_id
            || crate::chat_protocol::validation::ed25519_key_id(k).map(|id| id.as_str() == actor_key_id).unwrap_or(false)
    });
    if !actor_key_authorized {
        return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized));
    }

    if coord.is_coordinator && !coord.is_recipient_home {
        let recipient_authorized_keys = resolver.resolve_authorized_device_keys(recipient_did).await.map_err(|_| failure(PublicationError::Store(crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError::RecipientKeysUnavailable)))?;
        if recipient_authorized_keys.is_empty() {
            return Err(failure(PublicationError::Store(crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError::RecipientKeysUnavailable)));
        }

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
        let entry_row: Option<Vec<u8>> = sqlx::query_scalar("SELECT accepted_payload_bytes FROM chat.entries WHERE transition_id = $1")
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
                serde_json::from_slice(&signed_pub).map_err(|_| ChatFailure::invariant(endpoint))?
            );
            let deliveries = parsed_req.pointer("/body/artifacts/welcome/deliveries")
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
            let payload_bytes = serde_json::to_vec(&deliver_input).map_err(|_| ChatFailure::invariant(endpoint))?;

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
        ).await {
            let _ = crate::federation::queue::mark_delivered_by_id(pool, &queue_id).await;
        }
    }

    Ok(context::json_ok(response))
}
pub(super) async fn materialize_sender_home_published_mirror(
    pool: &DbPool,
    coord: &crate::federation::canonical_relay::CanonicalPairCoordinator,
    actor_did: &str,
    actor_device_id: uuid::Uuid,
    recipient_did: &str,
    request_id: uuid::Uuid,
    receipt_val: &serde_json::Value,
    entry: Option<&serde_json::Value>,
    client_signed_pub: Option<&serde_json::Value>,
    now: chrono::DateTime<chrono::Utc>,
    endpoint: ChatEndpoint,
) -> Result<serde_json::Value, ChatFailure> {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    // 1. Fast local idempotent replay check: if mirror already exists on sender home
    let existing: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT publication_receipt, signed_publication \
         FROM chat.direct_request_transport_inbox \
         WHERE request_id = $1 AND sender_did = $2 AND sender_device_id = $3 \
         LIMIT 1"
    )
    .bind(request_id)
    .bind(actor_did)
    .bind(actor_device_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;

    if let Some((receipt_bytes, signed_bytes)) = existing {
        if let Some(client_signed) = client_signed_pub {
            let stored_signed: serde_json::Value = serde_json::from_slice(&signed_bytes)
                .map_err(|_| ChatFailure::invariant(endpoint))?;
            if &stored_signed != client_signed {
                return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::IdempotencyConflict));
            }
        }
        let mut receipt: serde_json::Value = serde_json::from_slice(&receipt_bytes)
            .map_err(|_| ChatFailure::invariant(endpoint))?;
        receipt["$type"] = serde_json::json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
        return Ok(receipt);
    }

    // 2. Fail closed if necessary entry artifact is missing
    let Some(entry_val) = entry else {
        tracing::error!("published outcome lacks required entry artifact");
        return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest));
    };

    let signed_req_val = match client_signed_pub {
        Some(signed) => {
            if entry_val.get("signedRequest") != Some(signed) {
                tracing::error!("relayed entry signedRequest does not match client signedRequest");
                return Err(ChatFailure::invariant(endpoint));
            }
            signed
        }
        None => {
            entry_val.get("signedRequest").ok_or_else(|| {
                tracing::error!("relayed entry lacks signedRequest");
                ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
            })?
        }
    };

    // 3. Extract required artifacts from signed publication
    let full_welcome_b64 = signed_req_val.pointer("/body/artifacts/welcome/opaqueWelcome")
        .or_else(|| signed_req_val.pointer("/artifacts/welcome/opaqueWelcome"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            tracing::error!("signed publication lacks opaqueWelcome");
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
    let full_welcome_bytes = base64::engine::general_purpose::STANDARD.decode(full_welcome_b64)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    if full_welcome_bytes.is_empty() {
        return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest));
    }
    let full_welcome_sha256 = Sha256::digest(&full_welcome_bytes).to_vec();

    let deliveries = signed_req_val.pointer("/body/artifacts/welcome/deliveries")
        .or_else(|| signed_req_val.pointer("/artifacts/welcome/deliveries"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            tracing::error!("signed publication lacks deliveries");
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
    if deliveries.is_empty() {
        return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest));
    }

    let conversation_id = signed_req_val.pointer("/body/conversationId")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let first_message_id = signed_req_val.pointer("/body/firstMessageId")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;

    // 4. Resolve coordinator receipt authority key and verify coordinator P-256 signature
    let receipt_authority_did = receipt_val.pointer("/body/authorityDid")
        .or_else(|| receipt_val.pointer("/receipt/authorityDid"))
        .or_else(|| receipt_val.get("authorityDid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            tracing::error!("receipt missing authorityDid");
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
    if crate::identity::canonical_did(receipt_authority_did) != crate::identity::canonical_did(&coord.coordinator_did) {
        tracing::error!("receipt authorityDid {receipt_authority_did} does not match coordinator {}", coord.coordinator_did);
        return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized));
    }

    let receipt_key_id = receipt_val.pointer("/body/keyId")
        .or_else(|| receipt_val.pointer("/receipt/keyId"))
        .or_else(|| receipt_val.get("keyId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            tracing::error!("receipt missing keyId");
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;

    let resolver = crate::federation::resolver::DsResolver::with_default_endpoint(
        pool.clone(),
        crate::federation::resolver::build_resolver_http_client(),
        crate::identity::service_did(),
        crate::identity::self_endpoint(),
        std::env::var("DEFAULT_DS_ENDPOINT").ok(),
        3600,
    );

    let receipt_public_key = resolver
        .resolve_coordinator_receipt_key(pool, receipt_authority_did, receipt_key_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to resolve coordinator receipt key: {e:?}");
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::RelationshipPolicyUnavailable)
        })?;

    let receipt_bytes = serde_json::to_vec(receipt_val)
        .map_err(|_| ChatFailure::invariant(endpoint))?;

    let verified_receipt = crate::chat_protocol::direct_request_transcript::verify_received_signed_request(
        crate::chat_protocol::direct_request_transcript::DirectRequestKind::Outcome,
        &receipt_bytes,
        &receipt_public_key,
    )
    .map_err(|e| {
        tracing::error!("coordinator receipt signature verification failed: {e:?}");
        ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidSignature)
    })?;

    // 5. Resolve sender device key and verify sender publication signature
    let signer_key_id = signed_req_val.pointer("/body/keyId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;

    let local_signer: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT k.signing_public_key, d.auth_generation FROM chat.device_keys k \
         JOIN chat.devices d ON d.user_did=k.user_did AND d.device_id=k.device_id \
         WHERE k.user_did=$1 AND k.device_id=$2 AND k.key_id=$3 \
           AND k.revoked_at IS NULL AND d.revoked_at IS NULL AND d.status='active' \
           AND k.enrollment_auth_generation=d.auth_generation",
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(signer_key_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;

    let (signer_public_key, auth_generation) = match local_signer {
        Some((key, gen)) => (key, Some(gen)),
        None => {
            let authorized = resolver.resolve_authorized_device_keys(actor_did).await.map_err(|e| {
                tracing::error!("failed to resolve actor device keys from PDS: {e:?}");
                ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized)
            })?;
            let matching = authorized.into_iter().find(|k| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(k)) == signer_key_id
            }).ok_or_else(|| {
                tracing::error!("sender device key {signer_key_id} not authorized by PDS");
                ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized)
            })?;
            (matching, None)
        }
    };

    let signed_pub_bytes = serde_json::to_vec(signed_req_val)
        .map_err(|_| ChatFailure::invariant(endpoint))?;

    let verified_pub = crate::chat_protocol::direct_request_transcript::verify_signed_request(
        crate::chat_protocol::direct_request_transcript::DirectRequestKind::Publish,
        &signed_pub_bytes,
        &signer_public_key,
    )
    .map_err(|e| {
        tracing::error!("sender signed publication verification failed: {e:?}");
        ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidSignature)
    })?;

    if verified_pub.actor_did() != Some(actor_did)
        || verified_pub.actor_device_id() != Some(actor_device_id.to_string().as_str())
    {
        return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized));
    }
    if let Some(auth_gen) = auth_generation {
        if verified_pub.auth_generation() != Some(auth_gen as u64) {
            return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized));
        }
    }

    // 6. Cross-binding verifications: receipt to publication and entry
    let receipt_req_digest_b64 = verified_receipt.body().pointer("/receipt/requestDigest")
        .or_else(|| verified_receipt.body().get("requestDigest"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let receipt_req_digest = base64::engine::general_purpose::STANDARD.decode(receipt_req_digest_b64)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    if receipt_req_digest.as_slice() != verified_pub.request_digest() {
        tracing::error!("receipt requestDigest mismatch with publication digest");
        return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest));
    }

    let receipt_req_id = verified_receipt.body().pointer("/receipt/requestId")
        .or_else(|| verified_receipt.body().get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    if receipt_req_id != request_id.to_string() {
        return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest));
    }

    if verified_receipt.body().pointer("/receipt/conversationId").and_then(|v| v.as_str()) != Some(conversation_id.to_string().as_str())
        || verified_receipt.body().pointer("/receipt/firstMessageId").and_then(|v| v.as_str()) != Some(first_message_id.to_string().as_str())
        || verified_receipt.body().pointer("/receipt/actorDid").and_then(|v| v.as_str()) != Some(actor_did)
        || verified_receipt.body().pointer("/receipt/requestKind").and_then(|v| v.as_str()) != Some("publish")
    {
        return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest));
    }

    let entry_id = entry_val.get("entryId").and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| ChatFailure::invariant(endpoint))?;
    if entry_val.get("conversationId").and_then(|v| v.as_str()) != Some(conversation_id.to_string().as_str())
        || entry_val.get("seq").and_then(|v| v.as_i64()) != Some(1)
        || entry_val.get("signedRequest") != Some(signed_req_val)
    {
        return Err(ChatFailure::invariant(endpoint));
    }

    if let Some(entry_hash_b64) = verified_receipt.body().pointer("/receipt/entryHash").and_then(|v| v.as_str()) {
        let expected_hash = base64::engine::general_purpose::STANDARD.decode(entry_hash_b64)
            .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
        let mut untagged = entry_val.clone();
        if let Some(obj) = untagged.as_object_mut() {
            obj.remove("$type");
            obj.remove("publicationReceipt");
        }
        let untagged_bytes = serde_json::to_vec(&untagged).map_err(|_| ChatFailure::invariant(endpoint))?;
        let actual_hash = crate::chat_protocol::direct_request_transcript::direct_request_entry_hash(&untagged_bytes)
            .map_err(|_| ChatFailure::invariant(endpoint))?;
        if expected_hash != actual_hash {
            tracing::error!("receipt entryHash does not match entry");
            return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest));
        }
    }

    // 7. Materialize canonical entry and transport inbox rows (one per recipient device)
    let mut entry_to_store = entry_val.clone();
    if entry_to_store.get("$type").is_none() {
        entry_to_store["$type"] = serde_json::json!("blue.catbird.chat.defs#directRequestEntry");
    }
    if entry_to_store.get("publicationReceipt").is_none() {
        entry_to_store["publicationReceipt"] = receipt_val.clone();
    }
    let entry_bytes = serde_json::to_vec(&entry_to_store)
        .map_err(|_| ChatFailure::invariant(endpoint))?;

    let import_until = receipt_val.pointer("/receipt/importUntil")
        .or_else(|| signed_req_val.pointer("/body/importUntil"))
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| now + chrono::Duration::days(30));

    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!("sender home pool.begin failed: {e}");
        ChatFailure::storage(endpoint)
    })?;

    let mut inserted_recipient_devices = 0;
    for d in deliveries {
        let rec_did = d["recipientDid"].as_str().unwrap_or_default();
        if rec_did != recipient_did {
            continue;
        }
        let rec_device_id = d["recipientDeviceId"].as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
        let prov_bytes = serde_json::to_vec(&d["provenance"])
            .map_err(|_| ChatFailure::invariant(endpoint))?;

        inserted_recipient_devices += 1;

        let inserted = sqlx::query(
            "INSERT INTO chat.direct_request_transport_inbox ( \
                request_id, conversation_id, first_message_id, coordinator_did, \
                sender_did, sender_device_id, recipient_did, recipient_device_id, \
                request_entry, signed_publication, full_welcome, full_welcome_sha256, \
                provenance, publication_receipt, import_until, status, created_at, updated_at \
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'pending', $16, $16) \
            ON CONFLICT (request_id, recipient_device_id) DO NOTHING"
        )
        .bind(request_id)
        .bind(conversation_id)
        .bind(first_message_id)
        .bind(&coord.coordinator_did)
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(rec_did)
        .bind(rec_device_id)
        .bind(&entry_bytes)
        .bind(&signed_pub_bytes)
        .bind(&full_welcome_bytes)
        .bind(&full_welcome_sha256)
        .bind(&prov_bytes)
        .bind(&receipt_bytes)
        .bind(import_until)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("sender home insert transport inbox failed: {e}");
            ChatFailure::storage(endpoint)
        })?;

        if inserted.rows_affected() == 0 {
            let (existing_signed, existing_receipt): (Vec<u8>, Vec<u8>) = sqlx::query_as(
                "SELECT signed_publication, publication_receipt \
                 FROM chat.direct_request_transport_inbox WHERE request_id=$1 AND recipient_device_id=$2"
            )
            .bind(request_id)
            .bind(rec_device_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
            if existing_signed != signed_pub_bytes || existing_receipt != receipt_bytes {
                return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::IdempotencyConflict));
            }
        }
    }

    if inserted_recipient_devices == 0 {
        return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest));
    }

    let entry_inserted = sqlx::query(
        "INSERT INTO chat.direct_request_transport_entries ( \
            conversation_id, seq, entry_id, entry_bytes, created_at \
         ) VALUES ($1, 1, $2, $3, $4) \
         ON CONFLICT (conversation_id, seq) DO NOTHING"
    )
    .bind(conversation_id)
    .bind(entry_id)
    .bind(&entry_bytes)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("sender home insert transport entry failed: {e}");
        ChatFailure::storage(endpoint)
    })?;

    if entry_inserted.rows_affected() == 0 {
        let existing: Vec<u8> = sqlx::query_scalar(
            "SELECT entry_bytes FROM chat.direct_request_transport_entries \
             WHERE conversation_id=$1 AND seq=1"
        )
        .bind(conversation_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
        if existing != entry_bytes {
            return Err(ChatFailure::protocol(endpoint, ChatProtocolErrorCode::IdempotencyConflict));
        }
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("sender home tx.commit failed: {e}");
        ChatFailure::storage(endpoint)
    })?;

    let mut return_receipt = receipt_val.clone();
    return_receipt["$type"] = serde_json::json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
    crate::chat_protocol::direct_request_transcript::present_read_presentation(
        "directRequestOutcome",
        &mut return_receipt,
    )
    .map_err(|_| ChatFailure::invariant(endpoint))?;

    Ok(return_receipt)
}
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
