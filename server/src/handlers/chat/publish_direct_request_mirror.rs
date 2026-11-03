use base64::Engine;
use sha2::{Digest, Sha256};

use crate::handlers::chat::ChatFailure;
use crate::{
    chat_protocol::error::{ChatEndpoint, ChatProtocolErrorCode},
    storage::DbPool,
};

#[allow(clippy::too_many_arguments)]
pub(in crate::handlers::chat) async fn materialize_sender_home_published_mirror(
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
    // 1. Fast local idempotent replay check: if mirror already exists on sender home.
    // A mirror whose opening ciphertext was pruned (O7) keeps only its digest.
    type MirrorReplay = (Vec<u8>, Option<Vec<u8>>, Vec<u8>);
    let existing: Option<MirrorReplay> = sqlx::query_as(
        "SELECT publication_receipt, signed_publication, signed_publication_sha256 \
         FROM chat.direct_request_transport_inbox \
         WHERE request_id = $1 AND sender_did = $2 AND sender_device_id = $3 \
         LIMIT 1",
    )
    .bind(request_id)
    .bind(actor_did)
    .bind(actor_device_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;

    if let Some((receipt_bytes, signed_bytes, signed_sha256)) = existing {
        if let Some(client_signed) = client_signed_pub {
            let same = match signed_bytes {
                Some(signed_bytes) => {
                    &serde_json::from_slice::<serde_json::Value>(&signed_bytes)
                        .map_err(|_| ChatFailure::invariant(endpoint))?
                        == client_signed
                }
                None => {
                    Sha256::digest(
                        serde_json::to_vec(client_signed)
                            .map_err(|_| ChatFailure::invariant(endpoint))?,
                    )
                    .as_slice()
                        == signed_sha256.as_slice()
                }
            };
            if !same {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::IdempotencyConflict,
                ));
            }
        }
        let mut receipt: serde_json::Value =
            serde_json::from_slice(&receipt_bytes).map_err(|_| ChatFailure::invariant(endpoint))?;
        receipt["$type"] = serde_json::json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
        let mut receipt =
            crate::chat_protocol::direct_request_transcript::normalize_read_presentation(
                &serde_json::to_vec(&receipt).map_err(|_| ChatFailure::invariant(endpoint))?,
                "directRequestOutcome",
                true,
            )
            .map_err(|_| ChatFailure::invariant(endpoint))?;
        crate::chat_protocol::direct_request_transcript::present_read_presentation(
            "directRequestOutcome",
            &mut receipt,
        )
        .map_err(|_| ChatFailure::invariant(endpoint))?;
        return Ok(receipt);
    }

    // 2. Fail closed if necessary entry artifact is missing
    let Some(entry) = entry else {
        tracing::error!("published outcome lacks required entry artifact");
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    };
    let entry_val = crate::chat_protocol::direct_request_transcript::normalize_read_presentation(
        &serde_json::to_vec(entry).map_err(|_| ChatFailure::invariant(endpoint))?,
        "directRequestEntry",
        true,
    )
    .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let entry_val = &entry_val;

    let signed_req_val = match client_signed_pub {
        Some(signed) => {
            if entry_val.get("signedRequest") != Some(signed) {
                tracing::error!("relayed entry signedRequest does not match client signedRequest");
                return Err(ChatFailure::invariant(endpoint));
            }
            signed
        }
        None => entry_val.get("signedRequest").ok_or_else(|| {
            tracing::error!("relayed entry lacks signedRequest");
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?,
    };

    // 3. Extract required artifacts from signed publication
    let full_welcome_b64 = signed_req_val
        .pointer("/body/artifacts/welcome/opaqueWelcome")
        .or_else(|| signed_req_val.pointer("/artifacts/welcome/opaqueWelcome"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            tracing::error!("signed publication lacks opaqueWelcome");
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
    let full_welcome_bytes = base64::engine::general_purpose::STANDARD
        .decode(full_welcome_b64)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    if full_welcome_bytes.is_empty() {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }
    let full_welcome_sha256 = Sha256::digest(&full_welcome_bytes).to_vec();

    let deliveries = signed_req_val
        .pointer("/body/artifacts/welcome/deliveries")
        .or_else(|| signed_req_val.pointer("/artifacts/welcome/deliveries"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            tracing::error!("signed publication lacks deliveries");
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
    if deliveries.is_empty() {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }

    let conversation_id = signed_req_val
        .pointer("/body/conversationId")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let first_message_id = signed_req_val
        .pointer("/body/firstMessageId")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;

    // 4. Resolve coordinator receipt authority key and verify coordinator P-256 signature
    let receipt_authority_did = receipt_val
        .pointer("/body/authorityDid")
        .or_else(|| receipt_val.pointer("/receipt/authorityDid"))
        .or_else(|| receipt_val.get("authorityDid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            tracing::error!("receipt missing authorityDid");
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
        })?;
    if crate::identity::canonical_did(receipt_authority_did)
        != crate::identity::canonical_did(&coord.coordinator_did)
    {
        tracing::error!(
            "receipt authorityDid {receipt_authority_did} does not match coordinator {}",
            coord.coordinator_did
        );
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    }

    let receipt_key_id = receipt_val
        .pointer("/body/keyId")
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
        .map_err(|error| key_failure(endpoint, ChatProtocolErrorCode::InvalidSignature, error))?;

    let receipt_bytes =
        serde_json::to_vec(receipt_val).map_err(|_| ChatFailure::invariant(endpoint))?;

    let verified_receipt =
        crate::chat_protocol::direct_request_transcript::verify_received_signed_request(
            crate::chat_protocol::direct_request_transcript::DirectRequestKind::Outcome,
            &receipt_bytes,
            &receipt_public_key,
        )
        .map_err(|e| {
            tracing::error!("coordinator receipt signature verification failed: {e:?}");
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidSignature)
        })?;

    // 5. Resolve sender device key and verify sender publication signature (all HTTP before tx)
    let signer_key_id = signed_req_val
        .pointer("/body/keyId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;

    let (signer_public_key, auth_generation) = crate::federation::group_relay::active_device_key(
        pool,
        actor_did,
        actor_device_id,
        signer_key_id,
    )
    .await
    .map_err(|error| key_failure(endpoint, ChatProtocolErrorCode::NotAuthorized, error))?;

    let signed_pub_bytes =
        serde_json::to_vec(signed_req_val).map_err(|_| ChatFailure::invariant(endpoint))?;
    let verified_pub = crate::chat_protocol::direct_request_transcript::verify_signed_request(
        crate::chat_protocol::direct_request_transcript::DirectRequestKind::Publish,
        &signed_pub_bytes,
        &signer_public_key,
    )
    .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidSignature))?;
    if verified_pub.actor_did() != Some(actor_did)
        || verified_pub.actor_device_id() != Some(actor_device_id.to_string().as_str())
        || verified_pub.auth_generation() != Some(auth_generation as u64)
    {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    }
    let i13_public_key = resolver
        .resolve_i13_receipt_key(&coord.coordinator_did)
        .await
        .map_err(|error| key_failure(endpoint, ChatProtocolErrorCode::InvalidSignature, error))?;
    crate::chat_protocol::direct_request_transcript::verify_direct_request_opening_receipt(
        &verified_pub,
        entry_val,
        &verified_receipt,
        &coord.coordinator_did,
        &i13_public_key,
    )
    .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidSignature))?;

    // 6. Cross-binding verifications: receipt to publication and entry
    let receipt_req_digest_b64 = verified_receipt
        .body()
        .pointer("/receipt/requestDigest")
        .or_else(|| verified_receipt.body().get("requestDigest"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let receipt_req_digest = base64::engine::general_purpose::STANDARD
        .decode(receipt_req_digest_b64)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    if receipt_req_digest.as_slice() != verified_pub.request_digest() {
        tracing::error!("receipt requestDigest mismatch with publication digest");
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }

    let receipt_req_id = verified_receipt
        .body()
        .pointer("/receipt/requestId")
        .or_else(|| verified_receipt.body().get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    if receipt_req_id != request_id.to_string() {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }

    if verified_receipt
        .body()
        .pointer("/receipt/conversationId")
        .and_then(|v| v.as_str())
        != Some(conversation_id.to_string().as_str())
        || verified_receipt
            .body()
            .pointer("/receipt/firstMessageId")
            .and_then(|v| v.as_str())
            != Some(first_message_id.to_string().as_str())
        || verified_receipt
            .body()
            .pointer("/receipt/actorDid")
            .and_then(|v| v.as_str())
            != Some(actor_did)
        || verified_receipt
            .body()
            .pointer("/receipt/requestKind")
            .and_then(|v| v.as_str())
            != Some("publish")
    {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }

    let entry_id = entry_val
        .get("entryId")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| ChatFailure::invariant(endpoint))?;
    let entry_seq = entry_val["seq"]
        .as_i64()
        .ok_or_else(|| ChatFailure::invariant(endpoint))?;
    if entry_val.get("conversationId").and_then(|v| v.as_str())
        != Some(conversation_id.to_string().as_str())
        || entry_val.get("seq").and_then(|v| v.as_u64()).is_none()
        || entry_val.get("signedRequest") != Some(signed_req_val)
    {
        return Err(ChatFailure::invariant(endpoint));
    }

    // 7. Materialize canonical entry and transport inbox rows (one per recipient device)
    let entry_bytes =
        serde_json::to_vec(entry_val).map_err(|_| ChatFailure::invariant(endpoint))?;

    let import_until = signed_req_val
        .pointer("/body/importUntil")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .ok_or_else(|| ChatFailure::invariant(endpoint))?;

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
        let rec_device_id = d["recipientDeviceId"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| {
                ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
            })?;
        let prov_bytes =
            serde_json::to_vec(&d["provenance"]).map_err(|_| ChatFailure::invariant(endpoint))?;

        inserted_recipient_devices += 1;

        // Explicit id: inventory session identity hashes delivery_id, so a DB-random
        // default would break byte-identical sim replay (random in production too).
        let delivery_id = crate::sim_hooks::mint_entry_uuid_v4(
            b"chat.direct_request_transport_inbox",
            &[&request_id.as_bytes()[..], &rec_device_id.as_bytes()[..]],
        );
        let inserted = sqlx::query(
            "INSERT INTO chat.direct_request_transport_inbox ( \
                request_id, conversation_id, first_message_id, coordinator_did, \
                sender_did, sender_device_id, recipient_did, recipient_device_id, \
                request_entry, signed_publication, full_welcome, full_welcome_sha256, \
                provenance, publication_receipt, import_until, status, created_at, updated_at, \
                delivery_id \
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'pending', $16, $16, $17) \
            ON CONFLICT (request_id, recipient_device_id) DO NOTHING",
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
        .bind(delivery_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("sender home insert transport inbox failed: {e}");
            ChatFailure::storage(endpoint)
        })?;

        if inserted.rows_affected() == 0 {
            let (existing_sha256, existing_receipt): (Vec<u8>, Vec<u8>) = sqlx::query_as(
                "SELECT signed_publication_sha256, publication_receipt \
                 FROM chat.direct_request_transport_inbox WHERE request_id=$1 AND recipient_device_id=$2",
            )
            .bind(request_id)
            .bind(rec_device_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
            if existing_sha256.as_slice() != Sha256::digest(&signed_pub_bytes).as_slice()
                || existing_receipt != receipt_bytes
            {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::IdempotencyConflict,
                ));
            }
        }
    }

    if inserted_recipient_devices == 0 {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }

    let stored = crate::chat_protocol::repository::delivery::insert_transport_entry(
        &mut tx,
        conversation_id,
        entry_seq,
        entry_id,
        &entry_bytes,
        now,
    )
    .await
    .map_err(|e| {
        tracing::error!("sender home insert transport entry failed: {e}");
        ChatFailure::storage(endpoint)
    })?;
    if stored == crate::chat_protocol::repository::delivery::TransportEntryInsert::Conflict {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::IdempotencyConflict,
        ));
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("sender home tx.commit failed: {e}");
        ChatFailure::storage(endpoint)
    })?;

    let mut return_receipt = receipt_val.clone();
    return_receipt["$type"] =
        serde_json::json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
    crate::chat_protocol::direct_request_transcript::present_read_presentation(
        "directRequestOutcome",
        &mut return_receipt,
    )
    .map_err(|_| ChatFailure::invariant(endpoint))?;

    Ok(return_receipt)
}

/// A key the mirror is verified against could not be looked up. By type (see
/// `direct_requests::dependency_failure`): this DS's own store failing is a
/// storage failure, a source that could not answer now the endpoint's
/// retryable `CapacityUnavailable`, and only an authoritative answer the
/// declared `refused`. `RelationshipPolicyUnavailable` is declared by neither
/// publish nor outcome.
fn key_failure(
    endpoint: ChatEndpoint,
    refused: ChatProtocolErrorCode,
    error: crate::federation::FederationError,
) -> ChatFailure {
    crate::handlers::chat::direct_requests::dependency_failure(endpoint, error, |_| {
        ChatFailure::protocol(endpoint, refused)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::{FederationError, ResolutionFailureKind};
    use axum::{http::StatusCode, response::IntoResponse as _};

    /// The receipt, I13 and sender device keys of the mirror, on publish and
    /// outcome: this DS's store is 500, a DID document or home that could not
    /// answer now 503 `CapacityUnavailable` with `Retry-After: 5`, and an
    /// authoritative refusal the declared `InvalidSignature` or
    /// `NotAuthorized`.
    #[tokio::test]
    async fn a_mirror_key_lookup_failure_is_answered_by_its_type() {
        for endpoint in [
            ChatEndpoint::PublishDirectRequest,
            ChatEndpoint::GetDirectRequestOutcome,
        ] {
            for refused in [
                ChatProtocolErrorCode::InvalidSignature,
                ChatProtocolErrorCode::NotAuthorized,
            ] {
                for (error, status, retry_after, name) in [
                    (
                        FederationError::Database(sqlx::Error::PoolTimedOut),
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        "InternalServerError",
                    ),
                    (
                        FederationError::ResolutionFailed {
                            did: "did:web:coordinator.example.com".into(),
                            kind: ResolutionFailureKind::DnsTemporary("SERVFAIL".into()),
                        },
                        StatusCode::SERVICE_UNAVAILABLE,
                        Some("5"),
                        "CapacityUnavailable",
                    ),
                    (
                        FederationError::NotFound("receipt key not in the DID document".into()),
                        StatusCode::UNAUTHORIZED,
                        None,
                        refused.as_str(),
                    ),
                    (
                        FederationError::Forbidden(
                            "device key is not current at its authoritative home".into(),
                        ),
                        StatusCode::UNAUTHORIZED,
                        None,
                        refused.as_str(),
                    ),
                ] {
                    let response = key_failure(endpoint, refused, error).into_response();
                    assert_eq!(response.status(), status, "{endpoint:?} {name}");
                    assert_eq!(
                        response
                            .headers()
                            .get(axum::http::header::RETRY_AFTER)
                            .and_then(|value| value.to_str().ok()),
                        retry_after,
                        "{endpoint:?} {name}"
                    );
                    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                        .await
                        .unwrap();
                    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(body["error"], name, "{endpoint:?}");
                }
            }
        }
    }
}
