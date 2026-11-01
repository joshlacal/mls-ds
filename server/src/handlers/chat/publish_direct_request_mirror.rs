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
    // 1. Fast local idempotent replay check: if mirror already exists on sender home
    let existing: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT publication_receipt, signed_publication \
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

    if let Some((receipt_bytes, signed_bytes)) = existing {
        if let Some(client_signed) = client_signed_pub {
            let stored_signed: serde_json::Value = serde_json::from_slice(&signed_bytes)
                .map_err(|_| ChatFailure::invariant(endpoint))?;
            if &stored_signed != client_signed {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::IdempotencyConflict,
                ));
            }
        }
        let mut receipt: serde_json::Value =
            serde_json::from_slice(&receipt_bytes).map_err(|_| ChatFailure::invariant(endpoint))?;
        receipt["$type"] = serde_json::json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
        return Ok(receipt);
    }

    // 2. Fail closed if necessary entry artifact is missing
    let Some(entry_val) = entry else {
        tracing::error!("published outcome lacks required entry artifact");
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    };

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
        .map_err(|e| {
            tracing::error!("Failed to resolve coordinator receipt key: {e:?}");
            ChatFailure::protocol(
                endpoint,
                ChatProtocolErrorCode::RelationshipPolicyUnavailable,
            )
        })?;

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
            let authorized = resolver
                .resolve_authorized_device_keys(actor_did)
                .await
                .map_err(|e| {
                    tracing::error!("failed to resolve actor device keys from PDS: {e:?}");
                    ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized)
                })?;
            let matching = authorized
                .into_iter()
                .find(|k| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(k))
                        == signer_key_id
                })
                .ok_or_else(|| {
                    tracing::error!("sender device key {signer_key_id} not authorized by PDS");
                    ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized)
                })?;
            (matching, None)
        }
    };

    let signed_pub_bytes =
        serde_json::to_vec(signed_req_val).map_err(|_| ChatFailure::invariant(endpoint))?;

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
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    }
    if let Some(auth_gen) = auth_generation {
        if verified_pub.auth_generation() != Some(auth_gen as u64) {
            return Err(ChatFailure::protocol(
                endpoint,
                ChatProtocolErrorCode::NotAuthorized,
            ));
        }
    }

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
    if entry_val.get("conversationId").and_then(|v| v.as_str())
        != Some(conversation_id.to_string().as_str())
        || entry_val.get("seq").and_then(|v| v.as_i64()) != Some(1)
        || entry_val.get("signedRequest") != Some(signed_req_val)
    {
        return Err(ChatFailure::invariant(endpoint));
    }

    if let Some(entry_hash_b64) = verified_receipt
        .body()
        .pointer("/receipt/entryHash")
        .and_then(|v| v.as_str())
    {
        let expected_hash = base64::engine::general_purpose::STANDARD
            .decode(entry_hash_b64)
            .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
        let mut untagged = entry_val.clone();
        if let Some(obj) = untagged.as_object_mut() {
            obj.remove("$type");
            obj.remove("publicationReceipt");
        }
        let untagged_bytes =
            serde_json::to_vec(&untagged).map_err(|_| ChatFailure::invariant(endpoint))?;
        let actual_hash =
            crate::chat_protocol::direct_request_transcript::direct_request_entry_hash(
                &untagged_bytes,
            )
            .map_err(|_| ChatFailure::invariant(endpoint))?;
        if expected_hash != actual_hash {
            tracing::error!("receipt entryHash does not match entry");
            return Err(ChatFailure::protocol(
                endpoint,
                ChatProtocolErrorCode::InvalidRequest,
            ));
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
    let entry_bytes =
        serde_json::to_vec(&entry_to_store).map_err(|_| ChatFailure::invariant(endpoint))?;

    let import_until = receipt_val
        .pointer("/receipt/importUntil")
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
        let rec_device_id = d["recipientDeviceId"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| {
                ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
            })?;
        let prov_bytes =
            serde_json::to_vec(&d["provenance"]).map_err(|_| ChatFailure::invariant(endpoint))?;

        inserted_recipient_devices += 1;

        let inserted = sqlx::query(
            "INSERT INTO chat.direct_request_transport_inbox ( \
                request_id, conversation_id, first_message_id, coordinator_did, \
                sender_did, sender_device_id, recipient_did, recipient_device_id, \
                request_entry, signed_publication, full_welcome, full_welcome_sha256, \
                provenance, publication_receipt, import_until, status, created_at, updated_at \
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'pending', $16, $16) \
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
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("sender home insert transport inbox failed: {e}");
            ChatFailure::storage(endpoint)
        })?;

        if inserted.rows_affected() == 0 {
            let (existing_signed, existing_receipt): (Vec<u8>, Vec<u8>) = sqlx::query_as(
                "SELECT signed_publication, publication_receipt \
                 FROM chat.direct_request_transport_inbox WHERE request_id=$1 AND recipient_device_id=$2",
            )
            .bind(request_id)
            .bind(rec_device_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
            if existing_signed != signed_pub_bytes || existing_receipt != receipt_bytes {
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

    let entry_inserted = sqlx::query(
        "INSERT INTO chat.direct_request_transport_entries ( \
            conversation_id, seq, entry_id, entry_bytes, created_at \
         ) VALUES ($1, 1, $2, $3, $4) \
         ON CONFLICT (conversation_id, seq) DO NOTHING",
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
             WHERE conversation_id=$1 AND seq=1",
        )
        .bind(conversation_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
        if existing != entry_bytes {
            return Err(ChatFailure::protocol(
                endpoint,
                ChatProtocolErrorCode::IdempotencyConflict,
            ));
        }
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
