//! XRPC compositor for acceptConversation.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::{
            acceptance::{self, AcceptanceFacadeError},
            prelude::PreludeError,
        },
        state_machine::StateMachineError,
    },
    storage::DbPool,
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let endpoint = ChatEndpoint::AcceptConversation;
    handle_inner(&pool, &runtime, endpoint, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

#[derive(sqlx::FromRow)]
struct TransportInboxRow {
    recipient_device_id: uuid::Uuid,
    request_id: uuid::Uuid,
    status: String,
    request_entry: Vec<u8>,
    acceptance_outcome: Option<Vec<u8>>,
    acceptance_proof: Option<Vec<u8>>,
    import_until: chrono::DateTime<chrono::Utc>,
}

async fn handle_inner(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let v2 =
        crate::chat_protocol::direct_request_transcript::direct_request_acceptance_endpoint_is_v2(
            body,
        )
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    if v2 {
        context::require_cutover(runtime, endpoint)?;
        let signer = runtime.request_receipt_signer().ok_or_else(|| {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::CutoverRequired)
        })?;
        let principal = context::verify_service_principal(pool, endpoint, headers).await?;
        #[derive(serde::Deserialize)]
        struct Envelope<'a> {
            #[serde(rename = "directRequest", borrow)]
            request: &'a serde_json::value::RawValue,
        }
        let envelope: Envelope = serde_json::from_slice(body)
            .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
        let now = crate::chat_protocol::validation::TrustedRequestInstant::capture()
            .map_err(|_| ChatFailure::invariant(endpoint))?
            .datetime();

        let parsed_req: serde_json::Value = serde_json::from_str(envelope.request.get())
            .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
        // Authenticate the signed acceptance before reading any state it names
        // (pending, deleted or unknown conversations): a request this DS cannot
        // verify is `InvalidSignature`, exactly as the coordinator's admission
        // answers it, and discloses nothing.
        let unverified =
            || ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidSignature);
        let device_id = parsed_req
            .pointer("/body/actorDeviceId")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(unverified)?;
        let key_id = parsed_req
            .pointer("/body/keyId")
            .and_then(|v| v.as_str())
            .ok_or_else(unverified)?;
        let device_key: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT k.signing_public_key, d.auth_generation FROM chat.device_keys k \
             JOIN chat.devices d ON d.user_did=k.user_did AND d.device_id=k.device_id \
             WHERE k.user_did=$1 AND k.device_id=$2 AND k.key_id=$3 \
               AND k.revoked_at IS NULL AND d.revoked_at IS NULL AND d.status='active' \
               AND k.enrollment_auth_generation<=d.auth_generation \
               AND NOT EXISTS(SELECT 1 FROM chat.device_keys newer \
                    WHERE newer.user_did=k.user_did AND newer.device_id=k.device_id \
                      AND newer.enrollment_auth_generation>k.enrollment_auth_generation \
                      AND newer.enrollment_auth_generation<=d.auth_generation)",
        )
        .bind(principal.did())
        .bind(device_id)
        .bind(key_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
        let (public_key, generation) = device_key.ok_or_else(unverified)?;
        let verified = crate::chat_protocol::direct_request_transcript::verify_signed_request(
            crate::chat_protocol::direct_request_transcript::DirectRequestKind::Accept,
            envelope.request.get().as_bytes(),
            &public_key,
        )
        .map_err(|_| unverified())?;
        if verified.actor_did() != Some(principal.did())
            || verified.actor_device_id() != Some(device_id.to_string().as_str())
            || verified.auth_generation() != Some(generation as u64)
        {
            return Err(unverified());
        }
        let request_id_str = parsed_req
            .pointer("/body/requestId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
            })?;
        let request_id = uuid::Uuid::parse_str(request_id_str)
            .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
        let transition_id_str = parsed_req
            .pointer("/body/transitionId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
            })?;
        let transition_id = uuid::Uuid::parse_str(transition_id_str)
            .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;

        let convo_id_str = parsed_req["body"]["prior"]["conversationId"]
            .as_str()
            .unwrap_or_default();
        let conversation_id = uuid::Uuid::parse_str(convo_id_str)
            .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;

        let creator_did: Option<String> = sqlx::query_scalar(
            "SELECT created_by_did FROM chat.participants WHERE conversation_id=$1 AND current_membership"
        )
        .bind(conversation_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;

        let (creator_did, is_inbox) = if let Some(c) = creator_did {
            (Some(c), false)
        } else {
            let sender: Option<String> = sqlx::query_scalar(
                "SELECT sender_did FROM chat.direct_request_transport_inbox WHERE conversation_id=$1"
            )
            .bind(conversation_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
            (sender, true)
        };

        let Some(creator) = creator_did.as_ref() else {
            return Err(ChatFailure::protocol(
                endpoint,
                ChatProtocolErrorCode::InvitationNotPending,
            ));
        };

        let parties = [creator.as_str(), principal.did()];
        let coord = match crate::federation::canonical_relay::resolve_pair_coordinator(
            pool,
            creator,
            principal.did(),
        )
        .await
        {
            Ok(coord) => coord,
            Err(error) => {
                // A deleted account's declaration is typically gone: the deletion
                // this DS holds is the final answer.
                if party_deleted(pool, endpoint, conversation_id, parties).await? {
                    return Err(ChatFailure::protocol(
                        endpoint,
                        ChatProtocolErrorCode::InvitationNotPending,
                    ));
                }
                return Err(coordinator_failure(endpoint, "pair coordinator", &error));
            }
        };
        if !coord.is_coordinator {
            if is_inbox {
                let inbox_rows: Vec<TransportInboxRow> = sqlx::query_as(
                    "SELECT recipient_device_id, request_id, status, \
                            COALESCE(request_entry, redacted_request_entry) AS request_entry, \
                            acceptance_outcome, acceptance_proof, import_until \
                     FROM chat.direct_request_transport_inbox \
                     WHERE conversation_id=$1 AND recipient_did=$2",
                )
                .bind(conversation_id)
                .bind(principal.did())
                .fetch_all(pool)
                .await
                .map_err(|_| ChatFailure::storage(endpoint))?;

                if inbox_rows.is_empty() {
                    return Err(ChatFailure::protocol(
                        endpoint,
                        ChatProtocolErrorCode::InvitationNotPending,
                    ));
                }

                let caller_row = inbox_rows
                    .iter()
                    .find(|r| r.recipient_device_id == device_id)
                    .ok_or_else(|| {
                        ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized)
                    })?;

                if caller_row.request_id != request_id {
                    return Err(ChatFailure::protocol(
                        endpoint,
                        ChatProtocolErrorCode::InvalidRequest,
                    ));
                }

                let existing_entry_bytes: Option<Vec<u8>> = sqlx::query_scalar(
                    "SELECT entry_bytes FROM chat.direct_request_transport_entries \
                     WHERE conversation_id=$1 AND seq=2",
                )
                .bind(conversation_id)
                .fetch_optional(pool)
                .await
                .map_err(|_| ChatFailure::storage(endpoint))?;

                let any_accepted = inbox_rows.iter().any(|r| r.status == "accepted");
                // A request not accepted here whose party's deletion reached this
                // transport-only home is final; its seq 2 holds that deletion.
                if !any_accepted && party_deleted(pool, endpoint, conversation_id, parties).await? {
                    return Err(ChatFailure::protocol(
                        endpoint,
                        ChatProtocolErrorCode::InvitationNotPending,
                    ));
                }

                if existing_entry_bytes.is_some() || any_accepted {
                    let old_signed_request = if let Some(entry_bytes) = &existing_entry_bytes {
                        let old_entry: serde_json::Value = serde_json::from_slice(entry_bytes)
                            .map_err(|_| ChatFailure::invariant(endpoint))?;
                        old_entry.get("signedRequest").cloned()
                    } else if let Some(acc) = inbox_rows.iter().find(|r| r.status == "accepted") {
                        if let Some(proof_b) = &acc.acceptance_proof {
                            let proof_val: serde_json::Value = serde_json::from_slice(proof_b)
                                .ok()
                                .unwrap_or(serde_json::Value::Null);
                            proof_val.pointer("/entry/signedRequest").cloned()
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let old_req =
                        old_signed_request.ok_or_else(|| ChatFailure::invariant(endpoint))?;
                    if old_req != parsed_req {
                        return Err(ChatFailure::protocol(
                            endpoint,
                            ChatProtocolErrorCode::IdempotencyConflict,
                        ));
                    }

                    if let Some(acc) = inbox_rows.iter().find(|r| r.status == "accepted") {
                        if let (Some(proof_b), Some(outcome_b)) =
                            (&acc.acceptance_proof, &acc.acceptance_outcome)
                        {
                            let stored_outcome: serde_json::Value =
                                serde_json::from_slice(outcome_b)
                                    .map_err(|_| ChatFailure::invariant(endpoint))?;
                            let stored_proof: serde_json::Value =
                                serde_json::from_slice(proof_b)
                                    .map_err(|_| ChatFailure::invariant(endpoint))?;
                            let presented_proof =
                                stored_outcome.get("acceptanceProof").ok_or_else(|| {
                                    ChatFailure::protocol(
                                        endpoint,
                                        ChatProtocolErrorCode::InvalidRequest,
                                    )
                                })?;
                            let normalized_proof = crate::chat_protocol::direct_request_transcript::normalize_read_presentation(
                                &serde_json::to_vec(presented_proof).map_err(|_| ChatFailure::invariant(endpoint))?,
                                "directRequestAcceptanceProof", false,
                            ).map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
                            let presented_coordinates =
                                stored_outcome.get("coordinates").ok_or_else(|| {
                                    ChatFailure::protocol(
                                        endpoint,
                                        ChatProtocolErrorCode::InvalidRequest,
                                    )
                                })?;
                            let normalized_coordinates = crate::chat_protocol::direct_request_transcript::normalize_read_presentation(
                                &serde_json::to_vec(presented_coordinates).map_err(|_| ChatFailure::invariant(endpoint))?,
                                "conversationCoordinates", false,
                            ).map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
                            if normalized_proof != stored_proof
                                || Some(&normalized_coordinates) != parsed_req.pointer("/body/next")
                            {
                                return Err(ChatFailure::protocol(
                                    endpoint,
                                    ChatProtocolErrorCode::InvalidRequest,
                                ));
                            }
                            if let Some(entry_bytes) = &existing_entry_bytes {
                                let old_entry: serde_json::Value =
                                    serde_json::from_slice(entry_bytes)
                                        .map_err(|_| ChatFailure::invariant(endpoint))?;
                                if let Some(outcome_entry) = stored_outcome.get("entry") {
                                    let normalized_entry = crate::chat_protocol::direct_request_transcript::normalize_read_presentation(
                                        &serde_json::to_vec(outcome_entry).map_err(|_| ChatFailure::invariant(endpoint))?,
                                        "directRequestAcceptanceEntry", false,
                                    ).map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
                                    if normalized_entry != old_entry {
                                        return Err(ChatFailure::protocol(
                                            endpoint,
                                            ChatProtocolErrorCode::InvalidRequest,
                                        ));
                                    }
                                }
                            }
                            let needs_mirror = inbox_rows.iter().any(|r| {
                                r.status != "accepted"
                                    || r.acceptance_proof.is_none()
                                    || r.acceptance_outcome.is_none()
                            });
                            if needs_mirror {
                                sqlx::query(
                                    "UPDATE chat.direct_request_transport_inbox \
                                     SET status='accepted', acceptance_proof=$2, acceptance_outcome=$3, \
                                         updated_at=$4 \
                                     WHERE conversation_id=$1 AND status='pending'",
                                )
                                .bind(conversation_id)
                                .bind(proof_b)
                                .bind(outcome_b)
                                .bind(crate::sim_hooks::current_utc())
                                .execute(pool)
                                .await
                                .map_err(|_| ChatFailure::storage(endpoint))?;
                            }
                            return Ok(context::json_ok(outcome_b.clone()));
                        }
                    }
                }

                if caller_row.status != "pending" || caller_row.import_until < now {
                    return Err(ChatFailure::protocol(
                        endpoint,
                        ChatProtocolErrorCode::InvitationNotPending,
                    ));
                }

                let intro_val: serde_json::Value =
                    serde_json::from_slice(&caller_row.request_entry)
                        .map_err(|_| ChatFailure::invariant(endpoint))?;
                if intro_val.get("conversationId").and_then(|v| v.as_str())
                    != Some(conversation_id.to_string().as_str())
                    || intro_val.get("seq").and_then(|v| v.as_i64()) != Some(1)
                    || intro_val.pointer("/signedRequest/body/next")
                        != parsed_req.pointer("/body/prior")
                {
                    return Err(ChatFailure::protocol(
                        endpoint,
                        ChatProtocolErrorCode::StaleCoordinates,
                    ));
                }
            }

            let payload = crate::federation::canonical_relay::DeliverAcceptanceInput {
                conversation_id,
                direct_request: parsed_req.clone(),
            };
            let output = crate::federation::canonical_relay::relay_acceptance_to_coordinator(
                coord.coordinator_endpoint(),
                &coord.coordinator_did,
                payload,
            )
            .await
            .map_err(|error| coordinator_failure(endpoint, "relayed acceptance", &error))?;

            // Verify coordinator acceptance proof and entry before commit
            let proof_receipt = output
                .acceptance_proof
                .pointer("/receipt/body")
                .ok_or_else(|| {
                    ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
                })?;
            if proof_receipt["authorityDid"].as_str() != Some(coord.coordinator_did.as_str()) {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::NotAuthorized,
                ));
            }
            if proof_receipt["requestId"].as_str() != Some(request_id_str) {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::InvalidRequest,
                ));
            }
            let key_id_receipt = proof_receipt["keyId"].as_str().ok_or_else(|| {
                ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
            })?;

            let entry_seq = output
                .entry
                .get("seq")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| {
                    ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
                })?;
            if entry_seq != 2 {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::InvalidRequest,
                ));
            }
            let entry_id_str = output
                .entry
                .get("entryId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
                })?;
            if entry_id_str != transition_id_str {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::InvalidRequest,
                ));
            }
            let entry_convo = output
                .entry
                .get("conversationId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest)
                })?;
            if entry_convo != conversation_id.to_string().as_str() {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::InvalidRequest,
                ));
            }
            if output.entry.get("signedRequest") != Some(&parsed_req) {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::InvalidRequest,
                ));
            }

            let resolver = crate::federation::resolver::DsResolver::with_default_endpoint(
                pool.clone(),
                crate::federation::resolver::build_resolver_http_client(),
                crate::identity::service_did(),
                crate::identity::self_endpoint(),
                std::env::var("DEFAULT_DS_ENDPOINT").ok(),
                3600,
            );
            let authority_key = resolver
                .resolve_coordinator_receipt_key(pool, &coord.coordinator_did, key_id_receipt)
                .await
                .map_err(|error| {
                    coordinator_failure(endpoint, "coordinator receipt key", &error)
                })?;

            let proof_bytes = serde_json::to_vec(&output.acceptance_proof)
                .map_err(|_| ChatFailure::invariant(endpoint))?;
            let verified_proof = crate::chat_protocol::direct_request_transcript::verify_received_direct_request_acceptance_proof(
                &proof_bytes,
                &authority_key,
                &public_key,
            )
            .map_err(|e| {
                tracing::error!("verify_received_direct_request_acceptance_proof failed: {e:?}");
                ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidSignature)
            })?;

            let mut untagged_entry = output.entry.clone();
            if let Some(obj) = untagged_entry.as_object_mut() {
                obj.remove("$type");
                obj.remove("acceptanceProof");
            }
            if verified_proof.get("entry") != Some(&untagged_entry) {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::InvalidRequest,
                ));
            }

            use base64::Engine as _;
            let outcome_raw = base64::engine::general_purpose::STANDARD
                .decode(&output.outcome_bytes)
                .map_err(|_| ChatFailure::invariant(endpoint))?;
            if outcome_raw.is_empty() {
                return Err(ChatFailure::invariant(endpoint));
            }
            let outcome_val: serde_json::Value = serde_json::from_slice(&outcome_raw)
                .map_err(|_| ChatFailure::invariant(endpoint))?;
            if outcome_val.get("coordinates") != parsed_req.pointer("/body/next") {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::InvalidRequest,
                ));
            }
            if outcome_val.get("acceptanceProof") != Some(&output.acceptance_proof) {
                return Err(ChatFailure::protocol(
                    endpoint,
                    ChatProtocolErrorCode::InvalidRequest,
                ));
            }
            if let Some(outcome_entry) = outcome_val.get("entry") {
                let mut untagged_outcome_entry = outcome_entry.clone();
                if let Some(obj) = untagged_outcome_entry.as_object_mut() {
                    obj.remove("$type");
                }
                if untagged_outcome_entry != untagged_entry {
                    return Err(ChatFailure::protocol(
                        endpoint,
                        ChatProtocolErrorCode::InvalidRequest,
                    ));
                }
            }

            let presented_outcome =
                crate::chat_protocol::direct_request_transcript::present_endpoint_output(
                    endpoint.nsid(),
                    outcome_raw,
                )
                .map_err(|_| ChatFailure::invariant(endpoint))?;

            if is_inbox {
                let mut tx = pool.begin().await.map_err(|e| {
                    tracing::error!("accept_conversation pool.begin failed: {e}");
                    ChatFailure::storage(endpoint)
                })?;
                let updated = sqlx::query(
                    "UPDATE chat.direct_request_transport_inbox \
                     SET status='accepted', acceptance_proof=$2, acceptance_outcome=$3, \
                         updated_at=$4 \
                     WHERE conversation_id=$1 AND status='pending'",
                )
                .bind(conversation_id)
                .bind(&proof_bytes)
                .bind(&presented_outcome)
                .bind(crate::sim_hooks::current_utc())
                .execute(&mut *tx)
                .await
                .map_err(|_| ChatFailure::storage(endpoint))?;

                if updated.rows_affected() == 0 {
                    let existing: Option<Vec<u8>> = sqlx::query_scalar(
                        "SELECT entry_bytes FROM chat.direct_request_transport_entries \
                         WHERE conversation_id=$1 AND seq=2",
                    )
                    .bind(conversation_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| ChatFailure::storage(endpoint))?;

                    if let Some(entry_bytes) = existing {
                        let old_entry: serde_json::Value = serde_json::from_slice(&entry_bytes)
                            .map_err(|_| ChatFailure::invariant(endpoint))?;
                        if old_entry.get("signedRequest") != Some(&parsed_req) {
                            return Err(ChatFailure::protocol(
                                endpoint,
                                ChatProtocolErrorCode::IdempotencyConflict,
                            ));
                        }
                    } else {
                        return Err(ChatFailure::protocol(
                            endpoint,
                            ChatProtocolErrorCode::InvitationNotPending,
                        ));
                    }
                }

                let entry_bytes = serde_json::to_vec(&output.entry)
                    .map_err(|_| ChatFailure::invariant(endpoint))?;
                let stored = crate::chat_protocol::repository::delivery::insert_transport_entry(
                    &mut tx,
                    conversation_id,
                    2,
                    transition_id,
                    &entry_bytes,
                    crate::sim_hooks::current_utc(),
                )
                .await
                .map_err(|_| ChatFailure::storage(endpoint))?;
                if stored
                    == crate::chat_protocol::repository::delivery::TransportEntryInsert::Conflict
                {
                    return Err(ChatFailure::protocol(
                        endpoint,
                        ChatProtocolErrorCode::IdempotencyConflict,
                    ));
                }
                tx.commit().await.map_err(|e| {
                    tracing::error!("accept_conversation tx.commit failed: {e}");
                    ChatFailure::storage(endpoint)
                })?;
            } else {
                crate::federation::canonical_relay::ingest_remote_acceptance_entry(
                    pool,
                    Some(runtime.sse_state()),
                    &coord.coordinator_did,
                    conversation_id,
                    &output.entry,
                    &output.acceptance_proof,
                )
                .await
                .map_err(|e| {
                    tracing::error!("Failed to ingest remote acceptance entry locally: {e}");
                    ChatFailure::storage(endpoint)
                })?;
            }

            return Ok(context::json_ok(presented_outcome));
        }
        let current_status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM chat.participants WHERE conversation_id = $1 AND user_did = $2 AND current_membership"
        )
        .bind(conversation_id)
        .bind(principal.did())
        .fetch_optional(pool)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;

        let mut tx = pool
            .begin()
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
        let bytes = acceptance::accept_direct_request(
            &mut tx,
            &principal,
            envelope.request.get().as_bytes(),
            signer,
            runtime.relationship_authority().as_ref(),
            now,
        )
        .await
        .map_err(|error| {
            use acceptance::DirectAcceptanceError as E;
            use ChatProtocolErrorCode as C;
            match error {
                E::Retention(crate::chat_protocol::repository::direct_request_retention::RetentionError::Database(_)) => ChatFailure::storage(endpoint),
                E::Retention(_) => ChatFailure::protocol_with_retry(endpoint,C::CapacityUnavailable,Some(30)),
                E::Database(error) => {
                    log_direct_acceptance_storage_error("execution", &error);
                    ChatFailure::storage(endpoint)
                },
                E::InvalidSignature => ChatFailure::protocol(endpoint, C::InvalidSignature),
                E::InvalidRequest => ChatFailure::protocol(endpoint, C::InvalidRequest),
                E::NotPending | E::Expired => {
                    ChatFailure::protocol(endpoint, C::InvitationNotPending)
                }
                E::StaleCoordinates => ChatFailure::protocol(endpoint, C::StaleCoordinates),
                E::Blocked => ChatFailure::protocol(endpoint, C::BlockedRelationship),
                E::PolicySourceUnavailable => ChatFailure::unavailable(endpoint),
                E::PolicyUnavailable => {
                    ChatFailure::protocol(endpoint, C::RelationshipPolicyUnavailable)
                }
                E::Invariant => ChatFailure::invariant(endpoint),
            }
        })?;
        tx.commit().await.map_err(|error| {
            log_direct_acceptance_storage_error("commit", &error);
            ChatFailure::storage(endpoint)
        })?;
        if !coord.is_sender_home {
            let entry_row: Vec<u8> = sqlx::query_scalar(
                "SELECT accepted_payload_bytes FROM chat.entries WHERE conversation_id=$1 AND seq=2"
            )
            .bind(conversation_id)
            .fetch_one(pool)
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
            let entry_val =
                serde_json::from_slice(&entry_row).map_err(|_| ChatFailure::invariant(endpoint))?;
            let proof_val: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| ChatFailure::invariant(endpoint))?;
            let proof = proof_val
                .get("acceptanceProof")
                .ok_or_else(|| ChatFailure::invariant(endpoint))?;
            let deliver_input = crate::federation::canonical_relay::DeliverAcceptanceEntryInput {
                conversation_id,
                entry: entry_val,
                acceptance_proof: proof.clone(),
            };
            if let Err(error) =
                crate::federation::canonical_relay::deliver_acceptance_entry_to_peer(
                    &coord.sender_home.endpoint,
                    &coord.sender_home.did,
                    deliver_input.clone(),
                )
                .await
            {
                // Committed: the acceptance stands, and its durable queue row
                // delivers this entry once the sender's home answers.
                tracing::warn!(
                    ?error,
                    "Failed to deliver acceptance entry to peer, queueing for retry"
                );
                sqlx::query(
                    "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, last_error, next_retry_at) \
                     SELECT $1, $2, $3, $4, $5, $6, $7, $8 \
                      WHERE NOT EXISTS (SELECT 1 FROM outbound_queue WHERE id = $1) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(format!("acceptance-delivery-{conversation_id}"))
                .bind(&coord.sender_home.did)
                .bind(&coord.sender_home.endpoint)
                .bind("blue.catbird.mlsDS.deliverAcceptanceEntry")
                .bind(serde_json::to_vec(&deliver_input).map_err(|_| ChatFailure::invariant(endpoint))?)
                .bind(conversation_id.to_string())
                .bind(error.to_string())
                .bind(crate::sim_hooks::current_utc() + chrono::Duration::seconds(5))
                .execute(pool)
                .await
                .map_err(|_| ChatFailure::storage(endpoint))?;
            }
        }

        return Ok(context::json_ok(
            crate::chat_protocol::direct_request_transcript::present_endpoint_output(
                endpoint.nsid(),
                bytes,
            )
            .map_err(|_| ChatFailure::invariant(endpoint))?,
        ));
    }
    let admission =
        context::admit_signed_operation_only(pool, runtime, endpoint, headers, body).await?;
    if let Some(output) = crate::federation::group_relay::try_relay_home_group_operation(
        pool,
        admission.subject(),
        admission.device_id(),
        endpoint.nsid(),
        body,
    )
    .await
    .map_err(|error| error.into_failure(endpoint))?
    {
        return Ok(context::json_ok(
            serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(endpoint))?,
        ));
    }
    execute_admitted(pool, admission, runtime.relationship_authority().as_ref()).await
}

pub(crate) async fn execute_admitted<
    T: crate::chat_protocol::relationship_policy::PublicTransport,
>(
    pool: &DbPool,
    admission: crate::chat_protocol::repository::auth::SignedOperationAdmission,
    relationship_authority: &crate::chat_protocol::relationship_policy::RelationshipAuthority<T>,
) -> Result<Response, ChatFailure> {
    let endpoint = ChatEndpoint::AcceptConversation;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let prepared = crate::chat_protocol::repository::prelude::prepare_signed_operation(
        &mut transaction,
        admission,
    )
    .await
    .map_err(|error| context::operation_prelude_failure(endpoint, error))?;
    let outcome =
        acceptance::execute_prepared_acceptance(&mut transaction, prepared, relationship_authority)
            .await
            .map_err(|error| acceptance_failure(endpoint, error))?;
    let response = context::canonical_json_response(
        endpoint,
        outcome.status(),
        outcome.response_bytes().to_vec(),
    )?;
    let value = serde_json::from_slice(outcome.response_bytes())
        .map_err(|_| ChatFailure::invariant(endpoint))?;
    let fanout =
        crate::federation::group_fanout::prepare_group_entry_fanout(&mut transaction, &value)
            .await
            .map_err(|_| ChatFailure::storage(endpoint))?;
    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    // Committed with its queued fan-out; the queue retries a failed send.
    if let Some(fanout) = fanout {
        let _ = fanout.deliver(pool, None).await;
    }
    Ok(response)
}

fn acceptance_failure(endpoint: ChatEndpoint, error: AcceptanceFacadeError) -> ChatFailure {
    tracing::error!("acceptance_failure: {:?}", error);
    use AcceptanceFacadeError as E;
    use ChatProtocolErrorCode as C;
    use StateMachineError as S;
    match error {
        E::Database(_) => ChatFailure::storage(endpoint),
        E::Prelude(PreludeError::Authorization(error)) => {
            context::auth_repository_failure(endpoint, error)
        }
        E::Prelude(error) => context::operation_prelude_failure(endpoint, error),
        E::Primitive(_) => ChatFailure::protocol(endpoint, C::InvalidSignature),
        E::Conversation(error) => match error {
            crate::chat_protocol::repository::core::ConversationStateHydrationError::Database(_) => {
                ChatFailure::storage(endpoint)
            }
            crate::chat_protocol::repository::core::ConversationStateHydrationError::ReadSetMismatch => {
                ChatFailure::protocol(endpoint, C::StaleCoordinates)
            }
            _ => ChatFailure::protocol(endpoint, C::ConversationNotFound),
        },
        E::RecoveryPackage(error) => match error {
            crate::chat_protocol::repository::core::RecoveryPackageHydrationError::Database(_) => {
                ChatFailure::storage(endpoint)
            }
            crate::chat_protocol::repository::core::RecoveryPackageHydrationError::PackageMissing => {
                ChatFailure::protocol(endpoint, C::KeyPackageUnavailable)
            }
            _ => ChatFailure::invariant(endpoint),
        },
        E::Relationship(error) => {
            use crate::chat_protocol::repository::relationship::RelationshipRepositoryError as R;
            match error {
                R::Database(_) => ChatFailure::storage(endpoint),
                // A relationship source that could not answer now decided nothing.
                R::Unavailable => ChatFailure::unavailable(endpoint),
                R::InvalidProjection | R::InvalidAuthorityConfiguration(_) => {
                    ChatFailure::invariant(endpoint)
                }
            }
        }
        E::StateMachine(S::StaleCoordinates) => {
            ChatFailure::protocol(endpoint, C::StaleCoordinates)
        }
        E::StateMachine(S::InvitationNotPending) => {
            ChatFailure::protocol(endpoint, C::InvitationNotPending)
        }
        E::StateMachine(S::NotParticipant) => ChatFailure::protocol(endpoint, C::NotParticipant),
        E::StateMachine(S::InvalidPolicyAuthority) => {
            ChatFailure::protocol(endpoint, C::BlockedRelationship)
        }
        E::StateMachine(S::WorkExpired) => ChatFailure::protocol(endpoint, C::InvitationNotPending),
        E::MissingMutation
        | E::InvalidCanonicalMaterial
        | E::StateMachine(_)
        | E::ExecutionContext(_)
        | E::Executor(_) => ChatFailure::invariant(endpoint),
    }
}

/// A federation step of a direct acceptance failed: resolving the pair's
/// coordinator, relaying to it, or resolving its receipt key. This DS's store
/// failing is storage; a closed gate, or a coordinator, home or resolver that
/// could not answer now, decided nothing; a coordinator that refused, or one
/// that cannot be routed or verified, is a refusal.
fn coordinator_failure(
    endpoint: ChatEndpoint,
    stage: &'static str,
    error: &crate::federation::FederationError,
) -> ChatFailure {
    use crate::federation::FederationError as F;
    use ChatProtocolErrorCode as C;
    tracing::error!(
        stage,
        ?error,
        "direct request acceptance federation failure"
    );
    match error {
        F::Database(_) | F::Storage(_) => ChatFailure::storage(endpoint),
        error if error.is_retryable() => ChatFailure::unavailable(endpoint),
        F::BlockedRelationship => ChatFailure::protocol(endpoint, C::BlockedRelationship),
        F::RemoteError { status: 409, .. } => ChatFailure::protocol(endpoint, C::StaleCoordinates),
        F::RemoteError {
            status: 400 | 404 | 422,
            ..
        }
        | F::InvalidRequest(_)
        | F::InvalidEnvelope { .. } => ChatFailure::protocol(endpoint, C::InvalidRequest),
        _ => ChatFailure::protocol(endpoint, C::NotAuthorized),
    }
}

fn log_direct_acceptance_storage_error(stage: &'static str, error: &sqlx::Error) {
    use sha2::{Digest, Sha256};
    let database = error.as_database_error();
    tracing::error!(
        stage,
        sqlstate = database
            .and_then(|e| e.code())
            .as_deref()
            .unwrap_or("non_database"),
        constraint = database.and_then(|e| e.constraint()).unwrap_or("none"),
        message_fingerprint = database
            .map(|e| format!("{:x}", Sha256::digest(e.message().as_bytes())))
            .unwrap_or_else(|| "none".into()),
        "direct request acceptance database failure"
    );
}

/// Whether this DS holds an `accountDeletedEntry` of either of `parties` in
/// `conversation_id`: sequenced here, or a transport-only home's copy.
async fn party_deleted(
    pool: &DbPool,
    endpoint: ChatEndpoint,
    conversation_id: uuid::Uuid,
    parties: [&str; 2],
) -> Result<bool, ChatFailure> {
    let mut read = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let deletions = crate::chat_protocol::repository::conversation::load_account_deletions(
        &mut read,
        conversation_id,
    )
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;
    Ok(deletions
        .iter()
        .any(|deletion| parties.contains(&deletion.deleted_did.as_str())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_protocol::{
        error::ErrorExposure, repository::relationship::RelationshipRepositoryError as R,
    };
    use crate::federation::FederationError;
    use axum::http::{header::RETRY_AFTER, StatusCode};

    fn wire(failure: ChatFailure) -> (StatusCode, Option<String>, Option<ChatProtocolErrorCode>) {
        let code = failure.code();
        let response = failure.into_response();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .map(|value| value.to_str().unwrap().to_owned());
        (response.status(), retry_after, code)
    }

    /// A group acceptance's relationship source that could not answer now is
    /// the declared retryable answer, and this DS's store failing is storage.
    #[test]
    fn group_acceptance_relationship_failures_keep_their_class() {
        let endpoint = ChatEndpoint::AcceptConversation;
        assert_eq!(
            wire(acceptance_failure(
                endpoint,
                AcceptanceFacadeError::Relationship(R::Unavailable)
            )),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("5".to_owned()),
                Some(ChatProtocolErrorCode::RelationshipPolicyUnavailable)
            )
        );
        let stored = acceptance_failure(
            endpoint,
            AcceptanceFacadeError::Relationship(R::Database(sqlx::Error::PoolTimedOut)),
        );
        assert!(matches!(stored.exposure(), ErrorExposure::StorageFailure));
        assert_eq!(
            wire(stored),
            (StatusCode::INTERNAL_SERVER_ERROR, None, None)
        );
    }

    /// A relayed direct acceptance's federation step: this DS's store failing
    /// is storage, a source that could not answer now is retryable, and a
    /// definitive answer is a refusal (never a 503 without a retry hint).
    #[test]
    fn direct_acceptance_federation_failures_keep_their_class() {
        let endpoint = ChatEndpoint::AcceptConversation;
        let unavailable = Some(ChatProtocolErrorCode::RelationshipPolicyUnavailable);
        let remote = |status| FederationError::RemoteError {
            status,
            body: String::new(),
        };
        for (error, expected) in [
            (
                FederationError::Database(sqlx::Error::PoolTimedOut),
                (StatusCode::INTERNAL_SERVER_ERROR, None, None),
            ),
            (
                remote(503),
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Some("5".to_owned()),
                    unavailable,
                ),
            ),
            (
                FederationError::BlockedRelationship,
                (
                    StatusCode::BAD_REQUEST,
                    None,
                    Some(ChatProtocolErrorCode::BlockedRelationship),
                ),
            ),
            (
                remote(429),
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Some("5".to_owned()),
                    unavailable,
                ),
            ),
            (
                remote(404),
                (
                    StatusCode::BAD_REQUEST,
                    None,
                    Some(ChatProtocolErrorCode::InvalidRequest),
                ),
            ),
            (
                remote(409),
                (
                    StatusCode::BAD_REQUEST,
                    None,
                    Some(ChatProtocolErrorCode::StaleCoordinates),
                ),
            ),
            (
                remote(403),
                (
                    StatusCode::UNAUTHORIZED,
                    None,
                    Some(ChatProtocolErrorCode::NotAuthorized),
                ),
            ),
            (
                FederationError::InvalidProof,
                (
                    StatusCode::UNAUTHORIZED,
                    None,
                    Some(ChatProtocolErrorCode::NotAuthorized),
                ),
            ),
        ] {
            assert_eq!(
                wire(coordinator_failure(endpoint, "test", &error)),
                expected,
                "{error:?}"
            );
        }
    }
}
