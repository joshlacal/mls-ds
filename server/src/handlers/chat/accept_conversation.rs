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
        let convo_id_str = parsed_req["body"]["prior"]["conversationId"].as_str().unwrap_or_default();
        let conversation_id = uuid::Uuid::parse_str(convo_id_str).unwrap_or_default();

        let creator_did: Option<String> = sqlx::query_scalar("SELECT created_by_did FROM chat.participants WHERE conversation_id = $1 AND current_membership AND status = 'pending'")
            .bind(conversation_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

        if let Some(creator) = &creator_did {
            if let Ok(coord) = crate::federation::canonical_relay::resolve_pair_coordinator(pool, creator, principal.did()).await {
                if !coord.is_coordinator {
                    let payload = crate::federation::canonical_relay::DeliverAcceptanceInput {
                        conversation_id,
                        direct_request: parsed_req,
                    };
                    let output = crate::federation::canonical_relay::relay_acceptance_to_coordinator(
                        &coord.coordinator_endpoint(),
                        &coord.coordinator_did,
                        payload,
                    ).await.map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::RelationshipPolicyUnavailable))?;

                    let _ = crate::federation::canonical_relay::ingest_remote_acceptance_entry(
                        pool,
                        Some(runtime.sse_state()),
                        conversation_id,
                        &output.entry,
                        &output.acceptance_proof,
                    ).await;

                    use base64::Engine as _;
                    let outcome_bytes = base64::engine::general_purpose::STANDARD.decode(&output.outcome_bytes)
                        .map_err(|_| ChatFailure::invariant(endpoint))?;
                    return Ok(context::json_ok(outcome_bytes));
                }
            }
        }
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
        if let Some(creator) = &creator_did {
            if let Ok(coord) = crate::federation::canonical_relay::resolve_pair_coordinator(pool, creator, principal.did()).await {
                if coord.is_coordinator && !coord.is_sender_home {
                    let entry_row: Option<Vec<u8>> = sqlx::query_scalar("SELECT accepted_payload_bytes FROM chat.entries WHERE conversation_id = $1 AND seq = 2")
                        .bind(conversation_id)
                        .fetch_optional(pool)
                        .await
                        .ok()
                        .flatten();
                    let entry_val = entry_row.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(serde_json::json!({}));
                    let proof_val: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
                    let deliver_input = crate::federation::canonical_relay::DeliverAcceptanceEntryInput {
                        conversation_id,
                        entry: entry_val,
                        acceptance_proof: proof_val.get("acceptanceProof").cloned().unwrap_or(serde_json::Value::Null),
                    };
                    if let Err(e) = crate::federation::canonical_relay::deliver_acceptance_entry_to_peer(
                        &coord.sender_home.endpoint,
                        &coord.sender_home.did,
                        deliver_input,
                    ).await {
                        tracing::warn!("Failed to deliver acceptance entry to peer (sync/outbox will retry): {e}");
                    }
                }
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
    let outcome = acceptance::execute_prepared_acceptance(
        &mut transaction,
        prepared,
        runtime.relationship_authority().as_ref(),
    )
    .await
    .map_err(|error| acceptance_failure(endpoint, error))?;
    let response = context::canonical_json_response(
        endpoint,
        outcome.status(),
        outcome.response_bytes().to_vec(),
    )?;
    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
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
        E::Relationship(_) => ChatFailure::invariant(endpoint),
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
