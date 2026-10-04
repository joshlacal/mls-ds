//! `blue.catbird.chat.acknowledgeWelcome` and `rejectWelcome` compositors.
//!
//! The repository facade owns every authority-bearing step: aggregate and
//! terminal locks, canonical response material, executor preparation/apply,
//! and replay post-state validation.  This module owns only the HTTP boundary,
//! one outer transaction, idempotency completion, and commit.

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
            prelude,
            welcome_terminal::{
                self, WelcomeTerminalFacadeError, WelcomeTerminalTransactionOutcome,
            },
        },
    },
    storage::DbPool,
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

pub(super) async fn handle_acknowledgement(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(
        &pool,
        &runtime,
        ChatEndpoint::AcknowledgeWelcome,
        &headers,
        &body,
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
}

pub(super) async fn handle_rejection(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(
        &pool,
        &runtime,
        ChatEndpoint::RejectWelcome,
        &headers,
        &body,
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
}

async fn handle(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    // Admission verifies transport/signature evidence but deliberately does
    // not expose any completed response bytes.  Arbitration and all replay
    // post-state checks occur under this one caller-owned transaction.
    let admission =
        context::admit_signed_operation_only(pool, runtime, endpoint, headers, body).await?;
    let actor_did = admission.subject().to_string();
    let actor_device_id = admission.device_id();

    let body_json: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    let signed_req = body_json.as_ref()
        .and_then(|v| v.get("signedRequest"))
        .unwrap_or(body_json.as_ref().unwrap_or(&serde_json::Value::Null));
    let welcome_id_str = signed_req.pointer("/body/welcomeId")
        .or_else(|| signed_req.pointer("/body/id"))
        .and_then(|v| v.as_str());

    if let Some(welcome_str) = welcome_id_str {
        if let Ok(welcome_id) = uuid::Uuid::parse_str(welcome_str) {
            let in_transport_inbox: Option<(String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
                "SELECT status, updated_at FROM chat.direct_request_transport_inbox \
                 WHERE request_id = $1 AND recipient_did = $2 AND recipient_device_id = $3"
            )
            .bind(welcome_id)
            .bind(&actor_did)
            .bind(actor_device_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

            if let Some((existing_status, updated_at)) = in_transport_inbox {
                let now = chrono::Utc::now();
                let (target_status, output_dto) = match endpoint {
                    ChatEndpoint::AcknowledgeWelcome => {
                        let ts = if existing_status == "accepted" { updated_at } else { now };
                        (
                            "accepted",
                            serde_json::json!({
                                "status": "acknowledged",
                                "acknowledgedAt": ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                            }),
                        )
                    }
                    ChatEndpoint::RejectWelcome => {
                        let ts = if existing_status == "rejected" { updated_at } else { now };
                        (
                            "rejected",
                            serde_json::json!({
                                "status": "rejected",
                                "rejectedAt": ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                            }),
                        )
                    }
                    _ => return Err(ChatFailure::invariant(endpoint)),
                };

                if existing_status != target_status {
                    sqlx::query(
                        "UPDATE chat.direct_request_transport_inbox \
                         SET status = $1, updated_at = $2 \
                         WHERE request_id = $3 AND recipient_did = $4 AND recipient_device_id = $5"
                    )
                    .bind(target_status)
                    .bind(now)
                    .bind(welcome_id)
                    .bind(&actor_did)
                    .bind(actor_device_id)
                    .execute(pool)
                    .await
                    .map_err(|_| ChatFailure::storage(endpoint))?;
                }

                let resp_bytes = serde_json::to_vec(&output_dto)
                    .map_err(|_| ChatFailure::invariant(endpoint))?;
                return context::canonical_json_response(endpoint, 200, resp_bytes);
            }
        }
    }
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let operation = prelude::prepare_signed_operation(&mut transaction, admission)
        .await
        .map_err(|error| context::operation_prelude_failure(endpoint, error))?;
    let outcome = welcome_terminal::prepare_welcome_terminal(&mut transaction, operation)
        .await
        .map_err(|error| welcome_failure(endpoint, error))?;

    let response = match outcome {
        WelcomeTerminalTransactionOutcome::Replay { response, .. } => {
            context::replay_response(endpoint, &response)?
        }
        WelcomeTerminalTransactionOutcome::Prepared(first) => {
            let applied = first
                .apply(&mut transaction)
                .await
                .map_err(|error| welcome_failure(endpoint, error))?;
            let event_position = applied.applied.event_positions.first().copied();
            let response = applied.response;
            applied
                .completion
                .complete(&mut transaction, &response, event_position)
                .await
                .map_err(|error| welcome_failure(endpoint, error))?;
            context::canonical_json_response(
                endpoint,
                response.status(),
                response.as_bytes().to_vec(),
            )?
        }
        WelcomeTerminalTransactionOutcome::Classified {
            completion,
            response,
            ..
        } => {
            completion
                .complete(&mut transaction, &response, None)
                .await
                .map_err(|error| welcome_failure(endpoint, error))?;
            context::canonical_json_response(
                endpoint,
                response.status(),
                response.as_bytes().to_vec(),
            )?
        }
    };

    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    Ok(response)
}

fn welcome_failure(endpoint: ChatEndpoint, error: WelcomeTerminalFacadeError) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use WelcomeTerminalFacadeError as E;

    match error {
        E::FreshMissing => ChatFailure::protocol(endpoint,C::WelcomeNotFound),
        E::FreshTerminal => ChatFailure::protocol(endpoint, if endpoint == ChatEndpoint::AcknowledgeWelcome { C::AcknowledgementConflict } else { C::RejectionConflict }),
        E::Retention(crate::chat_protocol::repository::direct_request_retention::RetentionError::Database(_)) => ChatFailure::storage(endpoint),
        E::Retention(_) => ChatFailure::protocol_with_retry(endpoint, C::CapacityUnavailable, Some(30)),
        E::InvalidRequest => ChatFailure::protocol(endpoint, C::InvalidRequest),
        E::Prelude(error) => context::operation_prelude_failure(endpoint, error),
        // A quarantined aggregate fails the exact read-set check before the
        // facade can classify its Welcome. Preserve the two declared conflict
        // codes; every other lock, hydration, seal, or executor failure remains
        // storage or invariant failure.
        E::WelcomeLock(crate::chat_protocol::repository::core::WelcomeLockError::Database(_))
        | E::ExecutionHydration(
            crate::chat_protocol::repository::execution_context::ExecutionContextHydrationError::Database(_),
        ) => ChatFailure::storage(endpoint),
        E::Aggregate(crate::chat_protocol::repository::core::ConversationStateHydrationError::ReadSetMismatch) => {
            match endpoint {
                ChatEndpoint::AcknowledgeWelcome => {
                    ChatFailure::protocol(endpoint, C::AcknowledgementConflict)
                }
                ChatEndpoint::RejectWelcome => {
                    ChatFailure::protocol(endpoint, C::RejectionConflict)
                }
                _ => ChatFailure::invariant(endpoint),
            }
        }
        E::Aggregate(_)
        | E::WelcomeLock(_)
        | E::StateMachine(_)
        | E::ExecutionHydration(_)
        | E::Execution(_)
        | E::ReplayPostState => ChatFailure::invariant(endpoint),
    }
}
