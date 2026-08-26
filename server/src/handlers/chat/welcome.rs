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
            context::replay_response(&response)
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
        E::InvalidRequest => ChatFailure::protocol(endpoint, C::InvalidRequest),
        E::Prelude(error) => context::operation_prelude_failure(endpoint, error),
        // The only semantic terminal outcomes are represented by the facade's
        // canonical completed responses above.  A lock/hydration/seal/executor
        // failure is never reclassified as a client-visible Welcome outcome.
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
