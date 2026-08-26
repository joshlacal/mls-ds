//! `blue.catbird.chat.revokeDevice` — complete G6 device-revocation compositor.

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
            revocation::{self, DeviceRevocationFacadeError, DeviceRevocationTransactionOutcome},
        },
    },
    storage::DbPool,
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

const ENDPOINT: ChatEndpoint = ChatEndpoint::RevokeDevice;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    revoke(&pool, &runtime, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn revoke(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_signed_operation_only(pool, runtime, ENDPOINT, headers, body).await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let prepared = prelude::prepare_signed_operation(&mut transaction, admission)
        .await
        .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?;
    let outcome = revocation::prepare_device_revocation(&mut transaction, prepared)
        .await
        .map_err(revocation_failure)?;

    let response = match outcome {
        DeviceRevocationTransactionOutcome::Replay(replay) => {
            context::replay_response(replay.response())
        }
        DeviceRevocationTransactionOutcome::First(mut first) => {
            let application = first
                .prepare_application(&mut transaction)
                .await
                .map_err(revocation_failure)?;
            let seal = application.apply().await.map_err(revocation_failure)?;
            let applied = first.finish(seal).map_err(revocation_failure)?;
            let completed = applied
                .complete(&mut transaction)
                .await
                .map_err(revocation_failure)?;
            let status = completed.status();
            context::canonical_json_response(ENDPOINT, status, completed.into_response_bytes())?
        }
    };

    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    Ok(response)
}

fn revocation_failure(error: DeviceRevocationFacadeError) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use DeviceRevocationFacadeError as E;

    match error {
        E::Database(_) | E::DeviceViewDatabase(_) => ChatFailure::storage(ENDPOINT),
        E::Prelude(error) => context::operation_prelude_failure(ENDPOINT, error),
        E::TargetMissing => ChatFailure::protocol(ENDPOINT, C::DeviceNotFound),
        E::TargetRevoked => ChatFailure::protocol(ENDPOINT, C::DeviceRevoked),
        E::AuthenticationGenerationConflict => {
            ChatFailure::protocol(ENDPOINT, C::AuthenticationGenerationConflict)
        }
        E::Conversation(
            crate::chat_protocol::repository::core::ConversationStateHydrationError::ReadSetMismatch,
        ) => ChatFailure::protocol(ENDPOINT, C::IdempotencyConflict),
        E::G6Prelude(_)
        | E::Conversation(_)
        | E::TargetProjection
        | E::StateMachine(_)
        | E::Execution(_)
        | E::Integrity => ChatFailure::invariant(ENDPOINT),
    }
}
