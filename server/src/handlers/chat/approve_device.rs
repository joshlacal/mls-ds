//! `blue.catbird.chat.approveDevice` — cross-device enrollment approval (`D-2`).

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
            device_approval::{self, DeviceApprovalFacadeError, DeviceApprovalTransactionOutcome},
            prelude,
        },
    },
    storage::DbPool,
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

const ENDPOINT: ChatEndpoint = ChatEndpoint::ApproveDevice;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    approve(&pool, &runtime, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn approve(
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
    let outcome = device_approval::execute_device_approval(&mut transaction, prepared)
        .await
        .map_err(approval_failure)?;

    let response = match outcome {
        DeviceApprovalTransactionOutcome::Replay(replay) => {
            context::replay_response(ENDPOINT, &replay)?
        }
        DeviceApprovalTransactionOutcome::First {
            target_did: _,
            target_device_id: _,
            status,
            response_bytes,
        } => context::canonical_json_response(ENDPOINT, status, response_bytes)?,
    };

    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    runtime.notify_events();
    Ok(response)
}

fn approval_failure(error: DeviceApprovalFacadeError) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use DeviceApprovalFacadeError as E;

    match error {
        E::Database(_) => ChatFailure::storage(ENDPOINT),
        E::Prelude(error) => context::operation_prelude_failure(ENDPOINT, error),
        E::SelfApproval | E::TargetBindingMismatch => {
            ChatFailure::protocol(ENDPOINT, C::InvalidRequest)
        }
        E::TargetMissing => ChatFailure::protocol(ENDPOINT, C::DeviceNotFound),
        E::TargetAlreadyActive => ChatFailure::protocol(ENDPOINT, C::DeviceAlreadyActive),
        E::TargetRevoked => ChatFailure::protocol(ENDPOINT, C::DeviceRevoked),
        E::AuthenticationGenerationConflict => {
            ChatFailure::protocol(ENDPOINT, C::AuthenticationGenerationConflict)
        }
        E::Integrity => ChatFailure::invariant(ENDPOINT),
    }
}
