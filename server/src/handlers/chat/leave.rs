//! HTTP compositors for requestLeave, cancelLeave, and closeConversation.
//! Authentication and DPoP admission remain in `context`; this module owns
//! only the caller transaction and endpoint-specific error mapping.

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
            leave::{self, LeaveFacadeError},
            prelude,
        },
        state_machine::StateMachineError,
    },
    storage::DbPool,
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

pub(super) async fn handle_request(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    execute(&pool, &runtime, ChatEndpoint::RequestLeave, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

pub(super) async fn handle_cancellation(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    execute(&pool, &runtime, ChatEndpoint::CancelLeave, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

pub(super) async fn handle_close(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    execute(
        &pool,
        &runtime,
        ChatEndpoint::CloseConversation,
        &headers,
        &body,
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
}

async fn execute(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_signed_operation_only(pool, runtime, endpoint, headers, body).await?;
    let closing = match endpoint {
        ChatEndpoint::CloseConversation => closed_conversation_id(body),
        _ => None,
    };
    let c33_peer = match closing {
        Some(conversation_id) => {
            c33_peer_home(pool, endpoint, admission.subject(), conversation_id).await?
        }
        None => None,
    };
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let prepared = prelude::prepare_signed_operation(&mut tx, admission)
        .await
        .map_err(|error| {
            logged(
                endpoint,
                "prelude",
                error,
                context::operation_prelude_failure,
            )
        })?;
    // The wipe below debits the global direct-request budget: take it here,
    // after the operation lock and before the close's identity and head locks.
    if let Some(conversation_id) = closing {
        crate::chat_protocol::repository::close_terminal::lock_wipe_request_budget(
            &mut tx,
            conversation_id,
        )
        .await
        .map_err(|error| {
            tracing::error!(?error, %conversation_id, "close request budget lock failed");
            ChatFailure::storage(endpoint)
        })?;
    }
    // Boxed, like the relay's close future: inline, the transition's state would
    // size every await of this handler (and every caller holding it).
    let outcome = Box::pin(leave::execute_prepared_leave(&mut tx, prepared))
        .await
        .map_err(|error| logged(endpoint, "transition", error, map_failure))?;
    let response =
        context::canonical_json_response(endpoint, outcome.status, outcome.response_bytes.clone())?;
    let mut prepared_space = None;
    let mut prepared_group_fanout = None;
    if let Some(completion) = outcome.completion {
        let (authority, scope, guard) = completion.into_parts();
        prelude::complete_operation(
            &mut tx,
            &authority,
            scope,
            guard,
            outcome.status,
            &outcome.response_bytes,
            outcome.event_position,
        )
        .await
        .map_err(|error| {
            logged(
                endpoint,
                "completion",
                error,
                context::operation_prelude_failure,
            )
        })?;
        let resp_val: serde_json::Value = serde_json::from_slice(&outcome.response_bytes)
            .map_err(|_| ChatFailure::invariant(endpoint))?;
        // A C33 close goes, after the wipe, to the peer's transport-only home on
        // the stream a group close takes; its receiver verifies and wipes it.
        prepared_group_fanout = match &c33_peer {
            Some((peer, home)) => {
                crate::federation::group_fanout::prepare_c33_close_fanout(
                    &mut tx, &resp_val, peer, home,
                )
                .await
            }
            None => {
                crate::federation::group_fanout::prepare_group_entry_fanout(&mut tx, &resp_val)
                    .await
            }
        }
        .map_err(|e| {
            tracing::error!(error = %e, "leave/close group fanout preparation failed");
            ChatFailure::storage(endpoint)
        })?;
        if endpoint == ChatEndpoint::CloseConversation {
            let cid = resp_val
                .pointer("/result/entry/conversationId")
                .or_else(|| resp_val.pointer("/entry/conversationId"))
                .and_then(serde_json::Value::as_str)
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .ok_or_else(|| ChatFailure::invariant(endpoint))?;
            let gen = resp_val
                .pointer("/result/entry/signedRequest/body/prior/generation")
                .or_else(|| resp_val.pointer("/entry/generation"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let first_event = outcome
                .event_position
                .ok_or_else(|| ChatFailure::invariant(endpoint))?;
            let close_entry = resp_val
                .pointer("/result/entry")
                .ok_or_else(|| ChatFailure::invariant(endpoint))?;
            match close_entry
                .pointer("/signedRequest/body/conversationKind")
                .and_then(serde_json::Value::as_str)
            {
                Some("group") => {
                    if let Some(fanout) = prepared_group_fanout.as_mut() {
                        let signer = runtime.i13_receipt_signer().ok_or_else(|| {
                            tracing::error!(
                                "group close fanout requires the dedicated I13 receipt signer"
                            );
                            ChatFailure::storage(endpoint)
                        })?;
                        crate::federation::group_fanout::attach_close_authority(
                            &mut tx,
                            fanout,
                            close_entry,
                            signer,
                        )
                        .await
                        .map_err(|error| {
                            tracing::error!(%error, conversation_id = %cid, "group close authority preparation failed");
                            ChatFailure::storage(endpoint)
                        })?;
                    }
                }
                Some("direct") => {}
                _ => return Err(ChatFailure::invariant(endpoint)),
            }
            crate::chat_protocol::repository::close_terminal::attach_local_close_entry(
                &mut tx,
                cid,
                first_event,
                close_entry,
            )
            .await
            .map_err(|error| {
                tracing::error!(?error, conversation_id = %cid, "close terminal entry attach failed");
                ChatFailure::storage(endpoint)
            })?;
            prepared_space =
                crate::space_host::revocation_fanout::prepare_space_deleted_fanout_in_tx(
                    &mut tx, cid, gen,
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "prepare_space_deleted_fanout_in_tx failed");
                    ChatFailure::storage(endpoint)
                })?;
            // Fire the close's pending deferred graph checks while that graph
            // is complete; rows deleted by the wipe queue none (migration
            // 20261102000003), so it can then run with deferred foreign keys.
            for statement in [
                "SET CONSTRAINTS ALL IMMEDIATE",
                "SET CONSTRAINTS ALL DEFERRED",
            ] {
                sqlx::query(statement)
                    .execute(&mut *tx)
                    .await
                    .map_err(|error| {
                        tracing::error!(?error, conversation_id = %cid, "close graph validation failed");
                        ChatFailure::storage(endpoint)
                    })?;
            }
            // O7: the wipe removes the application entries; their `sendMessage`
            // receipts lose the same ciphertext in this transaction.
            crate::chat_protocol::repository::delivery::erase_idempotency_payloads(
                &mut tx,
                crate::chat_protocol::repository::delivery::ReceiptErasure::Entries {
                    conversation_id: cid,
                    seq: None,
                },
                crate::sim_hooks::current_utc(),
            )
            .await
            .map_err(|error| {
                tracing::error!(?error, conversation_id = %cid, "close receipt erasure failed");
                ChatFailure::storage(endpoint)
            })?;
            let wiped: bool =
                sqlx::query_scalar("SELECT chat.wipe_closed_conversation_operational_rows($1)")
                    .bind(cid)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|error| {
                        tracing::error!(
                            ?error,
                            conversation_id = %cid,
                            "wipe_closed_conversation_operational_rows failed"
                        );
                        ChatFailure::storage(endpoint)
                    })?;
            if !wiped {
                return Err(ChatFailure::invariant(endpoint));
            }
            // The wipe emptied this conversation's queue; the close goes last.
            if let Some(fanout) = prepared_group_fanout.as_ref() {
                fanout.enqueue(&mut tx).await.map_err(|error| {
                    tracing::error!(%error, conversation_id = %cid, "close fanout enqueue failed");
                    ChatFailure::storage(endpoint)
                })?;
            }
        }
    }
    tx.commit().await.map_err(|error| {
        tracing::error!(
            ?error,
            endpoint = endpoint.nsid(),
            "leave/close commit failed"
        );
        ChatFailure::storage(endpoint)
    })?;
    if let Some(fanout) = prepared_group_fanout {
        runtime.spawn_post_commit_group_entry_fanout(pool, fanout);
    }
    if endpoint == ChatEndpoint::RequestLeave {
        runtime.spawn_post_commit_membership_transition(pool, &outcome.response_bytes);
    }
    runtime.spawn_post_commit_close_conversation(
        pool,
        endpoint,
        &outcome.response_bytes,
        prepared_space,
    );
    runtime.notify_events();
    Ok(response)
}

/// The conversation a signed close names (`prior.conversationId`).
fn closed_conversation_id(body: &[u8]) -> Option<uuid::Uuid> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .pointer("/signedRequest/body/prior/conversationId")?
        .as_str()?
        .parse()
        .ok()
}

/// The peer and its transport-only home when `actor` closes a direct pair this
/// DS coordinates (C33), resolved from the peer's declaration before the close's
/// transaction (M-F04); `None` where the peer is homed here, declares no home,
/// or is itself deleted in the pair. This DS's own store failing, or a source
/// that could not answer now, refuses the close rather than strand that home's
/// copies: a storage failure, or the retryable `CapacityUnavailable`.
async fn c33_peer_home(
    pool: &DbPool,
    endpoint: ChatEndpoint,
    actor: &str,
    conversation_id: uuid::Uuid,
) -> Result<Option<(String, String)>, ChatFailure> {
    let peer: Option<String> = sqlx::query_scalar(
        "SELECT CASE WHEN direct_did_low = $2 THEN direct_did_high ELSE direct_did_low END \
           FROM chat.conversations \
          WHERE conversation_id = $1 AND kind = 'direct' AND NOT is_remote \
            AND lifecycle = 'active' AND $2 IN (direct_did_low, direct_did_high)",
    )
    .bind(conversation_id)
    .bind(actor)
    .fetch_optional(pool)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;
    let Some(peer) = peer else {
        return Ok(None);
    };
    match crate::federation::group_relay::C33PeerHomes::peer_home(pool, conversation_id, &peer)
        .await
    {
        Ok(home) => Ok(home.map(|home| (peer, home))),
        // Matched first: `FederationError::is_retryable` holds for `Database`.
        Err(
            error @ (crate::federation::FederationError::Database(_)
            | crate::federation::FederationError::Storage(_)),
        ) => {
            tracing::error!(%error, %conversation_id, "closeConversation refused: this DS's store failed resolving the C33 peer's home");
            Err(ChatFailure::storage(endpoint))
        }
        Err(error) if error.is_retryable() => {
            tracing::warn!(%error, %conversation_id, "closeConversation refused: the C33 peer's home did not resolve");
            Err(ChatFailure::unavailable(endpoint))
        }
        // ponytail: a permanently unresolvable home cannot be addressed; the
        // close proceeds and that home keeps its copies until its own expiry.
        Err(error) => {
            tracing::warn!(%error, %conversation_id, "C33 peer home is unresolvable; its close is owed nowhere");
            Ok(None)
        }
    }
}

/// Map `error`, logging its cause when no protocol code reaches the wire.
fn logged<E: std::fmt::Debug>(
    endpoint: ChatEndpoint,
    step: &'static str,
    error: E,
    map: impl FnOnce(ChatEndpoint, E) -> ChatFailure,
) -> ChatFailure {
    let detail = format!("{error:?}");
    let failure = map(endpoint, error);
    if failure.code().is_none() {
        tracing::error!(endpoint = endpoint.nsid(), step, error = %detail, "leave/close internal failure");
    }
    failure
}

fn map_failure(endpoint: ChatEndpoint, error: LeaveFacadeError) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use LeaveFacadeError as E;
    use StateMachineError as S;
    match error {
        E::Retention(crate::chat_protocol::repository::direct_request_retention::RetentionError::Database(_)) => ChatFailure::storage(endpoint),
        E::Retention(_) => ChatFailure::protocol_with_retry(endpoint,C::CapacityUnavailable,Some(30)),
        E::Database(_) | E::Authorization(_) => ChatFailure::storage(endpoint),
        E::IdempotencyKeyMismatch => ChatFailure::protocol(endpoint, C::InvalidRequest),
        E::Prelude(error) => context::operation_prelude_failure(endpoint, error),
        E::Conversation(error) => match error {
            crate::chat_protocol::repository::core::ConversationStateHydrationError::Database(_) => {
                ChatFailure::storage(endpoint)
            }
            crate::chat_protocol::repository::core::ConversationStateHydrationError::ReadSetMismatch => {
                ChatFailure::protocol(endpoint, C::StaleCoordinates)
            }
            _ => ChatFailure::protocol(endpoint, C::ConversationNotFound),
        },
        E::Transition(crate::chat_protocol::repository::transition::TransitionRepositoryError::Database(_))
        | E::ExecutionContext(crate::chat_protocol::repository::execution_context::ExecutionContextHydrationError::Database(_))
        | E::Executor(crate::chat_protocol::state_machine::ExecutorError::Transition(crate::chat_protocol::repository::transition::TransitionRepositoryError::Database(_))) => ChatFailure::storage(endpoint),
        E::Transition(crate::chat_protocol::repository::transition::TransitionRepositoryError::CompareAndSetConflict)
        | E::Executor(crate::chat_protocol::state_machine::ExecutorError::Transition(crate::chat_protocol::repository::transition::TransitionRepositoryError::CompareAndSetConflict))
        | E::StateMachine(S::StaleCoordinates)
        | E::StateMachine(S::ConversationClosed) => ChatFailure::protocol(endpoint, C::StaleCoordinates),
        E::StateMachine(S::CoordinateOverflow) => ChatFailure::protocol(endpoint, C::CoordinateOverflow),
        E::StateMachine(S::DirectParticipantMutationForbidden) => ChatFailure::protocol(endpoint, C::DirectParticipantMutationForbidden),
        E::StateMachine(S::LastAdminRequired) => ChatFailure::protocol(endpoint, C::LastAdminRequired),
        E::StateMachine(S::NotMember) => {
            if endpoint == ChatEndpoint::RequestLeave { ChatFailure::protocol(endpoint, C::NotMember) }
            else { ChatFailure::protocol(endpoint, C::NotAuthorized) }
        }
        E::StateMachine(S::NotParticipant) => {
            if endpoint == ChatEndpoint::CloseConversation { ChatFailure::protocol(endpoint, C::NotParticipant) }
            else { ChatFailure::protocol(endpoint, C::NotAuthorized) }
        }
        E::StateMachine(S::ConversationCloseNotAllowed) => ChatFailure::protocol(endpoint, C::ConversationCloseNotAllowed),
        E::StateMachine(S::LeaveAlreadyPending) => ChatFailure::protocol(endpoint, C::LeaveAlreadyPending),
        E::StateMachine(S::LeaveRequestNotFound) => ChatFailure::protocol(endpoint, C::LeaveRequestNotFound),
        E::StateMachine(S::WorkExpired) => {
            if endpoint == ChatEndpoint::CancelLeave { ChatFailure::protocol(endpoint, C::CancellationConflict) }
            else { ChatFailure::protocol(endpoint, C::LeaveRequestExpired) }
        }
        E::MissingMutation | E::UnsupportedMutation | E::InvalidCanonicalMaterial
        | E::ExecutionContext(_) | E::Transition(_) | E::Executor(_) | E::StateMachine(_) => ChatFailure::invariant(endpoint),
    }
}
