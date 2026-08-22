//! `blue.catbird.chat.sendMessage` clean procedure.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};
use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::{
            message_delivery::{self, MessageDeliveryError},
            prelude::{self, PreparedChatAdmission},
        },
    },
    storage::DbPool,
};

const ENDPOINT: ChatEndpoint = ChatEndpoint::SendMessage;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    send(&pool, &runtime, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn send(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_signed_operation_only(pool, runtime, ENDPOINT, headers, body).await?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let prepared = prelude::prepare_chat_admission(&mut tx, admission)
        .await
        .map_err(|e| context::operation_prelude_failure(ENDPOINT, e))?;
    match prepared {
        PreparedChatAdmission::Replay(replay) => {
            let response = context::replay_response(&replay);
            tx.commit()
                .await
                .map_err(|_| ChatFailure::storage(ENDPOINT))?;
            Ok(response)
        }
        PreparedChatAdmission::First(first) => {
            let (authority, scope, completion) = first.into_execution_parts();
            let (response_bytes, event_position) = message_delivery::send(
                &mut tx,
                &authority,
                &scope,
                runtime.relationship_authority().as_ref(),
            )
            .await
            .map_err(|e| {
                tracing::error!("message_delivery::send error: {:?}", e);
                map_failure(e)
            })?;
            prelude::complete_operation(
                &mut tx,
                &authority,
                scope,
                completion,
                200,
                &response_bytes,
                event_position,
            )
            .await
            .map_err(|e| {
                tracing::error!("complete_operation error: {:?}", e);
                context::operation_prelude_failure(ENDPOINT, e)
            })?;
            tx.commit()
                .await
                .map_err(|e| {
                    tracing::error!("tx.commit error: {:?}", e);
                    ChatFailure::storage(ENDPOINT)
                })?;
            context::canonical_json_response(ENDPOINT, 200, response_bytes)
        }
    }
}

fn map_failure(error: MessageDeliveryError) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    match &error {
        MessageDeliveryError::Database(e) => {
            tracing::error!("MessageDeliveryError::Database: {:?}", e);
            ChatFailure::storage(ENDPOINT)
        }
        MessageDeliveryError::InvalidApplicationMessage => {
            ChatFailure::protocol(ENDPOINT, C::InvalidApplicationMessage)
        }
        MessageDeliveryError::InvalidCoordinates => {
            ChatFailure::protocol(ENDPOINT, C::StaleCoordinates)
        }
        MessageDeliveryError::ConversationNotFound => {
            ChatFailure::protocol(ENDPOINT, C::ConversationNotFound)
        }
        MessageDeliveryError::ConversationNotAccepted => {
            ChatFailure::protocol(ENDPOINT, C::ConversationNotAccepted)
        }
        MessageDeliveryError::DeviceNotLeaf => ChatFailure::protocol(ENDPOINT, C::DeviceNotLeaf),
        MessageDeliveryError::RecipientNotReady => {
            ChatFailure::protocol(ENDPOINT, C::RecipientNotReady)
        }
        MessageDeliveryError::RelationshipPolicyUnavailable => {
            ChatFailure::protocol(ENDPOINT, C::RelationshipPolicyUnavailable)
        }
        MessageDeliveryError::BlockedRelationship => {
            ChatFailure::protocol(ENDPOINT, C::BlockedRelationship)
        }
        MessageDeliveryError::BlobNotFound => ChatFailure::protocol(ENDPOINT, C::BlobNotFound),
        MessageDeliveryError::BlobBindingConflict => {
            ChatFailure::protocol(ENDPOINT, C::BlobBindingConflict)
        }
        MessageDeliveryError::IdempotencyConflict => {
            ChatFailure::protocol(ENDPOINT, C::IdempotencyConflict)
        }
        MessageDeliveryError::RateLimited | MessageDeliveryError::Invariant => {
            ChatFailure::invariant(ENDPOINT)
        }
    }
}
