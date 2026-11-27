//! `blue.catbird.chat.publishTyping` clean ephemeral procedure.

use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use super::{context, errors::ChatFailure, runtime::ChatRuntime};
use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::{
            message_delivery::{self, MessageDeliveryError},
            prelude::{self},
        },
    },
    storage::DbPool,
};

const ENDPOINT: ChatEndpoint = ChatEndpoint::PublishTyping;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    publish(&pool, &runtime, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn publish(
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
    let prepared = prelude::prepare_typing_admission(&mut tx, admission)
        .await
        .map_err(|e| context::operation_prelude_failure(ENDPOINT, e))?;
    let (authority, scope) = prepared.into_execution_parts();
    let response_bytes = message_delivery::typing(
        &mut tx,
        &authority,
        &scope,
        runtime.relationship_authority().as_ref(),
    )
    .await
    .map_err(map_failure)?;
    let response_value: serde_json::Value =
        serde_json::from_slice(&response_bytes).map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let event = response_value
        .get("typing")
        .cloned()
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let roundtrip: crate::blue_catbird::chat::publish_typing::Output =
        serde_json::from_value(response_value.clone())
            .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let _ = serde_json::to_value(roundtrip).map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    tx.rollback()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    runtime.publish_typing(event).await;
    context::canonical_json_response(ENDPOINT, 200, response_bytes)
}

fn map_failure(error: MessageDeliveryError) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    match error {
        MessageDeliveryError::Database(_) => ChatFailure::storage(ENDPOINT),
        MessageDeliveryError::InvalidCoordinates => {
            ChatFailure::protocol(ENDPOINT, C::StaleCoordinates)
        }
        MessageDeliveryError::DeviceNotLeaf => ChatFailure::protocol(ENDPOINT, C::DeviceNotLeaf),
        MessageDeliveryError::RecipientNotReady => {
            ChatFailure::protocol(ENDPOINT, C::RecipientNotReady)
        }
        MessageDeliveryError::RelationshipPolicyUnavailable => {
            ChatFailure::protocol(ENDPOINT, C::RelationshipPolicyUnavailable)
        }
        MessageDeliveryError::RelationshipSourceUnavailable => ChatFailure::unavailable(ENDPOINT),
        MessageDeliveryError::BlockedRelationship => {
            ChatFailure::protocol(ENDPOINT, C::BlockedRelationship)
        }
        MessageDeliveryError::RateLimited => ChatFailure::protocol(ENDPOINT, C::RateLimited),
        MessageDeliveryError::ConversationNotFound => {
            ChatFailure::protocol(ENDPOINT, C::ConversationNotFound)
        }
        MessageDeliveryError::ConversationNotAccepted => {
            ChatFailure::protocol(ENDPOINT, C::ConversationNotAccepted)
        }
        MessageDeliveryError::NotAuthorized => ChatFailure::protocol(ENDPOINT, C::NotAuthorized),
        MessageDeliveryError::IdempotencyConflict => {
            ChatFailure::protocol(ENDPOINT, C::IdempotencyConflict)
        }
        MessageDeliveryError::InvalidApplicationMessage
        | MessageDeliveryError::BlobNotFound
        | MessageDeliveryError::BlobBindingConflict
        | MessageDeliveryError::StaleSend
        | MessageDeliveryError::Invariant => ChatFailure::invariant(ENDPOINT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A typing check whose relationship source could not answer now is the
    /// declared retryable answer (503, `Retry-After: 5`).
    #[test]
    fn relationship_source_unavailable_is_retryable() {
        let failure = map_failure(MessageDeliveryError::RelationshipSourceUnavailable);
        assert_eq!(
            failure.code(),
            Some(ChatProtocolErrorCode::RelationshipPolicyUnavailable)
        );
        let response = failure.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .unwrap(),
            "5"
        );
    }
}
