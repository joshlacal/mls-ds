//! Single-transaction request publication transport. A success response is only
//! constructed after commit; no separate creation, Add or send endpoint runs.
use super::{context, errors::ChatFailure, runtime::ChatRuntime};
use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::direct_request_publication::{self, PublicationError, PublicationPreparation},
        validation::TrustedRequestInstant,
    },
    storage::DbPool,
};
use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    inner(&pool, &runtime, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}
async fn inner(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let endpoint = ChatEndpoint::PublishDirectRequest;
    context::require_cutover(runtime, endpoint)?;
    let signer = runtime
        .request_receipt_signer()
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::CutoverRequired))?;
    let principal = context::verify_service_principal(pool, endpoint, headers).await?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope<'a> {
        #[serde(rename = "signedRequest", borrow)]
        signed_request: &'a serde_json::value::RawValue,
    }
    let envelope: Envelope = serde_json::from_slice(body)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    let now = TrustedRequestInstant::capture()
        .map_err(|_| ChatFailure::invariant(endpoint))?
        .datetime();
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let prepared = direct_request_publication::prepare_publication(
        &mut tx,
        &principal,
        envelope.signed_request.get().as_bytes(),
        signer,
        runtime.relationship_authority().as_ref(),
        now,
        runtime.request_producers_enabled(),
    )
    .await
    .map_err(failure)?;
    let bytes = match prepared {
        PublicationPreparation::Terminal(bytes) => bytes,
        PublicationPreparation::Ready(prepared) => direct_request_publication::execute_publication(
            &mut tx,
            *prepared,
            signer,
            runtime.relationship_authority().as_ref(),
        )
        .await
        .map_err(failure)?,
    };
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ChatFailure::invariant(endpoint))?;
    receipt["$type"] = serde_json::json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
    let response = serde_json::to_vec(&serde_json::json!({"outcome":receipt}))
        .map_err(|_| ChatFailure::invariant(endpoint))?;
    tx.commit().await.map_err(|error| {
        trace_database_failure("commit", &error);
        ChatFailure::storage(endpoint)
    })?;
    Ok(context::json_ok(response))
}
fn failure(error: PublicationError) -> ChatFailure {
    use crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError as E;
    let endpoint = ChatEndpoint::PublishDirectRequest;
    match error {
        PublicationError::Disabled => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::CutoverRequired)
        }
        PublicationError::Database(error) | PublicationError::Store(E::Database(error)) => {
            trace_database_failure("prepare_or_execute", &error);
            ChatFailure::storage(endpoint)
        }
        PublicationError::Store(E::InvalidSignature) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidSignature)
        }
        PublicationError::Store(E::IdentityConflict) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::PreparationConflict)
        }
        PublicationError::Store(E::Expired) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::PreparationExpired)
        }
        PublicationError::Store(E::IncludedAuthorityChanged) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::PreparationRevoked)
        }
        PublicationError::Store(E::PolicyDenied) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::RequestPolicyDenied)
        }
        PublicationError::Store(E::QuotaExceeded) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::CapacityUnavailable)
        }
        PublicationError::Store(E::RecipientKeysUnavailable) => {
            ChatFailure::protocol(endpoint, ChatProtocolErrorCode::RecipientKeysUnavailable)
        }
        _ => ChatFailure::invariant(endpoint),
    }
}

fn trace_database_failure(stage: &'static str, error: &sqlx::Error) {
    use sha2::{Digest, Sha256};
    // Database messages/details can interpolate a rejected row's contents.
    // A fingerprint identifies static migration exceptions without logging
    // signed envelopes, ciphertext, registration tokens, or SQL parameters.
    let database = error.as_database_error();
    tracing::error!(
        stage,
        code = database
            .and_then(|error| error.code())
            .as_deref()
            .unwrap_or("non_database"),
        constraint = database
            .and_then(|error| error.constraint())
            .unwrap_or("none"),
        message_fingerprint = database
            .map(|error| format!("{:x}", Sha256::digest(error.message().as_bytes())))
            .as_deref()
            .unwrap_or("none"),
        "encrypted request publication transaction failed"
    );
}

#[cfg(test)]
mod signature_error_tests {
    use super::*;
    use crate::chat_protocol::repository::direct_request_preparation::DirectRequestStoreError;

    #[tokio::test]
    async fn invalid_publication_signature_uses_declared_public_error() {
        let failure = failure(PublicationError::Store(
            DirectRequestStoreError::InvalidSignature,
        ));
        assert_eq!(
            failure.code(),
            Some(ChatProtocolErrorCode::InvalidSignature)
        );
        let response = failure.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"error":"InvalidSignature", "message":"InvalidSignature"})
        );
    }
}
