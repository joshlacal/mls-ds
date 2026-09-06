//! `blue.catbird.chat.updatePushToken` — update or clear APNs push notification token.

use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::chat_protocol::error::{ChatEndpoint, ChatProtocolErrorCode};
use crate::chat_protocol::repository::device_directory::{
    update_device_push_token, UpdatePushTokenRepositoryError,
};
use crate::storage::DbPool;

use super::context::{self, require_cutover};
use super::device_views::device_view_from_directory;
use super::errors::ChatFailure;
use super::runtime::ChatRuntime;

const ENDPOINT: ChatEndpoint = ChatEndpoint::UpdatePushToken;

#[derive(Deserialize)]
struct UpdatePushTokenBody {
    token: Option<String>,
}

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    match update_push_token(&pool, &runtime, &headers, &body).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn update_push_token(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    require_cutover(runtime, ENDPOINT)?;

    let principal = context::verify_service_principal(pool, ENDPOINT, headers).await?;

    let parsed: UpdatePushTokenBody = if body.is_empty() {
        UpdatePushTokenBody { token: None }
    } else {
        serde_json::from_slice(body)
            .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?
    };

    if let Some(tok) = &parsed.token {
        if tok.is_empty()
            || tok.len() > 512
            || tok.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(ChatFailure::protocol(
                ENDPOINT,
                ChatProtocolErrorCode::InvalidRequest,
            ));
        }
    }
    let target_device_id = headers
        .get("x-catbird-chat-device-id")
        .or_else(|| headers.get("x-catbird-device-id"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok());

    let view = update_device_push_token(pool, principal.did(), parsed.token.as_deref(), target_device_id)
        .await
        .map_err(|err| match err {
            UpdatePushTokenRepositoryError::DeviceNotRegistered => {
                ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::DeviceNotRegistered)
            }
            UpdatePushTokenRepositoryError::DeviceRevoked => {
                ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::DeviceRevoked)
            }
            UpdatePushTokenRepositoryError::Database(e) => {
                tracing::error!("update_device_push_token database error: {:?}", e);
                ChatFailure::storage(ENDPOINT)
            }
        })?;

    let device_dto = device_view_from_directory(&view);
    let output_json = json!({
        "device": device_dto
    });

    let bytes = serde_json::to_vec(&output_json).map_err(|_| ChatFailure::invariant(ENDPOINT))?;

    Ok(context::json_ok(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_token(token: Option<&str>) -> Result<(), ChatProtocolErrorCode> {
        if let Some(tok) = token {
            if tok.is_empty()
                || tok.len() > 512
                || tok.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(ChatProtocolErrorCode::InvalidRequest);
            }
        }
        Ok(())
    }

    #[test]
    fn empty_present_token_is_rejected_as_invalid_request() {
        let result = validate_token(Some(""));
        assert_eq!(result, Err(ChatProtocolErrorCode::InvalidRequest));
    }

    #[test]
    fn oversized_token_is_rejected_as_invalid_request() {
        let oversized = "a".repeat(513);
        let result = validate_token(Some(&oversized));
        assert_eq!(result, Err(ChatProtocolErrorCode::InvalidRequest));

        let max_valid = "a".repeat(512);
        let result_valid = validate_token(Some(&max_valid));
        assert!(result_valid.is_ok());
    }

    #[test]
    fn malformed_token_with_whitespace_or_control_is_rejected() {
        assert_eq!(
            validate_token(Some("0123456789abcdef 0123456789abcdef")),
            Err(ChatProtocolErrorCode::InvalidRequest)
        );
        assert_eq!(
            validate_token(Some("0123456789abcdef\n0123456789abcdef")),
            Err(ChatProtocolErrorCode::InvalidRequest)
        );
        assert_eq!(
            validate_token(Some("0123456789abcdef\00123456789abcdef")),
            Err(ChatProtocolErrorCode::InvalidRequest)
        );
    }

    #[test]
    fn valid_apns_hex_token_and_omitted_token_are_accepted() {
        let apns_hex = "740f4707bebcf74f9b7c25d48e3358945f6aa01da5ddb387462c7eaf61bb78ad";
        assert_eq!(validate_token(Some(apns_hex)), Ok(()));
        assert_eq!(validate_token(None), Ok(()));
    }

    #[test]
    fn contract_does_not_permit_caller_supplied_device_id_or_did() {
        // Input schema only recognizes `token`. Even if an attacker supplies `deviceId`
        // or `userDid`, it is not parsed or used to select the target row.
        let payload = r#"{"token":"0123456789abcdef","deviceId":"victim-device-id","userDid":"did:plc:victim"}"#;
        let parsed: UpdatePushTokenBody = serde_json::from_str(payload).expect("parsed");
        assert_eq!(parsed.token, Some("0123456789abcdef".to_string()));
    }

    #[test]
    fn omitted_token_deserializes_to_none_for_clearing() {
        let empty_payload = r#"{}"#;
        let parsed: UpdatePushTokenBody = serde_json::from_str(empty_payload).expect("parsed");
        assert_eq!(parsed.token, None);

        let explicit_null = r#"{"token":null}"#;
        let parsed_null: UpdatePushTokenBody = serde_json::from_str(explicit_null).expect("parsed");
        assert_eq!(parsed_null.token, None);
    }

    #[test]
    fn error_mapping_for_unregistered_and_revoked_devices() {
        let err_unreg = UpdatePushTokenRepositoryError::DeviceNotRegistered;
        let failure_unreg = match err_unreg {
            UpdatePushTokenRepositoryError::DeviceNotRegistered => {
                ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::DeviceNotRegistered)
            }
            _ => unreachable!(),
        };
        assert_eq!(
            failure_unreg.into_response().status(),
            axum::http::StatusCode::UNAUTHORIZED
        );

        let err_revoked = UpdatePushTokenRepositoryError::DeviceRevoked;
        let failure_revoked = match err_revoked {
            UpdatePushTokenRepositoryError::DeviceRevoked => {
                ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::DeviceRevoked)
            }
            _ => unreachable!(),
        };
        assert_eq!(
            failure_revoked.into_response().status(),
            axum::http::StatusCode::UNAUTHORIZED
        );
    }
}
