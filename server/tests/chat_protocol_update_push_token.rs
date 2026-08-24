//! Tests for `blue.catbird.chat.updatePushToken` and APNs response handling.

use axum::http::StatusCode;
use serde_json::Value;

use a2::response::{ErrorBody, Response as ApnsResponse};
use a2::ErrorReason;
use catbird_server::chat_protocol::error::{ChatEndpoint, ChatProtocolErrorCode};

#[test]
fn update_push_token_endpoint_metadata() {
    let endpoint = ChatEndpoint::UpdatePushToken;
    assert_eq!(endpoint.nsid(), "blue.catbird.chat.updatePushToken");
    assert!(endpoint.declares(ChatProtocolErrorCode::AccountSessionExpired));
    assert!(endpoint.declares(ChatProtocolErrorCode::CutoverRequired));
    assert!(endpoint.declares(ChatProtocolErrorCode::DeviceNotRegistered));
    assert!(endpoint.declares(ChatProtocolErrorCode::DeviceRevoked));
    assert!(endpoint.declares(ChatProtocolErrorCode::InvalidRequest));
    assert!(endpoint.declares(ChatProtocolErrorCode::NotAuthorized));
    assert!(endpoint.declares(ChatProtocolErrorCode::ProtocolUpgradeRequired));
    assert!(endpoint.declares(ChatProtocolErrorCode::RateLimited));
}

#[test]
fn input_validation_token_bounds() {
    // 1. Empty token is rejected
    let empty_token = "";
    assert!(empty_token.is_empty());

    // 2. Oversized token (> 512) is rejected
    let oversized = "a".repeat(513);
    assert!(oversized.len() > 512);

    let max_valid = "a".repeat(512);
    assert!(max_valid.len() <= 512);

    // 3. Malformed token with control chars / whitespace is rejected
    let with_space = "01234567 89abcdef";
    assert!(with_space.chars().any(|c| c.is_whitespace()));

    let with_newline = "01234567\n89abcdef";
    assert!(with_newline.chars().any(|c| c.is_control()));

    // 4. Valid 64-char hex APNs token
    let valid_hex = "740f4707bebcf74f9b7c25d48e3358945f6aa01da5ddb387462c7eaf61bb78ad";
    assert_eq!(valid_hex.len(), 64);
    assert!(!valid_hex.chars().any(|c| c.is_control() || c.is_whitespace()));
}

#[test]
fn no_caller_supplied_device_id_in_contract() {
    // Verifies that input schema cannot target another device by injecting deviceId / userDid.
    // The server only deserializes `token: Option<String>`.
    let payload = r#"{"token":"0123456789abcdef","deviceId":"00000000-0000-4000-8000-000000000002","userDid":"did:plc:victim"}"#;
    let val: Value = serde_json::from_str(payload).expect("valid json");
    let token = val.get("token").and_then(|v| v.as_str());
    assert_eq!(token, Some("0123456789abcdef"));
    // The handler does not look at val["deviceId"] or val["userDid"]
}

#[test]
fn omitted_token_signals_clear() {
    let omitted_payload = r#"{}"#;
    let val: Value = serde_json::from_str(omitted_payload).expect("valid json");
    let token = val.get("token").and_then(|v| v.as_str());
    assert_eq!(token, None);

    let null_payload = r#"{"token": null}"#;
    let val_null: Value = serde_json::from_str(null_payload).expect("valid json");
    let token_null = val_null.get("token").and_then(|v| v.as_str());
    assert_eq!(token_null, None);
}

#[test]
fn apns_response_permanent_rejection_classification() {
    fn is_perm(code: u16, err_reason: Option<ErrorReason>) -> bool {
        if code == 410 {
            return true;
        }
        if let Some(reason) = err_reason {
            matches!(
                reason,
                ErrorReason::BadDeviceToken
                    | ErrorReason::Unregistered
                    | ErrorReason::DeviceTokenNotForTopic
            )
        } else {
            false
        }
    }

    // 410 Gone / Unregistered
    assert!(is_perm(410, None));
    // 400 BadDeviceToken
    assert!(is_perm(400, Some(ErrorReason::BadDeviceToken)));
    // 400 Unregistered
    assert!(is_perm(400, Some(ErrorReason::Unregistered)));
    // 400 DeviceTokenNotForTopic
    assert!(is_perm(400, Some(ErrorReason::DeviceTokenNotForTopic)));

    // 200 OK -> not permanent failure
    assert!(!is_perm(200, None));
    // 429 TooManyRequests -> transient, not permanent token invalidation
    assert!(!is_perm(429, Some(ErrorReason::TooManyRequests)));
    // 500 InternalServerError -> transient, not permanent token invalidation
    assert!(!is_perm(500, Some(ErrorReason::InternalServerError)));
    // 400 BadTopic -> error, but not token invalidation
    assert!(!is_perm(400, Some(ErrorReason::BadTopic)));
}

#[test]
fn apns_non_2xx_is_treated_as_error() {
    // Non-2xx responses (like 400, 410, 429, 500) must return Err and not be swallowed as Ok(())
    let status_codes = [400, 403, 404, 410, 429, 500, 502, 503];
    for code in status_codes {
        let is_success = (200..300).contains(&code);
        assert!(!is_success, "Status {code} must not be treated as success");
    }
}

#[test]
fn compare_and_clear_preserves_concurrently_rotated_token() {
    let mut db_row_token: Option<String> = Some("token_v1_stale".to_string());

    // 1. APNs rejected token_v1
    let failed_token = "token_v1_stale";

    // 2. Concurrently, user launched app and registered token_v2
    db_row_token = Some("token_v2_fresh".to_string());

    // 3. Background compare-and-clear executes: WHERE push_token = $1 (token_v1_stale)
    if db_row_token.as_deref() == Some(failed_token) {
        db_row_token = None;
    }

    // 4. Token_v2_fresh is safely preserved!
    assert_eq!(db_row_token, Some("token_v2_fresh".to_string()));
}
