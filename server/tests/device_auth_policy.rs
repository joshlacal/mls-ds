use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use catbird_server::{
    auth::device_auth::VerifiedDeviceRequest,
    config::{DeviceAuthMode, DeviceAuthPolicyAction},
    metrics::DeviceAuthPolicyMetricOutcome,
    middleware::device_auth::{
        device_auth_policy_action, single_dpop_header, DeviceAuthPolicyRejection,
    },
};

#[test]
fn rollout_matrix_is_closed_and_unknown_mls_chat_nsids_deny() {
    use DeviceAuthMode::{Enroll, Observe, Require};
    use DeviceAuthPolicyAction::{Allow, EnforceEnrollment, ObserveWouldDeny, RequireBinding};

    for mode in [Observe, Enroll, Require] {
        assert_eq!(
            device_auth_policy_action(mode, "blue.catbird.mlsChat.beginDeviceAuthBinding"),
            Ok(EnforceEnrollment)
        );
        assert_eq!(
            device_auth_policy_action(mode, "blue.catbird.mlsChat.registerDevice"),
            Ok(Allow)
        );
        assert_eq!(
            device_auth_policy_action(mode, "blue.catbird.mlsChat.getConvos"),
            Ok(Allow)
        );
    }

    assert_eq!(
        device_auth_policy_action(Observe, "blue.catbird.mlsChat.updateCursor"),
        Ok(ObserveWouldDeny)
    );
    assert_eq!(
        device_auth_policy_action(Observe, "blue.catbird.mlsChat.commitGroupChange"),
        Ok(ObserveWouldDeny)
    );
    assert_eq!(
        device_auth_policy_action(Enroll, "blue.catbird.mlsChat.updateCursor"),
        Ok(RequireBinding)
    );
    assert_eq!(
        device_auth_policy_action(Enroll, "blue.catbird.mlsChat.commitGroupChange"),
        Ok(Allow)
    );
    assert_eq!(
        device_auth_policy_action(Require, "blue.catbird.mlsChat.updateCursor"),
        Ok(RequireBinding)
    );
    assert_eq!(
        device_auth_policy_action(Require, "blue.catbird.mlsChat.commitGroupChange"),
        Ok(RequireBinding)
    );

    assert_eq!(
        device_auth_policy_action(Observe, "blue.catbird.mlsChat.futureMutation"),
        Err(DeviceAuthPolicyRejection)
    );
    assert_eq!(
        device_auth_policy_action(Require, "blue.catbird.mlsChat.getConvosSuffix"),
        Err(DeviceAuthPolicyRejection)
    );
}

#[test]
fn dpop_header_must_have_exactly_one_canonical_field_value() {
    let mut absent = HeaderMap::new();
    assert_eq!(single_dpop_header(&absent), Err(DeviceAuthPolicyRejection));

    absent.insert("dpop", HeaderValue::from_static("proof"));
    assert_eq!(single_dpop_header(&absent), Ok("proof"));

    let mut duplicate = absent.clone();
    duplicate.append("dpop", HeaderValue::from_static("second-proof"));
    assert_eq!(
        single_dpop_header(&duplicate),
        Err(DeviceAuthPolicyRejection)
    );

    let mut comma_combined = HeaderMap::new();
    comma_combined.insert("dpop", HeaderValue::from_static("proof,second-proof"));
    assert_eq!(
        single_dpop_header(&comma_combined),
        Err(DeviceAuthPolicyRejection)
    );

    let mut non_utf8 = HeaderMap::new();
    non_utf8.insert(
        "dpop",
        HeaderValue::from_bytes(&[0xff]).expect("opaque header value is valid HTTP"),
    );
    assert_eq!(
        single_dpop_header(&non_utf8),
        Err(DeviceAuthPolicyRejection)
    );
}

#[tokio::test]
async fn all_policy_failures_share_one_generic_wire_denial() {
    let response = DeviceAuthPolicyRejection.into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "error": "Unauthorized",
            "message": "Authentication or device authorization denied"
        })
    );
    let rendered = String::from_utf8(bytes.to_vec()).unwrap();
    for forbidden in [
        "dpop",
        "device_id",
        "jkt",
        "registry",
        "replay",
        "issuer",
        "target",
        "token",
    ] {
        assert!(!rendered.to_ascii_lowercase().contains(forbidden));
    }

    // Keep Body imported and type-checked against the actual Axum response
    // body used by the shared extractor rejection.
    let _: Body = DeviceAuthPolicyRejection.into_response().into_body();
}

#[test]
fn policy_metrics_have_only_closed_non_sensitive_outcomes() {
    assert_eq!(DeviceAuthPolicyMetricOutcome::Verified.as_str(), "verified");
    assert_eq!(
        DeviceAuthPolicyMetricOutcome::WouldDeny.as_str(),
        "would_deny"
    );
}

#[test]
fn verified_device_request_is_cloneable_for_downstream_cas_handoff() {
    fn assert_clone<T: Clone>() {}
    assert_clone::<VerifiedDeviceRequest>();
}
