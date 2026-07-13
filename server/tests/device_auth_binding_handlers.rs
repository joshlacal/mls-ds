//! Contract tests for the Wave 1 device-auth enrollment handlers.
//!
//! The handler source is included directly because the coordinator owns its
//! eventual `handlers/mls_chat/mod.rs` registration. These shims preserve the
//! same `crate::...` imports the source uses when compiled by the server.

mod auth {
    pub use catbird_server::auth::*;
}
mod generated {
    pub use catbird_server::generated::*;
}
mod metrics {
    pub use catbird_server::metrics::*;
}
mod sqlx_jacquard {
    pub use catbird_server::sqlx_jacquard::*;
}
mod storage {
    pub use catbird_server::storage::*;
}

#[path = "../src/handlers/mls_chat/device_auth_binding.rs"]
mod device_auth_binding;

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    routing::post,
    Router,
};
use catbird_server::auth::device_auth::DeviceAuthError;
use catbird_server::config::{
    classify_device_auth_endpoint, DeviceAuthEndpointClass, DeviceAuthMode, DeviceAuthPolicyAction,
};
use catbird_server::metrics::{DeviceAuthMetricEndpoint, DeviceAuthMetricOutcome};
use device_auth_binding::{
    begin_device_auth_binding, begin_error_contract, complete_device_auth_binding,
    complete_error_contract, extract_dpop_proof, validate_challenge_id, validate_device_id,
    validate_signature,
};
use tower_util::util::ServiceExt;

#[test]
fn begin_input_bounds_are_exact_and_whitespace_is_rejected() {
    assert!(validate_device_id("d").is_ok());
    assert!(validate_device_id(&"d".repeat(64)).is_ok());
    assert!(validate_device_id("").is_err());
    assert!(validate_device_id(&"d".repeat(65)).is_err());
    assert!(validate_device_id(" device-a").is_err());
    assert!(validate_device_id("device-a ").is_err());
    assert!(validate_device_id("device\ta").is_err());
}

#[test]
fn complete_input_bounds_are_exact() {
    assert!(validate_challenge_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    assert!(validate_challenge_id("").is_err());
    assert!(validate_challenge_id(&"a".repeat(129)).is_err());
    assert!(validate_challenge_id("not-a-uuid").is_err());

    assert!(validate_signature(&[0_u8; 64]).is_ok());
    assert!(validate_signature(&[0_u8; 63]).is_err());
    assert!(validate_signature(&[0_u8; 65]).is_err());
}

#[test]
fn dpop_requires_exactly_one_nonempty_header() {
    let missing = HeaderMap::new();
    assert_eq!(extract_dpop_proof(&missing), Err(StatusCode::UNAUTHORIZED));

    let mut one = HeaderMap::new();
    one.insert("dpop", HeaderValue::from_static("proof.jwt.value"));
    assert_eq!(extract_dpop_proof(&one), Ok("proof.jwt.value"));

    let mut duplicate = HeaderMap::new();
    duplicate.append("dpop", HeaderValue::from_static("first.jwt.value"));
    duplicate.append("dpop", HeaderValue::from_static("second.jwt.value"));
    assert_eq!(
        extract_dpop_proof(&duplicate),
        Err(StatusCode::UNAUTHORIZED)
    );

    let mut empty = HeaderMap::new();
    empty.insert("dpop", HeaderValue::from_static(""));
    assert_eq!(extract_dpop_proof(&empty), Err(StatusCode::UNAUTHORIZED));
}

#[test]
fn typed_error_statuses_preserve_complete_outcomes() {
    assert_eq!(
        complete_error_contract(DeviceAuthError::ChallengeNotFound).0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        complete_error_contract(DeviceAuthError::ChallengeExpired).0,
        StatusCode::GONE
    );
    assert_eq!(
        complete_error_contract(DeviceAuthError::ChallengeAlreadyUsed).0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        complete_error_contract(DeviceAuthError::BindingMismatch).0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        complete_error_contract(DeviceAuthError::InvalidIdentitySignature).0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        complete_error_contract(DeviceAuthError::RegistryMismatch).0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        complete_error_contract(DeviceAuthError::Storage("redacted".into())).0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn typed_error_statuses_preserve_begin_outcomes() {
    assert_eq!(
        begin_error_contract(DeviceAuthError::RegistryMismatch).0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        begin_error_contract(DeviceAuthError::Storage("redacted".into())).0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        begin_error_contract(DeviceAuthError::Replay).0,
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn endpoint_classifier_is_exact_and_unknown_fails_closed() {
    assert_eq!(
        classify_device_auth_endpoint("blue.catbird.mlsChat.beginDeviceAuthBinding"),
        Some(DeviceAuthEndpointClass::Enrollment)
    );
    assert_eq!(
        classify_device_auth_endpoint("blue.catbird.mlsChat.getConvos"),
        Some(DeviceAuthEndpointClass::Read)
    );
    assert_eq!(
        classify_device_auth_endpoint("blue.catbird.mlsChat.registerDevice"),
        Some(DeviceAuthEndpointClass::Bootstrap)
    );
    assert_eq!(
        classify_device_auth_endpoint("blue.catbird.mlsChat.updateCursor"),
        Some(DeviceAuthEndpointClass::Canary)
    );
    assert_eq!(
        classify_device_auth_endpoint("blue.catbird.mlsChat.commitGroupChange"),
        Some(DeviceAuthEndpointClass::Mutation)
    );
    assert_eq!(
        classify_device_auth_endpoint("blue.catbird.mlsChat.commitGroupChangeSuffix"),
        None
    );

    for nsid in [
        "blue.catbird.mlsChat.subscribeEvents",
        "blue.catbird.mlsChat.addMembers",
        "blue.catbird.mlsChat.removeMembers",
        "blue.catbird.mlsChat.processExternalCommit",
        "blue.catbird.mlsChat.publishGroupInfo",
        "blue.catbird.mlsChat.syncKeyPackages",
        "blue.catbird.mlsChat.getGroupInfo",
        "blue.catbird.mlsChat.getKeyPackageStats",
    ] {
        assert!(
            classify_device_auth_endpoint(nsid).is_some(),
            "active route {nsid} must have an explicit class"
        );
    }
    assert!(
        DeviceAuthMode::Require
            .action_for_nsid("blue.catbird.mlsChat.unknownMutation")
            .is_err(),
        "unknown endpoints fail closed"
    );
}

#[test]
fn mode_class_matrix_is_exhaustive_and_does_not_activate_transitions() {
    use DeviceAuthEndpointClass::{Bootstrap, Canary, Enrollment, Mutation, Read};
    use DeviceAuthPolicyAction::{Allow, EnforceEnrollment, ObserveWouldDeny, RequireBinding};

    for mode in [
        DeviceAuthMode::Observe,
        DeviceAuthMode::Enroll,
        DeviceAuthMode::Require,
    ] {
        assert_eq!(mode.action_for(Enrollment), EnforceEnrollment);
        assert_eq!(mode.action_for(Bootstrap), Allow);
        assert_eq!(mode.action_for(Read), Allow);
    }

    assert_eq!(DeviceAuthMode::Observe.action_for(Canary), ObserveWouldDeny);
    assert_eq!(
        DeviceAuthMode::Observe.action_for(Mutation),
        ObserveWouldDeny
    );
    assert_eq!(DeviceAuthMode::Enroll.action_for(Canary), RequireBinding);
    assert_eq!(DeviceAuthMode::Enroll.action_for(Mutation), Allow);
    assert_eq!(DeviceAuthMode::Require.action_for(Canary), RequireBinding);
    assert_eq!(DeviceAuthMode::Require.action_for(Mutation), RequireBinding);
}

#[test]
fn unknown_mode_is_rejected_instead_of_downgraded() {
    assert_eq!("observe".parse(), Ok(DeviceAuthMode::Observe));
    assert_eq!("enroll".parse(), Ok(DeviceAuthMode::Enroll));
    assert_eq!("require".parse(), Ok(DeviceAuthMode::Require));
    assert!("disabled".parse::<DeviceAuthMode>().is_err());
    assert!("".parse::<DeviceAuthMode>().is_err());
}

#[test]
fn metric_labels_are_closed_enums() {
    assert_eq!(DeviceAuthMetricEndpoint::Begin.as_str(), "begin");
    assert_eq!(DeviceAuthMetricEndpoint::Complete.as_str(), "complete");
    assert_eq!(DeviceAuthMetricOutcome::Success.as_str(), "success");
    assert_eq!(DeviceAuthMetricOutcome::WouldDeny.as_str(), "would_deny");
    assert_eq!(
        DeviceAuthMetricOutcome::Unauthorized.as_str(),
        "unauthorized"
    );
    assert_eq!(
        DeviceAuthMetricOutcome::InvalidInput.as_str(),
        "invalid_input"
    );
    assert_eq!(DeviceAuthMetricOutcome::NotFound.as_str(), "not_found");
    assert_eq!(DeviceAuthMetricOutcome::Conflict.as_str(), "conflict");
    assert_eq!(DeviceAuthMetricOutcome::Expired.as_str(), "expired");
    assert_eq!(
        DeviceAuthMetricOutcome::InvalidSignature.as_str(),
        "invalid_signature"
    );
    assert_eq!(DeviceAuthMetricOutcome::Unavailable.as_str(), "unavailable");
}

#[tokio::test]
async fn auth_user_runs_before_sealed_extensions_and_body_extractors() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool");
    let app = Router::new()
        .route(
            "/xrpc/blue.catbird.mlsChat.beginDeviceAuthBinding",
            post(begin_device_auth_binding),
        )
        .route(
            "/xrpc/blue.catbird.mlsChat.completeDeviceAuthBinding",
            post(complete_device_auth_binding),
        )
        .with_state(pool);

    // Deliberately omit Authorization. Even with malformed JSON and no sealed
    // extensions, AuthUser must reject first instead of exposing a 500.
    let request = Request::builder()
        .method("POST")
        .uri("/xrpc/blue.catbird.mlsChat.beginDeviceAuthBinding")
        .header("content-type", "application/json")
        .body(Body::from("{"))
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires fresh Postgres via TEST_DATABASE_URL with PR22 migration applied"]
async fn postgres_binding_schema_has_mandatory_device_index() {
    let database_url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("connect to test Postgres");
    let index: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.idx_device_auth_challenges_device')::text")
            .fetch_one(&pool)
            .await
            .expect("read index catalog");

    assert_eq!(index.as_deref(), Some("idx_device_auth_challenges_device"));
}
