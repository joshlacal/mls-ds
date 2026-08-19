//! Shared ADR-016 device-auth rollout gate.
//!
//! Bearer authentication remains owned by [`crate::auth::AuthUser`]. This
//! gate runs exactly once after that extractor has verified the bearer,
//! resolved the effective principal, and consumed the bearer JTI. Enrollment
//! endpoints keep proof ownership in their handlers; bootstrap and read paths
//! remain compatible; observe/require paths call the existing exact verifier.

use axum::{
    http::{Extensions, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use once_cell::sync::OnceCell;
use serde_json::json;
use std::{fmt, future::Future};

use crate::{
    auth::{
        device_auth::{
            verify_gateway_device_request, DeviceAuthError, VerifiedDeviceRequest,
            VerifiedRequestTarget,
        },
        VerifiedGatewayBearer,
    },
    config::{DeviceAuthMode, DeviceAuthPolicyAction},
    metrics::{record_device_auth_policy, DeviceAuthPolicyMetricOutcome},
    storage::DbPool,
};

static INSTALLED_DEVICE_AUTH_MODE: OnceCell<DeviceAuthMode> = OnceCell::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceAuthModeAlreadyInstalled;

impl fmt::Display for DeviceAuthModeAlreadyInstalled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("device-auth mode was already installed")
    }
}

impl std::error::Error for DeviceAuthModeAlreadyInstalled {}

/// Install the mode that startup already parsed and validated. The request
/// path never reads process environment and cannot silently change posture.
pub fn install_device_auth_mode(
    mode: DeviceAuthMode,
) -> Result<(), DeviceAuthModeAlreadyInstalled> {
    INSTALLED_DEVICE_AUTH_MODE
        .set(mode)
        .map_err(|_| DeviceAuthModeAlreadyInstalled)
}

/// Return the startup-installed mode. `None` keeps this writer commit inert
/// until the coordinator lands the required startup integration in `main.rs`.
pub fn installed_device_auth_mode() -> Option<DeviceAuthMode> {
    INSTALLED_DEVICE_AUTH_MODE.get().copied()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceAuthPolicyRejection;

impl fmt::Display for DeviceAuthPolicyRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("authentication or device authorization denied")
    }
}

impl std::error::Error for DeviceAuthPolicyRejection {}

impl IntoResponse for DeviceAuthPolicyRejection {
    fn into_response(self) -> Response {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized",
                "message": "Authentication or device authorization denied",
            })),
        )
            .into_response()
    }
}

/// Select policy only through the exact closed classifier. Unknown MLS-chat
/// NSIDs fail closed and are never inferred from prefixes or method shape.
pub fn device_auth_policy_action(
    mode: DeviceAuthMode,
    nsid: &str,
) -> Result<DeviceAuthPolicyAction, DeviceAuthPolicyRejection> {
    mode.action_for_nsid(nsid)
        .map_err(|_| DeviceAuthPolicyRejection)
}

/// Extract one non-empty, canonical DPoP field value. Multiple header lines,
/// comma-combined values, whitespace, and non-UTF-8 values are all rejected.
pub fn single_dpop_header(headers: &HeaderMap) -> Result<&str, DeviceAuthPolicyRejection> {
    let mut values = headers.get_all("dpop").iter();
    let value = values.next().ok_or(DeviceAuthPolicyRejection)?;
    if values.next().is_some() {
        return Err(DeviceAuthPolicyRejection);
    }
    let proof = value.to_str().map_err(|_| DeviceAuthPolicyRejection)?;
    if proof.is_empty() || proof.trim() != proof || proof.contains(',') {
        return Err(DeviceAuthPolicyRejection);
    }
    Ok(proof)
}

async fn enforce_device_auth_policy_with<F, Fut, R>(
    mode: DeviceAuthMode,
    nsid: &str,
    headers: &HeaderMap,
    extensions: &mut Extensions,
    verify: F,
    record_observation: R,
) -> Result<(), DeviceAuthPolicyRejection>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<VerifiedDeviceRequest, DeviceAuthError>>,
    R: FnOnce(DeviceAuthPolicyMetricOutcome),
{
    use DeviceAuthPolicyAction::{Allow, EnforceEnrollment, ObserveWouldDeny, RequireBinding};

    match device_auth_policy_action(mode, nsid)? {
        Allow | EnforceEnrollment => Ok(()),
        ObserveWouldDeny => {
            let verification = match single_dpop_header(headers) {
                Ok(proof) => verify(proof.to_owned()).await,
                Err(_) => Err(DeviceAuthError::MalformedProof),
            };
            let outcome = match verification {
                Ok(verified) => {
                    extensions.insert(verified);
                    DeviceAuthPolicyMetricOutcome::Verified
                }
                Err(_) => DeviceAuthPolicyMetricOutcome::WouldDeny,
            };
            record_observation(outcome);
            Ok(())
        }
        RequireBinding => {
            let proof = single_dpop_header(headers)?.to_owned();
            let verified = verify(proof).await.map_err(|_| DeviceAuthPolicyRejection)?;
            extensions.insert(verified);
            Ok(())
        }
    }
}

/// Apply the selected policy with the exact bearer, sealed request target,
/// replay store, active device registry, and current time.
pub async fn enforce_device_auth_policy(
    mode: DeviceAuthMode,
    nsid: &str,
    headers: &HeaderMap,
    extensions: &mut Extensions,
    pool: &DbPool,
    bearer: &VerifiedGatewayBearer,
    request_target: &VerifiedRequestTarget,
    now: DateTime<Utc>,
) -> Result<(), DeviceAuthPolicyRejection> {
    enforce_device_auth_policy_with(
        mode,
        nsid,
        headers,
        extensions,
        |proof| async move {
            verify_gateway_device_request(pool, &proof, bearer, request_target, now).await
        },
        record_device_auth_policy,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::device_auth::{DeviceAuthError, VerifiedDeviceRequest};
    use axum::http::{Extensions, HeaderMap, HeaderValue};
    use std::sync::{Arc, Mutex};

    fn proof_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("dpop", HeaderValue::from_static("proof"));
        headers
    }

    fn verified() -> VerifiedDeviceRequest {
        VerifiedDeviceRequest::fixture_for_policy_test(
            "did:plc:alice",
            "device-a",
            &"a".repeat(43),
            7,
        )
    }

    #[tokio::test]
    async fn allow_and_enrollment_never_consume_dpop_or_call_the_verifier() {
        for (mode, nsid) in [
            (DeviceAuthMode::Require, "blue.catbird.chat.getConversations"),
            (
                DeviceAuthMode::Require,
                "blue.catbird.chat.enrollDevice",
            ),
            (
                DeviceAuthMode::Enroll,
                "blue.catbird.chat.sendMessage",
            ),
        ] {
            let calls = Arc::new(Mutex::new(0));
            let calls_for_verifier = calls.clone();
            let mut extensions = Extensions::new();
            let outcomes = Arc::new(Mutex::new(Vec::new()));
            let outcomes_for_recorder = outcomes.clone();
            let result = enforce_device_auth_policy_with(
                mode,
                nsid,
                &HeaderMap::new(),
                &mut extensions,
                move |_| {
                    *calls_for_verifier.lock().unwrap() += 1;
                    async { Err(DeviceAuthError::MalformedProof) }
                },
                move |outcome| outcomes_for_recorder.lock().unwrap().push(outcome),
            )
            .await;

            assert_eq!(result, Ok(()));
            assert_eq!(*calls.lock().unwrap(), 0);
            assert!(outcomes.lock().unwrap().is_empty());
            assert!(extensions.get::<VerifiedDeviceRequest>().is_none());
        }
    }

    #[tokio::test]
    async fn observe_passes_invalid_requests_without_minting_authority() {
        for headers in [HeaderMap::new(), {
            let mut duplicate = proof_headers();
            duplicate.append("dpop", HeaderValue::from_static("second"));
            duplicate
        }] {
            let mut extensions = Extensions::new();
            let outcomes = Arc::new(Mutex::new(Vec::new()));
            let outcomes_for_recorder = outcomes.clone();
            let result = enforce_device_auth_policy_with(
                DeviceAuthMode::Observe,
                "blue.catbird.chat.sendMessage",
                &headers,
                &mut extensions,
                |_| async { panic!("malformed header must not reach verifier") },
                move |outcome| outcomes_for_recorder.lock().unwrap().push(outcome),
            )
            .await;
            assert_eq!(result, Ok(()));
            assert_eq!(
                *outcomes.lock().unwrap(),
                vec![DeviceAuthPolicyMetricOutcome::WouldDeny]
            );
            assert!(extensions.get::<VerifiedDeviceRequest>().is_none());
        }

        for verification in [
            Err(DeviceAuthError::UntrustedDelegation),
            Err(DeviceAuthError::RegistryMismatch),
        ] {
            let mut extensions = Extensions::new();
            let outcomes = Arc::new(Mutex::new(Vec::new()));
            let outcomes_for_recorder = outcomes.clone();
            let result = enforce_device_auth_policy_with(
                DeviceAuthMode::Observe,
                "blue.catbird.chat.sendMessage",
                &proof_headers(),
                &mut extensions,
                move |_| async move { verification },
                move |outcome| outcomes_for_recorder.lock().unwrap().push(outcome),
            )
            .await;
            assert_eq!(result, Ok(()));
            assert_eq!(
                *outcomes.lock().unwrap(),
                vec![DeviceAuthPolicyMetricOutcome::WouldDeny]
            );
            assert!(extensions.get::<VerifiedDeviceRequest>().is_none());
        }
    }

    #[tokio::test]
    async fn observe_inserts_authority_only_after_full_verification_succeeds() {
        let mut extensions = Extensions::new();
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let outcomes_for_recorder = outcomes.clone();

        assert_eq!(
            enforce_device_auth_policy_with(
                DeviceAuthMode::Observe,
                "blue.catbird.chat.sendMessage",
                &proof_headers(),
                &mut extensions,
                |_| async { Ok(verified()) },
                move |outcome| outcomes_for_recorder.lock().unwrap().push(outcome),
            )
            .await,
            Ok(())
        );

        assert_eq!(
            *outcomes.lock().unwrap(),
            vec![DeviceAuthPolicyMetricOutcome::Verified]
        );
        let inserted = extensions
            .get::<VerifiedDeviceRequest>()
            .expect("fully verified observe request carries opaque authority");
        assert_eq!(inserted.user_did(), "did:plc:alice");
        assert_eq!(inserted.device_id(), "device-a");
        assert_eq!(inserted.auth_generation(), 7);
    }

    #[tokio::test]
    async fn require_rejects_generically_and_inserts_only_exact_verified_authority() {
        for verification in [
            Err(DeviceAuthError::MalformedProof),
            Err(DeviceAuthError::InvalidJwk),
            Err(DeviceAuthError::InvalidProofSignature),
            Err(DeviceAuthError::ThumbprintMismatch),
            Err(DeviceAuthError::TokenHashMismatch),
            Err(DeviceAuthError::RequestTargetMismatch),
            Err(DeviceAuthError::ProofTimeInvalid),
            Err(DeviceAuthError::Replay),
            Err(DeviceAuthError::UntrustedDelegation),
            Err(DeviceAuthError::MissingDeviceClaims),
            Err(DeviceAuthError::RegistryMismatch),
            Err(DeviceAuthError::Storage("sensitive".into())),
        ] {
            let mut extensions = Extensions::new();
            let result = enforce_device_auth_policy_with(
                DeviceAuthMode::Require,
                "blue.catbird.chat.sendMessage",
                &proof_headers(),
                &mut extensions,
                move |_| async move { verification },
                |_| panic!("require mode must not emit observe-only metrics"),
            )
            .await;
            assert_eq!(result, Err(DeviceAuthPolicyRejection));
            assert!(extensions.get::<VerifiedDeviceRequest>().is_none());
        }

        let mut extensions = Extensions::new();
        assert_eq!(
            enforce_device_auth_policy_with(
                DeviceAuthMode::Require,
                "blue.catbird.chat.sendMessage",
                &proof_headers(),
                &mut extensions,
                |_| async { Ok(verified()) },
                |_| panic!("require mode must not emit observe-only metrics"),
            )
            .await,
            Ok(())
        );
        let inserted = extensions
            .get::<VerifiedDeviceRequest>()
            .expect("verified authority inserted");
        assert_eq!(inserted.user_did(), "did:plc:alice");
        assert_eq!(inserted.device_id(), "device-a");
        assert_eq!(inserted.auth_generation(), 7);
    }

    #[tokio::test]
    async fn unknown_nsid_fails_closed_before_verification() {
        let mut extensions = Extensions::new();
        let result = enforce_device_auth_policy_with(
            DeviceAuthMode::Observe,
            "blue.catbird.chat.futureMutation",
            &proof_headers(),
            &mut extensions,
            |_| async { panic!("unknown endpoint must not reach verifier") },
            |_| panic!("unknown endpoint must not emit observe metrics"),
        )
        .await;
        assert_eq!(result, Err(DeviceAuthPolicyRejection));
    }
}
