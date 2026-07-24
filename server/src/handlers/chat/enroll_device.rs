//! `blue.catbird.chat.enrollDevice` — enrollment-bootstrap device registration.
//!
//! Composes the certified enrollment authority with the key-package persistence
//! sink in one transaction: the enrollment inserts the principal/device/device-key
//! rows and records the exact idempotent response, then the same transaction
//! publishes the validated key-package batch (its owner-key FK is satisfied by the
//! just-inserted device key; the deferred live-limit + mapping triggers fire at
//! COMMIT, so enrollment + key packages are atomic — a key-package constraint
//! rolls the whole enrollment back).
//!
//! deviceView counts follow the Option A ruling: a first enrollment requires the
//! device id to not pre-exist, so there is no prior key-package state to read
//! back; `availablePackageCount` is exactly the validated batch size and
//! `reservedPackageCount` is `0`. The idempotent replay returns those exact stored
//! bytes, and a live-DB conformance test asserts the post-enroll
//! `read_device_view` counts equal the returned counts.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use jacquard_common::deps::bytes::Bytes as JacquardBytes;
use jacquard_common::deps::smol_str::SmolStr;
use jacquard_common::DefaultStr;

use catbird_atproto::generated::blue_catbird::chat as chat_dto;

use crate::chat_protocol::error::ChatEndpoint;
use crate::chat_protocol::repository::auth::{self, EnrollmentBusinessOutcome};
use crate::chat_protocol::repository::key_packages::{self, KeyPackageOwner, NewKeyPackage};
use crate::chat_protocol::transcript::VerifiedMutationProjection;
use crate::chat_protocol::validation::basic_credential_identity;
use crate::chat_protocol::wire::{self, KeyPackageValidationPolicy};
use crate::sqlx_jacquard::chrono_to_datetime;
use crate::storage::DbPool;

use super::context::{self, Admission};
use super::device_views::{extract_key_packages, key_package_failure, RawKeyPackage};
use super::errors::ChatFailure;
use super::runtime::ChatRuntime;

/// The per-key-package wire byte cap: the `keyPackageArtifact.bytes` lexicon
/// `maxLength` (65536). `wire::validate_key_package` additionally enforces its own
/// absolute ceiling, so this is the tighter, protocol-declared bound.
const MAX_KEY_PACKAGE_BYTES: usize = 65536;

const ENDPOINT: ChatEndpoint = ChatEndpoint::EnrollDevice;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match enroll(&pool, &runtime, &headers, &body).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn enroll(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let authority = match context::admit_enrollment(pool, runtime, ENDPOINT, headers, body).await? {
        Admission::Replay(response) => return Ok(response),
        Admission::Execute(authority) => authority,
    };

    // The MLS key packages travel in the signed enrollment body; the auth layer
    // proved the body signature and grant binding. The handler reads them from the
    // CERTIFIED canonical projection (correct bytes encoding) and validates each
    // package's MLS wire form against the device identity + declared signing key.
    let mutation = authority
        .mutation()
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let VerifiedMutationProjection::DeviceEnrollment(projection) = mutation.projection() else {
        return Err(ChatFailure::invariant(ENDPOINT));
    };
    let (raw_packages, expected_signature_key) =
        extract_key_packages(&projection.body(), ENDPOINT)?;
    let key_id = mutation.key_id().as_str().to_owned();

    let expected_credential = basic_credential_identity(authority.subject(), authority.device_id());
    let now_unix = trusted_unix_seconds(&authority)?;

    let validated = validate_key_packages(
        &raw_packages,
        &expected_credential,
        &expected_signature_key,
        now_unix,
    )?;
    let packages: Vec<NewKeyPackage<'_>> = raw_packages
        .iter()
        .zip(validated.iter())
        .map(|(raw, valid)| NewKeyPackage {
            key_package_ref: &raw.key_package_ref,
            wrapper_bytes: &raw.wrapper,
            init_key: valid.init_key(),
            not_before_unix: valid.not_before(),
            not_after_unix: valid.not_after(),
        })
        .collect();

    let trusted_at = authority.trusted_instant().datetime();
    let batch_count =
        i64::try_from(packages.len()).map_err(|_| ChatFailure::invariant(ENDPOINT))?;

    // deviceView is fully derivable for a fresh device (Option A): first
    // enrollment installs generation 1, status active, and the batch as available
    // packages with none reserved.
    let device = chat_dto::DeviceView::<DefaultStr> {
        auth_generation: 1,
        available_package_count: batch_count,
        created_at: chrono_to_datetime(trusted_at),
        device_id: SmolStr::from(authority.device_id().as_str()),
        dpop_jkt: SmolStr::from(authority.dpop_jkt().as_str()),
        key_id: SmolStr::from(key_id.as_str()),
        reserved_package_count: 0,
        signature_public_key: JacquardBytes::from(expected_signature_key),
        status: SmolStr::from("active"),
        updated_at: chrono_to_datetime(trusted_at),
        extra_data: None,
    };
    let output = chat_dto::enroll_device::EnrollDeviceOutput::<DefaultStr> {
        device,
        extra_data: None,
    };
    let response_bytes =
        serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(ENDPOINT))?;

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let guard = match auth::prepare_enrollment_business(&mut transaction, &authority)
        .await
        .map_err(|error| context::auth_repository_failure(ENDPOINT, error))?
    {
        EnrollmentBusinessOutcome::CompletedReplay(response) => {
            return Ok(context::replay_response(&response));
        }
        EnrollmentBusinessOutcome::FirstExecution(guard) => guard,
    };

    auth::persist_enrollment_and_completion(
        &mut transaction,
        &authority,
        guard,
        200,
        &response_bytes,
        None,
    )
    .await
    .map_err(|error| context::auth_repository_failure(ENDPOINT, error))?;

    let owner = KeyPackageOwner {
        user_did: authority.subject().as_str(),
        device_id: canonical_device_uuid(&authority)?,
        key_id: &key_id,
        auth_generation: 1,
    };
    key_packages::publish_key_packages(&mut transaction, &owner, &packages, trusted_at)
        .await
        .map_err(|error| key_package_failure(ENDPOINT, error))?;

    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    Ok(context::json_ok(response_bytes))
}

fn validate_key_packages(
    packages: &[RawKeyPackage],
    expected_credential: &[u8],
    expected_signature_key: &[u8],
    now_unix: u64,
) -> Result<Vec<wire::ValidatedKeyPackage>, ChatFailure> {
    use crate::chat_protocol::error::ChatProtocolErrorCode as C;
    if packages.is_empty() {
        return Err(ChatFailure::protocol(ENDPOINT, C::InvalidRequest));
    }
    let mut validated = Vec::with_capacity(packages.len());
    for package in packages {
        let policy = KeyPackageValidationPolicy {
            expected_basic_credential: expected_credential,
            expected_signature_key,
            now_unix_seconds: now_unix,
            max_bytes: MAX_KEY_PACKAGE_BYTES,
        };
        let valid = wire::validate_key_package(&package.wrapper, policy)
            .map_err(|_| ChatFailure::protocol(ENDPOINT, C::InvalidKeyPackage))?;
        // The declared `keyPackageRef` must equal the reference computed from the
        // validated wire bytes; a mismatch is a forged/duplicate reference.
        if valid.key_package_ref().as_slice() != package.key_package_ref.as_slice() {
            return Err(ChatFailure::protocol(ENDPOINT, C::InvalidKeyPackage));
        }
        validated.push(valid);
    }
    Ok(validated)
}

fn trusted_unix_seconds(
    authority: &crate::chat_protocol::dpop::VerifiedChatDeviceRequest,
) -> Result<u64, ChatFailure> {
    u64::try_from(authority.trusted_instant().datetime().timestamp())
        .map_err(|_| ChatFailure::invariant(ENDPOINT))
}

fn canonical_device_uuid(
    authority: &crate::chat_protocol::dpop::VerifiedChatDeviceRequest,
) -> Result<uuid::Uuid, ChatFailure> {
    uuid::Uuid::parse_str(authority.device_id().as_str())
        .map_err(|_| ChatFailure::invariant(ENDPOINT))
}
