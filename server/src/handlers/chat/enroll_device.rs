//! `blue.catbird.chat.enrollDevice` — enrollment-bootstrap device registration.
//!
//! Composes the certified enrollment authority with the key-package persistence
//! sink in one transaction: the enrollment inserts the principal/device/device-key
//! rows, publishes the validated key-package batch, and only then records the
//! exact idempotent response (its owner-key FK is satisfied by the
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
use petrel_core::Bytes as LexiconBytes;

use crate::blue_catbird::chat as chat_dto;

use crate::atproto_conv::chrono_to_datetime;
use crate::chat_protocol::error::ChatEndpoint;
use crate::chat_protocol::repository::key_packages::NewKeyPackage;
use crate::chat_protocol::repository::prelude::{self, PreparedEnrollmentOperation};
use crate::chat_protocol::wire::{self, KeyPackageValidationPolicy};
use crate::storage::DbPool;

use super::context;
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
    let admission =
        context::admit_enrollment_operation_only(pool, runtime, ENDPOINT, headers, body).await?;

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let prepared = match prelude::prepare_enrollment_operation(&mut transaction, admission)
        .await
        .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?
    {
        PreparedEnrollmentOperation::Replay(response) => {
            transaction
                .commit()
                .await
                .map_err(|_| ChatFailure::storage(ENDPOINT))?;
            return context::replay_response(ENDPOINT, &response);
        }
        PreparedEnrollmentOperation::First(prepared) => prepared,
    };

    // The MLS key packages travel in the signed enrollment body. Read and
    // validate them only through the borrowed absence-scope authority, then
    // persist effects before consuming completion authority.
    let response_bytes = {
        let effect = prepared.effect_authority();
        let projection = effect
            .enrollment_projection()
            .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?;
        let device_name = match projection.body().get("deviceName") {
            Some(crate::chat_protocol::transcript::CanonicalValueRef::Text(value)) => {
                value.to_owned()
            }
            _ => return Err(ChatFailure::invariant(ENDPOINT)),
        };
        let (raw_packages, expected_signature_key) =
            extract_key_packages(&projection.body(), ENDPOINT)?;
        let key_id = effect
            .key_id()
            .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?
            .to_owned();
        let expected_credential = effect.basic_credential_identity();
        let now_unix = u64::try_from(effect.trusted_instant().timestamp())
            .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
        let validated = validate_key_packages(
            &raw_packages,
            &expected_credential,
            &expected_signature_key,
            now_unix,
        )?;
        let trusted_at = effect.trusted_instant();
        let batch_count =
            i64::try_from(raw_packages.len()).map_err(|_| ChatFailure::invariant(ENDPOINT))?;
        let enrolled_status =
            prelude::persist_enrollment_bootstrap_effects(&mut transaction, &effect)
                .await
                .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?;
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
        prelude::publish_enrollment_key_packages(&mut transaction, &effect, &packages)
            .await
            .map_err(|error| key_package_failure(ENDPOINT, error))?;
        let coarse_active_at =
            crate::chat_protocol::device_activity::coarse_activity_day(trusted_at);
        let device = chat_dto::DeviceView {
            auth_generation: 1,
            available_package_count: batch_count,
            created_at: chrono_to_datetime(trusted_at),
            device_id: String::from(effect.device_id().to_string()),
            device_name: Some(String::from(device_name.as_str())),
            dormant_at: None,
            key_id: String::from(key_id.as_str()),
            last_active_at: Some(chrono_to_datetime(coarse_active_at)),
            reserved_package_count: 0,
            signature_public_key: LexiconBytes(expected_signature_key.to_vec()),
            status: crate::atproto_conv::open_enum(enrolled_status),
            updated_at: chrono_to_datetime(trusted_at),
            extra_data: None,
        };
        let output = chat_dto::enroll_device::Output { device };
        catbird_server::atproto_conv::wire_json_bytes(&output)
            .map_err(|_| ChatFailure::invariant(ENDPOINT))?
    };

    prelude::complete_enrollment_bootstrap_operation(
        &mut transaction,
        prepared.into_completion_guard(),
        200,
        &response_bytes,
        None,
    )
    .await
    .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?;

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
