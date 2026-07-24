//! `blue.catbird.chat.replenishKeyPackages` — ordinary-signed key-package top-up.
//!
//! Arbitrates the idempotency claim, re-establishes the locked device authority,
//! validates the key-package batch against the device's REGISTERED signing key
//! (continuity: a replenishment cannot introduce a package under a different
//! signing identity), publishes the batch, then reads the single post-publish
//! `deviceView` (the one count source) and records the exact idempotent response —
//! all in one transaction.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use catbird_atproto::generated::blue_catbird::chat as chat_dto;
use jacquard_common::DefaultStr;

use crate::chat_protocol::error::{ChatEndpoint, ChatProtocolErrorCode};
use crate::chat_protocol::repository::auth::{self, BusinessIdempotencyOutcome};
use crate::chat_protocol::repository::device_directory::read_device_view;
use crate::chat_protocol::repository::key_packages::{self, KeyPackageOwner, NewKeyPackage};
use crate::chat_protocol::transcript::VerifiedMutationProjection;
use crate::chat_protocol::validation::basic_credential_identity;
use crate::chat_protocol::wire::{self, KeyPackageValidationPolicy};
use crate::storage::DbPool;

use super::context::{self, Admission};
use super::device_views::{
    device_view_from_directory, directory_failure, extract_key_packages, key_package_failure,
    RawKeyPackage,
};
use super::errors::ChatFailure;
use super::runtime::ChatRuntime;

const MAX_KEY_PACKAGE_BYTES: usize = 65536;
const ENDPOINT: ChatEndpoint = ChatEndpoint::ReplenishKeyPackages;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match replenish(&pool, &runtime, &headers, &body).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn replenish(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let authority = match context::admit_signed(pool, runtime, ENDPOINT, headers, body).await? {
        Admission::Replay(response) => return Ok(response),
        Admission::Execute(authority) => authority,
    };

    // Key packages come from the certified canonical projection (correct bytes
    // encoding), not the generated DTO.
    let mutation = authority
        .mutation()
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let VerifiedMutationProjection::KeyPackageReplenishment(projection) = mutation.projection()
    else {
        return Err(ChatFailure::invariant(ENDPOINT));
    };
    let (raw_packages, _body_signature_key) = extract_key_packages(&projection.body(), ENDPOINT)?;

    let subject = authority.subject().as_str().to_owned();
    let device_uuid = uuid::Uuid::parse_str(authority.device_id().as_str())
        .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let expected_credential = basic_credential_identity(authority.subject(), authority.device_id());
    let now_unix = u64::try_from(authority.trusted_instant().datetime().timestamp())
        .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let trusted_at = authority.trusted_instant().datetime();

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let idempotency = match auth::arbitrate_business_idempotency(&mut transaction, &authority)
        .await
        .map_err(|error| context::auth_repository_failure(ENDPOINT, error))?
    {
        BusinessIdempotencyOutcome::CompletedReplay(response) => {
            return Ok(context::replay_response(&response));
        }
        BusinessIdempotencyOutcome::FirstExecution(guard) => guard,
    };

    let authority_guard = auth::recheck_business_authority(&mut transaction, &authority)
        .await
        .map_err(|error| context::auth_repository_failure(ENDPOINT, error))?;

    // Continuity: publish against the device's registered signing key + key id.
    let signing_key = authority_guard
        .stored_signing_public_key()
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?
        .to_vec();
    let key_id = authority_guard
        .stored_key_id()
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?
        .to_owned();
    let auth_generation = authority_guard
        .stored_auth_generation()
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;

    let validated =
        validate_key_packages(&raw_packages, &expected_credential, &signing_key, now_unix)?;
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

    let owner = KeyPackageOwner {
        user_did: &subject,
        device_id: device_uuid,
        key_id: &key_id,
        auth_generation,
    };
    key_packages::publish_key_packages(&mut transaction, &owner, &packages, trusted_at)
        .await
        .map_err(|error| key_package_failure(ENDPOINT, error))?;

    // Single count source: the post-publish device view.
    let view = read_device_view(&mut transaction, &subject, device_uuid)
        .await
        .map_err(|error| directory_failure(ENDPOINT, error))?
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let output = chat_dto::replenish_key_packages::ReplenishKeyPackagesOutput::<DefaultStr> {
        device: device_view_from_directory(&view),
        extra_data: None,
    };
    let response_bytes =
        serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(ENDPOINT))?;

    auth::record_completed_idempotency(
        &mut transaction,
        &authority,
        &idempotency,
        200,
        &response_bytes,
        None,
    )
    .await
    .map_err(|error| context::auth_repository_failure(ENDPOINT, error))?;

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
    if packages.is_empty() {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }
    let mut validated = Vec::with_capacity(packages.len());
    for package in packages {
        let policy = KeyPackageValidationPolicy {
            expected_basic_credential: expected_credential,
            expected_signature_key,
            now_unix_seconds: now_unix,
            max_bytes: MAX_KEY_PACKAGE_BYTES,
        };
        let valid = wire::validate_key_package(&package.wrapper, policy).map_err(|_| {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidKeyPackage)
        })?;
        if valid.key_package_ref().as_slice() != package.key_package_ref.as_slice() {
            return Err(ChatFailure::protocol(
                ENDPOINT,
                ChatProtocolErrorCode::InvalidKeyPackage,
            ));
        }
        validated.push(valid);
    }
    Ok(validated)
}
