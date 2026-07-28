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
use crate::chat_protocol::repository::device_directory::read_device_view;
use crate::chat_protocol::repository::key_packages::NewKeyPackage;
use crate::chat_protocol::repository::prelude::{self, OperationOnlyArbitration};
use crate::chat_protocol::wire::{self, KeyPackageValidationPolicy};
use crate::storage::DbPool;

use super::context;
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
    let admission =
        context::admit_replenishment_operation_only(pool, runtime, ENDPOINT, headers, body).await?;

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let reservation =
        match prelude::arbitrate_replenishment_operation_only(&mut transaction, &admission)
            .await
            .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?
        {
            OperationOnlyArbitration::Replay(replay) => {
                let response = prelude::validate_replenishment_operation_replay(
                    &mut transaction,
                    admission,
                    replay,
                )
                .await
                .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| ChatFailure::storage(ENDPOINT))?;
                return Ok(context::replay_response(&response));
            }
            OperationOnlyArbitration::First(reservation) => reservation,
        };

    let prepared = prelude::prepare_replenishment_prelude(&mut transaction, admission, reservation)
        .await
        .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?;

    let (subject, device_id) = {
        let effect = prepared.key_package_authority();
        let projection = effect
            .replenishment_projection()
            .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?;
        let (raw_packages, _body_signature_key) =
            extract_key_packages(&projection.body(), ENDPOINT)?;
        let expected_credential = effect.basic_credential_identity();
        let now_unix = u64::try_from(effect.trusted_instant().timestamp())
            .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
        let validated = validate_key_packages(
            &raw_packages,
            &expected_credential,
            effect
                .signing_public_key()
                .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?,
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
        prelude::publish_replenishment_key_packages(&mut transaction, &effect, &packages)
            .await
            .map_err(|error| key_package_failure(ENDPOINT, error))?;
        (effect.subject().to_owned(), effect.device_id())
    };

    // Single count source: the post-publish device view.
    let view = read_device_view(&mut transaction, &subject, device_id)
        .await
        .map_err(|error| directory_failure(ENDPOINT, error))?
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let output = chat_dto::replenish_key_packages::ReplenishKeyPackagesOutput::<DefaultStr> {
        device: device_view_from_directory(&view),
        extra_data: None,
    };
    let response_bytes =
        serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(ENDPOINT))?;

    prelude::complete_replenishment_operation(
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
