//! `blue.catbird.chat.rebindDeviceAuthentication` — rebind-bootstrap DPoP rotation.
//!
//! Applies the rebind under its locked old-state authority, then reads the
//! post-CAS device view. A rebind rotates only the DPoP binding + auth generation,
//! never key packages, so the returned view has unchanged counts / key id /
//! createdAt and the newly persisted thumbprint, generation, and update time. A
//! live-DB conformance test asserts the post-rebind `read_device_view` matches
//! the returned view on counts + key id + createdAt.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use catbird_atproto::generated::blue_catbird::chat as chat_dto;
use jacquard_common::DefaultStr;

use crate::chat_protocol::error::ChatEndpoint;
use crate::chat_protocol::repository::device_directory::read_device_view;
use crate::chat_protocol::repository::prelude::{self, PreparedRebindOperation};
use crate::storage::DbPool;

use super::context;
use super::device_views::{device_view_from_directory, directory_failure};
use super::errors::ChatFailure;
use super::runtime::ChatRuntime;

const ENDPOINT: ChatEndpoint = ChatEndpoint::RebindDeviceAuthentication;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match rebind(&pool, &runtime, &headers, &body).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn rebind(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_rebind_operation_only(pool, runtime, ENDPOINT, headers, body).await?;

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let prepared = match prelude::prepare_rebind_operation(&mut transaction, admission)
        .await
        .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?
    {
        PreparedRebindOperation::Replay(response) => {
            transaction
                .commit()
                .await
                .map_err(|_| ChatFailure::storage(ENDPOINT))?;
            return Ok(context::replay_response(&response));
        }
        PreparedRebindOperation::First(prepared) => prepared,
    };
    let (subject, device_id) = {
        let effect = prepared.effect_authority();
        let subject = effect.subject().to_owned();
        let device_id = effect.device_id();
        prelude::persist_rebind_bootstrap_effects(&mut transaction, &effect)
            .await
            .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?;
        (subject, device_id)
    };

    // The exact old-state scope remains locked through the CAS and this one
    // post-write projection, so the output is the durable terminal state.
    let view = read_device_view(&mut transaction, &subject, device_id)
        .await
        .map_err(|error| directory_failure(ENDPOINT, error))?
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    let output =
        chat_dto::rebind_device_authentication::RebindDeviceAuthenticationOutput::<DefaultStr> {
            device: device_view_from_directory(&view),
            extra_data: None,
        };
    let response_bytes =
        serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(ENDPOINT))?;

    prelude::complete_rebind_bootstrap_operation(
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
