//! `blue.catbird.chat.rebindDeviceAuthentication` — rebind-bootstrap DPoP rotation.
//!
//! Reads the device view BEFORE persisting the rebind (a rebind rotates only the
//! DPoP binding + auth generation, never the key packages, so pre == post on
//! counts / key id / createdAt) and returns a `deviceView` that overrides exactly
//! the three fields the mutation changes: `dpopJkt` becomes the new proven
//! thumbprint, `authGeneration` increments by one, and `updatedAt` is the trusted
//! request instant. A live-DB conformance test asserts the post-rebind
//! `read_device_view` matches the returned view on counts + key id + createdAt.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use catbird_atproto::generated::blue_catbird::chat as chat_dto;
use jacquard_common::deps::smol_str::SmolStr;
use jacquard_common::DefaultStr;

use crate::chat_protocol::error::ChatEndpoint;
use crate::chat_protocol::repository::auth::{self, RebindBusinessOutcome};
use crate::chat_protocol::repository::device_directory::read_device_view;
use crate::sqlx_jacquard::chrono_to_datetime;
use crate::storage::DbPool;

use super::context::{self, Admission};
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
    let authority = match context::admit_rebind(pool, runtime, ENDPOINT, headers, body).await? {
        Admission::Replay(response) => return Ok(response),
        Admission::Execute(authority) => authority,
    };

    let subject = authority.subject().as_str().to_owned();
    let device_uuid = uuid::Uuid::parse_str(authority.device_id().as_str())
        .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let trusted_at = authority.trusted_instant().datetime();

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let guard = match auth::prepare_rebind_business(&mut transaction, &authority)
        .await
        .map_err(|error| context::auth_repository_failure(ENDPOINT, error))?
    {
        RebindBusinessOutcome::CompletedReplay(response) => {
            return Ok(context::replay_response(&response));
        }
        RebindBusinessOutcome::FirstExecution(guard) => guard,
    };

    // Pre-persist read: counts / key id / createdAt / signing key / status are all
    // unchanged by the rebind, so this is the post-state for every field except
    // the three the rebind rotates below.
    let view = read_device_view(&mut transaction, &subject, device_uuid)
        .await
        .map_err(|error| directory_failure(ENDPOINT, error))?
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;

    let mut device = device_view_from_directory(&view);
    device.dpop_jkt = SmolStr::from(authority.dpop_jkt().as_str());
    device.auth_generation = view
        .auth_generation
        .checked_add(1)
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    device.updated_at = chrono_to_datetime(trusted_at);

    let output =
        chat_dto::rebind_device_authentication::RebindDeviceAuthenticationOutput::<DefaultStr> {
            device,
            extra_data: None,
        };
    let response_bytes =
        serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(ENDPOINT))?;

    auth::persist_rebind_and_completion(
        &mut transaction,
        &authority,
        guard,
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
