use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::Utc;
use jacquard_axum::ExtractXrpc;

use crate::{
    auth::{
        device_auth::{
            begin_binding, complete_binding, parse_binding_challenge_id,
            verify_gateway_enrollment_request, DeviceAuthError, VerifiedRequestTarget,
        },
        AuthUser, VerifiedGatewayBearer,
    },
    generated::blue_catbird::mlsChat::{
        begin_device_auth_binding::{
            BeginDeviceAuthBindingError, BeginDeviceAuthBindingOutput,
            BeginDeviceAuthBindingRequest,
        },
        complete_device_auth_binding::{
            CompleteDeviceAuthBindingError, CompleteDeviceAuthBindingOutput,
            CompleteDeviceAuthBindingRequest,
        },
    },
    metrics::{
        record_device_auth_binding, DeviceAuthMetricEndpoint as MetricEndpoint,
        DeviceAuthMetricOutcome as MetricOutcome,
    },
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const DPOP_HEADER: &str = "dpop";

const MSG_DPOP_REQUIRED: &str = "A single DPoP proof is required";
const MSG_UNAUTHORIZED: &str = "The device proof is not authorized";
const MSG_INVALID_DEVICE_ID: &str = "The device identifier is invalid";
const MSG_DEVICE_NOT_FOUND: &str = "The active device registration was not found";
const MSG_BINDING_UNAVAILABLE: &str = "Device binding is temporarily unavailable";
const MSG_CHALLENGE_NOT_FOUND: &str = "The binding challenge was not found";
const MSG_CHALLENGE_EXPIRED: &str = "The binding challenge has expired";
const MSG_CHALLENGE_USED: &str = "The binding challenge was already used";
const MSG_BINDING_MISMATCH: &str = "The binding challenge does not match this device";
const MSG_INVALID_SIGNATURE: &str = "The device identity signature is invalid";

#[derive(Debug)]
pub struct BeginBindingHttpError(pub(crate) StatusCode, BeginDeviceAuthBindingError);

impl IntoResponse for BeginBindingHttpError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

#[derive(Debug)]
pub struct CompleteBindingHttpError(pub(crate) StatusCode, CompleteDeviceAuthBindingError);

impl IntoResponse for CompleteBindingHttpError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

pub(crate) fn validate_device_id(value: &str) -> Result<(), ()> {
    if (1..=64).contains(&value.len())
        && value.trim() == value
        && !value.chars().any(char::is_whitespace)
    {
        Ok(())
    } else {
        Err(())
    }
}

pub(crate) fn validate_challenge_id(value: &str) -> Result<uuid::Uuid, ()> {
    if !(1..=128).contains(&value.len()) || value.trim() != value {
        return Err(());
    }
    parse_binding_challenge_id(value).map_err(|_| ())
}

pub(crate) fn validate_signature(value: &[u8]) -> Result<(), ()> {
    (value.len() == 64).then_some(()).ok_or(())
}

/// Extract exactly one DPoP field-value. Header combination is deliberately
/// forbidden because a proof JWT is a singleton security credential.
pub(crate) fn extract_dpop_proof(headers: &HeaderMap) -> Result<&str, StatusCode> {
    let mut values = headers.get_all(DPOP_HEADER).iter();
    let value = values.next().ok_or(StatusCode::UNAUTHORIZED)?;
    if values.next().is_some() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let proof = value.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
    if proof.is_empty() || proof.trim() != proof || proof.contains(',') {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(proof)
}

fn begin_dpop_error(headers: &HeaderMap) -> BeginBindingHttpError {
    if headers.get_all(DPOP_HEADER).iter().next().is_none() {
        BeginBindingHttpError(
            StatusCode::UNAUTHORIZED,
            BeginDeviceAuthBindingError::DpopRequired(Some(MSG_DPOP_REQUIRED.into())),
        )
    } else {
        BeginBindingHttpError(
            StatusCode::UNAUTHORIZED,
            BeginDeviceAuthBindingError::Unauthorized(Some(MSG_UNAUTHORIZED.into())),
        )
    }
}

fn complete_dpop_error(headers: &HeaderMap) -> CompleteBindingHttpError {
    if headers.get_all(DPOP_HEADER).iter().next().is_none() {
        CompleteBindingHttpError(
            StatusCode::UNAUTHORIZED,
            CompleteDeviceAuthBindingError::DpopRequired(Some(MSG_DPOP_REQUIRED.into())),
        )
    } else {
        CompleteBindingHttpError(
            StatusCode::UNAUTHORIZED,
            CompleteDeviceAuthBindingError::Unauthorized(Some(MSG_UNAUTHORIZED.into())),
        )
    }
}

pub(crate) fn begin_error_contract(error: DeviceAuthError) -> BeginBindingHttpError {
    match error {
        DeviceAuthError::RegistryMismatch => BeginBindingHttpError(
            StatusCode::NOT_FOUND,
            BeginDeviceAuthBindingError::DeviceNotFound(Some(MSG_DEVICE_NOT_FOUND.into())),
        ),
        DeviceAuthError::Storage(_) => BeginBindingHttpError(
            StatusCode::SERVICE_UNAVAILABLE,
            BeginDeviceAuthBindingError::BindingUnavailable(Some(MSG_BINDING_UNAVAILABLE.into())),
        ),
        _ => BeginBindingHttpError(
            StatusCode::UNAUTHORIZED,
            BeginDeviceAuthBindingError::Unauthorized(Some(MSG_UNAUTHORIZED.into())),
        ),
    }
}

pub(crate) fn complete_error_contract(error: DeviceAuthError) -> CompleteBindingHttpError {
    match error {
        DeviceAuthError::ChallengeNotFound => CompleteBindingHttpError(
            StatusCode::NOT_FOUND,
            CompleteDeviceAuthBindingError::ChallengeNotFound(Some(MSG_CHALLENGE_NOT_FOUND.into())),
        ),
        DeviceAuthError::ChallengeExpired => CompleteBindingHttpError(
            StatusCode::GONE,
            CompleteDeviceAuthBindingError::ChallengeExpired(Some(MSG_CHALLENGE_EXPIRED.into())),
        ),
        DeviceAuthError::ChallengeAlreadyUsed => CompleteBindingHttpError(
            StatusCode::CONFLICT,
            CompleteDeviceAuthBindingError::ChallengeAlreadyUsed(Some(MSG_CHALLENGE_USED.into())),
        ),
        DeviceAuthError::BindingMismatch => CompleteBindingHttpError(
            StatusCode::CONFLICT,
            CompleteDeviceAuthBindingError::BindingMismatch(Some(MSG_BINDING_MISMATCH.into())),
        ),
        DeviceAuthError::InvalidIdentitySignature => CompleteBindingHttpError(
            StatusCode::FORBIDDEN,
            CompleteDeviceAuthBindingError::InvalidSignature(Some(MSG_INVALID_SIGNATURE.into())),
        ),
        DeviceAuthError::RegistryMismatch => CompleteBindingHttpError(
            StatusCode::NOT_FOUND,
            CompleteDeviceAuthBindingError::DeviceNotFound(Some(MSG_DEVICE_NOT_FOUND.into())),
        ),
        DeviceAuthError::Storage(_) => CompleteBindingHttpError(
            StatusCode::SERVICE_UNAVAILABLE,
            CompleteDeviceAuthBindingError::BindingUnavailable(Some(
                MSG_BINDING_UNAVAILABLE.into(),
            )),
        ),
        _ => CompleteBindingHttpError(
            StatusCode::UNAUTHORIZED,
            CompleteDeviceAuthBindingError::Unauthorized(Some(MSG_UNAUTHORIZED.into())),
        ),
    }
}

fn begin_outcome(status: StatusCode) -> MetricOutcome {
    match status {
        StatusCode::BAD_REQUEST => MetricOutcome::InvalidInput,
        StatusCode::NOT_FOUND => MetricOutcome::NotFound,
        StatusCode::SERVICE_UNAVAILABLE => MetricOutcome::Unavailable,
        _ => MetricOutcome::Unauthorized,
    }
}

fn complete_outcome(status: StatusCode) -> MetricOutcome {
    match status {
        StatusCode::BAD_REQUEST => MetricOutcome::InvalidInput,
        StatusCode::NOT_FOUND => MetricOutcome::NotFound,
        StatusCode::CONFLICT => MetricOutcome::Conflict,
        StatusCode::GONE => MetricOutcome::Expired,
        StatusCode::FORBIDDEN => MetricOutcome::InvalidSignature,
        StatusCode::SERVICE_UNAVAILABLE => MetricOutcome::Unavailable,
        _ => MetricOutcome::Unauthorized,
    }
}

/// Begin device enrollment. `AuthUser` intentionally precedes both sealed
/// extension extractors so it is the only component able to mint them.
#[tracing::instrument(skip(pool, _auth_user, bearer, target, headers, input))]
pub async fn begin_device_auth_binding(
    State(pool): State<DbPool>,
    _auth_user: AuthUser,
    Extension(bearer): Extension<VerifiedGatewayBearer>,
    Extension(target): Extension<VerifiedRequestTarget>,
    headers: HeaderMap,
    ExtractXrpc(input): ExtractXrpc<BeginDeviceAuthBindingRequest>,
) -> Result<Json<BeginDeviceAuthBindingOutput>, BeginBindingHttpError> {
    let proof = extract_dpop_proof(&headers).map_err(|_| {
        let error = begin_dpop_error(&headers);
        record_device_auth_binding(MetricEndpoint::Begin, begin_outcome(error.0));
        error
    })?;
    let device_id = input.device_id.as_ref();
    if validate_device_id(device_id).is_err() {
        record_device_auth_binding(MetricEndpoint::Begin, MetricOutcome::InvalidInput);
        return Err(BeginBindingHttpError(
            StatusCode::BAD_REQUEST,
            BeginDeviceAuthBindingError::InvalidDeviceId(Some(MSG_INVALID_DEVICE_ID.into())),
        ));
    }

    let enrollment = verify_gateway_enrollment_request(&pool, proof, &bearer, &target, Utc::now())
        .await
        .map_err(|error| {
            let error = begin_error_contract(error);
            record_device_auth_binding(MetricEndpoint::Begin, begin_outcome(error.0));
            error
        })?;
    if enrollment.device_id() != device_id {
        record_device_auth_binding(MetricEndpoint::Begin, MetricOutcome::InvalidInput);
        return Err(BeginBindingHttpError(
            StatusCode::BAD_REQUEST,
            BeginDeviceAuthBindingError::InvalidDeviceId(Some(MSG_INVALID_DEVICE_ID.into())),
        ));
    }

    let challenge = begin_binding(&pool, &enrollment, Utc::now())
        .await
        .map_err(|error| {
            let error = begin_error_contract(error);
            record_device_auth_binding(MetricEndpoint::Begin, begin_outcome(error.0));
            error
        })?;
    let challenge_bytes = challenge.challenge_bytes();
    if !(1..=512).contains(&challenge_bytes.len()) || challenge.binding_version != 1 {
        record_device_auth_binding(MetricEndpoint::Begin, MetricOutcome::Unavailable);
        return Err(BeginBindingHttpError(
            StatusCode::SERVICE_UNAVAILABLE,
            BeginDeviceAuthBindingError::BindingUnavailable(Some(MSG_BINDING_UNAVAILABLE.into())),
        ));
    }

    record_device_auth_binding(MetricEndpoint::Begin, MetricOutcome::Success);
    Ok(Json(BeginDeviceAuthBindingOutput {
        binding_version: i64::from(challenge.binding_version),
        challenge: challenge_bytes.into(),
        challenge_id: challenge.challenge_id.to_string().into(),
        expires_at: chrono_to_datetime(challenge.expires_at),
        extra_data: Default::default(),
    }))
}

/// Complete device enrollment under the same verified gateway/DPoP tuple.
#[tracing::instrument(skip(pool, _auth_user, bearer, target, headers, input))]
pub async fn complete_device_auth_binding(
    State(pool): State<DbPool>,
    _auth_user: AuthUser,
    Extension(bearer): Extension<VerifiedGatewayBearer>,
    Extension(target): Extension<VerifiedRequestTarget>,
    headers: HeaderMap,
    ExtractXrpc(input): ExtractXrpc<CompleteDeviceAuthBindingRequest>,
) -> Result<Json<CompleteDeviceAuthBindingOutput>, CompleteBindingHttpError> {
    let proof = extract_dpop_proof(&headers).map_err(|_| {
        let error = complete_dpop_error(&headers);
        record_device_auth_binding(MetricEndpoint::Complete, complete_outcome(error.0));
        error
    })?;
    let challenge_id = validate_challenge_id(input.challenge_id.as_ref()).map_err(|_| {
        record_device_auth_binding(MetricEndpoint::Complete, MetricOutcome::NotFound);
        CompleteBindingHttpError(
            StatusCode::NOT_FOUND,
            CompleteDeviceAuthBindingError::ChallengeNotFound(Some(MSG_CHALLENGE_NOT_FOUND.into())),
        )
    })?;
    if validate_signature(&input.signature).is_err() {
        record_device_auth_binding(MetricEndpoint::Complete, MetricOutcome::InvalidInput);
        return Err(CompleteBindingHttpError(
            StatusCode::BAD_REQUEST,
            CompleteDeviceAuthBindingError::InvalidSignature(Some(MSG_INVALID_SIGNATURE.into())),
        ));
    }

    let enrollment = verify_gateway_enrollment_request(&pool, proof, &bearer, &target, Utc::now())
        .await
        .map_err(|error| {
            let error = complete_error_contract(error);
            record_device_auth_binding(MetricEndpoint::Complete, complete_outcome(error.0));
            error
        })?;
    let completed = complete_binding(
        &pool,
        &enrollment,
        challenge_id,
        &input.signature,
        Utc::now(),
    )
    .await
    .map_err(|error| {
        let error = complete_error_contract(error);
        record_device_auth_binding(MetricEndpoint::Complete, complete_outcome(error.0));
        error
    })?;

    record_device_auth_binding(MetricEndpoint::Complete, MetricOutcome::Success);
    Ok(Json(CompleteDeviceAuthBindingOutput {
        binding_version: i64::from(completed.version),
        bound_at: chrono_to_datetime(completed.bound_at),
        device_id: completed.device_id.into(),
        extra_data: Default::default(),
    }))
}
