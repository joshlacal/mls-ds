// Replay consumption and database-bound authorization for clean chat.
//
// This is the authority seam between cryptographic evidence and business
// mutations. Every cryptographically valid token/proof/auth-transaction set
// is inserted as one PostgreSQL statement. Semantic authorization failures
// are deliberately returned only after that transaction commits, so a bad
// device binding can never be retried with the same proof material.

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, QueryBuilder, Transaction};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

#[cfg(test)]
use super::super::validation::{ed25519_key_id, BareDid, KeyThumbprint};
use super::super::{
    dpop::{self, PreReplayCryptographicVerification, VerifiedChatDeviceRequest},
    model::AuthPrimitiveError,
    transcript::{
        decode_canonical_signed_mutation, verify_ed25519_strict, CanonicalRebindBootstrap,
        CanonicalSignedMutation, CanonicalValueRef, SignedMutationKind, VerifiedEnrollmentBody,
        VerifiedMutationProjection, VerifiedSignedMutation,
    },
    validation::{CanonicalUuidV4, NumericDate},
};

const UNIQUE_VIOLATION: &str = "23505";

#[derive(Debug, Error)]
pub(crate) enum AuthRepositoryError {
    #[error("clean-chat replay material has already been consumed")]
    ReplayDetected,
    #[error("clean-chat device is not registered")]
    DeviceNotRegistered,
    #[error("clean-chat device is already registered")]
    DeviceAlreadyRegistered,
    #[error("clean-chat device is revoked")]
    DeviceRevoked,
    #[error("clean-chat immutable device key is missing")]
    DeviceKeyMissing,
    #[error("clean-chat immutable device key is revoked")]
    DeviceKeyRevoked,
    #[error("clean-chat request is bound to a different actor, endpoint, or key")]
    RequestBindingMismatch,
    #[error("clean-chat DPoP binding no longer matches the stored device")]
    DpopBindingMismatch,
    #[error("clean-chat authentication generation no longer matches the stored device")]
    AuthenticationGenerationMismatch,
    #[error("clean-chat idempotency key conflicts with a completed request")]
    IdempotencyConflict,
    #[error("clean-chat idempotency record failed its independent integrity check")]
    CorruptIdempotencyRecord,
    #[error("clean-chat request does not carry exact accepted wrapper bytes")]
    MissingAcceptedRequestBytes,
    #[error("clean-chat endpoint does not accept this authorization shape")]
    UnsupportedAuthorizationShape,
    #[error("invalid clean-chat completion record")]
    InvalidCompletion,
    #[error(transparent)]
    Primitive(#[from] AuthPrimitiveError),
    #[error("clean-chat authorization database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryAuthorityClass {
    ExistingDevice,
    EnrollmentBootstrap,
    RebindBootstrap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplayAuditIds {
    token: Uuid,
    proof: Uuid,
    auth_transaction: Option<Uuid>,
}

impl ReplayAuditIds {
    pub(crate) fn token(self) -> Uuid {
        self.token
    }

    pub(crate) fn proof(self) -> Uuid {
        self.proof
    }

    pub(crate) fn auth_transaction(self) -> Option<Uuid> {
        self.auth_transaction
    }
}

/// Sealed proof that the repository committed an exact replay set and locked
/// the database binding used for authorization. Its fields and constructors
/// are private to this module; sibling modules can inspect but cannot mint it.
#[derive(Debug)]
pub(crate) struct RepositoryAuthorityReceipt {
    replay_ids: ReplayAuditIds,
    class: RepositoryAuthorityClass,
    operation_id: Option<Uuid>,
    locked_jkt: Option<String>,
    locked_auth_generation: Option<i64>,
    locked_key_id: Option<String>,
    locked_signing_key_sha256: Option<[u8; 32]>,
}

impl RepositoryAuthorityReceipt {
    fn enrollment(replay_ids: ReplayAuditIds, operation_id: Uuid) -> Self {
        Self {
            replay_ids,
            class: RepositoryAuthorityClass::EnrollmentBootstrap,
            operation_id: Some(operation_id),
            locked_jkt: None,
            locked_auth_generation: None,
            locked_key_id: None,
            locked_signing_key_sha256: None,
        }
    }

    fn existing(
        replay_ids: ReplayAuditIds,
        operation_id: Option<Uuid>,
        state: &LockedDeviceAuthority,
        class: RepositoryAuthorityClass,
    ) -> Self {
        Self {
            replay_ids,
            class,
            operation_id,
            locked_jkt: Some(state.dpop_jkt.clone()),
            locked_auth_generation: Some(state.auth_generation),
            locked_key_id: Some(state.key_id.clone()),
            locked_signing_key_sha256: Some(Sha256::digest(&state.signing_public_key).into()),
        }
    }

    pub(crate) fn replay_ids(&self) -> ReplayAuditIds {
        self.replay_ids
    }

    pub(crate) fn class(&self) -> RepositoryAuthorityClass {
        self.class
    }

    pub(crate) fn operation_id(&self) -> Option<Uuid> {
        self.operation_id
    }

    pub(crate) fn locked_jkt(&self) -> Option<&str> {
        self.locked_jkt.as_deref()
    }

    pub(crate) fn locked_auth_generation(&self) -> Option<i64> {
        self.locked_auth_generation
    }

    pub(crate) fn locked_key_id(&self) -> Option<&str> {
        self.locked_key_id.as_deref()
    }

    pub(crate) fn locked_signing_key_sha256(&self) -> Option<&[u8; 32]> {
        self.locked_signing_key_sha256.as_ref()
    }
}

/// Narrow Reset integration fixture. It derives the operation identifier and
/// immutable signer binding from an already verified Reset mutation and cannot
/// mint receipts for other protocol operations.
#[cfg(test)]
pub(crate) fn reset_existing_device_receipt_for_test(
    mutation: &VerifiedSignedMutation,
    dpop_jkt: &str,
    signing_public_key: &[u8],
) -> Result<RepositoryAuthorityReceipt, AuthRepositoryError> {
    let operation_id = match mutation.projection() {
        VerifiedMutationProjection::ResetRequest(reset) => {
            Uuid::from_bytes(*reset.reset_request_id().as_bytes())
        }
        VerifiedMutationProjection::ResetActivation(reset) => {
            Uuid::from_bytes(*reset.transition_id().as_bytes())
        }
        _ => return Err(AuthRepositoryError::UnsupportedAuthorizationShape),
    };
    let auth_generation = i64::try_from(mutation.auth_generation())
        .ok()
        .filter(|generation| *generation > 0)
        .ok_or(AuthRepositoryError::RequestBindingMismatch)?;
    if operation_id.get_version_num() != 4
        || operation_id.get_variant() != uuid::Variant::RFC4122
        || KeyThumbprint::parse(dpop_jkt).is_err()
        || ed25519_key_id(signing_public_key)
            .map(|key_id| key_id.as_str() != mutation.key_id().as_str())
            .unwrap_or(true)
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    Ok(RepositoryAuthorityReceipt {
        replay_ids: ReplayAuditIds {
            token: Uuid::new_v4(),
            proof: Uuid::new_v4(),
            auth_transaction: None,
        },
        class: RepositoryAuthorityClass::ExistingDevice,
        operation_id: Some(operation_id),
        locked_jkt: Some(dpop_jkt.to_owned()),
        locked_auth_generation: Some(auth_generation),
        locked_key_id: Some(mutation.key_id().as_str().to_owned()),
        locked_signing_key_sha256: Some(Sha256::digest(signing_public_key).into()),
    })
}

pub(crate) enum AuthorizationOutcome {
    FirstExecution(VerifiedChatDeviceRequest),
    CompletedReplay(CompletedIdempotentResponse),
}

pub(crate) struct CompletedIdempotentResponse {
    status: i32,
    response_bytes: Vec<u8>,
    response_sha256: [u8; 32],
    event_position: Option<i64>,
    completed_at: DateTime<Utc>,
}

impl fmt::Debug for AuthorizationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirstExecution(authority) => formatter
                .debug_tuple("AuthorizationOutcome::FirstExecution")
                .field(authority)
                .finish(),
            Self::CompletedReplay(_) => {
                formatter.write_str("AuthorizationOutcome::CompletedReplay(<redacted>)")
            }
        }
    }
}

impl fmt::Debug for CompletedIdempotentResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletedIdempotentResponse(<redacted>)")
    }
}

/// Sealed projection of the registration/key rows locked in the caller-owned
/// business transaction. Downstream planners consume this value instead of
/// issuing a second query with a different lock order.
#[derive(Debug)]
pub(crate) struct BusinessAuthorityGuard {
    transaction_id: String,
    class: RepositoryAuthorityClass,
    subject: String,
    device_id: Uuid,
    stored_dpop_jkt: Option<String>,
    stored_auth_generation: Option<i64>,
    stored_key_id: Option<String>,
    stored_signing_public_key: Option<Vec<u8>>,
    trusted_instant: DateTime<Utc>,
}

/// Opaque proof that this transaction acquired the globally canonical
/// operation advisory lock before any identity-domain lock. Construction is
/// confined to `reserve_canonical_operation`.
pub(super) struct CanonicalOperationReservationGuard {
    transaction_id: String,
    operation_id: Uuid,
}

impl fmt::Debug for CanonicalOperationReservationGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalOperationReservationGuard(<sealed>)")
    }
}

impl CanonicalOperationReservationGuard {
    pub(super) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(super) fn operation_id(&self) -> Uuid {
        self.operation_id
    }
}

/// Closed authority projection for the G6 lock prelude. It can only be minted
/// from a repository-issued `BusinessAuthorityGuard`; no field constructor,
/// clone, or loose-value reseal exists.
#[derive(Debug)]
pub(crate) struct G6BusinessAuthorityBinding {
    transaction_id: String,
    actor_did: String,
    actor_device_id: Uuid,
    dpop_jkt: String,
    auth_generation: i64,
    key_id: String,
    signing_public_key: Vec<u8>,
    trusted_instant: DateTime<Utc>,
    domain_digest: [u8; 32],
}

impl G6BusinessAuthorityBinding {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(crate) fn actor_did(&self) -> &str {
        &self.actor_did
    }

    pub(crate) fn actor_device_id(&self) -> Uuid {
        self.actor_device_id
    }

    pub(crate) fn dpop_jkt(&self) -> &str {
        &self.dpop_jkt
    }

    pub(crate) fn auth_generation(&self) -> i64 {
        self.auth_generation
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn signing_public_key(&self) -> &[u8] {
        &self.signing_public_key
    }

    pub(crate) fn trusted_instant(&self) -> DateTime<Utc> {
        self.trusted_instant
    }

    pub(crate) fn domain_digest(&self) -> &[u8; 32] {
        &self.domain_digest
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        transaction_id: String,
        actor_did: String,
        actor_device_id: Uuid,
        dpop_jkt: String,
        auth_generation: i64,
        key_id: String,
        signing_public_key: Vec<u8>,
        trusted_instant: DateTime<Utc>,
    ) -> Self {
        let domain_digest = g6_business_authority_digest(
            &transaction_id,
            &actor_did,
            actor_device_id,
            &dpop_jkt,
            auth_generation,
            &key_id,
            &signing_public_key,
            trusted_instant,
        );
        Self {
            transaction_id,
            actor_did,
            actor_device_id,
            dpop_jkt,
            auth_generation,
            key_id,
            signing_public_key,
            trusted_instant,
            domain_digest,
        }
    }
}

impl BusinessAuthorityGuard {
    /// Exact PostgreSQL transaction identity that held the device/key lock.
    /// Other non-forgeable repository guards must carry the same value before
    /// state planning or persistence may consume them together.
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(crate) fn class(&self) -> RepositoryAuthorityClass {
        self.class
    }

    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }

    pub(crate) fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub(crate) fn stored_dpop_jkt(&self) -> Option<&str> {
        self.stored_dpop_jkt.as_deref()
    }

    pub(crate) fn stored_auth_generation(&self) -> Option<i64> {
        self.stored_auth_generation
    }

    pub(crate) fn stored_key_id(&self) -> Option<&str> {
        self.stored_key_id.as_deref()
    }

    pub(crate) fn stored_signing_public_key(&self) -> Option<&[u8]> {
        self.stored_signing_public_key.as_deref()
    }

    pub(crate) fn trusted_instant(&self) -> DateTime<Utc> {
        self.trusted_instant
    }

    /// Seal this already-locked authority for the G6 prelude without exposing
    /// any constructor that accepts caller-selected authority fields.
    pub(crate) fn seal_g6_binding(&self) -> Option<G6BusinessAuthorityBinding> {
        if self.class != RepositoryAuthorityClass::ExistingDevice {
            return None;
        }
        let dpop_jkt = self.stored_dpop_jkt.as_ref()?.clone();
        let auth_generation = self.stored_auth_generation?;
        let key_id = self.stored_key_id.as_ref()?.clone();
        let signing_public_key = self.stored_signing_public_key.as_ref()?.clone();
        if auth_generation <= 0 || signing_public_key.is_empty() {
            return None;
        }
        let domain_digest = g6_business_authority_digest(
            &self.transaction_id,
            &self.subject,
            self.device_id,
            &dpop_jkt,
            auth_generation,
            &key_id,
            &signing_public_key,
            self.trusted_instant,
        );
        Some(G6BusinessAuthorityBinding {
            transaction_id: self.transaction_id.clone(),
            actor_did: self.subject.clone(),
            actor_device_id: self.device_id,
            dpop_jkt,
            auth_generation,
            key_id,
            signing_public_key,
            trusted_instant: self.trusted_instant,
            domain_digest,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn g6_business_authority_digest(
    transaction_id: &str,
    actor_did: &str,
    actor_device_id: Uuid,
    dpop_jkt: &str,
    auth_generation: i64,
    key_id: &str,
    signing_public_key: &[u8],
    trusted_instant: DateTime<Utc>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-G6-BUSINESS-AUTHORITY\0");
    for value in [
        transaction_id.as_bytes(),
        actor_did.as_bytes(),
        dpop_jkt.as_bytes(),
        key_id.as_bytes(),
        signing_public_key,
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(actor_device_id.as_bytes());
    digest.update(auth_generation.to_be_bytes());
    digest.update(trusted_instant.timestamp_millis().to_be_bytes());
    digest.finalize().into()
}

impl CompletedIdempotentResponse {
    #[cfg(test)]
    pub(super) fn debug_redaction_sentinel_for_test(status: i32, response_bytes: Vec<u8>) -> Self {
        Self {
            status,
            response_sha256: Sha256::digest(&response_bytes).into(),
            response_bytes,
            event_position: Some(9_223_372_036_854_775_000),
            completed_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }
    }

    pub(crate) fn status(&self) -> i32 {
        self.status
    }

    pub(crate) fn response_bytes(&self) -> &[u8] {
        &self.response_bytes
    }

    pub(crate) fn response_sha256(&self) -> &[u8; 32] {
        &self.response_sha256
    }

    pub(crate) fn event_position(&self) -> Option<i64> {
        self.event_position
    }

    pub(crate) fn completed_at(&self) -> DateTime<Utc> {
        self.completed_at
    }
}

enum Arbitration<T> {
    First(T),
    Completed(CompletedIdempotentResponse),
}

impl<T: fmt::Debug> fmt::Debug for Arbitration<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::First(value) => formatter
                .debug_tuple("Arbitration::First")
                .field(value)
                .finish(),
            Self::Completed(_) => formatter.write_str("Arbitration::Completed(<redacted>)"),
        }
    }
}

#[derive(Debug)]
struct FirstSignedExecution {
    receipt: RepositoryAuthorityReceipt,
    signing_public_key: Vec<u8>,
}

#[derive(Debug, FromRow)]
struct DeviceRow {
    status: String,
    dpop_jkt: String,
    auth_generation: i64,
}

#[derive(Debug, FromRow)]
struct DeviceKeyRow {
    key_id: String,
    signing_public_key: Vec<u8>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
struct LockedDeviceAuthority {
    dpop_jkt: String,
    auth_generation: i64,
    key_id: String,
    signing_public_key: Vec<u8>,
}

#[derive(Debug, FromRow)]
struct IdempotencyRow {
    request_digest: Vec<u8>,
    accepted_request_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    signature: Option<Vec<u8>>,
    completed_status: i32,
    response_bytes: Vec<u8>,
    response_sha256: Vec<u8>,
    event_position: Option<i64>,
    historical_jkt: Option<String>,
    current_jkt: Option<String>,
    completed_at: DateTime<Utc>,
}

struct RequestMaterial {
    operation_id: Uuid,
    accepted_request_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: [u8; 32],
    signature: [u8; 64],
    historical_jkt: Option<String>,
    current_jkt: Option<String>,
}

pub(crate) enum BusinessIdempotencyOutcome {
    FirstExecution(BusinessIdempotencyGuard),
    CompletedReplay(CompletedIdempotentResponse),
}

impl fmt::Debug for BusinessIdempotencyOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirstExecution(guard) => formatter
                .debug_tuple("BusinessIdempotencyOutcome::FirstExecution")
                .field(guard)
                .finish(),
            Self::CompletedReplay(_) => {
                formatter.write_str("BusinessIdempotencyOutcome::CompletedReplay(<redacted>)")
            }
        }
    }
}

/// Non-forgeable claim on one idempotency key in one PostgreSQL transaction.
/// Completion recording requires this guard, closing the skip-arbitration API
/// path and detecting attempts to carry the guard into another transaction.
#[derive(Debug)]
pub(crate) struct BusinessIdempotencyGuard {
    transaction_id: String,
    subject: String,
    endpoint: String,
    operation_id: Uuid,
    request_digest: [u8; 32],
    signature: [u8; 64],
}

pub(crate) enum EnrollmentBusinessOutcome {
    FirstExecution(EnrollmentBusinessGuard),
    CompletedReplay(CompletedIdempotentResponse),
}

impl fmt::Debug for EnrollmentBusinessOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirstExecution(guard) => formatter
                .debug_tuple("EnrollmentBusinessOutcome::FirstExecution")
                .field(guard)
                .finish(),
            Self::CompletedReplay(_) => {
                formatter.write_str("EnrollmentBusinessOutcome::CompletedReplay(<redacted>)")
            }
        }
    }
}

/// Transaction-bound enrollment authority. This value is intentionally
/// non-Clone and can only be minted after the caller owns both the operation
/// claim and the canonical principal/device identity lock.
#[derive(Debug)]
pub(crate) struct EnrollmentBusinessGuard {
    idempotency: BusinessIdempotencyGuard,
    authority: BusinessAuthorityGuard,
}

pub(crate) enum RebindBusinessOutcome {
    FirstExecution(RebindBusinessGuard),
    CompletedReplay(CompletedIdempotentResponse),
}

impl fmt::Debug for RebindBusinessOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirstExecution(guard) => formatter
                .debug_tuple("RebindBusinessOutcome::FirstExecution")
                .field(guard)
                .finish(),
            Self::CompletedReplay(_) => {
                formatter.write_str("RebindBusinessOutcome::CompletedReplay(<redacted>)")
            }
        }
    }
}

/// Transaction-bound rebind authority. This value is intentionally non-Clone
/// and carries the exact old device/key rows locked by the caller.
#[derive(Debug)]
pub(crate) struct RebindBusinessGuard {
    idempotency: BusinessIdempotencyGuard,
    authority: BusinessAuthorityGuard,
}

#[derive(Debug)]
struct ReplayInsertRow {
    replay_id: Uuid,
    replay_namespace: &'static str,
    issuer: Option<String>,
    token_jti: Option<Uuid>,
    jkt: Option<String>,
    proof_jti_bytes: Option<Vec<u8>>,
    auth_txn: Option<Uuid>,
    token_hash: Option<Vec<u8>>,
    proof_hash: Option<Vec<u8>>,
    subject_did: Option<String>,
    audience: Option<String>,
    lxm: Option<String>,
    device_id: Option<Uuid>,
    chat_instance: Option<Uuid>,
    htu: Option<String>,
    htm: Option<String>,
    key_id: Option<String>,
    signing_key_sha256: Option<Vec<u8>>,
    enrollment_transcript_sha256: Option<Vec<u8>>,
    auth_time: Option<DateTime<Utc>>,
    token_iat: Option<DateTime<Utc>>,
    token_exp: Option<DateTime<Utc>>,
    proof_iat: Option<DateTime<Utc>>,
    consumed_at: DateTime<Utc>,
    retain_until: DateTime<Utc>,
}

pub(crate) async fn authorize_unsigned_request(
    pool: &PgPool,
    pre_replay: PreReplayCryptographicVerification,
) -> Result<AuthorizationOutcome, AuthRepositoryError> {
    let unsupported_shape = endpoint_accepts_signed_mutation(pre_replay.endpoint().as_str())
        || pre_replay.enrollment_body().is_some()
        || pre_replay.rebind_bootstrap().is_some();

    let mut transaction = pool.begin().await?;
    let replay_ids = consume_replay_set(&mut transaction, &pre_replay).await?;
    let decision = if unsupported_shape {
        Err(AuthRepositoryError::UnsupportedAuthorizationShape)
    } else {
        match lock_existing_authority(&mut transaction, &pre_replay).await {
            Ok(state) => Ok(RepositoryAuthorityReceipt::existing(
                replay_ids,
                None,
                &state,
                RepositoryAuthorityClass::ExistingDevice,
            )),
            Err(error) => Err(error),
        }
    };
    let receipt = commit_semantic_decision(transaction, decision).await?;
    Ok(AuthorizationOutcome::FirstExecution(
        dpop::mint_unsigned_repository_authority(pre_replay, receipt),
    ))
}

pub(crate) async fn authorize_signed_request(
    pool: &PgPool,
    pre_replay: PreReplayCryptographicVerification,
    canonical: CanonicalSignedMutation,
) -> Result<AuthorizationOutcome, AuthRepositoryError> {
    let unsupported_shape =
        !endpoint_accepts_kind(pre_replay.endpoint().as_str(), canonical.kind())
            || pre_replay.enrollment_body().is_some()
            || pre_replay.rebind_bootstrap().is_some()
            || pre_replay.auth_transaction_replay().is_some();

    let mut transaction = pool.begin().await?;
    let replay_ids = consume_replay_set(&mut transaction, &pre_replay).await?;
    let decision = if unsupported_shape {
        Err(AuthRepositoryError::UnsupportedAuthorizationShape)
    } else {
        arbitrate_signed(&mut transaction, &pre_replay, &canonical, replay_ids).await
    };
    let decision = commit_semantic_decision(transaction, decision).await?;
    match decision {
        Arbitration::Completed(response) => Ok(AuthorizationOutcome::CompletedReplay(response)),
        Arbitration::First(first) => {
            let authority = dpop::mint_signed_repository_authority(
                pre_replay,
                canonical,
                &first.signing_public_key,
                first.receipt,
            )?;
            Ok(AuthorizationOutcome::FirstExecution(authority))
        }
    }
}

pub(crate) async fn authorize_enrollment_request(
    pool: &PgPool,
    pre_replay: PreReplayCryptographicVerification,
) -> Result<AuthorizationOutcome, AuthRepositoryError> {
    let unsupported_shape = pre_replay.endpoint().as_str() != "blue.catbird.chat.enrollDevice"
        || pre_replay.enrollment_body().is_none()
        || pre_replay.rebind_bootstrap().is_some()
        || pre_replay.auth_transaction_replay().is_none();

    let mut transaction = pool.begin().await?;
    let replay_ids = consume_replay_set(&mut transaction, &pre_replay).await?;
    let decision = if unsupported_shape {
        Err(AuthRepositoryError::UnsupportedAuthorizationShape)
    } else {
        arbitrate_enrollment(&mut transaction, &pre_replay, replay_ids).await
    };
    let decision = commit_semantic_decision(transaction, decision).await?;
    match decision {
        Arbitration::Completed(response) => Ok(AuthorizationOutcome::CompletedReplay(response)),
        Arbitration::First(receipt) => {
            let authority = dpop::mint_enrollment_repository_authority(pre_replay, receipt)?;
            Ok(AuthorizationOutcome::FirstExecution(authority))
        }
    }
}

pub(crate) async fn authorize_rebind_request(
    pool: &PgPool,
    pre_replay: PreReplayCryptographicVerification,
) -> Result<AuthorizationOutcome, AuthRepositoryError> {
    let unsupported_shape = pre_replay.endpoint().as_str()
        != "blue.catbird.chat.rebindDeviceAuthentication"
        || pre_replay.rebind_bootstrap().is_none()
        || pre_replay.enrollment_body().is_some()
        || pre_replay.auth_transaction_replay().is_some();

    let mut transaction = pool.begin().await?;
    let replay_ids = consume_replay_set(&mut transaction, &pre_replay).await?;
    let decision = if unsupported_shape {
        Err(AuthRepositoryError::UnsupportedAuthorizationShape)
    } else {
        arbitrate_rebind(&mut transaction, &pre_replay, replay_ids).await
    };
    let decision = commit_semantic_decision(transaction, decision).await?;
    match decision {
        Arbitration::Completed(response) => Ok(AuthorizationOutcome::CompletedReplay(response)),
        Arbitration::First(first) => {
            let authority = dpop::mint_rebind_repository_authority(
                pre_replay,
                &first.signing_public_key,
                first.receipt,
            )?;
            Ok(AuthorizationOutcome::FirstExecution(authority))
        }
    }
}

/// Re-establishes the exact locked binding in the caller-owned business
/// transaction. Handlers must call this before making any mutation authorized
/// by `VerifiedChatDeviceRequest`.
pub(crate) async fn recheck_business_authority(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
) -> Result<BusinessAuthorityGuard, AuthRepositoryError> {
    let receipt = authority.repository_receipt();
    if receipt.class() == RepositoryAuthorityClass::EnrollmentBootstrap {
        lock_identity_slot(
            transaction,
            authority.subject().as_str(),
            canonical_uuid(authority.device_id()),
        )
        .await?;
        let existing: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM chat.devices WHERE user_did = $1 AND device_id = $2 FOR UPDATE",
        )
        .bind(authority.subject().as_str())
        .bind(canonical_uuid(authority.device_id()))
        .fetch_optional(&mut **transaction)
        .await?;
        return if existing.is_none() {
            let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
                .fetch_one(&mut **transaction)
                .await?;
            Ok(BusinessAuthorityGuard {
                transaction_id,
                class: receipt.class(),
                subject: authority.subject().as_str().to_owned(),
                device_id: canonical_uuid(authority.device_id()),
                stored_dpop_jkt: None,
                stored_auth_generation: None,
                stored_key_id: None,
                stored_signing_public_key: None,
                trusted_instant: authority.trusted_instant().datetime(),
            })
        } else {
            Err(AuthRepositoryError::DeviceAlreadyRegistered)
        };
    }

    let state = if receipt.class() == RepositoryAuthorityClass::RebindBootstrap {
        lock_device_and_key(
            transaction,
            authority.subject().as_str(),
            canonical_uuid(authority.device_id()),
        )
        .await?
    } else {
        lock_existing_authority(transaction, authority.pre_replay()).await?
    };
    if !locked_state_matches_receipt(receipt, &state) {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    Ok(BusinessAuthorityGuard {
        transaction_id,
        class: receipt.class(),
        subject: authority.subject().as_str().to_owned(),
        device_id: canonical_uuid(authority.device_id()),
        stored_dpop_jkt: Some(state.dpop_jkt),
        stored_auth_generation: Some(state.auth_generation),
        stored_key_id: Some(state.key_id),
        stored_signing_public_key: Some(state.signing_public_key),
        trusted_instant: authority.trusted_instant().datetime(),
    })
}

pub(super) async fn reserve_canonical_operation(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
) -> Result<CanonicalOperationReservationGuard, AuthRepositoryError> {
    let material = request_material_for_authority(authority)?;
    let lock_key = format!("chat-operation-id:{}", material.operation_id);
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut **transaction)
        .await?;
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    Ok(CanonicalOperationReservationGuard {
        transaction_id,
        operation_id: material.operation_id,
    })
}

#[derive(Debug, FromRow)]
pub(crate) struct LockedCanonicalDeviceProjection {
    user_did: String,
    device_id: Uuid,
    status: String,
    dpop_jkt: String,
    auth_generation: i64,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
pub(crate) struct LockedCanonicalKeyProjection {
    user_did: String,
    device_id: Uuid,
    key_id: String,
    signing_public_key: Vec<u8>,
    enrollment_auth_generation: i64,
    revoked_at: Option<DateTime<Utc>>,
}

pub(super) struct LockedCanonicalAuthorityScope {
    receipt_id: Uuid,
    actor: BusinessAuthorityGuard,
    principals: Vec<String>,
    devices: Vec<LockedCanonicalDeviceProjection>,
    keys: Vec<LockedCanonicalKeyProjection>,
    scope_digest: [u8; 32],
}

impl LockedCanonicalDeviceProjection {
    pub(crate) fn user_did(&self) -> &str {
        &self.user_did
    }

    pub(crate) fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub(crate) fn status(&self) -> &str {
        &self.status
    }

    pub(crate) fn dpop_jkt(&self) -> &str {
        &self.dpop_jkt
    }

    pub(crate) fn auth_generation(&self) -> i64 {
        self.auth_generation
    }

    pub(crate) fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }
}

impl LockedCanonicalKeyProjection {
    pub(crate) fn user_did(&self) -> &str {
        &self.user_did
    }

    pub(crate) fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    fn signing_public_key(&self) -> &[u8] {
        &self.signing_public_key
    }

    pub(crate) fn signing_public_key_sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.signing_public_key).into()
    }

    pub(crate) fn enrollment_auth_generation(&self) -> i64 {
        self.enrollment_auth_generation
    }

    pub(crate) fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }
}

impl LockedCanonicalAuthorityScope {
    pub(super) fn receipt_id(&self) -> Uuid {
        self.receipt_id
    }

    pub(super) fn transaction_id(&self) -> &str {
        self.actor.transaction_id()
    }

    pub(super) fn actor_class(&self) -> RepositoryAuthorityClass {
        self.actor.class()
    }

    pub(super) fn actor_did(&self) -> &str {
        self.actor.subject()
    }

    pub(super) fn actor_device_id(&self) -> Uuid {
        self.actor.device_id()
    }

    pub(super) fn actor_dpop_jkt(&self) -> Option<&str> {
        self.actor.stored_dpop_jkt()
    }

    pub(super) fn actor_auth_generation(&self) -> Option<i64> {
        self.actor.stored_auth_generation()
    }

    pub(super) fn actor_key_id(&self) -> Option<&str> {
        self.actor.stored_key_id()
    }

    pub(super) fn actor_signing_public_key(&self) -> Option<&[u8]> {
        self.actor.stored_signing_public_key()
    }

    pub(super) fn trusted_instant(&self) -> DateTime<Utc> {
        self.actor.trusted_instant()
    }

    pub(super) fn principals(&self) -> &[String] {
        &self.principals
    }

    pub(super) fn devices(&self) -> &[LockedCanonicalDeviceProjection] {
        &self.devices
    }

    pub(super) fn keys(&self) -> &[LockedCanonicalKeyProjection] {
        &self.keys
    }

    pub(super) fn signing_public_key_for(
        &self,
        did: &str,
        device_id: Uuid,
        key_id: &str,
        enrollment_auth_generation: i64,
    ) -> Option<&[u8]> {
        self.keys
            .iter()
            .find(|key| {
                key.user_did() == did
                    && key.device_id() == device_id
                    && key.key_id() == key_id
                    && key.enrollment_auth_generation() == enrollment_auth_generation
            })
            .map(|key| key.signing_public_key())
    }

    pub(super) fn actor_projected_signing_public_key(&self) -> Option<&[u8]> {
        let actor_key_id = self.actor.stored_key_id()?;
        let mut matches = self.keys.iter().filter(|key| {
            key.user_did() == self.actor.subject()
                && key.device_id() == self.actor.device_id()
                && key.key_id() == actor_key_id
        });
        let key = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(key.signing_public_key())
    }

    pub(super) fn scope_digest(&self) -> &[u8; 32] {
        &self.scope_digest
    }
}

/// Locks one already-canonical principal/device scope and projects the actor
/// from those exact rows. Non-actor devices may legitimately have no keys;
/// the actor must retain the exact active key bound by repository admission.
pub(super) async fn lock_canonical_business_authority_scope(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    operation: &CanonicalOperationReservationGuard,
    principals: &[String],
    devices: &[(String, Uuid)],
) -> Result<LockedCanonicalAuthorityScope, AuthRepositoryError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if operation.transaction_id != transaction_id
        || authority.repository_receipt().operation_id() != Some(operation.operation_id)
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let locked_principals: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT user_did
          FROM chat.principals
         WHERE user_did = ANY($1::text[])
         ORDER BY convert_to(user_did,'UTF8')
         FOR UPDATE
        "#,
    )
    .bind(principals)
    .fetch_all(&mut **transaction)
    .await?;
    if locked_principals != principals {
        return Err(AuthRepositoryError::DeviceNotRegistered);
    }

    let dids = devices
        .iter()
        .map(|(did, _)| did.clone())
        .collect::<Vec<_>>();
    let device_ids = devices.iter().map(|(_, id)| *id).collect::<Vec<_>>();
    let locked_devices: Vec<LockedCanonicalDeviceProjection> = sqlx::query_as(
        r#"
        WITH requested(user_did,device_id) AS (
            SELECT * FROM unnest($1::text[],$2::uuid[])
        )
        SELECT device.user_did,device.device_id,device.status,device.dpop_jkt,
               device.auth_generation,device.revoked_at
          FROM requested
          JOIN chat.devices device USING (user_did,device_id)
         ORDER BY convert_to(device.user_did,'UTF8'),uuid_send(device.device_id)
         FOR UPDATE OF device
        "#,
    )
    .bind(&dids)
    .bind(&device_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if locked_devices.len() != devices.len()
        || locked_devices
            .iter()
            .zip(devices)
            .any(|(row, expected)| row.user_did != expected.0 || row.device_id != expected.1)
    {
        return Err(AuthRepositoryError::DeviceNotRegistered);
    }

    let locked_keys: Vec<LockedCanonicalKeyProjection> = sqlx::query_as(
        r#"
        WITH requested(user_did,device_id) AS (
            SELECT * FROM unnest($1::text[],$2::uuid[])
        )
        SELECT key.user_did,key.device_id,key.key_id,key.signing_public_key,
               key.enrollment_auth_generation,key.revoked_at
          FROM requested
          JOIN chat.device_keys key USING (user_did,device_id)
         ORDER BY convert_to(key.user_did,'UTF8'),uuid_send(key.device_id),
                  convert_to(key.key_id,'UTF8')
         FOR UPDATE OF key
        "#,
    )
    .bind(&dids)
    .bind(&device_ids)
    .fetch_all(&mut **transaction)
    .await?;

    let actor_did = authority.subject().as_str();
    let actor_device_id = canonical_uuid(authority.device_id());
    let actor = locked_devices
        .iter()
        .find(|row| row.user_did == actor_did && row.device_id == actor_device_id)
        .ok_or(AuthRepositoryError::RequestBindingMismatch)?;
    let receipt = authority.repository_receipt();
    if receipt.class() != RepositoryAuthorityClass::ExistingDevice
        || actor.status != "active"
        || actor.revoked_at.is_some()
        || actor.dpop_jkt != authority.dpop_jkt().as_str()
        || receipt.locked_jkt() != Some(actor.dpop_jkt.as_str())
        || receipt.locked_auth_generation() != Some(actor.auth_generation)
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let mutation = authority
        .mutation()
        .ok_or(AuthRepositoryError::UnsupportedAuthorizationShape)?;
    let actor_key = locked_keys
        .iter()
        .find(|row| {
            row.user_did == actor_did
                && row.device_id == actor_device_id
                && row.key_id == mutation.key_id().as_str()
        })
        .ok_or(AuthRepositoryError::DeviceKeyMissing)?;
    let signing_key_sha256: [u8; 32] = Sha256::digest(&actor_key.signing_public_key).into();
    let requested_generation = i64::try_from(mutation.auth_generation())
        .map_err(|_| AuthRepositoryError::AuthenticationGenerationMismatch)?;
    if actor_key.revoked_at.is_some()
        || actor.auth_generation != requested_generation
        || receipt.locked_key_id() != Some(actor_key.key_id.as_str())
        || receipt.locked_signing_key_sha256() != Some(&signing_key_sha256)
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    verify_ed25519_strict(
        &actor_key.signing_public_key,
        mutation.transcript_bytes(),
        mutation.signature(),
    )?;
    let actor = BusinessAuthorityGuard {
        transaction_id,
        class: receipt.class(),
        subject: actor_did.to_owned(),
        device_id: actor_device_id,
        stored_dpop_jkt: Some(actor.dpop_jkt.clone()),
        stored_auth_generation: Some(actor.auth_generation),
        stored_key_id: Some(actor_key.key_id.clone()),
        stored_signing_public_key: Some(actor_key.signing_public_key.clone()),
        trusted_instant: authority.trusted_instant().datetime(),
    };
    let scope_digest =
        canonical_locked_scope_digest(&locked_principals, &locked_devices, &locked_keys);
    Ok(LockedCanonicalAuthorityScope {
        receipt_id: Uuid::new_v4(),
        actor,
        principals: locked_principals,
        devices: locked_devices,
        keys: locked_keys,
        scope_digest,
    })
}

fn canonical_locked_scope_digest(
    principals: &[String],
    devices: &[LockedCanonicalDeviceProjection],
    keys: &[LockedCanonicalKeyProjection],
) -> [u8; 32] {
    fn bind_bytes(digest: &mut Sha256, value: &[u8]) {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }

    fn bind_optional_instant(digest: &mut Sha256, value: Option<DateTime<Utc>>) {
        match value {
            Some(value) => {
                digest.update([1]);
                digest.update(value.timestamp_micros().to_be_bytes());
            }
            None => digest.update([0]),
        }
    }

    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-CANONICAL-AUTHORITY-SCOPE\0");
    digest.update((principals.len() as u64).to_be_bytes());
    for principal in principals {
        bind_bytes(&mut digest, principal.as_bytes());
    }
    digest.update((devices.len() as u64).to_be_bytes());
    for device in devices {
        bind_bytes(&mut digest, device.user_did.as_bytes());
        digest.update(device.device_id.as_bytes());
        bind_bytes(&mut digest, device.status.as_bytes());
        bind_bytes(&mut digest, device.dpop_jkt.as_bytes());
        digest.update(device.auth_generation.to_be_bytes());
        bind_optional_instant(&mut digest, device.revoked_at);
    }
    digest.update((keys.len() as u64).to_be_bytes());
    for key in keys {
        bind_bytes(&mut digest, key.user_did.as_bytes());
        digest.update(key.device_id.as_bytes());
        bind_bytes(&mut digest, key.key_id.as_bytes());
        digest.update(<[u8; 32]>::from(Sha256::digest(&key.signing_public_key)));
        digest.update(key.enrollment_auth_generation.to_be_bytes());
        bind_optional_instant(&mut digest, key.revoked_at);
    }
    digest.finalize().into()
}

/// Repository-slice test seam for operations whose production caller already
/// completed cryptographic authorization. It derives every authority field
/// from exact locked rows; callers supply only the identity and trusted T.
#[cfg(test)]
pub(crate) async fn recheck_existing_business_authority_for_test(
    transaction: &mut Transaction<'_, Postgres>,
    subject: &str,
    device_id: Uuid,
    trusted_instant: DateTime<Utc>,
) -> Result<BusinessAuthorityGuard, AuthRepositoryError> {
    let device_bytes = device_id.as_bytes();
    if BareDid::parse(subject).is_err()
        || device_bytes[6] >> 4 != 4
        || device_bytes[8] >> 6 != 2
        || trusted_instant.timestamp_millis() < 0
        || trusted_instant.timestamp_subsec_nanos() % 1_000_000 != 0
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    let device: Option<DeviceRow> = sqlx::query_as(
        r#"
        SELECT status,dpop_jkt,auth_generation
          FROM chat.devices
         WHERE user_did=$1 AND device_id=$2
         FOR UPDATE
        "#,
    )
    .bind(subject)
    .bind(device_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let device = device.ok_or(AuthRepositoryError::DeviceNotRegistered)?;
    if device.status != "active" {
        return Err(AuthRepositoryError::DeviceRevoked);
    }
    if device.auth_generation <= 0 || KeyThumbprint::parse(&device.dpop_jkt).is_err() {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let keys: Vec<(String, Vec<u8>, i64, Option<DateTime<Utc>>)> = sqlx::query_as(
        r#"
        SELECT key_id,signing_public_key,enrollment_auth_generation,revoked_at
          FROM chat.device_keys
         WHERE user_did=$1 AND device_id=$2
         ORDER BY convert_to(key_id,'UTF8')
         FOR UPDATE
        "#,
    )
    .bind(subject)
    .bind(device_id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut eligible = None;
    for (key_id, signing_public_key, enrollment_auth_generation, revoked_at) in keys {
        if revoked_at.is_some() || enrollment_auth_generation != device.auth_generation {
            continue;
        }
        let canonical = KeyThumbprint::parse(&key_id)
            .map_err(|_| AuthRepositoryError::RequestBindingMismatch)?;
        let derived = ed25519_key_id(&signing_public_key)
            .map_err(|_| AuthRepositoryError::RequestBindingMismatch)?;
        if canonical != derived || eligible.is_some() {
            return Err(AuthRepositoryError::RequestBindingMismatch);
        }
        eligible = Some((key_id, signing_public_key));
    }
    let (key_id, signing_public_key) = eligible.ok_or(AuthRepositoryError::DeviceKeyMissing)?;
    Ok(BusinessAuthorityGuard {
        transaction_id,
        class: RepositoryAuthorityClass::ExistingDevice,
        subject: subject.to_owned(),
        device_id,
        stored_dpop_jkt: Some(device.dpop_jkt),
        stored_auth_generation: Some(device.auth_generation),
        stored_key_id: Some(key_id),
        stored_signing_public_key: Some(signing_public_key),
        trusted_instant,
    })
}

/// Serializes step two of idempotent execution inside the caller's business
/// transaction. Call this before `recheck_business_authority` or any effects.
/// A concurrent identical winner is returned as a completed replay after its
/// transaction commits; a different exact wrapper under the same key conflicts.
pub(crate) async fn arbitrate_business_idempotency(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
) -> Result<BusinessIdempotencyOutcome, AuthRepositoryError> {
    let endpoint = authority.endpoint().as_str();
    if !endpoint_has_idempotency_record(endpoint) {
        return Err(AuthRepositoryError::InvalidCompletion);
    }
    let material = request_material_for_authority(authority)?;
    let lock_key = format!(
        "chat-idempotency:{}:{}:{}:{}:{}",
        authority.subject().as_str().len(),
        authority.subject().as_str(),
        endpoint.len(),
        endpoint,
        material.operation_id
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut **transaction)
        .await?;
    match completed_replay(transaction, authority.pre_replay(), &material).await? {
        Some(response) => {
            validate_completed_business_authority(transaction, authority).await?;
            Ok(BusinessIdempotencyOutcome::CompletedReplay(response))
        }
        None => {
            let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
                .fetch_one(&mut **transaction)
                .await?;
            Ok(BusinessIdempotencyOutcome::FirstExecution(
                BusinessIdempotencyGuard {
                    transaction_id,
                    subject: authority.subject().as_str().to_owned(),
                    endpoint: endpoint.to_owned(),
                    operation_id: material.operation_id,
                    request_digest: material.request_digest,
                    signature: material.signature,
                },
            ))
        }
    }
}

async fn validate_completed_business_authority(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
) -> Result<(), AuthRepositoryError> {
    if authority.endpoint().as_str() == "blue.catbird.chat.revokeDevice" {
        if validate_completed_self_revocation_authority(transaction, authority).await? {
            return Ok(());
        }
    }
    let state = match lock_device_and_key(
        transaction,
        authority.subject().as_str(),
        canonical_uuid(authority.device_id()),
    )
    .await
    {
        Ok(state) => state,
        Err(AuthRepositoryError::DeviceRevoked)
            if authority.endpoint().as_str() == "blue.catbird.chat.revokeDevice"
                && validate_completed_self_revocation_authority(transaction, authority).await? =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    match authority.repository_receipt().class() {
        RepositoryAuthorityClass::EnrollmentBootstrap => {
            let body = authority
                .pre_replay()
                .enrollment_body()
                .ok_or(AuthRepositoryError::UnsupportedAuthorizationShape)?;
            validate_completed_enrollment_authority(authority.pre_replay(), body, &state)
        }
        RepositoryAuthorityClass::RebindBootstrap => {
            let mutation = authority
                .mutation()
                .ok_or(AuthRepositoryError::UnsupportedAuthorizationShape)?;
            validate_completed_rebind_business_authority(authority, mutation, &state)
        }
        RepositoryAuthorityClass::ExistingDevice => {
            if state.dpop_jkt != authority.dpop_jkt().as_str() {
                return Err(AuthRepositoryError::DpopBindingMismatch);
            }
            let mutation = authority
                .mutation()
                .ok_or(AuthRepositoryError::UnsupportedAuthorizationShape)?;
            if state.key_id != mutation.key_id().as_str() {
                return Err(AuthRepositoryError::RequestBindingMismatch);
            }
            let generation = i64::try_from(mutation.auth_generation())
                .map_err(|_| AuthRepositoryError::AuthenticationGenerationMismatch)?;
            if state.auth_generation != generation {
                return Err(AuthRepositoryError::AuthenticationGenerationMismatch);
            }
            if !locked_state_matches_receipt(authority.repository_receipt(), &state) {
                return Err(AuthRepositoryError::RequestBindingMismatch);
            }
            verify_ed25519_strict(
                &state.signing_public_key,
                mutation.transcript_bytes(),
                mutation.signature(),
            )?;
            Ok(())
        }
    }
}

async fn validate_completed_self_revocation_authority(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
) -> Result<bool, AuthRepositoryError> {
    let receipt = authority.repository_receipt();
    let mutation = authority
        .mutation()
        .filter(|mutation| mutation.kind() == SignedMutationKind::DeviceRevocation)
        .ok_or(AuthRepositoryError::UnsupportedAuthorizationShape)?;
    let generation = i64::try_from(mutation.auth_generation())
        .map_err(|_| AuthRepositoryError::AuthenticationGenerationMismatch)?;
    if receipt.class() != RepositoryAuthorityClass::ExistingDevice
        || receipt.locked_jkt() != Some(authority.dpop_jkt().as_str())
        || receipt.locked_auth_generation() != Some(generation)
        || receipt.locked_key_id() != Some(mutation.key_id().as_str())
        || receipt.locked_signing_key_sha256().is_none()
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let operation_id = receipt
        .operation_id()
        .ok_or(AuthRepositoryError::RequestBindingMismatch)?;
    validate_completed_self_revocation_material(
        transaction,
        operation_id,
        authority.subject().as_str(),
        canonical_uuid(authority.device_id()),
        authority.dpop_jkt().as_str(),
        mutation.key_id().as_str(),
        generation,
        mutation.transcript_bytes(),
        mutation.signature(),
        receipt.locked_signing_key_sha256(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn validate_completed_self_revocation_material(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    actor_did: &str,
    actor_device_id: Uuid,
    historical_jkt: &str,
    actor_key_id: &str,
    actor_auth_generation: i64,
    signing_transcript_bytes: &[u8],
    signature: &[u8],
    expected_signing_key_sha256: Option<&[u8; 32]>,
) -> Result<bool, AuthRepositoryError> {
    let signing_public_key: Option<Vec<u8>> = sqlx::query_scalar(
        r#"
        SELECT actor_key.signing_public_key
          FROM chat.idempotency_records completed
          JOIN chat.device_revocations terminal
            ON terminal.revocation_id = completed.operation_id
           AND terminal.actor_did = completed.principal_did
           AND terminal.request_digest = completed.request_digest
           AND terminal.accepted_request_bytes = completed.accepted_request_bytes
           AND terminal.signing_transcript_bytes = completed.signing_transcript_bytes
           AND terminal.signature = completed.signature
           AND terminal.accepted_at = completed.completed_at
          JOIN chat.devices target
            ON target.user_did = terminal.target_did
           AND target.device_id = terminal.target_device_id
           AND target.status = 'revoked'
           AND target.auth_generation = terminal.target_auth_generation
           AND target.revocation_id = terminal.revocation_id
           AND target.revoked_at = terminal.accepted_at
          JOIN chat.device_keys actor_key
            ON actor_key.user_did = terminal.actor_did
           AND actor_key.device_id = terminal.actor_device_id
           AND actor_key.key_id = terminal.actor_key_id
           AND actor_key.revocation_id = terminal.revocation_id
           AND actor_key.revoked_at = terminal.accepted_at
         WHERE completed.operation_id = $1
           AND completed.endpoint_nsid = 'blue.catbird.chat.revokeDevice'
           AND completed.principal_did = $2
           AND completed.historical_jkt = $3
           AND completed.current_jkt IS NULL
           AND terminal.actor_did = terminal.target_did
           AND terminal.actor_device_id = terminal.target_device_id
           AND terminal.actor_did = $2
           AND terminal.actor_device_id = $4
           AND terminal.actor_key_id = $5
           AND terminal.actor_auth_generation = $6
           AND target.dpop_jkt = $3
        "#,
    )
    .bind(operation_id)
    .bind(actor_did)
    .bind(historical_jkt)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .bind(actor_auth_generation)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(signing_public_key) = signing_public_key else {
        return Ok(false);
    };
    let signing_key_sha256: [u8; 32] = Sha256::digest(&signing_public_key).into();
    if expected_signing_key_sha256.is_some_and(|expected| expected != &signing_key_sha256) {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    verify_ed25519_strict(&signing_public_key, signing_transcript_bytes, signature)?;
    Ok(true)
}

/// Persists the immutable exact-response replay record inside the same
/// caller-owned transaction as the business mutation and event append.
pub(crate) async fn record_completed_idempotency(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    guard: &BusinessIdempotencyGuard,
    completed_status: i32,
    response_bytes: &[u8],
    event_position: Option<i64>,
) -> Result<(), AuthRepositoryError> {
    if !completion_status_is_valid(completed_status) || response_bytes.is_empty() {
        return Err(AuthRepositoryError::InvalidCompletion);
    }
    let endpoint = authority.endpoint().as_str();
    if !endpoint_has_idempotency_record(endpoint) {
        return Err(AuthRepositoryError::InvalidCompletion);
    }
    let operation_id = authority
        .repository_receipt()
        .operation_id()
        .ok_or(AuthRepositoryError::InvalidCompletion)?;
    let mutation = authority
        .mutation()
        .ok_or(AuthRepositoryError::InvalidCompletion)?;
    let accepted_request_bytes = mutation
        .accepted_wrapper_bytes()
        .ok_or(AuthRepositoryError::MissingAcceptedRequestBytes)?;
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if guard.transaction_id != transaction_id
        || guard.subject != authority.subject().as_str()
        || guard.endpoint != endpoint
        || guard.operation_id != operation_id
        || guard.request_digest != *mutation.request_digest()
        || guard.signature != *mutation.signature()
    {
        return Err(AuthRepositoryError::InvalidCompletion);
    }
    let (historical_jkt, current_jkt) = completion_jkts(authority);
    let response_sha256: [u8; 32] = Sha256::digest(response_bytes).into();

    let result = sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records (
            principal_did, endpoint_nsid, operation_id, request_digest,
            accepted_request_bytes, signing_transcript_bytes, signature,
            completed_status, response_bytes, response_sha256, event_position,
            historical_jkt, current_jkt, completed_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        "#,
    )
    .bind(authority.subject().as_str())
    .bind(endpoint)
    .bind(operation_id)
    .bind(mutation.request_digest().as_slice())
    .bind(accepted_request_bytes)
    .bind(mutation.transcript_bytes())
    .bind(mutation.signature().as_slice())
    .bind(completed_status)
    .bind(response_bytes)
    .bind(response_sha256.as_slice())
    .bind(event_position)
    .bind(historical_jkt)
    .bind(current_jkt)
    .bind(authority.trusted_instant().datetime())
    .execute(&mut **transaction)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(error) if is_unique_violation(&error) => Err(AuthRepositoryError::IdempotencyConflict),
        Err(error) => Err(AuthRepositoryError::Database(error)),
    }
}

pub(crate) async fn prepare_enrollment_business(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
) -> Result<EnrollmentBusinessOutcome, AuthRepositoryError> {
    if authority.endpoint().as_str() != "blue.catbird.chat.enrollDevice"
        || authority.repository_receipt().class() != RepositoryAuthorityClass::EnrollmentBootstrap
    {
        return Err(AuthRepositoryError::UnsupportedAuthorizationShape);
    }
    let idempotency = match arbitrate_business_idempotency(transaction, authority).await? {
        BusinessIdempotencyOutcome::CompletedReplay(response) => {
            return Ok(EnrollmentBusinessOutcome::CompletedReplay(response));
        }
        BusinessIdempotencyOutcome::FirstExecution(guard) => guard,
    };
    let authority_guard = recheck_business_authority(transaction, authority).await?;
    if authority_guard.class() != RepositoryAuthorityClass::EnrollmentBootstrap
        || authority_guard.transaction_id() != idempotency.transaction_id
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    Ok(EnrollmentBusinessOutcome::FirstExecution(
        EnrollmentBusinessGuard {
            idempotency,
            authority: authority_guard,
        },
    ))
}

pub(crate) async fn persist_enrollment_and_completion(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    guard: EnrollmentBusinessGuard,
    completed_status: i32,
    response_bytes: &[u8],
    event_position: Option<i64>,
) -> Result<(), AuthRepositoryError> {
    let EnrollmentBusinessGuard {
        idempotency,
        authority: authority_guard,
    } = guard;
    validate_business_guard_transaction(transaction, authority, &authority_guard).await?;
    if authority_guard.class != RepositoryAuthorityClass::EnrollmentBootstrap
        || authority_guard.stored_dpop_jkt.is_some()
        || authority_guard.stored_auth_generation.is_some()
        || authority_guard.stored_key_id.is_some()
        || authority_guard.stored_signing_public_key.is_some()
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let mutation = authority
        .mutation()
        .ok_or(AuthRepositoryError::UnsupportedAuthorizationShape)?;
    let VerifiedMutationProjection::DeviceEnrollment(projection) = mutation.projection() else {
        return Err(AuthRepositoryError::UnsupportedAuthorizationShape);
    };
    if mutation.auth_generation() != 0 {
        return Err(AuthRepositoryError::AuthenticationGenerationMismatch);
    }
    let body = projection.body();
    let device_name = match body.get("deviceName") {
        Some(CanonicalValueRef::Text(value)) => value,
        _ => return Err(AuthRepositoryError::RequestBindingMismatch),
    };
    let dpop_jkt = match body.get("dpopJkt") {
        Some(CanonicalValueRef::Thumbprint(value)) => value.as_str(),
        _ => return Err(AuthRepositoryError::RequestBindingMismatch),
    };
    let signing_public_key = match body.get("signaturePublicKey") {
        Some(CanonicalValueRef::Bytes(value)) => value,
        _ => return Err(AuthRepositoryError::RequestBindingMismatch),
    };
    if dpop_jkt != authority.dpop_jkt().as_str()
        || mutation.key_id().as_str()
            != authority
                .pre_replay()
                .enrollment()
                .ok_or(AuthRepositoryError::UnsupportedAuthorizationShape)?
                .key_id()
                .as_str()
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let trusted_at = authority_guard.trusted_instant;
    sqlx::query(
        "INSERT INTO chat.principals(user_did, created_at) VALUES ($1,$2) ON CONFLICT (user_did) DO NOTHING",
    )
    .bind(&authority_guard.subject)
    .bind(trusted_at)
    .execute(&mut **transaction)
    .await?;
    let inserted_device = sqlx::query(
        r#"
        INSERT INTO chat.devices (
            user_did, device_id, device_name, status, dpop_jkt,
            auth_generation, capabilities, created_at, updated_at
        ) VALUES ($1,$2,$3,'active',$4,1,chat.protocol_capabilities(),$5,$5)
        "#,
    )
    .bind(&authority_guard.subject)
    .bind(authority_guard.device_id)
    .bind(device_name)
    .bind(dpop_jkt)
    .bind(trusted_at)
    .execute(&mut **transaction)
    .await?;
    if inserted_device.rows_affected() != 1 {
        return Err(AuthRepositoryError::DeviceAlreadyRegistered);
    }
    let inserted_key = sqlx::query(
        r#"
        INSERT INTO chat.device_keys (
            user_did, device_id, key_id, signing_public_key,
            enrollment_auth_generation, created_at
        ) VALUES ($1,$2,$3,$4,1,$5)
        "#,
    )
    .bind(&authority_guard.subject)
    .bind(authority_guard.device_id)
    .bind(mutation.key_id().as_str())
    .bind(signing_public_key)
    .bind(trusted_at)
    .execute(&mut **transaction)
    .await?;
    if inserted_key.rows_affected() != 1 {
        return Err(AuthRepositoryError::DeviceKeyMissing);
    }
    record_completed_idempotency(
        transaction,
        authority,
        &idempotency,
        completed_status,
        response_bytes,
        event_position,
    )
    .await
}

pub(crate) async fn prepare_rebind_business(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
) -> Result<RebindBusinessOutcome, AuthRepositoryError> {
    if authority.endpoint().as_str() != "blue.catbird.chat.rebindDeviceAuthentication"
        || authority.repository_receipt().class() != RepositoryAuthorityClass::RebindBootstrap
    {
        return Err(AuthRepositoryError::UnsupportedAuthorizationShape);
    }
    let idempotency = match arbitrate_business_idempotency(transaction, authority).await? {
        BusinessIdempotencyOutcome::CompletedReplay(response) => {
            return Ok(RebindBusinessOutcome::CompletedReplay(response));
        }
        BusinessIdempotencyOutcome::FirstExecution(guard) => guard,
    };
    let authority_guard = recheck_business_authority(transaction, authority).await?;
    if authority_guard.class() != RepositoryAuthorityClass::RebindBootstrap
        || authority_guard.transaction_id() != idempotency.transaction_id
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    Ok(RebindBusinessOutcome::FirstExecution(RebindBusinessGuard {
        idempotency,
        authority: authority_guard,
    }))
}

pub(crate) async fn persist_rebind_and_completion(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    guard: RebindBusinessGuard,
    completed_status: i32,
    response_bytes: &[u8],
    event_position: Option<i64>,
) -> Result<(), AuthRepositoryError> {
    let RebindBusinessGuard {
        idempotency,
        authority: authority_guard,
    } = guard;
    validate_business_guard_transaction(transaction, authority, &authority_guard).await?;
    if authority_guard.class != RepositoryAuthorityClass::RebindBootstrap {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let mutation = authority
        .mutation()
        .ok_or(AuthRepositoryError::UnsupportedAuthorizationShape)?;
    let VerifiedMutationProjection::DeviceAuthenticationRebind(projection) = mutation.projection()
    else {
        return Err(AuthRepositoryError::UnsupportedAuthorizationShape);
    };
    let expected_generation = i64::try_from(mutation.auth_generation())
        .map_err(|_| AuthRepositoryError::AuthenticationGenerationMismatch)?;
    let new_generation = expected_generation
        .checked_add(1)
        .ok_or(AuthRepositoryError::AuthenticationGenerationMismatch)?;
    let body = projection.body();
    let current_jkt = match body.get("currentDpopJkt") {
        Some(CanonicalValueRef::Thumbprint(value)) => value.as_str(),
        _ => return Err(AuthRepositoryError::RequestBindingMismatch),
    };
    let new_jkt = match body.get("newDpopJkt") {
        Some(CanonicalValueRef::Thumbprint(value)) => value.as_str(),
        _ => return Err(AuthRepositoryError::RequestBindingMismatch),
    };
    if authority_guard.stored_dpop_jkt.as_deref() != Some(current_jkt)
        || authority_guard.stored_auth_generation != Some(expected_generation)
        || authority_guard.stored_key_id.as_deref() != Some(mutation.key_id().as_str())
        || authority_guard.stored_signing_public_key.is_none()
        || authority.dpop_jkt().as_str() != new_jkt
        || current_jkt == new_jkt
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let updated = sqlx::query(
        r#"
        UPDATE chat.devices
           SET dpop_jkt = $4, auth_generation = $5, updated_at = $6
         WHERE user_did = $1
           AND device_id = $2
           AND status = 'active'
           AND dpop_jkt = $3
           AND auth_generation = $7
        "#,
    )
    .bind(&authority_guard.subject)
    .bind(authority_guard.device_id)
    .bind(current_jkt)
    .bind(new_jkt)
    .bind(new_generation)
    .bind(authority_guard.trusted_instant)
    .bind(expected_generation)
    .execute(&mut **transaction)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(AuthRepositoryError::AuthenticationGenerationMismatch);
    }
    record_completed_idempotency(
        transaction,
        authority,
        &idempotency,
        completed_status,
        response_bytes,
        event_position,
    )
    .await
}

async fn validate_business_guard_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    guard: &BusinessAuthorityGuard,
) -> Result<(), AuthRepositoryError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if transaction_id != guard.transaction_id
        || guard.subject != authority.subject().as_str()
        || guard.device_id != canonical_uuid(authority.device_id())
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    Ok(())
}

async fn arbitrate_signed(
    transaction: &mut Transaction<'_, Postgres>,
    pre_replay: &PreReplayCryptographicVerification,
    canonical: &CanonicalSignedMutation,
    replay_ids: ReplayAuditIds,
) -> Result<Arbitration<FirstSignedExecution>, AuthRepositoryError> {
    if canonical.actor_did() != pre_replay.subject()
        || canonical.actor_device_id() != pre_replay.device_id()
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }

    let material = request_material_for_canonical(pre_replay, canonical)?;
    let completed = if let Some(material) = material.as_ref() {
        completed_replay(transaction, pre_replay, material).await?
    } else {
        None
    };
    let exact_self_revocation = canonical_is_exact_self_target_revocation(canonical)?;

    if exact_self_revocation && completed.is_some() {
        let material = material
            .as_ref()
            .ok_or(AuthRepositoryError::RequestBindingMismatch)?;
        if !validate_completed_self_revocation_material(
            transaction,
            material.operation_id,
            pre_replay.subject().as_str(),
            canonical_uuid(pre_replay.device_id()),
            pre_replay.dpop_jkt().as_str(),
            canonical.key_id().as_str(),
            i64::try_from(canonical.auth_generation())
                .map_err(|_| AuthRepositoryError::AuthenticationGenerationMismatch)?,
            canonical.transcript_bytes(),
            canonical.signature(),
            None,
        )
        .await?
        {
            return Err(AuthRepositoryError::CorruptIdempotencyRecord);
        }
        return Ok(Arbitration::Completed(
            completed.expect("completed response checked above"),
        ));
    }

    let state = match lock_existing_authority(transaction, pre_replay).await {
        Ok(state) => state,
        Err(AuthRepositoryError::DeviceRevoked) if exact_self_revocation => {
            let material = material
                .as_ref()
                .ok_or(AuthRepositoryError::RequestBindingMismatch)?;
            let Some(response) = completed_replay(transaction, pre_replay, material).await? else {
                return Err(AuthRepositoryError::DeviceRevoked);
            };
            if !validate_completed_self_revocation_material(
                transaction,
                material.operation_id,
                pre_replay.subject().as_str(),
                canonical_uuid(pre_replay.device_id()),
                pre_replay.dpop_jkt().as_str(),
                canonical.key_id().as_str(),
                i64::try_from(canonical.auth_generation())
                    .map_err(|_| AuthRepositoryError::AuthenticationGenerationMismatch)?,
                canonical.transcript_bytes(),
                canonical.signature(),
                None,
            )
            .await?
            {
                return Err(AuthRepositoryError::CorruptIdempotencyRecord);
            }
            return Ok(Arbitration::Completed(response));
        }
        Err(error) => return Err(error),
    };
    if canonical.kind() == SignedMutationKind::KeyPackageReplenishment {
        validate_replenishment_binding(pre_replay, canonical, &state)?;
    }
    let body_generation = i64::try_from(canonical.auth_generation())
        .map_err(|_| AuthRepositoryError::AuthenticationGenerationMismatch)?;
    if canonical.key_id().as_str() != state.key_id {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    if body_generation != state.auth_generation {
        return Err(AuthRepositoryError::AuthenticationGenerationMismatch);
    }
    if let Some(response) = completed {
        verify_ed25519_strict(
            &state.signing_public_key,
            canonical.transcript_bytes(),
            canonical.signature(),
        )?;
        return Ok(Arbitration::Completed(response));
    }
    let receipt = RepositoryAuthorityReceipt::existing(
        replay_ids,
        material.as_ref().map(|value| value.operation_id),
        &state,
        RepositoryAuthorityClass::ExistingDevice,
    );
    Ok(Arbitration::First(FirstSignedExecution {
        receipt,
        signing_public_key: state.signing_public_key,
    }))
}

async fn arbitrate_enrollment(
    transaction: &mut Transaction<'_, Postgres>,
    pre_replay: &PreReplayCryptographicVerification,
    replay_ids: ReplayAuditIds,
) -> Result<Arbitration<RepositoryAuthorityReceipt>, AuthRepositoryError> {
    let body = pre_replay
        .enrollment_body()
        .ok_or(AuthRepositoryError::UnsupportedAuthorizationShape)?;
    let material = RequestMaterial {
        operation_id: canonical_uuid(body.idempotency_key()),
        accepted_request_bytes: body.accepted_wrapper_bytes().to_vec(),
        signing_transcript_bytes: body.mutation().transcript_bytes().to_vec(),
        request_digest: *body.request_digest(),
        signature: *body.signature(),
        historical_jkt: None,
        current_jkt: Some(body.dpop_jkt().as_str().to_owned()),
    };
    if let Some(response) = completed_replay(transaction, pre_replay, &material).await? {
        let state = lock_device_and_key(
            transaction,
            pre_replay.subject().as_str(),
            canonical_uuid(pre_replay.device_id()),
        )
        .await?;
        validate_completed_enrollment_authority(pre_replay, body, &state)?;
        return Ok(Arbitration::Completed(response));
    }

    lock_identity_slot(
        transaction,
        pre_replay.subject().as_str(),
        canonical_uuid(pre_replay.device_id()),
    )
    .await?;
    let existing: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM chat.devices WHERE user_did = $1 AND device_id = $2 FOR UPDATE",
    )
    .bind(pre_replay.subject().as_str())
    .bind(canonical_uuid(pre_replay.device_id()))
    .fetch_optional(&mut **transaction)
    .await?;
    if existing.is_some() {
        return Err(AuthRepositoryError::DeviceAlreadyRegistered);
    }
    Ok(Arbitration::First(RepositoryAuthorityReceipt::enrollment(
        replay_ids,
        material.operation_id,
    )))
}

async fn arbitrate_rebind(
    transaction: &mut Transaction<'_, Postgres>,
    pre_replay: &PreReplayCryptographicVerification,
    replay_ids: ReplayAuditIds,
) -> Result<Arbitration<FirstSignedExecution>, AuthRepositoryError> {
    let bootstrap = pre_replay
        .rebind_bootstrap()
        .ok_or(AuthRepositoryError::UnsupportedAuthorizationShape)?;
    let decoded_bootstrap = decode_canonical_signed_mutation(bootstrap.accepted_wrapper_bytes())?;
    if decoded_bootstrap.kind() != SignedMutationKind::DeviceAuthenticationRebind
        || decoded_bootstrap.request_digest() != bootstrap.request_digest()
        || decoded_bootstrap.signature() != bootstrap.signature()
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let material = RequestMaterial {
        operation_id: canonical_uuid(bootstrap.idempotency_key()),
        accepted_request_bytes: bootstrap.accepted_wrapper_bytes().to_vec(),
        signing_transcript_bytes: decoded_bootstrap.transcript_bytes().to_vec(),
        request_digest: *bootstrap.request_digest(),
        signature: *bootstrap.signature(),
        historical_jkt: Some(bootstrap.current_dpop_jkt().as_str().to_owned()),
        current_jkt: Some(bootstrap.new_dpop_jkt().as_str().to_owned()),
    };
    if let Some(response) = completed_replay(transaction, pre_replay, &material).await? {
        let state = lock_device_and_key(
            transaction,
            pre_replay.subject().as_str(),
            canonical_uuid(pre_replay.device_id()),
        )
        .await?;
        validate_completed_rebind_authority(pre_replay, bootstrap, &state)?;
        return Ok(Arbitration::Completed(response));
    }

    let state = lock_device_and_key(
        transaction,
        pre_replay.subject().as_str(),
        canonical_uuid(pre_replay.device_id()),
    )
    .await?;
    if state.dpop_jkt != bootstrap.current_dpop_jkt().as_str()
        || pre_replay.dpop_jkt() != bootstrap.new_dpop_jkt()
    {
        return Err(AuthRepositoryError::DpopBindingMismatch);
    }
    let expected_generation = i64::try_from(bootstrap.expected_auth_generation())
        .map_err(|_| AuthRepositoryError::AuthenticationGenerationMismatch)?;
    if state.auth_generation != expected_generation {
        return Err(AuthRepositoryError::AuthenticationGenerationMismatch);
    }
    if state.key_id != bootstrap.key_id().as_str() {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let receipt = RepositoryAuthorityReceipt::existing(
        replay_ids,
        Some(material.operation_id),
        &state,
        RepositoryAuthorityClass::RebindBootstrap,
    );
    Ok(Arbitration::First(FirstSignedExecution {
        receipt,
        signing_public_key: state.signing_public_key,
    }))
}

fn validate_completed_enrollment_authority(
    pre_replay: &PreReplayCryptographicVerification,
    body: &VerifiedEnrollmentBody,
    state: &LockedDeviceAuthority,
) -> Result<(), AuthRepositoryError> {
    if state.dpop_jkt != body.dpop_jkt().as_str()
        || state.dpop_jkt != pre_replay.dpop_jkt().as_str()
    {
        return Err(AuthRepositoryError::DpopBindingMismatch);
    }
    if state.auth_generation != 1 {
        return Err(AuthRepositoryError::AuthenticationGenerationMismatch);
    }
    if state.key_id != body.key_id().as_str() {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    let VerifiedMutationProjection::DeviceEnrollment(projection) = body.mutation().projection()
    else {
        return Err(AuthRepositoryError::UnsupportedAuthorizationShape);
    };
    let projection_body = projection.body();
    let signing_public_key = match projection_body.get("signaturePublicKey") {
        Some(CanonicalValueRef::Bytes(value)) => value,
        _ => return Err(AuthRepositoryError::RequestBindingMismatch),
    };
    if state.signing_public_key.as_slice() != signing_public_key
        || Sha256::digest(&state.signing_public_key).as_slice()
            != body.signing_key_sha256().as_slice()
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    verify_ed25519_strict(
        &state.signing_public_key,
        body.mutation().transcript_bytes(),
        body.signature(),
    )?;
    Ok(())
}

fn validate_completed_rebind_authority(
    pre_replay: &PreReplayCryptographicVerification,
    bootstrap: &CanonicalRebindBootstrap,
    state: &LockedDeviceAuthority,
) -> Result<(), AuthRepositoryError> {
    if state.dpop_jkt != bootstrap.new_dpop_jkt().as_str()
        || state.dpop_jkt != pre_replay.dpop_jkt().as_str()
    {
        return Err(AuthRepositoryError::DpopBindingMismatch);
    }
    let expected_generation = i64::try_from(bootstrap.expected_auth_generation())
        .map_err(|_| AuthRepositoryError::AuthenticationGenerationMismatch)?;
    let completed_generation = expected_generation
        .checked_add(1)
        .ok_or(AuthRepositoryError::AuthenticationGenerationMismatch)?;
    if state.auth_generation != completed_generation {
        return Err(AuthRepositoryError::AuthenticationGenerationMismatch);
    }
    if state.key_id != bootstrap.key_id().as_str() {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    pre_replay.verify_rebind_stored_signing_key(&state.signing_public_key)?;
    Ok(())
}

fn validate_completed_rebind_business_authority(
    authority: &VerifiedChatDeviceRequest,
    mutation: &VerifiedSignedMutation,
    state: &LockedDeviceAuthority,
) -> Result<(), AuthRepositoryError> {
    let VerifiedMutationProjection::DeviceAuthenticationRebind(projection) = mutation.projection()
    else {
        return Err(AuthRepositoryError::UnsupportedAuthorizationShape);
    };
    let body = projection.body();
    let current_jkt = match body.get("currentDpopJkt") {
        Some(CanonicalValueRef::Thumbprint(value)) => value.as_str(),
        _ => return Err(AuthRepositoryError::RequestBindingMismatch),
    };
    let new_jkt = match body.get("newDpopJkt") {
        Some(CanonicalValueRef::Thumbprint(value)) => value.as_str(),
        _ => return Err(AuthRepositoryError::RequestBindingMismatch),
    };
    if state.dpop_jkt != new_jkt || state.dpop_jkt != authority.dpop_jkt().as_str() {
        return Err(AuthRepositoryError::DpopBindingMismatch);
    }
    let expected_generation = i64::try_from(mutation.auth_generation())
        .map_err(|_| AuthRepositoryError::AuthenticationGenerationMismatch)?;
    let completed_generation = expected_generation
        .checked_add(1)
        .ok_or(AuthRepositoryError::AuthenticationGenerationMismatch)?;
    if state.auth_generation != completed_generation {
        return Err(AuthRepositoryError::AuthenticationGenerationMismatch);
    }
    let receipt = authority.repository_receipt();
    let signing_key_sha256: [u8; 32] = Sha256::digest(&state.signing_public_key).into();
    if state.key_id != mutation.key_id().as_str()
        || receipt.locked_jkt() != Some(current_jkt)
        || receipt.locked_auth_generation() != Some(expected_generation)
        || receipt.locked_key_id() != Some(state.key_id.as_str())
        || receipt.locked_signing_key_sha256() != Some(&signing_key_sha256)
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    verify_ed25519_strict(
        &state.signing_public_key,
        mutation.transcript_bytes(),
        mutation.signature(),
    )?;
    Ok(())
}

async fn completed_replay(
    transaction: &mut Transaction<'_, Postgres>,
    pre_replay: &PreReplayCryptographicVerification,
    material: &RequestMaterial,
) -> Result<Option<CompletedIdempotentResponse>, AuthRepositoryError> {
    let row: Option<IdempotencyRow> = sqlx::query_as(
        r#"
        SELECT request_digest, accepted_request_bytes, signing_transcript_bytes,
               signature, completed_status, response_bytes, response_sha256,
               event_position, historical_jkt, current_jkt, completed_at
        FROM chat.idempotency_records
        WHERE principal_did = $1 AND endpoint_nsid = $2 AND operation_id = $3
        "#,
    )
    .bind(pre_replay.subject().as_str())
    .bind(pre_replay.endpoint().as_str())
    .bind(material.operation_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    if !exact_request_material_matches(material, &row)
        || !completed_replay_jkt_matches(pre_replay, material, &row)
    {
        return Err(AuthRepositoryError::IdempotencyConflict);
    }

    let digest: [u8; 32] = row
        .response_sha256
        .as_slice()
        .try_into()
        .map_err(|_| AuthRepositoryError::CorruptIdempotencyRecord)?;
    if Sha256::digest(&row.response_bytes).as_slice() != digest {
        return Err(AuthRepositoryError::CorruptIdempotencyRecord);
    }
    Ok(Some(CompletedIdempotentResponse {
        status: row.completed_status,
        response_bytes: row.response_bytes,
        response_sha256: digest,
        event_position: row.event_position,
        completed_at: row.completed_at,
    }))
}

/// Loads exact completed material and validates the current or retained
/// terminal authority before the response capability crosses the auth module.
/// No repository sibling can observe response bytes from an unvalidated row.
pub(super) async fn load_validated_completed_business_replay(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
) -> Result<Option<CompletedIdempotentResponse>, AuthRepositoryError> {
    let material = request_material_for_authority(authority)?;
    let response = completed_replay(transaction, authority.pre_replay(), &material).await?;
    if response.is_some() {
        validate_completed_business_authority(transaction, authority).await?;
    }
    Ok(response)
}

fn completed_replay_jkt_matches(
    pre_replay: &PreReplayCryptographicVerification,
    material: &RequestMaterial,
    row: &IdempotencyRow,
) -> bool {
    completed_replay_jkt_shape(
        pre_replay.endpoint().as_str(),
        pre_replay.dpop_jkt().as_str(),
        material.historical_jkt.as_deref(),
        material.current_jkt.as_deref(),
        row.historical_jkt.as_deref(),
        row.current_jkt.as_deref(),
    )
}

fn completed_replay_jkt_shape(
    endpoint: &str,
    proof_jkt: &str,
    expected_historical_jkt: Option<&str>,
    expected_current_jkt: Option<&str>,
    recorded_historical_jkt: Option<&str>,
    recorded_current_jkt: Option<&str>,
) -> bool {
    let exact_shape = recorded_historical_jkt == expected_historical_jkt
        && recorded_current_jkt == expected_current_jkt;
    let proof_shape = match endpoint {
        "blue.catbird.chat.enrollDevice" | "blue.catbird.chat.rebindDeviceAuthentication" => {
            expected_current_jkt == Some(proof_jkt)
        }
        "blue.catbird.chat.revokeDevice" => expected_historical_jkt == Some(proof_jkt),
        _ => true,
    };
    exact_shape && proof_shape
}

fn exact_request_material_matches(material: &RequestMaterial, row: &IdempotencyRow) -> bool {
    row.request_digest.as_slice() == material.request_digest.as_slice()
        && row.accepted_request_bytes.as_slice() == material.accepted_request_bytes.as_slice()
        && row.signing_transcript_bytes.as_slice() == material.signing_transcript_bytes.as_slice()
        && row
            .signature
            .as_deref()
            .is_some_and(|value| value == material.signature.as_slice())
}

async fn lock_existing_authority(
    transaction: &mut Transaction<'_, Postgres>,
    pre_replay: &PreReplayCryptographicVerification,
) -> Result<LockedDeviceAuthority, AuthRepositoryError> {
    let state = lock_device_and_key(
        transaction,
        pre_replay.subject().as_str(),
        canonical_uuid(pre_replay.device_id()),
    )
    .await?;
    if state.dpop_jkt != pre_replay.dpop_jkt().as_str() {
        return Err(AuthRepositoryError::DpopBindingMismatch);
    }
    Ok(state)
}

async fn lock_device_and_key(
    transaction: &mut Transaction<'_, Postgres>,
    subject: &str,
    device_id: Uuid,
) -> Result<LockedDeviceAuthority, AuthRepositoryError> {
    let device: Option<DeviceRow> = sqlx::query_as(
        r#"
        SELECT status, dpop_jkt, auth_generation
        FROM chat.devices
        WHERE user_did = $1 AND device_id = $2
        FOR UPDATE
        "#,
    )
    .bind(subject)
    .bind(device_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let device = device.ok_or(AuthRepositoryError::DeviceNotRegistered)?;
    if device.status != "active" {
        return Err(AuthRepositoryError::DeviceRevoked);
    }

    let key: Option<DeviceKeyRow> = sqlx::query_as(
        r#"
        SELECT key_id, signing_public_key, revoked_at
        FROM chat.device_keys
        WHERE user_did = $1 AND device_id = $2
        FOR UPDATE
        "#,
    )
    .bind(subject)
    .bind(device_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let key = key.ok_or(AuthRepositoryError::DeviceKeyMissing)?;
    if key.revoked_at.is_some() {
        return Err(AuthRepositoryError::DeviceKeyRevoked);
    }
    Ok(LockedDeviceAuthority {
        dpop_jkt: device.dpop_jkt,
        auth_generation: device.auth_generation,
        key_id: key.key_id,
        signing_public_key: key.signing_public_key,
    })
}

async fn lock_identity_slot(
    transaction: &mut Transaction<'_, Postgres>,
    subject: &str,
    device_id: Uuid,
) -> Result<(), AuthRepositoryError> {
    let identity = format!("{subject}#{device_id}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(identity)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn consume_replay_set(
    transaction: &mut Transaction<'_, Postgres>,
    pre_replay: &PreReplayCryptographicVerification,
) -> Result<ReplayAuditIds, AuthRepositoryError> {
    let ids = ReplayAuditIds {
        token: Uuid::new_v4(),
        proof: Uuid::new_v4(),
        auth_transaction: pre_replay.auth_transaction_replay().map(|_| Uuid::new_v4()),
    };
    let rows = replay_rows(pre_replay, ids)?;
    let expected_rows = rows.len() as u64;
    let mut query = QueryBuilder::<Postgres>::new(
        r#"
        INSERT INTO chat.dpop_replays (
            replay_id, replay_namespace, issuer, token_jti, jkt,
            proof_jti_bytes, auth_txn, token_hash, proof_hash, subject_did,
            audience, lxm, device_id, chat_instance, htu, htm, key_id,
            signing_key_sha256, enrollment_transcript_sha256, auth_time,
            token_iat, token_exp, proof_iat, consumed_at, retain_until
        )
        "#,
    );
    query.push_values(rows.iter(), |mut values, row| {
        values
            .push_bind(row.replay_id)
            .push_bind(row.replay_namespace)
            .push_bind(row.issuer.as_deref())
            .push_bind(row.token_jti)
            .push_bind(row.jkt.as_deref())
            .push_bind(row.proof_jti_bytes.as_deref())
            .push_bind(row.auth_txn)
            .push_bind(row.token_hash.as_deref())
            .push_bind(row.proof_hash.as_deref())
            .push_bind(row.subject_did.as_deref())
            .push_bind(row.audience.as_deref())
            .push_bind(row.lxm.as_deref())
            .push_bind(row.device_id)
            .push_bind(row.chat_instance)
            .push_bind(row.htu.as_deref())
            .push_bind(row.htm.as_deref())
            .push_bind(row.key_id.as_deref())
            .push_bind(row.signing_key_sha256.as_deref())
            .push_bind(row.enrollment_transcript_sha256.as_deref())
            .push_bind(row.auth_time)
            .push_bind(row.token_iat)
            .push_bind(row.token_exp)
            .push_bind(row.proof_iat)
            .push_bind(row.consumed_at)
            .push_bind(row.retain_until);
    });

    match query.build().execute(&mut **transaction).await {
        Ok(result) if result.rows_affected() == expected_rows => Ok(ids),
        Ok(_) => Err(AuthRepositoryError::Database(sqlx::Error::RowNotFound)),
        Err(error) if is_unique_violation(&error) => Err(AuthRepositoryError::ReplayDetected),
        Err(error) => Err(AuthRepositoryError::Database(error)),
    }
}

fn replay_rows(
    pre_replay: &PreReplayCryptographicVerification,
    ids: ReplayAuditIds,
) -> Result<Vec<ReplayInsertRow>, AuthRepositoryError> {
    let consumed_at = pre_replay.trusted_instant().datetime();
    let token_iat = numeric_datetime(pre_replay.token_iat())?;
    let token_exp = numeric_datetime(pre_replay.token_exp())?;
    let proof_iat = numeric_datetime(pre_replay.proof_iat())?;
    let proof_retain_until = proof_iat
        .checked_add_signed(Duration::seconds(120))
        .ok_or_else(|| AuthPrimitiveError::invalid("proof retention overflow"))?;
    let common_subject = pre_replay.subject().as_str().to_owned();
    let common_audience = pre_replay.audience().to_owned();
    let common_lxm = pre_replay.endpoint().as_str().to_owned();
    let common_device = canonical_uuid(pre_replay.device_id());
    let common_instance = canonical_uuid(pre_replay.chat_instance());
    let common_jkt = pre_replay.dpop_jkt().as_str().to_owned();

    let token = ReplayInsertRow {
        replay_id: ids.token,
        replay_namespace: "token",
        issuer: Some(pre_replay.token_replay().issuer().to_owned()),
        token_jti: Some(canonical_uuid(pre_replay.token_replay().jti())),
        jkt: Some(common_jkt.clone()),
        proof_jti_bytes: None,
        auth_txn: None,
        token_hash: Some(pre_replay.token_sha256().to_vec()),
        proof_hash: None,
        subject_did: Some(common_subject.clone()),
        audience: Some(common_audience.clone()),
        lxm: Some(common_lxm.clone()),
        device_id: Some(common_device),
        chat_instance: Some(common_instance),
        htu: None,
        htm: None,
        key_id: None,
        signing_key_sha256: None,
        enrollment_transcript_sha256: None,
        auth_time: None,
        token_iat: Some(token_iat),
        token_exp: Some(token_exp),
        proof_iat: None,
        consumed_at,
        retain_until: token_exp,
    };
    let proof = ReplayInsertRow {
        replay_id: ids.proof,
        replay_namespace: "proof",
        issuer: None,
        token_jti: None,
        jkt: Some(common_jkt.clone()),
        proof_jti_bytes: Some(pre_replay.proof_replay().jti_bytes().to_vec()),
        auth_txn: None,
        token_hash: Some(pre_replay.token_sha256().to_vec()),
        proof_hash: Some(pre_replay.proof_sha256().to_vec()),
        subject_did: Some(common_subject.clone()),
        audience: Some(common_audience.clone()),
        lxm: Some(common_lxm.clone()),
        device_id: Some(common_device),
        chat_instance: Some(common_instance),
        htu: Some(pre_replay.htu().to_owned()),
        htm: Some(pre_replay.method().as_str().to_owned()),
        key_id: None,
        signing_key_sha256: None,
        enrollment_transcript_sha256: None,
        auth_time: None,
        token_iat: None,
        token_exp: None,
        proof_iat: Some(proof_iat),
        consumed_at,
        retain_until: proof_retain_until,
    };
    let mut rows = vec![token, proof];

    if let Some(auth_transaction) = pre_replay.auth_transaction_replay() {
        let enrollment = pre_replay
            .enrollment()
            .ok_or(AuthRepositoryError::UnsupportedAuthorizationShape)?;
        let auth_time = numeric_datetime(enrollment.auth_time())?;
        let auth_retain_until = [
            token_exp,
            proof_retain_until,
            auth_time
                .checked_add_signed(Duration::seconds(300))
                .ok_or_else(|| AuthPrimitiveError::invalid("auth retention overflow"))?,
        ]
        .into_iter()
        .max()
        .expect("fixed non-empty retention set");
        rows.push(ReplayInsertRow {
            replay_id: ids
                .auth_transaction
                .expect("auth transaction replay ID is allocated with evidence"),
            replay_namespace: "authTxn",
            issuer: Some(auth_transaction.issuer().to_owned()),
            token_jti: None,
            jkt: Some(common_jkt),
            proof_jti_bytes: None,
            auth_txn: Some(canonical_uuid(auth_transaction.auth_txn())),
            token_hash: Some(pre_replay.token_sha256().to_vec()),
            proof_hash: Some(pre_replay.proof_sha256().to_vec()),
            subject_did: Some(common_subject),
            audience: Some(common_audience),
            lxm: Some(common_lxm),
            device_id: Some(common_device),
            chat_instance: Some(common_instance),
            htu: Some(pre_replay.htu().to_owned()),
            htm: Some(pre_replay.method().as_str().to_owned()),
            key_id: Some(enrollment.key_id().as_str().to_owned()),
            signing_key_sha256: Some(enrollment.signing_key_sha256().to_vec()),
            enrollment_transcript_sha256: Some(enrollment.enrollment_transcript_sha256().to_vec()),
            auth_time: Some(auth_time),
            token_iat: Some(token_iat),
            token_exp: Some(token_exp),
            proof_iat: Some(proof_iat),
            consumed_at,
            retain_until: auth_retain_until,
        });
    }
    Ok(rows)
}

async fn commit_semantic_decision<T>(
    transaction: Transaction<'_, Postgres>,
    decision: Result<T, AuthRepositoryError>,
) -> Result<T, AuthRepositoryError> {
    match decision {
        Err(error @ AuthRepositoryError::Database(_)) => {
            let _ = transaction.rollback().await;
            Err(error)
        }
        decision => {
            transaction.commit().await?;
            decision
        }
    }
}

fn request_material_for_canonical(
    pre_replay: &PreReplayCryptographicVerification,
    canonical: &CanonicalSignedMutation,
) -> Result<Option<RequestMaterial>, AuthRepositoryError> {
    let endpoint = pre_replay.endpoint().as_str();
    if !endpoint_has_idempotency_record(endpoint) {
        return Ok(None);
    }
    let accepted = canonical
        .accepted_wrapper_bytes()
        .ok_or(AuthRepositoryError::MissingAcceptedRequestBytes)?;
    let operation_id = operation_id_from_canonical(canonical)?;
    Ok(Some(RequestMaterial {
        operation_id,
        accepted_request_bytes: accepted.to_vec(),
        signing_transcript_bytes: canonical.transcript_bytes().to_vec(),
        request_digest: *canonical.request_digest(),
        signature: *canonical.signature(),
        historical_jkt: (endpoint == "blue.catbird.chat.revokeDevice")
            .then(|| pre_replay.dpop_jkt().as_str().to_owned()),
        current_jkt: None,
    }))
}

fn request_material_for_authority(
    authority: &VerifiedChatDeviceRequest,
) -> Result<RequestMaterial, AuthRepositoryError> {
    let mutation = authority
        .mutation()
        .ok_or(AuthRepositoryError::InvalidCompletion)?;
    let accepted = mutation
        .accepted_wrapper_bytes()
        .ok_or(AuthRepositoryError::MissingAcceptedRequestBytes)?;
    let operation_id = authority
        .repository_receipt()
        .operation_id()
        .ok_or(AuthRepositoryError::InvalidCompletion)?;
    let (historical_jkt, current_jkt) = completion_jkts(authority);
    Ok(RequestMaterial {
        operation_id,
        accepted_request_bytes: accepted.to_vec(),
        signing_transcript_bytes: mutation.transcript_bytes().to_vec(),
        request_digest: *mutation.request_digest(),
        signature: *mutation.signature(),
        historical_jkt: historical_jkt.map(str::to_owned),
        current_jkt: current_jkt.map(str::to_owned),
    })
}

fn operation_id_from_canonical(
    canonical: &CanonicalSignedMutation,
) -> Result<Uuid, AuthRepositoryError> {
    let raw = canonical
        .accepted_wrapper_bytes()
        .ok_or(AuthRepositoryError::MissingAcceptedRequestBytes)?;
    let value: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|_| AuthRepositoryError::MissingAcceptedRequestBytes)?;
    let text = value
        .get("body")
        .and_then(|body| body.get("idempotencyKey"))
        .and_then(serde_json::Value::as_str)
        .ok_or(AuthRepositoryError::MissingAcceptedRequestBytes)?;
    Ok(canonical_uuid(&CanonicalUuidV4::parse(text)?))
}

fn canonical_is_exact_self_target_revocation(
    canonical: &CanonicalSignedMutation,
) -> Result<bool, AuthRepositoryError> {
    if canonical.kind() != SignedMutationKind::DeviceRevocation {
        return Ok(false);
    }
    let raw = canonical
        .accepted_wrapper_bytes()
        .ok_or(AuthRepositoryError::MissingAcceptedRequestBytes)?;
    let value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| AuthRepositoryError::RequestBindingMismatch)?;
    let target_device_id = value
        .get("body")
        .and_then(|body| body.get("targetDeviceId"))
        .and_then(serde_json::Value::as_str)
        .ok_or(AuthRepositoryError::RequestBindingMismatch)?;
    Ok(canonical_uuid(&CanonicalUuidV4::parse(target_device_id)?)
        == canonical_uuid(canonical.actor_device_id()))
}

fn validate_replenishment_binding(
    pre_replay: &PreReplayCryptographicVerification,
    canonical: &CanonicalSignedMutation,
    state: &LockedDeviceAuthority,
) -> Result<(), AuthRepositoryError> {
    let accepted = canonical
        .accepted_wrapper_bytes()
        .ok_or(AuthRepositoryError::MissingAcceptedRequestBytes)?;
    let wrapper: serde_json::Value = serde_json::from_slice(accepted)
        .map_err(|_| AuthRepositoryError::MissingAcceptedRequestBytes)?;
    let body = wrapper
        .get("body")
        .and_then(serde_json::Value::as_object)
        .ok_or(AuthRepositoryError::RequestBindingMismatch)?;
    let body_jkt = body
        .get("dpopJkt")
        .and_then(serde_json::Value::as_str)
        .ok_or(AuthRepositoryError::RequestBindingMismatch)?;
    let public_key_text = body
        .get("signaturePublicKey")
        .and_then(serde_json::Value::as_str)
        .ok_or(AuthRepositoryError::RequestBindingMismatch)?;
    let public_key = STANDARD
        .decode(public_key_text)
        .map_err(|_| AuthRepositoryError::RequestBindingMismatch)?;
    if !replenishment_binding_matches(
        body_jkt,
        pre_replay.dpop_jkt().as_str(),
        &state.dpop_jkt,
        &public_key,
        &state.signing_public_key,
    ) || STANDARD.encode(&public_key) != public_key_text
    {
        return Err(AuthRepositoryError::RequestBindingMismatch);
    }
    Ok(())
}

fn replenishment_binding_matches(
    body_jkt: &str,
    proof_jkt: &str,
    stored_jkt: &str,
    body_public_key: &[u8],
    stored_public_key: &[u8],
) -> bool {
    body_jkt == proof_jkt && body_jkt == stored_jkt && body_public_key == stored_public_key
}

fn locked_state_matches_receipt(
    receipt: &RepositoryAuthorityReceipt,
    state: &LockedDeviceAuthority,
) -> bool {
    let signing_key_sha256: [u8; 32] = Sha256::digest(&state.signing_public_key).into();
    receipt.locked_jkt() == Some(state.dpop_jkt.as_str())
        && receipt.locked_auth_generation() == Some(state.auth_generation)
        && receipt.locked_key_id() == Some(state.key_id.as_str())
        && receipt.locked_signing_key_sha256() == Some(&signing_key_sha256)
}

fn completion_status_is_valid(status: i32) -> bool {
    (200..=599).contains(&status)
}

fn endpoint_has_idempotency_record(endpoint: &str) -> bool {
    matches!(
        endpoint,
        "blue.catbird.chat.acceptConversation"
            | "blue.catbird.chat.acknowledgeWelcome"
            | "blue.catbird.chat.activateReset"
            | "blue.catbird.chat.cancelLeafRecovery"
            | "blue.catbird.chat.cancelLeave"
            | "blue.catbird.chat.closeConversation"
            | "blue.catbird.chat.createConversation"
            | "blue.catbird.chat.deleteBlob"
            | "blue.catbird.chat.enrollDevice"
            | "blue.catbird.chat.prepareBlobUpload"
            | "blue.catbird.chat.rebindDeviceAuthentication"
            | "blue.catbird.chat.rejectWelcome"
            | "blue.catbird.chat.replenishKeyPackages"
            | "blue.catbird.chat.requestLeafRecovery"
            | "blue.catbird.chat.requestLeave"
            | "blue.catbird.chat.requestReset"
            | "blue.catbird.chat.revokeDevice"
            | "blue.catbird.chat.submitTransition"
    )
}

fn endpoint_accepts_signed_mutation(endpoint: &str) -> bool {
    // These endpoints are signed, but their pre-replay evidence must only be
    // minted by the dedicated enrollment/rebind verifiers and consumed by the
    // matching repository entry points. Keep them visible to the unsigned
    // fail-closed check without admitting them through generic signed auth.
    matches!(
        endpoint,
        "blue.catbird.chat.enrollDevice" | "blue.catbird.chat.rebindDeviceAuthentication"
    ) || SignedMutationKind::ALL
        .into_iter()
        .any(|kind| endpoint_accepts_kind(endpoint, kind))
}

fn endpoint_accepts_kind(endpoint: &str, kind: SignedMutationKind) -> bool {
    match endpoint {
        "blue.catbird.chat.replenishKeyPackages" => {
            kind == SignedMutationKind::KeyPackageReplenishment
        }
        "blue.catbird.chat.revokeDevice" => kind == SignedMutationKind::DeviceRevocation,
        "blue.catbird.chat.prepareBlobUpload" => kind == SignedMutationKind::BlobUploadPreparation,
        "blue.catbird.chat.deleteBlob" => kind == SignedMutationKind::BlobDeletion,
        "blue.catbird.chat.createConversation" => kind == SignedMutationKind::Creation,
        "blue.catbird.chat.submitTransition" => matches!(
            kind,
            SignedMutationKind::CommitTransition
                | SignedMutationKind::PolicyTransition
                | SignedMutationKind::MetadataTransition
                | SignedMutationKind::LeafRecoveryFulfillment
                | SignedMutationKind::ZeroLeafLeave
                | SignedMutationKind::LeaveCommitFulfillment
        ),
        "blue.catbird.chat.acceptConversation" => kind == SignedMutationKind::ParticipantAcceptance,
        "blue.catbird.chat.sendMessage" => kind == SignedMutationKind::ApplicationSend,
        "blue.catbird.chat.publishTyping" => kind == SignedMutationKind::Typing,
        "blue.catbird.chat.requestReset" => kind == SignedMutationKind::ResetRequest,
        "blue.catbird.chat.activateReset" => kind == SignedMutationKind::ResetActivation,
        "blue.catbird.chat.requestLeafRecovery" => kind == SignedMutationKind::LeafRecoveryRequest,
        "blue.catbird.chat.cancelLeafRecovery" => {
            kind == SignedMutationKind::LeafRecoveryCancellation
        }
        "blue.catbird.chat.closeConversation" => kind == SignedMutationKind::ConversationClose,
        "blue.catbird.chat.requestLeave" => kind == SignedMutationKind::LeaveRequest,
        "blue.catbird.chat.cancelLeave" => kind == SignedMutationKind::LeaveCancellation,
        "blue.catbird.chat.acknowledgeWelcome" => {
            kind == SignedMutationKind::WelcomeAcknowledgement
        }
        "blue.catbird.chat.rejectWelcome" => kind == SignedMutationKind::WelcomeRejection,
        _ => false,
    }
}

fn completion_jkts(authority: &VerifiedChatDeviceRequest) -> (Option<&str>, Option<&str>) {
    match authority.endpoint().as_str() {
        "blue.catbird.chat.enrollDevice" => (None, Some(authority.dpop_jkt().as_str())),
        "blue.catbird.chat.rebindDeviceAuthentication" => (
            authority.repository_receipt().locked_jkt(),
            Some(authority.dpop_jkt().as_str()),
        ),
        "blue.catbird.chat.revokeDevice" => (authority.repository_receipt().locked_jkt(), None),
        _ => (None, None),
    }
}

fn numeric_datetime(value: NumericDate) -> Result<DateTime<Utc>, AuthPrimitiveError> {
    DateTime::<Utc>::from_timestamp(value.get(), 0)
        .ok_or_else(|| AuthPrimitiveError::invalid("NumericDate outside database timestamp range"))
}

fn canonical_uuid(value: &CanonicalUuidV4) -> Uuid {
    Uuid::from_bytes(*value.as_bytes())
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database) if database.code().as_deref() == Some(UNIQUE_VIOLATION)
    )
}

#[allow(dead_code)]
fn _assert_verified_mutation_is_not_clone(_: &VerifiedSignedMutation) {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn material() -> RequestMaterial {
        RequestMaterial {
            operation_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            accepted_request_bytes: br#"{"body":"exact"}"#.to_vec(),
            signing_transcript_bytes: b"domain\0transcript".to_vec(),
            request_digest: [1; 32],
            signature: [2; 64],
            historical_jkt: None,
            current_jkt: None,
        }
    }

    fn completed_row(material: &RequestMaterial) -> IdempotencyRow {
        IdempotencyRow {
            request_digest: material.request_digest.to_vec(),
            accepted_request_bytes: material.accepted_request_bytes.clone(),
            signing_transcript_bytes: material.signing_transcript_bytes.clone(),
            signature: Some(material.signature.to_vec()),
            completed_status: 200,
            response_bytes: b"response".to_vec(),
            response_sha256: Sha256::digest(b"response").to_vec(),
            event_position: None,
            historical_jkt: material.historical_jkt.clone(),
            current_jkt: material.current_jkt.clone(),
            completed_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }
    }

    #[test]
    fn completed_response_debug_never_exposes_replay_material() {
        let response_bytes = vec![222, 173, 190, 239, 17, 34, 51, 68];
        let response = CompletedIdempotentResponse::debug_redaction_sentinel_for_test(
            598,
            response_bytes.clone(),
        );
        let rendered = format!("{response:?}");

        assert_eq!(rendered, "CompletedIdempotentResponse(<redacted>)");
        assert!(!rendered.contains("598"));
        assert!(!rendered.contains(&format!("{response_bytes:?}")));
        assert!(!rendered.contains(&format!("{:?}", response.response_sha256())));
    }

    #[test]
    fn completion_status_contract_excludes_informational_and_out_of_range_values() {
        assert!(!completion_status_is_valid(199));
        assert!(completion_status_is_valid(200));
        assert!(completion_status_is_valid(599));
        assert!(!completion_status_is_valid(600));
    }

    #[test]
    fn bootstrap_only_endpoints_are_not_generic_signed_authorization_shapes() {
        for (endpoint, kind) in [
            (
                "blue.catbird.chat.enrollDevice",
                SignedMutationKind::DeviceEnrollment,
            ),
            (
                "blue.catbird.chat.rebindDeviceAuthentication",
                SignedMutationKind::DeviceAuthenticationRebind,
            ),
        ] {
            assert!(
                endpoint_accepts_signed_mutation(endpoint),
                "unsigned authorization must still reject the signed-only endpoint",
            );
            assert!(
                !endpoint_accepts_kind(endpoint, kind),
                "bootstrap-only endpoint escaped its dedicated authorizer",
            );
        }
    }

    #[test]
    fn post_lock_identical_request_converges_but_changed_exact_material_conflicts() {
        let material = material();
        let mut row = completed_row(&material);
        assert!(exact_request_material_matches(&material, &row));

        row.accepted_request_bytes.push(b' ');
        assert!(!exact_request_material_matches(&material, &row));
        row = completed_row(&material);
        row.request_digest[0] ^= 1;
        assert!(!exact_request_material_matches(&material, &row));
        row = completed_row(&material);
        row.signature.as_mut().unwrap()[0] ^= 1;
        assert!(!exact_request_material_matches(&material, &row));
    }

    #[test]
    fn completed_bootstrap_and_revocation_replays_require_exact_recorded_jkts() {
        let old = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let new = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";

        assert!(completed_replay_jkt_shape(
            "blue.catbird.chat.rebindDeviceAuthentication",
            new,
            Some(old),
            Some(new),
            Some(old),
            Some(new),
        ));
        assert!(!completed_replay_jkt_shape(
            "blue.catbird.chat.rebindDeviceAuthentication",
            new,
            Some(old),
            Some(new),
            Some(new),
            Some(new),
        ));
        assert!(!completed_replay_jkt_shape(
            "blue.catbird.chat.rebindDeviceAuthentication",
            old,
            Some(old),
            Some(new),
            Some(old),
            Some(new),
        ));
        assert!(completed_replay_jkt_shape(
            "blue.catbird.chat.revokeDevice",
            old,
            Some(old),
            None,
            Some(old),
            None,
        ));
        assert!(!completed_replay_jkt_shape(
            "blue.catbird.chat.revokeDevice",
            new,
            Some(old),
            None,
            Some(old),
            None,
        ));
    }

    #[test]
    fn rebind_business_recheck_uses_the_locked_old_binding() {
        let old_state = LockedDeviceAuthority {
            dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            auth_generation: 7,
            key_id: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA".to_owned(),
            signing_public_key: vec![3; 32],
        };
        let receipt = RepositoryAuthorityReceipt::existing(
            ReplayAuditIds {
                token: Uuid::new_v4(),
                proof: Uuid::new_v4(),
                auth_transaction: None,
            },
            Some(Uuid::new_v4()),
            &old_state,
            RepositoryAuthorityClass::RebindBootstrap,
        );
        assert!(locked_state_matches_receipt(&receipt, &old_state));

        let post_cas_state = LockedDeviceAuthority {
            dpop_jkt: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA".to_owned(),
            auth_generation: 8,
            key_id: old_state.key_id.clone(),
            signing_public_key: old_state.signing_public_key.clone(),
        };
        assert!(!locked_state_matches_receipt(&receipt, &post_cas_state));
    }

    #[test]
    fn replenishment_assertions_bind_both_jkt_and_exact_immutable_public_key() {
        let jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let public_key = [7_u8; 32];
        assert!(replenishment_binding_matches(
            jkt,
            jkt,
            jkt,
            &public_key,
            &public_key,
        ));
        assert!(!replenishment_binding_matches(
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA",
            jkt,
            jkt,
            &public_key,
            &public_key,
        ));
        let different_key = [8_u8; 32];
        assert!(!replenishment_binding_matches(
            jkt,
            jkt,
            jkt,
            &different_key,
            &public_key,
        ));
    }

    #[test]
    fn canonical_locked_scope_digest_binds_membership_and_mutable_row_state() {
        let device_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let locked_at = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let device = |status: &str, generation: i64, revoked_at| LockedCanonicalDeviceProjection {
            user_did: "did:web:actor.example.com".to_owned(),
            device_id,
            status: status.to_owned(),
            dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            auth_generation: generation,
            revoked_at,
        };
        let key =
            |public_key: u8, enrollment_generation: i64, revoked_at| LockedCanonicalKeyProjection {
                user_did: "did:web:actor.example.com".to_owned(),
                device_id,
                key_id: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA".to_owned(),
                signing_public_key: vec![public_key; 32],
                enrollment_auth_generation: enrollment_generation,
                revoked_at,
            };
        let digest = |principals: Vec<String>,
                      devices: Vec<LockedCanonicalDeviceProjection>,
                      keys: Vec<LockedCanonicalKeyProjection>| {
            canonical_locked_scope_digest(&principals, &devices, &keys)
        };
        let principals = vec!["did:web:actor.example.com".to_owned()];
        let baseline = digest(
            principals.clone(),
            vec![device("active", 7, None)],
            vec![key(3, 7, None)],
        );

        assert_ne!(
            baseline,
            digest(
                vec![
                    "did:web:actor.example.com".to_owned(),
                    "did:web:principal-only.example.com".to_owned(),
                ],
                vec![device("active", 7, None)],
                vec![key(3, 7, None)],
            ),
        );
        assert_ne!(
            baseline,
            digest(
                principals.clone(),
                vec![device("revoked", 7, Some(locked_at))],
                vec![key(3, 7, None)],
            ),
        );
        assert_ne!(
            baseline,
            digest(
                principals.clone(),
                vec![device("active", 8, None)],
                vec![key(3, 7, None)],
            ),
        );
        assert_ne!(
            baseline,
            digest(
                principals.clone(),
                vec![device("active", 7, None)],
                vec![key(4, 7, None)],
            ),
        );
        assert_ne!(
            baseline,
            digest(
                principals.clone(),
                vec![device("active", 7, None)],
                vec![key(3, 8, None)],
            ),
        );
        assert_ne!(
            baseline,
            digest(
                principals,
                vec![device("active", 7, None)],
                vec![key(3, 7, Some(locked_at))],
            ),
        );
    }

    #[test]
    fn operation_id_can_only_be_extracted_from_strict_canonical_wrapper_evidence() {
        let operation_id = "22222222-2222-4222-8222-222222222222";
        let raw = serde_json::to_vec(&json!({
            "body": {
                "$type": "blue.catbird.chat.defs#blobDeletionBody",
                "signatureDomain": "CATBIRD-CHAT-BLOB-DELETE\u{0000}",
                "blobId": "33333333-3333-4333-8333-333333333333",
                "actorDid": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
                "actorDeviceId": "3b241101-e2bb-4255-8caf-4136c566a962",
                "keyId": "If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk",
                "authGeneration": 1,
                "idempotencyKey": operation_id,
                "signedAt": "2026-07-22T14:05:09.123Z"
            },
            "signature": STANDARD.encode([0_u8; 64]),
        }))
        .unwrap();
        let canonical = decode_canonical_signed_mutation(&raw).unwrap();
        assert_eq!(
            operation_id_from_canonical(&canonical).unwrap(),
            Uuid::parse_str(operation_id).unwrap(),
        );
    }

    #[test]
    fn self_revocation_classifier_requires_the_actor_device_as_exact_target() {
        let actor_device_id = "3b241101-e2bb-4255-8caf-4136c566a962";
        let canonical = |target_device_id: &str| {
            let raw = serde_json::to_vec(&json!({
                "body": {
                    "$type": SignedMutationKind::DeviceRevocation.type_id(),
                    "signatureDomain": String::from_utf8(
                        SignedMutationKind::DeviceRevocation.domain().to_vec()
                    ).unwrap(),
                    "actorDid": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
                    "actorDeviceId": actor_device_id,
                    "keyId": "If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk",
                    "authGeneration": 1,
                    "targetDeviceId": target_device_id,
                    "targetAuthGeneration": 1,
                    "idempotencyKey": "22222222-2222-4222-8222-222222222222",
                    "signedAt": "2026-07-22T14:05:09.123Z"
                },
                "signature": STANDARD.encode([0_u8; 64]),
            }))
            .unwrap();
            decode_canonical_signed_mutation(&raw).unwrap()
        };

        assert!(canonical_is_exact_self_target_revocation(&canonical(actor_device_id)).unwrap());
        assert!(!canonical_is_exact_self_target_revocation(&canonical(
            "44444444-4444-4444-8444-444444444444"
        ))
        .unwrap());
    }
}
