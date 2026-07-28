// Shared lock-order and durable-operation prelude for clean-chat mutations.
//
// This module is the only repository boundary allowed to acquire the global
// operation advisory lock and the canonical principal/device/key prefix used
// by multi-identity operations. It performs no network I/O.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

use super::{
    super::{
        dpop::VerifiedChatDeviceRequest,
        transcript::{SignedMutationKind, VerifiedMutationProjection, VerifiedSignedMutation},
        validation::BareDid,
    },
    auth::{self, CompletedIdempotentResponse, RepositoryAuthorityClass},
};

#[derive(Debug, Error)]
pub(crate) enum PreludeError {
    #[error("operation authority belongs to a different transaction")]
    ForeignTransaction,
    #[error("operation authority class is not supported by this prelude")]
    UnsupportedAuthority,
    #[error("operation identity is not canonical")]
    NonCanonicalOperation,
    #[error("identity scope is empty or non-canonical")]
    CanonicalScope,
    #[error("the canonical identity scope changed while it was being locked")]
    ScopeDrift,
    #[error("a required principal row is missing")]
    MissingPrincipal,
    #[error("a required device row is missing")]
    MissingDevice,
    #[error("a required device key row is missing")]
    MissingDeviceKey,
    #[error("the locked actor no longer matches request authority")]
    AuthorityBindingMismatch,
    #[error("operation ID is already bound to different immutable material")]
    OperationIdConflict,
    #[error("operation claim or receipt failed its integrity check")]
    ClaimIntegrity,
    #[error(transparent)]
    Authorization(#[from] auth::AuthRepositoryError),
    #[error("clean-chat prelude database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalDeviceIdentity {
    did: String,
    device_id: Uuid,
}

impl CanonicalDeviceIdentity {
    pub(crate) fn new(did: impl Into<String>, device_id: Uuid) -> Self {
        Self {
            did: did.into(),
            device_id,
        }
    }

    pub(crate) fn did(&self) -> &str {
        &self.did
    }

    pub(crate) fn device_id(&self) -> Uuid {
        self.device_id
    }
}

#[derive(Debug)]
pub(crate) struct CanonicalLockScope {
    principals: Vec<String>,
    devices: Vec<CanonicalDeviceIdentity>,
}

impl CanonicalLockScope {
    pub(crate) fn new(
        mut principals: Vec<String>,
        mut devices: Vec<CanonicalDeviceIdentity>,
    ) -> Result<Self, PreludeError> {
        if (principals.is_empty() && devices.is_empty())
            || principals.iter().any(|did| BareDid::parse(did).is_err())
            || devices.iter().any(|identity| {
                BareDid::parse(&identity.did).is_err() || identity.device_id.get_version_num() != 4
            })
        {
            return Err(PreludeError::CanonicalScope);
        }
        principals.extend(devices.iter().map(|identity| identity.did.clone()));
        principals.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        principals.dedup();
        devices.sort_unstable_by(|left, right| {
            left.did
                .as_bytes()
                .cmp(right.did.as_bytes())
                .then_with(|| left.device_id.as_bytes().cmp(right.device_id.as_bytes()))
        });
        devices.dedup();
        Ok(Self {
            principals,
            devices,
        })
    }

    pub(crate) fn principals(&self) -> &[String] {
        &self.principals
    }

    pub(crate) fn devices(&self) -> &[CanonicalDeviceIdentity] {
        &self.devices
    }
}

pub(crate) fn canonical_operation_lock_key(operation_id: Uuid) -> String {
    format!("chat-operation-id:{operation_id}")
}

#[derive(Clone, Debug)]
pub(crate) struct OperationClaimBinding {
    operation_id: Uuid,
    principal_did: String,
    endpoint_nsid: String,
    mutation_kind: String,
    request_digest: [u8; 32],
    accepted_request_sha256: [u8; 32],
    signature: [u8; 64],
    claimed_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub(crate) struct OperationClaimRow {
    operation_id: Uuid,
    principal_did: String,
    endpoint_nsid: String,
    mutation_kind: String,
    request_digest: Vec<u8>,
    accepted_request_sha256: Vec<u8>,
    signature: Vec<u8>,
    claimed_at: DateTime<Utc>,
}

impl OperationClaimRow {
    fn matches(&self, binding: &OperationClaimBinding) -> bool {
        self.operation_id == binding.operation_id
            && self.principal_did == binding.principal_did
            && self.endpoint_nsid == binding.endpoint_nsid
            && self.mutation_kind == binding.mutation_kind
            && self.request_digest.as_slice() == binding.request_digest
            && self.accepted_request_sha256.as_slice() == binding.accepted_request_sha256
            && self.signature.as_slice() == binding.signature
    }

    fn matches_exact(&self, binding: &OperationClaimBinding) -> bool {
        self.matches(binding) && self.claimed_at == binding.claimed_at
    }

    #[cfg(test)]
    fn for_test(
        operation_id: Uuid,
        principal_did: &str,
        endpoint_nsid: &str,
        mutation_kind: &str,
        request_digest: Vec<u8>,
        accepted_request_sha256: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            operation_id,
            principal_did: principal_did.to_owned(),
            endpoint_nsid: endpoint_nsid.to_owned(),
            mutation_kind: mutation_kind.to_owned(),
            request_digest,
            accepted_request_sha256,
            signature,
            claimed_at: DateTime::<Utc>::from_timestamp_millis(0)
                .expect("Unix epoch is a valid UTC timestamp"),
        }
    }
}

impl OperationClaimBinding {
    fn from_authority(authority: &VerifiedChatDeviceRequest) -> Result<Self, PreludeError> {
        let endpoint = authority.endpoint().as_str();
        if !endpoint_has_operation_claim(endpoint) {
            return Err(PreludeError::NonCanonicalOperation);
        }
        let mutation = authority
            .mutation()
            .ok_or(PreludeError::UnsupportedAuthority)?;
        let accepted_request_bytes = mutation
            .accepted_wrapper_bytes()
            .ok_or(PreludeError::NonCanonicalOperation)?;
        let operation_id = authority
            .repository_receipt()
            .operation_id()
            .ok_or(PreludeError::NonCanonicalOperation)?;
        if operation_id.get_version_num() != 4 {
            return Err(PreludeError::NonCanonicalOperation);
        }
        Ok(Self {
            operation_id,
            principal_did: authority.subject().as_str().to_owned(),
            endpoint_nsid: endpoint.to_owned(),
            mutation_kind: mutation.type_id().to_owned(),
            request_digest: *mutation.request_digest(),
            accepted_request_sha256: Sha256::digest(accepted_request_bytes).into(),
            signature: *mutation.signature(),
            claimed_at: authority.trusted_instant().datetime(),
        })
    }

    #[cfg(test)]
    fn for_test(
        operation_id: Uuid,
        principal_did: &str,
        endpoint_nsid: &str,
        mutation_kind: &str,
        request_digest: [u8; 32],
        accepted_request_sha256: [u8; 32],
        signature: [u8; 64],
        claimed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            operation_id,
            principal_did: principal_did.to_owned(),
            endpoint_nsid: endpoint_nsid.to_owned(),
            mutation_kind: mutation_kind.to_owned(),
            request_digest,
            accepted_request_sha256,
            signature,
            claimed_at,
        }
    }
}

fn endpoint_has_operation_claim(endpoint: &str) -> bool {
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

pub(crate) enum OperationArbitration {
    Replay(ReplayCandidate),
    First(OperationReservationGuard),
}

/// Operation arbitration for active handlers. The replay branch is deliberately
/// byte-opaque until endpoint authority has been locked in this transaction.
pub(crate) enum OperationOnlyArbitration {
    Replay(OperationReplayGuard),
    First(OperationReservationGuard),
}

pub(crate) struct OperationReplayGuard {
    operation_lock: auth::CanonicalOperationReservationGuard,
    binding: OperationClaimBinding,
}

impl fmt::Debug for OperationOnlyArbitration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replay(_) => formatter.write_str("OperationOnlyArbitration::Replay(<opaque>)"),
            Self::First(_) => formatter.write_str("OperationOnlyArbitration::First(<sealed>)"),
        }
    }
}

pub(crate) struct ReplayCandidate {
    transaction_id: String,
    binding: OperationClaimBinding,
    response: CompletedIdempotentResponse,
}

impl fmt::Debug for OperationArbitration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replay(_) => formatter.write_str("OperationArbitration::Replay(<redacted>)"),
            Self::First(reservation) => formatter
                .debug_tuple("OperationArbitration::First")
                .field(reservation)
                .finish(),
        }
    }
}

impl fmt::Debug for ReplayCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReplayCandidate(<redacted>)")
    }
}

#[derive(Debug)]
pub(crate) struct OperationReservationGuard {
    operation_lock: auth::CanonicalOperationReservationGuard,
    binding: OperationClaimBinding,
}

#[derive(Debug)]
struct OperationClaimGuard {
    transaction_id: String,
    binding: OperationClaimBinding,
}

pub(crate) struct PreparedBusinessPrelude {
    authority: ScopeBoundBusinessAuthority,
    operation: OperationClaimGuard,
}

#[must_use]
pub(crate) struct PreparedEnrollmentBootstrapPrelude {
    authority: VerifiedChatDeviceRequest,
    scope: auth::EnrollmentAbsenceLockedBootstrapScope,
    operation: OperationClaimGuard,
}

#[must_use]
pub(crate) struct PreparedRebindBootstrapPrelude {
    authority: VerifiedChatDeviceRequest,
    scope: auth::RebindOldStateLockedBootstrapScope,
    operation: OperationClaimGuard,
}

#[must_use]
pub(crate) struct PreparedReplenishmentPrelude {
    inner: PreparedBusinessPrelude,
    authority: VerifiedChatDeviceRequest,
}

pub(crate) struct EnrollmentBootstrapEffectAuthority<'a> {
    authority: &'a VerifiedChatDeviceRequest,
    scope: &'a auth::EnrollmentAbsenceLockedBootstrapScope,
}

pub(crate) struct RebindBootstrapEffectAuthority<'a> {
    authority: &'a VerifiedChatDeviceRequest,
    scope: &'a auth::RebindOldStateLockedBootstrapScope,
}

impl PreparedEnrollmentBootstrapPrelude {
    pub(crate) fn effect_authority(&self) -> EnrollmentBootstrapEffectAuthority<'_> {
        EnrollmentBootstrapEffectAuthority {
            authority: &self.authority,
            scope: &self.scope,
        }
    }

    pub(crate) fn into_completion_guard(self) -> BootstrapCompletionGuard {
        let current = self.scope.new_jkt().to_owned();
        let authority_digest = bootstrap_completion_digest(
            &self.operation.transaction_id,
            &self.operation.binding,
            self.scope.receipt_id(),
            self.scope.scope_digest(),
            self.scope.trusted_instant(),
            self.scope.subject(),
            self.scope.device_id(),
            &current,
            None,
            None,
            None,
            None,
        );
        BootstrapCompletionGuard {
            operation: self.operation,
            scope_receipt_id: self.scope.receipt_id(),
            authority_digest,
            scope_digest: *self.scope.scope_digest(),
            jkt_shape: BootstrapCompletionJktShape::Enrollment { current },
        }
    }
}

impl PreparedRebindBootstrapPrelude {
    pub(crate) fn effect_authority(&self) -> RebindBootstrapEffectAuthority<'_> {
        RebindBootstrapEffectAuthority {
            authority: &self.authority,
            scope: &self.scope,
        }
    }

    pub(crate) fn into_completion_guard(self) -> BootstrapCompletionGuard {
        let historical = self.scope.old_jkt().to_owned();
        let current = self.scope.new_jkt().to_owned();
        let key_id = self.scope.key_id().to_owned();
        let auth_generation = self.scope.old_auth_generation();
        let signing_key_sha256: [u8; 32] = Sha256::digest(self.scope.signing_public_key()).into();
        let authority_digest = bootstrap_completion_digest(
            &self.operation.transaction_id,
            &self.operation.binding,
            self.scope.receipt_id(),
            self.scope.scope_digest(),
            self.scope.trusted_instant(),
            self.scope.subject(),
            self.scope.device_id(),
            &current,
            Some(&historical),
            Some(&key_id),
            Some(auth_generation),
            Some(&signing_key_sha256),
        );
        BootstrapCompletionGuard {
            operation: self.operation,
            scope_receipt_id: self.scope.receipt_id(),
            authority_digest,
            scope_digest: *self.scope.scope_digest(),
            jkt_shape: BootstrapCompletionJktShape::Rebind {
                historical,
                current,
            },
        }
    }
}

impl PreparedReplenishmentPrelude {
    pub(crate) fn authority(&self) -> &VerifiedChatDeviceRequest {
        &self.authority
    }
    pub(crate) fn scope_authority(&self) -> &ScopeBoundBusinessAuthority {
        self.inner.scope_authority()
    }

    pub(crate) fn into_completion_guard(
        self,
    ) -> (BootstrapCompletionGuard, ScopeBoundBusinessAuthority) {
        let (scope, completion) = self.inner.into_execution_parts();
        let authority_digest = bootstrap_completion_digest(
            &completion.operation.transaction_id,
            &completion.operation.binding,
            completion.scope_receipt_id,
            &completion.scope_digest,
            scope.trusted_instant(),
            scope.actor_did(),
            scope.actor_device_id(),
            scope.actor_dpop_jkt().unwrap_or_default(),
            None,
            None,
            None,
            None,
        );
        (
            BootstrapCompletionGuard {
                operation: completion.operation,
                scope_receipt_id: completion.scope_receipt_id,
                authority_digest,
                scope_digest: completion.scope_digest,
                jkt_shape: BootstrapCompletionJktShape::Replenishment,
            },
            scope,
        )
    }
}

impl EnrollmentBootstrapEffectAuthority<'_> {
    pub(crate) fn request(&self) -> &VerifiedChatDeviceRequest {
        self.authority
    }
    pub(crate) fn subject(&self) -> &str {
        self.scope.subject()
    }
    pub(crate) fn device_id(&self) -> Uuid {
        self.scope.device_id()
    }
    pub(crate) fn trusted_instant(&self) -> DateTime<Utc> {
        self.scope.trusted_instant()
    }
}

impl RebindBootstrapEffectAuthority<'_> {
    pub(crate) fn request(&self) -> &VerifiedChatDeviceRequest {
        self.authority
    }
    pub(crate) fn subject(&self) -> &str {
        self.scope.subject()
    }
    pub(crate) fn device_id(&self) -> Uuid {
        self.scope.device_id()
    }
    pub(crate) fn old_jkt(&self) -> &str {
        self.scope.old_jkt()
    }
    pub(crate) fn new_jkt(&self) -> &str {
        self.scope.new_jkt()
    }
    pub(crate) fn old_auth_generation(&self) -> i64 {
        self.scope.old_auth_generation()
    }
    pub(crate) fn key_id(&self) -> &str {
        self.scope.key_id()
    }
    pub(crate) fn signing_public_key(&self) -> &[u8] {
        self.scope.signing_public_key()
    }
    pub(crate) fn trusted_instant(&self) -> DateTime<Utc> {
        self.scope.trusted_instant()
    }
}

impl fmt::Debug for PreparedBusinessPrelude {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedBusinessPrelude(<sealed>)")
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum ResetOperationClaimMutationForTest {
    OperationId,
    Principal,
    Transaction,
    RequestDigest,
    AcceptedWrapperHash,
    Signature,
    PresentedMutation,
    Endpoint,
    MutationKind,
}

/// Executes the real consuming Reset verifier against one deliberately altered
/// claim dimension. The fixture remains Reset-specific and derives its sealed
/// scope and baseline claim entirely from verified mutations.
#[cfg(test)]
pub(crate) fn reset_operation_claim_mutation_rejected_for_test(
    claimed_mutation: &VerifiedSignedMutation,
    presented_mutation: &VerifiedSignedMutation,
    dpop_jkt: &str,
    signing_public_key: &[u8],
    mutation: ResetOperationClaimMutationForTest,
) -> bool {
    let (operation_id, endpoint) = match claimed_mutation.projection() {
        VerifiedMutationProjection::ResetRequest(reset) => (
            Uuid::from_bytes(*reset.reset_request_id().as_bytes()),
            ResetOperationEndpoint::RequestReset,
        ),
        VerifiedMutationProjection::ResetActivation(reset) => (
            Uuid::from_bytes(*reset.transition_id().as_bytes()),
            ResetOperationEndpoint::ActivateReset,
        ),
        _ => return false,
    };
    let accepted_request_bytes = match claimed_mutation.accepted_wrapper_bytes() {
        Some(bytes) => bytes,
        None => return false,
    };
    let locked = match auth::reset_locked_scope_for_claim_test(
        claimed_mutation,
        dpop_jkt,
        signing_public_key,
    ) {
        Ok(locked) => locked,
        Err(_) => return false,
    };
    let transaction_id = locked.transaction_id().to_owned();
    let mut binding = OperationClaimBinding {
        operation_id,
        principal_did: claimed_mutation.actor_did().as_str().to_owned(),
        endpoint_nsid: endpoint.endpoint_nsid().to_owned(),
        mutation_kind: claimed_mutation.type_id().to_owned(),
        request_digest: *claimed_mutation.request_digest(),
        accepted_request_sha256: Sha256::digest(accepted_request_bytes).into(),
        signature: *claimed_mutation.signature(),
        claimed_at: claimed_mutation.signed_at().datetime(),
    };
    let mut operation_transaction_id = transaction_id;
    let mut presented_operation_id = operation_id;
    let mut presented_endpoint = endpoint;
    let presented = if matches!(
        mutation,
        ResetOperationClaimMutationForTest::PresentedMutation
    ) {
        presented_mutation
    } else {
        claimed_mutation
    };
    match mutation {
        ResetOperationClaimMutationForTest::OperationId => presented_operation_id = Uuid::new_v4(),
        ResetOperationClaimMutationForTest::Principal => binding.principal_did.push('x'),
        ResetOperationClaimMutationForTest::Transaction => operation_transaction_id.push('x'),
        ResetOperationClaimMutationForTest::RequestDigest => binding.request_digest[0] ^= 1,
        ResetOperationClaimMutationForTest::AcceptedWrapperHash => {
            binding.accepted_request_sha256[0] ^= 1
        }
        ResetOperationClaimMutationForTest::Signature => binding.signature[0] ^= 1,
        ResetOperationClaimMutationForTest::PresentedMutation => {}
        ResetOperationClaimMutationForTest::Endpoint => {
            presented_endpoint = match endpoint {
                ResetOperationEndpoint::RequestReset => ResetOperationEndpoint::ActivateReset,
                ResetOperationEndpoint::ActivateReset => ResetOperationEndpoint::RequestReset,
            }
        }
        ResetOperationClaimMutationForTest::MutationKind => {
            binding.mutation_kind = match claimed_mutation.kind() {
                SignedMutationKind::ResetRequest => SignedMutationKind::ResetActivation.type_id(),
                SignedMutationKind::ResetActivation => SignedMutationKind::ResetRequest.type_id(),
                _ => return false,
            }
            .to_owned()
        }
    }
    PreparedBusinessPrelude {
        authority: ScopeBoundBusinessAuthority { locked },
        operation: OperationClaimGuard {
            transaction_id: operation_transaction_id,
            binding,
        },
    }
    .verify_reset_operation(presented_endpoint, presented_operation_id, presented)
    .is_err()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryOperationEndpoint {
    RequestLeafRecovery,
    CancelLeafRecovery,
    SubmitRecoveryFulfillment,
}

impl RecoveryOperationEndpoint {
    fn endpoint_nsid(self) -> &'static str {
        match self {
            Self::RequestLeafRecovery => "blue.catbird.chat.requestLeafRecovery",
            Self::CancelLeafRecovery => "blue.catbird.chat.cancelLeafRecovery",
            Self::SubmitRecoveryFulfillment => "blue.catbird.chat.submitTransition",
        }
    }

    fn mutation_kind(self) -> &'static str {
        match self {
            Self::RequestLeafRecovery => "blue.catbird.chat.defs#leafRecoveryRequestBody",
            Self::CancelLeafRecovery => "blue.catbird.chat.defs#leafRecoveryCancellationBody",
            Self::SubmitRecoveryFulfillment => "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResetOperationEndpoint {
    RequestReset,
    ActivateReset,
}

impl ResetOperationEndpoint {
    fn endpoint_nsid(self) -> &'static str {
        match self {
            Self::RequestReset => "blue.catbird.chat.requestReset",
            Self::ActivateReset => "blue.catbird.chat.activateReset",
        }
    }

    fn mutation_kind(self) -> SignedMutationKind {
        match self {
            Self::RequestReset => SignedMutationKind::ResetRequest,
            Self::ActivateReset => SignedMutationKind::ResetActivation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeOperationEndpoint {
    AcknowledgeWelcome,
    RejectWelcome,
}

impl WelcomeOperationEndpoint {
    fn endpoint_nsid(self) -> &'static str {
        match self {
            Self::AcknowledgeWelcome => "blue.catbird.chat.acknowledgeWelcome",
            Self::RejectWelcome => "blue.catbird.chat.rejectWelcome",
        }
    }

    fn mutation_kind(self) -> SignedMutationKind {
        match self {
            Self::AcknowledgeWelcome => SignedMutationKind::WelcomeAcknowledgement,
            Self::RejectWelcome => SignedMutationKind::WelcomeRejection,
        }
    }
}

/// Single-use proof that the exact canonical principal/device/key projection
/// was locked after request admission. It deliberately exposes neither the raw
/// business guard nor a dereference/escape hatch to it.
pub(crate) struct ScopeBoundBusinessAuthority {
    locked: auth::LockedCanonicalAuthorityScope,
}

pub(crate) struct OperationCompletionGuard {
    operation: OperationClaimGuard,
    scope_receipt_id: Uuid,
    authority_digest: [u8; 32],
    scope_digest: [u8; 32],
}

/// Non-completing, data-only witness retained by the private Recovery graph.
/// Construction is confined to `PreparedBusinessPrelude`; the witness contains
/// no repository receipt or operation-completion capability.
#[must_use]
pub(crate) struct RecoveryPreludePrewriteWitness {
    transaction_id: Box<str>,
    operation: OperationClaimBinding,
    scope_receipt_id: Uuid,
    scope: auth::CanonicalAuthorityScopePrewriteSnapshot,
    completion_authority_digest: [u8; 32],
    witness_digest: [u8; 32],
    plan_seal: Option<RecoveryPreludePlanSeal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::chat_protocol::repository) enum RecoveryPreludePersistenceMode {
    Open,
    Cancelled,
    Fulfilled,
    ClientExpired {
        terminal_at: DateTime<Utc>,
        post_apply_error: RecoveryPreludeClientExpiryError,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::chat_protocol::repository) enum RecoveryPreludeClientExpiryError {
    CancellationConflict,
    RecoveryNotFound,
    RecoveryExpired,
    RecoverySuperseded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::chat_protocol::repository) enum RecoveryPreludePlanKind {
    RecoveryRequest,
    RecoveryCancellation,
    Commit,
    RecoveryExpiry,
}

/// Exact already-sealed Recovery aggregate/head coordinate copied into the
/// plan-binding digest. The constructor remains inside the repository tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::chat_protocol::repository) struct RecoveryPreludeAggregatePlanBinding {
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    group_id: [u8; 32],
    epoch: i64,
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
    aggregate_head_digest: [u8; 32],
    aggregate_graph_digest: [u8; 32],
    aggregate_snapshot_digest: Option<[u8; 32]>,
    recovery_head_digest: [u8; 32],
    recovery_graph_digest: [u8; 32],
    cross_binding_digest: [u8; 32],
}

impl RecoveryPreludeAggregatePlanBinding {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::chat_protocol::repository) fn new(
        conversation_id: Uuid,
        generation: i64,
        state_version: i64,
        group_id: [u8; 32],
        epoch: i64,
        group_context_hash: [u8; 32],
        confirmation_tag: [u8; 32],
        aggregate_head_digest: [u8; 32],
        aggregate_graph_digest: [u8; 32],
        aggregate_snapshot_digest: Option<[u8; 32]>,
        recovery_head_digest: [u8; 32],
        recovery_graph_digest: [u8; 32],
        cross_binding_digest: [u8; 32],
    ) -> Self {
        Self {
            conversation_id,
            generation,
            state_version,
            group_id,
            epoch,
            group_context_hash,
            confirmation_tag,
            aggregate_head_digest,
            aggregate_graph_digest,
            aggregate_snapshot_digest,
            recovery_head_digest,
            recovery_graph_digest,
            cross_binding_digest,
        }
    }
}

/// Repository-derived description of the actual private Recovery plan. The
/// fingerprint must cover the complete plan authority, head CAS, Recovery and
/// package effects; accepted-control bytes are independently hash-bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::chat_protocol::repository) struct RecoveryPreludePlanBinding {
    endpoint: RecoveryOperationEndpoint,
    mutation_kind: SignedMutationKind,
    mode: RecoveryPreludePersistenceMode,
    plan_kind: RecoveryPreludePlanKind,
    target_recovery_request_id: Uuid,
    transaction_id: Box<str>,
    graph_actor_did: Box<str>,
    graph_actor_device_id: Uuid,
    aggregate: RecoveryPreludeAggregatePlanBinding,
    plan_fingerprint: [u8; 32],
    accepted_control_sha256: Option<[u8; 32]>,
}

impl RecoveryPreludePlanBinding {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::chat_protocol::repository) fn new(
        endpoint: RecoveryOperationEndpoint,
        mutation_kind: SignedMutationKind,
        mode: RecoveryPreludePersistenceMode,
        plan_kind: RecoveryPreludePlanKind,
        target_recovery_request_id: Uuid,
        transaction_id: &str,
        graph_actor_did: &str,
        graph_actor_device_id: Uuid,
        aggregate: RecoveryPreludeAggregatePlanBinding,
        plan_fingerprint: [u8; 32],
        accepted_control_sha256: Option<[u8; 32]>,
    ) -> Self {
        Self {
            endpoint,
            mutation_kind,
            mode,
            plan_kind,
            target_recovery_request_id,
            transaction_id: transaction_id.to_owned().into_boxed_str(),
            graph_actor_did: graph_actor_did.to_owned().into_boxed_str(),
            graph_actor_device_id,
            aggregate,
            plan_fingerprint,
            accepted_control_sha256,
        }
    }
}

struct RecoveryPreludePlanSeal {
    binding: RecoveryPreludePlanBinding,
    seal_digest: [u8; 32],
}

impl fmt::Debug for RecoveryPreludePrewriteWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryPreludePrewriteWitness(<sealed>)")
    }
}

/// Single-use opaque completion capability for enrollment, rebind, and
/// replenishment bootstrap operations. The domain-separated digest binds
/// the exact operation claim, locked scope receipt, and JKT shape.
#[must_use]
pub(crate) struct BootstrapCompletionGuard {
    operation: OperationClaimGuard,
    scope_receipt_id: Uuid,
    authority_digest: [u8; 32],
    scope_digest: [u8; 32],
    jkt_shape: BootstrapCompletionJktShape,
}

#[cfg(test)]
impl BootstrapCompletionGuard {
    /// Pure test seam for exercising the same sealed guard dimensions that the
    /// async completion validator re-derives before its first write.
    pub(crate) fn matches_test_material(
        &self,
        transaction_id: &str,
        binding: &OperationClaimBinding,
        scope_receipt_id: Uuid,
        scope_digest: &[u8; 32],
        trusted_instant: DateTime<Utc>,
        subject: &str,
        device_id: Uuid,
        current_jkt: &str,
        historical_jkt: Option<&str>,
        key_id: Option<&str>,
        old_auth_generation: Option<i64>,
        signing_key_sha256: Option<&[u8; 32]>,
    ) -> bool {
        if self.operation.transaction_id != transaction_id
            || self.operation.binding.operation_id != binding.operation_id
            || self.operation.binding.principal_did != binding.principal_did
            || self.operation.binding.endpoint_nsid != binding.endpoint_nsid
            || self.operation.binding.mutation_kind != binding.mutation_kind
            || self.operation.binding.request_digest != binding.request_digest
            || self.operation.binding.accepted_request_sha256 != binding.accepted_request_sha256
            || self.operation.binding.signature != binding.signature
            || self.scope_receipt_id != scope_receipt_id
            || self.scope_digest != *scope_digest
        {
            return false;
        }
        let shape_matches = match &self.jkt_shape {
            BootstrapCompletionJktShape::Enrollment { current } => {
                historical_jkt.is_none() && current == current_jkt
            }
            BootstrapCompletionJktShape::Rebind {
                historical,
                current,
            } => historical_jkt == Some(historical.as_str()) && current == current_jkt,
            BootstrapCompletionJktShape::Replenishment => historical_jkt.is_none(),
        };
        shape_matches
            && bootstrap_completion_digest(
                transaction_id,
                binding,
                scope_receipt_id,
                scope_digest,
                trusted_instant,
                subject,
                device_id,
                current_jkt,
                historical_jkt,
                key_id,
                old_auth_generation,
                signing_key_sha256,
            ) == self.authority_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapCompletionJktShape {
    Enrollment { current: String },
    Rebind { historical: String, current: String },
    Replenishment,
}

impl ScopeBoundBusinessAuthority {
    fn receipt_id(&self) -> Uuid {
        self.locked.receipt_id()
    }

    pub(crate) fn transaction_id(&self) -> &str {
        self.locked.transaction_id()
    }

    pub(crate) fn actor_class(&self) -> RepositoryAuthorityClass {
        self.locked.actor_class()
    }

    pub(crate) fn actor_did(&self) -> &str {
        self.locked.actor_did()
    }

    pub(crate) fn actor_device_id(&self) -> Uuid {
        self.locked.actor_device_id()
    }

    pub(crate) fn actor_dpop_jkt(&self) -> Option<&str> {
        self.locked.actor_dpop_jkt()
    }

    pub(crate) fn actor_auth_generation(&self) -> Option<i64> {
        self.locked.actor_auth_generation()
    }

    pub(crate) fn actor_key_id(&self) -> Option<&str> {
        self.locked.actor_key_id()
    }

    pub(crate) fn actor_signing_public_key(&self) -> Option<&[u8]> {
        self.locked.actor_signing_public_key()
    }

    pub(crate) fn actor_projected_signing_public_key(&self) -> Option<&[u8]> {
        self.locked.actor_projected_signing_public_key()
    }

    pub(crate) fn signing_public_key_for(
        &self,
        did: &str,
        device_id: Uuid,
        key_id: &str,
        enrollment_auth_generation: i64,
    ) -> Option<&[u8]> {
        self.locked
            .signing_public_key_for(did, device_id, key_id, enrollment_auth_generation)
    }

    pub(crate) fn trusted_instant(&self) -> DateTime<Utc> {
        self.locked.trusted_instant()
    }

    pub(crate) fn principals(&self) -> &[String] {
        self.locked.principals()
    }

    pub(crate) fn devices(&self) -> &[auth::LockedCanonicalDeviceProjection] {
        self.locked.devices()
    }

    pub(crate) fn keys(&self) -> &[auth::LockedCanonicalKeyProjection] {
        self.locked.keys()
    }

    pub(crate) fn scope_digest(&self) -> &[u8; 32] {
        self.locked.scope_digest()
    }
}

impl RecoveryPreludePlanBinding {
    fn is_compatible_with(&self, witness: &RecoveryPreludePrewriteWitness) -> bool {
        let endpoint_matches = witness.operation.endpoint_nsid == self.endpoint.endpoint_nsid();
        let mutation_matches = witness.operation.mutation_kind == self.mutation_kind.type_id()
            && self.endpoint.mutation_kind() == self.mutation_kind.type_id();
        let shape_matches = match (
            self.endpoint,
            self.mutation_kind,
            self.mode,
            self.plan_kind,
            self.accepted_control_sha256,
        ) {
            (
                RecoveryOperationEndpoint::RequestLeafRecovery,
                SignedMutationKind::LeafRecoveryRequest,
                RecoveryPreludePersistenceMode::Open,
                RecoveryPreludePlanKind::RecoveryRequest,
                None,
            )
            | (
                RecoveryOperationEndpoint::CancelLeafRecovery,
                SignedMutationKind::LeafRecoveryCancellation,
                RecoveryPreludePersistenceMode::Cancelled,
                RecoveryPreludePlanKind::RecoveryCancellation,
                None,
            ) => true,
            (
                RecoveryOperationEndpoint::SubmitRecoveryFulfillment,
                SignedMutationKind::LeafRecoveryFulfillment,
                RecoveryPreludePersistenceMode::Fulfilled,
                RecoveryPreludePlanKind::Commit,
                Some(accepted_control_sha256),
            ) => accepted_control_sha256 != [0; 32],
            (
                RecoveryOperationEndpoint::CancelLeafRecovery,
                SignedMutationKind::LeafRecoveryCancellation,
                RecoveryPreludePersistenceMode::ClientExpired {
                    post_apply_error: RecoveryPreludeClientExpiryError::RecoveryNotFound,
                    ..
                },
                RecoveryPreludePlanKind::RecoveryExpiry,
                None,
            )
            | (
                RecoveryOperationEndpoint::SubmitRecoveryFulfillment,
                SignedMutationKind::LeafRecoveryFulfillment,
                RecoveryPreludePersistenceMode::ClientExpired {
                    post_apply_error: RecoveryPreludeClientExpiryError::RecoveryExpired,
                    ..
                },
                RecoveryPreludePlanKind::RecoveryExpiry,
                None,
            ) => true,
            _ => false,
        };
        endpoint_matches
            && mutation_matches
            && shape_matches
            && self.target_recovery_request_id.get_version_num() == 4
            && self.transaction_id.as_ref() == witness.transaction_id.as_ref()
            && self.graph_actor_did.as_ref() == witness.scope.actor_did()
            && self.graph_actor_device_id == witness.scope.actor_device_id()
            && self.graph_actor_did.as_ref() == witness.operation.principal_did
            && self.aggregate.conversation_id.get_version_num() == 4
            && self.aggregate.generation >= 0
            && self.aggregate.state_version >= 0
            && self.aggregate.epoch >= 0
            && self.aggregate.cross_binding_digest != [0; 32]
            && self.plan_fingerprint != [0; 32]
    }
}

impl RecoveryPreludePrewriteWitness {
    fn unbound(
        operation: OperationClaimBinding,
        scope_receipt_id: Uuid,
        scope: auth::CanonicalAuthorityScopePrewriteSnapshot,
        completion_authority_digest: [u8; 32],
    ) -> Self {
        let mut witness = Self {
            transaction_id: scope.transaction_id().to_owned().into_boxed_str(),
            operation,
            scope_receipt_id,
            scope,
            completion_authority_digest,
            witness_digest: [0; 32],
            plan_seal: None,
        };
        witness.witness_digest = witness.rederive_witness_digest();
        witness
    }

    pub(in crate::chat_protocol::repository) fn seal_recovery_plan(
        mut self,
        binding: RecoveryPreludePlanBinding,
    ) -> Result<Self, PreludeError> {
        if self.plan_seal.is_some()
            || self.witness_digest != self.rederive_witness_digest()
            || self.completion_authority_digest
                != completion_digest_from_prewrite_snapshot(
                    &self.scope,
                    self.scope_receipt_id,
                    &self.operation,
                )
            || !binding.is_compatible_with(&self)
        {
            return Err(PreludeError::ClaimIntegrity);
        }
        let seal_digest = self.rederive_plan_digest(&binding);
        self.plan_seal = Some(RecoveryPreludePlanSeal {
            binding,
            seal_digest,
        });
        Ok(self)
    }

    /// Validate the exact plan/claim/scope data before the first Recovery,
    /// event, or outbox write. This validator mints no authority.
    pub(in crate::chat_protocol::repository) async fn validate_recovery_prewrite(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        live_plan: &RecoveryPreludePlanBinding,
    ) -> Result<(), PreludeError> {
        let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
            .fetch_one(&mut **transaction)
            .await?;
        let Some(plan_seal) = self.plan_seal.as_ref() else {
            return Err(PreludeError::ClaimIntegrity);
        };
        if transaction_id != self.transaction_id.as_ref()
            || self.transaction_id.as_ref() != self.scope.transaction_id()
            || self.witness_digest != self.rederive_witness_digest()
            || self.completion_authority_digest
                != completion_digest_from_prewrite_snapshot(
                    &self.scope,
                    self.scope_receipt_id,
                    &self.operation,
                )
            || plan_seal.binding != *live_plan
            || !live_plan.is_compatible_with(self)
            || plan_seal.seal_digest != self.rederive_plan_digest(live_plan)
        {
            return Err(PreludeError::ForeignTransaction);
        }

        let live_claim: Option<OperationClaimRow> = sqlx::query_as(
            r#"
            SELECT operation_id,principal_did,endpoint_nsid,mutation_kind,
                   request_digest,accepted_request_sha256,signature,claimed_at
              FROM chat.operation_claims
             WHERE operation_id=$1
             FOR UPDATE
            "#,
        )
        .bind(self.operation.operation_id)
        .fetch_optional(&mut **transaction)
        .await?;
        if !live_claim
            .as_ref()
            .is_some_and(|claim| claim.matches_exact(&self.operation))
        {
            return Err(PreludeError::ClaimIntegrity);
        }

        auth::validate_canonical_authority_scope_prewrite(transaction, &self.scope).await?;
        Ok(())
    }

    fn rederive_witness_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"CATBIRD-CHAT-RECOVERY-PRELUDE-PREWRITE-WITNESS\0");
        for value in [
            self.transaction_id.as_bytes(),
            self.operation.principal_did.as_bytes(),
            self.operation.endpoint_nsid.as_bytes(),
            self.operation.mutation_kind.as_bytes(),
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        digest.update(self.operation.operation_id.as_bytes());
        digest.update(self.operation.request_digest);
        digest.update(self.operation.accepted_request_sha256);
        digest.update(self.operation.signature);
        digest.update(self.operation.claimed_at.timestamp_micros().to_be_bytes());
        digest.update(self.scope_receipt_id.as_bytes());
        digest.update(self.scope.scope_digest());
        digest.update(self.scope.snapshot_digest());
        digest.update(self.completion_authority_digest);
        digest.finalize().into()
    }

    fn rederive_plan_digest(&self, binding: &RecoveryPreludePlanBinding) -> [u8; 32] {
        fn bind_bytes(digest: &mut Sha256, value: &[u8]) {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }

        let mut digest = Sha256::new();
        digest.update(b"CATBIRD-CHAT-RECOVERY-PRELUDE-PLAN-BINDING\0");
        digest.update(self.witness_digest);
        digest.update([match binding.endpoint {
            RecoveryOperationEndpoint::RequestLeafRecovery => 1,
            RecoveryOperationEndpoint::CancelLeafRecovery => 2,
            RecoveryOperationEndpoint::SubmitRecoveryFulfillment => 3,
        }]);
        digest.update([match binding.mutation_kind {
            SignedMutationKind::LeafRecoveryRequest => 1,
            SignedMutationKind::LeafRecoveryCancellation => 2,
            SignedMutationKind::LeafRecoveryFulfillment => 3,
            _ => 0,
        }]);
        match binding.mode {
            RecoveryPreludePersistenceMode::Open => digest.update([1]),
            RecoveryPreludePersistenceMode::Cancelled => digest.update([2]),
            RecoveryPreludePersistenceMode::Fulfilled => digest.update([3]),
            RecoveryPreludePersistenceMode::ClientExpired {
                terminal_at,
                post_apply_error,
            } => {
                digest.update([4]);
                digest.update(terminal_at.timestamp_micros().to_be_bytes());
                digest.update([match post_apply_error {
                    RecoveryPreludeClientExpiryError::CancellationConflict => 1,
                    RecoveryPreludeClientExpiryError::RecoveryNotFound => 2,
                    RecoveryPreludeClientExpiryError::RecoveryExpired => 3,
                    RecoveryPreludeClientExpiryError::RecoverySuperseded => 4,
                }]);
            }
        }
        digest.update([match binding.plan_kind {
            RecoveryPreludePlanKind::RecoveryRequest => 1,
            RecoveryPreludePlanKind::RecoveryCancellation => 2,
            RecoveryPreludePlanKind::Commit => 3,
            RecoveryPreludePlanKind::RecoveryExpiry => 4,
        }]);
        digest.update(binding.target_recovery_request_id.as_bytes());
        for value in [
            binding.transaction_id.as_bytes(),
            binding.graph_actor_did.as_bytes(),
            self.scope.actor_did().as_bytes(),
            self.scope.actor_dpop_jkt().unwrap_or_default().as_bytes(),
            self.scope.actor_key_id().unwrap_or_default().as_bytes(),
        ] {
            bind_bytes(&mut digest, value);
        }
        digest.update(binding.graph_actor_device_id.as_bytes());
        digest.update([match self.scope.actor_class() {
            RepositoryAuthorityClass::ExistingDevice => 1,
            RepositoryAuthorityClass::EnrollmentBootstrap => 2,
            RepositoryAuthorityClass::RebindBootstrap => 3,
        }]);
        digest.update(self.scope.actor_device_id().as_bytes());
        digest.update(
            self.scope
                .actor_auth_generation()
                .unwrap_or_default()
                .to_be_bytes(),
        );
        digest.update(
            self.scope
                .actor_signing_key_sha256()
                .copied()
                .unwrap_or_default(),
        );
        digest.update(
            self.scope
                .trusted_instant()
                .timestamp_micros()
                .to_be_bytes(),
        );
        digest.update(binding.aggregate.conversation_id.as_bytes());
        digest.update(binding.aggregate.generation.to_be_bytes());
        digest.update(binding.aggregate.state_version.to_be_bytes());
        digest.update(binding.aggregate.group_id);
        digest.update(binding.aggregate.epoch.to_be_bytes());
        digest.update(binding.aggregate.group_context_hash);
        digest.update(binding.aggregate.confirmation_tag);
        digest.update(binding.aggregate.aggregate_head_digest);
        digest.update(binding.aggregate.aggregate_graph_digest);
        match binding.aggregate.aggregate_snapshot_digest {
            Some(value) => {
                digest.update([1]);
                digest.update(value);
            }
            None => digest.update([0]),
        }
        digest.update(binding.aggregate.recovery_head_digest);
        digest.update(binding.aggregate.recovery_graph_digest);
        digest.update(binding.aggregate.cross_binding_digest);
        digest.update(binding.plan_fingerprint);
        match binding.accepted_control_sha256 {
            Some(value) => {
                digest.update([1]);
                digest.update(value);
            }
            None => digest.update([0]),
        }
        digest.finalize().into()
    }
}

impl PreparedBusinessPrelude {
    pub(crate) fn scope_authority(&self) -> &ScopeBoundBusinessAuthority {
        &self.authority
    }

    /// Consume and return the prelude only when its private operation claim is
    /// the exact Recovery operation represented by `mutation`.
    pub(crate) fn verify_recovery_operation(
        self,
        endpoint: RecoveryOperationEndpoint,
        operation_id: Uuid,
        mutation: &VerifiedSignedMutation,
    ) -> Result<Self, PreludeError> {
        let accepted_request_bytes = mutation
            .accepted_wrapper_bytes()
            .ok_or(PreludeError::NonCanonicalOperation)?;
        let binding = &self.operation.binding;
        if operation_id.get_version_num() != 4
            || self.operation.transaction_id != self.authority.transaction_id()
            || binding.operation_id != operation_id
            || binding.principal_did != mutation.actor_did().as_str()
            || binding.endpoint_nsid != endpoint.endpoint_nsid()
            || binding.mutation_kind != endpoint.mutation_kind()
            || binding.mutation_kind != mutation.type_id()
            || binding.request_digest != *mutation.request_digest()
            || binding.accepted_request_sha256
                != <[u8; 32]>::from(Sha256::digest(accepted_request_bytes))
            || binding.signature != *mutation.signature()
        {
            return Err(PreludeError::ClaimIntegrity);
        }
        Ok(self)
    }

    pub(crate) fn verify_reset_operation(
        self,
        endpoint: ResetOperationEndpoint,
        operation_id: Uuid,
        mutation: &VerifiedSignedMutation,
    ) -> Result<Self, PreludeError> {
        self.verify_exact_operation_claim(
            endpoint.endpoint_nsid(),
            endpoint.mutation_kind(),
            operation_id,
            mutation,
        )
    }

    pub(crate) fn verify_device_revocation_operation(
        self,
        operation_id: Uuid,
        mutation: &VerifiedSignedMutation,
    ) -> Result<Self, PreludeError> {
        self.verify_exact_operation_claim(
            "blue.catbird.chat.revokeDevice",
            SignedMutationKind::DeviceRevocation,
            operation_id,
            mutation,
        )
    }

    pub(crate) fn verify_welcome_operation(
        self,
        endpoint: WelcomeOperationEndpoint,
        operation_id: Uuid,
        mutation: &VerifiedSignedMutation,
    ) -> Result<Self, PreludeError> {
        self.verify_exact_operation_claim(
            endpoint.endpoint_nsid(),
            endpoint.mutation_kind(),
            operation_id,
            mutation,
        )
    }

    fn verify_exact_operation_claim(
        self,
        endpoint_nsid: &str,
        mutation_kind: SignedMutationKind,
        operation_id: Uuid,
        mutation: &VerifiedSignedMutation,
    ) -> Result<Self, PreludeError> {
        let accepted_request_bytes = mutation
            .accepted_wrapper_bytes()
            .ok_or(PreludeError::NonCanonicalOperation)?;
        let binding = &self.operation.binding;
        if operation_id.get_version_num() != 4
            || self.operation.transaction_id != self.authority.transaction_id()
            || binding.operation_id != operation_id
            || binding.principal_did != mutation.actor_did().as_str()
            || binding.endpoint_nsid != endpoint_nsid
            || binding.mutation_kind != mutation_kind.type_id()
            || mutation.kind() != mutation_kind
            || binding.mutation_kind != mutation.type_id()
            || binding.request_digest != *mutation.request_digest()
            || binding.accepted_request_sha256
                != <[u8; 32]>::from(Sha256::digest(accepted_request_bytes))
            || binding.signature != *mutation.signature()
        {
            return Err(PreludeError::ClaimIntegrity);
        }
        Ok(self)
    }

    pub(crate) fn into_execution_parts(
        self,
    ) -> (ScopeBoundBusinessAuthority, OperationCompletionGuard) {
        let scope_digest = *self.authority.scope_digest();
        let scope_receipt_id = self.authority.receipt_id();
        let authority_digest =
            completion_digest_from_scope_authority(&self.authority, &self.operation.binding);
        (
            self.authority,
            OperationCompletionGuard {
                operation: self.operation,
                scope_receipt_id,
                authority_digest,
                scope_digest,
            },
        )
    }

    /// Recovery-only consuming split. The completion capability remains linear;
    /// the third sibling is an authority-free prewrite data witness.
    pub(crate) fn into_recovery_execution_parts(
        self,
    ) -> (
        ScopeBoundBusinessAuthority,
        OperationCompletionGuard,
        RecoveryPreludePrewriteWitness,
    ) {
        let scope_digest = *self.authority.scope_digest();
        let scope_receipt_id = self.authority.receipt_id();
        let completion_authority_digest =
            completion_digest_from_scope_authority(&self.authority, &self.operation.binding);
        let scope_snapshot = self.authority.locked.recovery_prewrite_snapshot();
        let prewrite = RecoveryPreludePrewriteWitness::unbound(
            self.operation.binding.clone(),
            scope_receipt_id,
            scope_snapshot,
            completion_authority_digest,
        );
        (
            self.authority,
            OperationCompletionGuard {
                operation: self.operation,
                scope_receipt_id,
                authority_digest: completion_authority_digest,
                scope_digest,
            },
            prewrite,
        )
    }
}

pub(crate) async fn arbitrate_operation(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
) -> Result<OperationArbitration, PreludeError> {
    let binding = OperationClaimBinding::from_authority(authority)?;
    let operation_lock = auth::reserve_canonical_operation(transaction, authority).await?;
    if operation_lock.operation_id() != binding.operation_id {
        return Err(PreludeError::NonCanonicalOperation);
    }
    let transaction_id = operation_lock.transaction_id().to_owned();
    let existing: Option<OperationClaimRow> = sqlx::query_as(
        r#"
        SELECT operation_id,principal_did,endpoint_nsid,mutation_kind,
               request_digest,accepted_request_sha256,signature,claimed_at
          FROM chat.operation_claims
         WHERE operation_id=$1
        "#,
    )
    .bind(binding.operation_id)
    .fetch_optional(&mut **transaction)
    .await?;

    if let Some(existing) = existing {
        if !existing.matches(&binding) {
            return Err(PreludeError::OperationIdConflict);
        }
        let response = auth::load_validated_completed_business_replay(transaction, authority)
            .await?
            .ok_or(PreludeError::ClaimIntegrity)?;
        return Ok(OperationArbitration::Replay(ReplayCandidate {
            transaction_id,
            binding,
            response,
        }));
    }

    Ok(OperationArbitration::First(OperationReservationGuard {
        operation_lock,
        binding,
    }))
}

pub(crate) async fn arbitrate_operation_only(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
) -> Result<OperationOnlyArbitration, PreludeError> {
    let binding = OperationClaimBinding::from_authority(authority)?;
    let operation_lock = auth::reserve_canonical_operation(transaction, authority).await?;
    if operation_lock.operation_id() != binding.operation_id {
        return Err(PreludeError::NonCanonicalOperation);
    }
    let existing: Option<OperationClaimRow> = sqlx::query_as(
        r#"
        SELECT operation_id,principal_did,endpoint_nsid,mutation_kind,
               request_digest,accepted_request_sha256,signature,claimed_at
          FROM chat.operation_claims
         WHERE operation_id=$1
        "#,
    )
    .bind(binding.operation_id)
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(existing) = existing {
        if !existing.matches(&binding) {
            return Err(PreludeError::OperationIdConflict);
        }
        return Ok(OperationOnlyArbitration::Replay(OperationReplayGuard {
            operation_lock,
            binding,
        }));
    }
    Ok(OperationOnlyArbitration::First(OperationReservationGuard {
        operation_lock,
        binding,
    }))
}

pub(crate) async fn prepare_enrollment_bootstrap_prelude(
    transaction: &mut Transaction<'_, Postgres>,
    admission: auth::EnrollmentOperationAdmission,
    reservation: OperationReservationGuard,
) -> Result<PreparedEnrollmentBootstrapPrelude, PreludeError> {
    let authority = admission.into_authority();
    let scope =
        auth::lock_enrollment_absence_scope(transaction, &authority, &reservation.operation_lock)
            .await?;
    let operation = claim_operation(transaction, reservation).await?;
    if !operation.binding.matches_authority(&authority)? {
        return Err(PreludeError::ClaimIntegrity);
    }
    Ok(PreparedEnrollmentBootstrapPrelude {
        authority,
        scope,
        operation,
    })
}

pub(crate) async fn prepare_rebind_bootstrap_prelude(
    transaction: &mut Transaction<'_, Postgres>,
    admission: auth::RebindOperationAdmission,
    reservation: OperationReservationGuard,
) -> Result<PreparedRebindBootstrapPrelude, PreludeError> {
    let authority = admission.into_authority();
    let scope =
        auth::lock_rebind_old_state_scope(transaction, &authority, &reservation.operation_lock)
            .await?;
    let operation = claim_operation(transaction, reservation).await?;
    if !operation.binding.matches_authority(&authority)? {
        return Err(PreludeError::ClaimIntegrity);
    }
    Ok(PreparedRebindBootstrapPrelude {
        authority,
        scope,
        operation,
    })
}

pub(crate) async fn prepare_replenishment_prelude(
    transaction: &mut Transaction<'_, Postgres>,
    admission: auth::ReplenishmentOperationAdmission,
    reservation: OperationReservationGuard,
) -> Result<PreparedReplenishmentPrelude, PreludeError> {
    let authority = admission.into_authority();
    let inner = prepare_actor_prelude(transaction, &authority, reservation).await?;
    Ok(PreparedReplenishmentPrelude { inner, authority })
}

async fn validate_operation_only_replay(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    replay: OperationReplayGuard,
) -> Result<CompletedIdempotentResponse, PreludeError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if replay.operation_lock.transaction_id() != transaction_id
        || replay.operation_lock.operation_id() != replay.binding.operation_id
        || !replay.binding.matches_authority(authority)?
    {
        return Err(PreludeError::ForeignTransaction);
    }
    auth::load_validated_completed_business_replay(transaction, authority)
        .await?
        .ok_or(PreludeError::ClaimIntegrity)
}

pub(crate) async fn validate_enrollment_operation_replay(
    transaction: &mut Transaction<'_, Postgres>,
    admission: auth::EnrollmentOperationAdmission,
    replay: OperationReplayGuard,
) -> Result<CompletedIdempotentResponse, PreludeError> {
    let authority = admission.into_authority();
    validate_operation_only_replay(transaction, &authority, replay).await
}

pub(crate) async fn validate_rebind_operation_replay(
    transaction: &mut Transaction<'_, Postgres>,
    admission: auth::RebindOperationAdmission,
    replay: OperationReplayGuard,
) -> Result<CompletedIdempotentResponse, PreludeError> {
    let authority = admission.into_authority();
    validate_operation_only_replay(transaction, &authority, replay).await
}

pub(crate) async fn validate_replenishment_operation_replay(
    transaction: &mut Transaction<'_, Postgres>,
    admission: auth::ReplenishmentOperationAdmission,
    replay: OperationReplayGuard,
) -> Result<CompletedIdempotentResponse, PreludeError> {
    let authority = admission.into_authority();
    validate_operation_only_replay(transaction, &authority, replay).await
}

pub(crate) async fn prepare_actor_prelude(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    reservation: OperationReservationGuard,
) -> Result<PreparedBusinessPrelude, PreludeError> {
    let scope = CanonicalLockScope::new(
        vec![authority.subject().as_str().to_owned()],
        vec![CanonicalDeviceIdentity::new(
            authority.subject().as_str(),
            Uuid::from_bytes(*authority.device_id().as_bytes()),
        )],
    )?;
    prepare_identity_scope_prelude(transaction, authority, reservation, scope).await
}

pub(crate) async fn prepare_identity_scope_prelude(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    reservation: OperationReservationGuard,
    scope: CanonicalLockScope,
) -> Result<PreparedBusinessPrelude, PreludeError> {
    let mut principals = scope.principals;
    principals.push(authority.subject().as_str().to_owned());
    let mut devices = scope.devices;
    devices.push(CanonicalDeviceIdentity::new(
        authority.subject().as_str(),
        Uuid::from_bytes(*authority.device_id().as_bytes()),
    ));
    let scope = CanonicalLockScope::new(principals, devices)?;
    let device_pairs = scope
        .devices
        .iter()
        .map(|identity| (identity.did.clone(), identity.device_id))
        .collect::<Vec<_>>();
    let business = auth::lock_canonical_business_authority_scope(
        transaction,
        authority,
        &reservation.operation_lock,
        &scope.principals,
        &device_pairs,
    )
    .await?;
    let operation = claim_operation(transaction, reservation).await?;
    Ok(PreparedBusinessPrelude {
        authority: ScopeBoundBusinessAuthority { locked: business },
        operation,
    })
}

pub(crate) async fn validate_replay(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    replay: ReplayCandidate,
) -> Result<CompletedIdempotentResponse, PreludeError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if replay.transaction_id != transaction_id || !replay.binding.matches_authority(authority)? {
        return Err(PreludeError::ForeignTransaction);
    }
    Ok(replay.response)
}

impl OperationClaimBinding {
    fn matches_authority(
        &self,
        authority: &VerifiedChatDeviceRequest,
    ) -> Result<bool, PreludeError> {
        let current = Self::from_authority(authority)?;
        Ok(self.operation_id == current.operation_id
            && self.principal_did == current.principal_did
            && self.endpoint_nsid == current.endpoint_nsid
            && self.mutation_kind == current.mutation_kind
            && self.request_digest == current.request_digest
            && self.accepted_request_sha256 == current.accepted_request_sha256
            && self.signature == current.signature)
    }
}

async fn claim_operation(
    transaction: &mut Transaction<'_, Postgres>,
    reservation: OperationReservationGuard,
) -> Result<OperationClaimGuard, PreludeError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if reservation.operation_lock.transaction_id() != transaction_id {
        return Err(PreludeError::ForeignTransaction);
    }
    let binding = reservation.binding;
    let inserted = sqlx::query(
        r#"
        INSERT INTO chat.operation_claims (
            operation_id,principal_did,endpoint_nsid,mutation_kind,
            request_digest,accepted_request_sha256,signature,claimed_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(binding.operation_id)
    .bind(&binding.principal_did)
    .bind(&binding.endpoint_nsid)
    .bind(&binding.mutation_kind)
    .bind(binding.request_digest.as_slice())
    .bind(binding.accepted_request_sha256.as_slice())
    .bind(binding.signature.as_slice())
    .bind(binding.claimed_at)
    .execute(&mut **transaction)
    .await;
    match inserted {
        Ok(_) => Ok(OperationClaimGuard {
            transaction_id,
            binding,
        }),
        Err(error)
            if error
                .as_database_error()
                .and_then(|db| db.code())
                .as_deref()
                == Some("23505") =>
        {
            Err(PreludeError::OperationIdConflict)
        }
        Err(error) => Err(PreludeError::Database(error)),
    }
}

pub(crate) async fn complete_operation(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    scope_authority: ScopeBoundBusinessAuthority,
    completion: OperationCompletionGuard,
    completed_status: i32,
    response_bytes: &[u8],
    event_position: Option<i64>,
) -> Result<(), PreludeError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    let OperationCompletionGuard {
        operation: claim,
        scope_receipt_id,
        authority_digest,
        scope_digest,
    } = completion;
    if claim.transaction_id != transaction_id
        || scope_authority.transaction_id() != transaction_id
        || scope_authority.receipt_id() != scope_receipt_id
        || scope_authority.scope_digest() != &scope_digest
        || authority_digest
            != completion_digest_from_scope_authority(&scope_authority, &claim.binding)
        || authority_digest
            != completion_digest_from_request(
                &transaction_id,
                authority,
                &claim.binding,
                scope_receipt_id,
                &scope_digest,
            )?
        || !claim.binding.matches_authority(authority)?
    {
        return Err(PreludeError::ForeignTransaction);
    }
    if !(200..=599).contains(&completed_status) || response_bytes.is_empty() {
        return Err(PreludeError::ClaimIntegrity);
    }
    let binding = claim.binding;
    let mutation = authority
        .mutation()
        .ok_or(PreludeError::UnsupportedAuthority)?;
    let accepted_request_bytes = mutation
        .accepted_wrapper_bytes()
        .ok_or(PreludeError::NonCanonicalOperation)?;
    let response_sha256: [u8; 32] = Sha256::digest(response_bytes).into();
    let historical_jkt = (binding.endpoint_nsid == "blue.catbird.chat.revokeDevice")
        .then(|| authority.dpop_jkt().as_str());
    let inserted = sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records(
            principal_did,endpoint_nsid,operation_id,request_digest,
            accepted_request_bytes,signing_transcript_bytes,signature,
            completed_status,response_bytes,response_sha256,event_position,
            historical_jkt,current_jkt,completed_at
        ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULL,$13)
        "#,
    )
    .bind(&binding.principal_did)
    .bind(&binding.endpoint_nsid)
    .bind(binding.operation_id)
    .bind(binding.request_digest.as_slice())
    .bind(accepted_request_bytes)
    .bind(mutation.transcript_bytes())
    .bind(binding.signature.as_slice())
    .bind(completed_status)
    .bind(response_bytes)
    .bind(response_sha256.as_slice())
    .bind(event_position)
    .bind(historical_jkt)
    .bind(authority.trusted_instant().datetime())
    .execute(&mut **transaction)
    .await;
    match inserted {
        Ok(_) => {}
        Err(error)
            if error
                .as_database_error()
                .and_then(|database| database.code())
                .as_deref()
                == Some("23505") =>
        {
            return Err(PreludeError::OperationIdConflict);
        }
        Err(error) => return Err(PreludeError::Database(error)),
    }
    Ok(())
}

pub(crate) async fn complete_enrollment_bootstrap_operation(
    transaction: &mut Transaction<'_, Postgres>,
    guard: BootstrapCompletionGuard,
    authority: &VerifiedChatDeviceRequest,
    completed_status: i32,
    response_bytes: &[u8],
    event_position: Option<i64>,
) -> Result<(), PreludeError> {
    validate_bootstrap_completion(transaction, &guard, authority).await?;
    let current = match &guard.jkt_shape {
        BootstrapCompletionJktShape::Enrollment { current } => current.clone(),
        _ => return Err(PreludeError::ClaimIntegrity),
    };
    insert_operation_completion(
        transaction,
        authority,
        guard.operation.binding,
        completed_status,
        response_bytes,
        event_position,
        None,
        Some(&current),
    )
    .await
}

pub(crate) async fn complete_rebind_bootstrap_operation(
    transaction: &mut Transaction<'_, Postgres>,
    guard: BootstrapCompletionGuard,
    authority: &VerifiedChatDeviceRequest,
    completed_status: i32,
    response_bytes: &[u8],
    event_position: Option<i64>,
) -> Result<(), PreludeError> {
    validate_bootstrap_completion(transaction, &guard, authority).await?;
    let (historical, current) = match &guard.jkt_shape {
        BootstrapCompletionJktShape::Rebind {
            historical,
            current,
        } => (historical.clone(), current.clone()),
        _ => return Err(PreludeError::ClaimIntegrity),
    };
    insert_operation_completion(
        transaction,
        authority,
        guard.operation.binding,
        completed_status,
        response_bytes,
        event_position,
        Some(&historical),
        Some(&current),
    )
    .await
}

pub(crate) async fn complete_replenishment_operation(
    transaction: &mut Transaction<'_, Postgres>,
    guard: BootstrapCompletionGuard,
    scope: ScopeBoundBusinessAuthority,
    authority: &VerifiedChatDeviceRequest,
    completed_status: i32,
    response_bytes: &[u8],
    event_position: Option<i64>,
) -> Result<(), PreludeError> {
    validate_bootstrap_completion(transaction, &guard, authority).await?;
    if !matches!(guard.jkt_shape, BootstrapCompletionJktShape::Replenishment) {
        return Err(PreludeError::ClaimIntegrity);
    }
    let completion = OperationCompletionGuard {
        operation: guard.operation,
        scope_receipt_id: guard.scope_receipt_id,
        authority_digest: guard.authority_digest,
        scope_digest: guard.scope_digest,
    };
    complete_operation(
        transaction,
        authority,
        scope,
        completion,
        completed_status,
        response_bytes,
        event_position,
    )
    .await
}

async fn validate_bootstrap_completion(
    transaction: &mut Transaction<'_, Postgres>,
    guard: &BootstrapCompletionGuard,
    authority: &VerifiedChatDeviceRequest,
) -> Result<(), PreludeError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if guard.operation.transaction_id != transaction_id {
        return Err(PreludeError::ForeignTransaction);
    }
    if !guard.operation.binding.matches_authority(authority)? {
        return Err(PreludeError::ForeignTransaction);
    }
    let (historical_jkt, _current_jkt) = match &guard.jkt_shape {
        BootstrapCompletionJktShape::Enrollment { current } => (None, Some(current.as_str())),
        BootstrapCompletionJktShape::Rebind {
            historical,
            current,
        } => (Some(historical.as_str()), Some(current.as_str())),
        BootstrapCompletionJktShape::Replenishment => (None, None),
    };
    let subject = authority.subject().as_str();
    let device_id = Uuid::from_bytes(*authority.device_id().as_bytes());
    let trusted_instant = authority.trusted_instant().datetime();
    let dpop_jkt = authority.dpop_jkt().as_str();
    let receipt = authority.repository_receipt();
    let fresh_digest = bootstrap_completion_digest(
        &transaction_id,
        &guard.operation.binding,
        guard.scope_receipt_id,
        &guard.scope_digest,
        trusted_instant,
        subject,
        device_id,
        dpop_jkt,
        historical_jkt,
        receipt.locked_key_id(),
        receipt.locked_auth_generation(),
        receipt.locked_signing_key_sha256(),
    );
    if fresh_digest != guard.authority_digest {
        return Err(PreludeError::ClaimIntegrity);
    }
    Ok(())
}

fn bootstrap_completion_digest(
    transaction_id: &str,
    binding: &OperationClaimBinding,
    scope_receipt_id: Uuid,
    scope_digest: &[u8; 32],
    trusted_instant: DateTime<Utc>,
    subject: &str,
    device_id: Uuid,
    current_jkt: &str,
    historical_jkt: Option<&str>,
    key_id: Option<&str>,
    old_auth_generation: Option<i64>,
    signing_key_sha256: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-BOOTSTRAP-COMPLETION\0");
    for value in [
        transaction_id.as_bytes(),
        scope_receipt_id.as_bytes(),
        subject.as_bytes(),
        current_jkt.as_bytes(),
        historical_jkt.unwrap_or_default().as_bytes(),
        key_id.unwrap_or_default().as_bytes(),
        binding.principal_did.as_bytes(),
        binding.endpoint_nsid.as_bytes(),
        binding.mutation_kind.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(device_id.as_bytes());
    digest.update(old_auth_generation.unwrap_or_default().to_be_bytes());
    digest.update(signing_key_sha256.copied().unwrap_or_default());
    digest.update(trusted_instant.timestamp_millis().to_be_bytes());
    digest.update(binding.operation_id.as_bytes());
    digest.update(binding.request_digest);
    digest.update(binding.accepted_request_sha256);
    digest.update(binding.signature);
    digest.update(binding.claimed_at.timestamp_micros().to_be_bytes());
    digest.update(scope_digest);
    digest.finalize().into()
}

#[allow(clippy::too_many_arguments)]
async fn insert_operation_completion(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    binding: OperationClaimBinding,
    completed_status: i32,
    response_bytes: &[u8],
    event_position: Option<i64>,
    historical_jkt: Option<&str>,
    current_jkt: Option<&str>,
) -> Result<(), PreludeError> {
    if !(200..=599).contains(&completed_status) || response_bytes.is_empty() {
        return Err(PreludeError::ClaimIntegrity);
    }
    let mutation = authority
        .mutation()
        .ok_or(PreludeError::UnsupportedAuthority)?;
    let accepted_request_bytes = mutation
        .accepted_wrapper_bytes()
        .ok_or(PreludeError::NonCanonicalOperation)?;
    if !binding.matches_authority(authority)? {
        return Err(PreludeError::ClaimIntegrity);
    }
    let response_sha256: [u8; 32] = Sha256::digest(response_bytes).into();
    let inserted = sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records(
            principal_did,endpoint_nsid,operation_id,request_digest,
            accepted_request_bytes,signing_transcript_bytes,signature,
            completed_status,response_bytes,response_sha256,event_position,
            historical_jkt,current_jkt,completed_at
        ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        "#,
    )
    .bind(&binding.principal_did)
    .bind(&binding.endpoint_nsid)
    .bind(binding.operation_id)
    .bind(binding.request_digest.as_slice())
    .bind(accepted_request_bytes)
    .bind(mutation.transcript_bytes())
    .bind(binding.signature.as_slice())
    .bind(completed_status)
    .bind(response_bytes)
    .bind(response_sha256.as_slice())
    .bind(event_position)
    .bind(historical_jkt)
    .bind(current_jkt)
    .bind(authority.trusted_instant().datetime())
    .execute(&mut **transaction)
    .await;
    match inserted {
        Ok(_) => Ok(()),
        Err(error)
            if error
                .as_database_error()
                .and_then(|database| database.code())
                .as_deref()
                == Some("23505") =>
        {
            Err(PreludeError::OperationIdConflict)
        }
        Err(error) => Err(PreludeError::Database(error)),
    }
}

fn completion_digest_from_scope_authority(
    authority: &ScopeBoundBusinessAuthority,
    binding: &OperationClaimBinding,
) -> [u8; 32] {
    let signing_key_sha256 = authority
        .actor_signing_public_key()
        .map(|key| <[u8; 32]>::from(Sha256::digest(key)));
    completion_authority_digest(
        authority.transaction_id(),
        authority.receipt_id(),
        authority.actor_class(),
        authority.actor_did(),
        authority.actor_device_id(),
        authority.actor_dpop_jkt(),
        authority.actor_auth_generation(),
        authority.actor_key_id(),
        signing_key_sha256.as_ref(),
        authority.trusted_instant(),
        binding,
        authority.scope_digest(),
    )
}

fn completion_digest_from_prewrite_snapshot(
    scope: &auth::CanonicalAuthorityScopePrewriteSnapshot,
    scope_receipt_id: Uuid,
    binding: &OperationClaimBinding,
) -> [u8; 32] {
    completion_authority_digest(
        scope.transaction_id(),
        scope_receipt_id,
        scope.actor_class(),
        scope.actor_did(),
        scope.actor_device_id(),
        scope.actor_dpop_jkt(),
        scope.actor_auth_generation(),
        scope.actor_key_id(),
        scope.actor_signing_key_sha256(),
        scope.trusted_instant(),
        binding,
        scope.scope_digest(),
    )
}

fn completion_digest_from_request(
    transaction_id: &str,
    authority: &VerifiedChatDeviceRequest,
    binding: &OperationClaimBinding,
    scope_receipt_id: Uuid,
    scope_digest: &[u8; 32],
) -> Result<[u8; 32], PreludeError> {
    let receipt = authority.repository_receipt();
    Ok(completion_authority_digest(
        transaction_id,
        scope_receipt_id,
        receipt.class(),
        authority.subject().as_str(),
        Uuid::from_bytes(*authority.device_id().as_bytes()),
        receipt.locked_jkt(),
        receipt.locked_auth_generation(),
        receipt.locked_key_id(),
        receipt.locked_signing_key_sha256(),
        authority.trusted_instant().datetime(),
        binding,
        scope_digest,
    ))
}

#[allow(clippy::too_many_arguments)]
fn completion_authority_digest(
    transaction_id: &str,
    scope_receipt_id: Uuid,
    class: RepositoryAuthorityClass,
    subject: &str,
    device_id: Uuid,
    dpop_jkt: Option<&str>,
    auth_generation: Option<i64>,
    key_id: Option<&str>,
    signing_key_sha256: Option<&[u8; 32]>,
    trusted_instant: DateTime<Utc>,
    binding: &OperationClaimBinding,
    scope_digest: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-OPERATION-COMPLETION\0");
    digest.update([match class {
        RepositoryAuthorityClass::ExistingDevice => 1,
        RepositoryAuthorityClass::EnrollmentBootstrap => 2,
        RepositoryAuthorityClass::RebindBootstrap => 3,
    }]);
    digest.update(scope_receipt_id.as_bytes());
    for value in [
        transaction_id.as_bytes(),
        subject.as_bytes(),
        dpop_jkt.unwrap_or_default().as_bytes(),
        key_id.unwrap_or_default().as_bytes(),
        binding.principal_did.as_bytes(),
        binding.endpoint_nsid.as_bytes(),
        binding.mutation_kind.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(device_id.as_bytes());
    digest.update(auth_generation.unwrap_or_default().to_be_bytes());
    digest.update(signing_key_sha256.copied().unwrap_or_default());
    digest.update(trusted_instant.timestamp_millis().to_be_bytes());
    digest.update(binding.operation_id.as_bytes());
    digest.update(binding.request_digest);
    digest.update(binding.accepted_request_sha256);
    digest.update(binding.signature);
    digest.update(binding.claimed_at.timestamp_micros().to_be_bytes());
    digest.update(scope_digest);
    digest.finalize().into()
}

#[cfg(test)]
#[path = "../../../tests/common/chat_protocol_prelude_unit.rs"]
mod tests;
