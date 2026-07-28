//! Transaction-owning G6 device-revocation facade.
//!
//! This is the only production seam that composes the complete G6 read/lock
//! order, pure batch planner, canonical prewrite execution capsule, and exact
//! completed-replay validation. It never begins or commits the caller's outer
//! transaction and never accepts caller-authored execution artifacts.

use chrono::{DateTime, Utc};
use jacquard_common::deps::{bytes::Bytes, smol_str::SmolStr};
use jacquard_common::DefaultStr;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use super::super::{
    dpop::VerifiedChatDeviceRequest,
    state_machine::{
        AppliedTransition, DeviceRevocationBatchPersistencePlan, HydrationAuthority,
        StateMachineError,
    },
    transcript::{
        decode_and_verify_signed_mutation, CanonicalValueRef, SignedMutationKind,
        VerifiedMutationProjection, VerifiedSignedMutation,
    },
};
use super::{
    auth::CompletedIdempotentResponse,
    core::{
        hydrate_locked_conversation_state, hydrate_locked_g6_prelude,
        lock_g6_revocation_prehead_scope, prepare_g6_identity_scope, seal_g6_scope_authority,
        ConversationStateHydrationError, LockedG6Prelude, LockedG6PreludeError,
    },
    device_directory::{
        lock_active_revocation_device_view, DeviceDirectoryView, RevocationDeviceViewError,
    },
    execution_context::{
        apply_device_revocation_batch_sequential,
        prepare_canonical_device_revocation_batch_execution,
        PreparedDeviceRevocationBatchExecution, SequentialDeviceRevocationError,
    },
    prelude::{
        complete_operation, lock_signed_operation_replay_authority,
        release_signed_operation_replay, LockedSignedOperationReplayAuthority,
        OperationCompletionGuard, PreludeError, PreparedSignedOperation,
        ScopeBoundBusinessAuthority, SignedOperationReplayPostStateProof,
    },
};
use catbird_atproto::generated::blue_catbird::chat as chat_dto;

const REVOKE_DEVICE_NSID: &str = "blue.catbird.chat.revokeDevice";
const G6_REPLAY_POST_STATE_DOMAIN: &[u8] = b"CATBIRD-CHAT-G6-REPLAY-POST-STATE\0";

#[derive(Debug, Error)]
pub(crate) enum DeviceRevocationFacadeError {
    #[error(transparent)]
    Prelude(#[from] PreludeError),
    #[error(transparent)]
    G6Prelude(#[from] LockedG6PreludeError),
    #[error(transparent)]
    Conversation(#[from] ConversationStateHydrationError),
    #[error("device revocation target is missing")]
    TargetMissing,
    #[error("device revocation target is already revoked")]
    TargetRevoked,
    #[error("device revocation target authentication generation changed")]
    AuthenticationGenerationConflict,
    #[error("device revocation target projection is corrupt")]
    TargetProjection,
    #[error("device revocation target projection database read failed")]
    DeviceViewDatabase(sqlx::Error),
    #[error(transparent)]
    StateMachine(#[from] StateMachineError),
    #[error(transparent)]
    Execution(#[from] SequentialDeviceRevocationError),
    #[error("device revocation request or durable post-state is inconsistent")]
    Integrity,
    #[error("device revocation replay validation database read failed")]
    Database(#[from] sqlx::Error),
}

impl From<RevocationDeviceViewError> for DeviceRevocationFacadeError {
    fn from(error: RevocationDeviceViewError) -> Self {
        match error {
            RevocationDeviceViewError::Database(error) => Self::DeviceViewDatabase(error),
            RevocationDeviceViewError::Missing => Self::TargetMissing,
            RevocationDeviceViewError::Revoked => Self::TargetRevoked,
            RevocationDeviceViewError::AuthGenerationConflict => {
                Self::AuthenticationGenerationConflict
            }
            RevocationDeviceViewError::Projection => Self::TargetProjection,
        }
    }
}

impl DeviceRevocationFacadeError {
    /// Once an executor/savepoint error makes the write outcome ambiguous, the
    /// caller must abandon or roll back its outer transaction.
    pub(crate) fn requires_outer_abort(&self) -> bool {
        matches!(self, Self::Execution(error) if error.requires_outer_abort())
    }
}

/// Canonical repository material for the sole `revokeDevice` output field.
#[derive(Clone, Debug)]
pub(crate) struct DeviceRevocationMaterial {
    revocation_id: Uuid,
    accepted_at: DateTime<Utc>,
    device: DeviceDirectoryView,
}

impl DeviceRevocationMaterial {
    pub(crate) fn revocation_id(&self) -> Uuid {
        self.revocation_id
    }

    pub(crate) fn accepted_at(&self) -> DateTime<Utc> {
        self.accepted_at
    }

    pub(crate) fn device(&self) -> &DeviceDirectoryView {
        &self.device
    }
}

/// Complete transaction outcome. A replay carries bytes only after exact G6
/// post-state validation; a first execution carries the linear apply authority.
pub(crate) enum DeviceRevocationTransactionOutcome {
    First(PreparedDeviceRevocationMutation),
    Replay(CompletedDeviceRevocationReplay),
}

pub(crate) struct CompletedDeviceRevocationReplay {
    material: DeviceRevocationMaterial,
    response: CompletedIdempotentResponse,
}

impl CompletedDeviceRevocationReplay {
    pub(crate) fn material(&self) -> &DeviceRevocationMaterial {
        &self.material
    }

    pub(crate) fn response(&self) -> &CompletedIdempotentResponse {
        &self.response
    }
}

/// First-execution authority after the complete discovery/lock/hydration/plan
/// prewrite. Its private G6 prelude may be consumed exactly once into a
/// savepoint-owning application capsule.
#[must_use]
pub(crate) struct PreparedDeviceRevocationMutation {
    execution_id: Uuid,
    authority: VerifiedChatDeviceRequest,
    scope: ScopeBoundBusinessAuthority,
    completion: OperationCompletionGuard,
    plan: DeviceRevocationBatchPersistencePlan,
    g6_prelude: Option<LockedG6Prelude>,
    material: DeviceRevocationMaterial,
    response: CanonicalDeviceRevocationResponse,
}

impl PreparedDeviceRevocationMutation {
    pub(crate) fn material(&self) -> &DeviceRevocationMaterial {
        &self.material
    }

    /// Freeze the canonical, repository-derived execution contexts in a
    /// savepoint. The returned capsule must be applied or explicitly rolled
    /// back before the caller reuses the borrowed outer transaction.
    pub(crate) async fn prepare_application<'transaction, 'connection, 'plan>(
        &'plan mut self,
        transaction: &'transaction mut Transaction<'connection, Postgres>,
    ) -> Result<PreparedDeviceRevocationApplication<'transaction, 'plan>, DeviceRevocationFacadeError>
    where
        'connection: 'transaction,
    {
        let prelude = self
            .g6_prelude
            .take()
            .ok_or(DeviceRevocationFacadeError::Integrity)?;
        let prepared =
            prepare_canonical_device_revocation_batch_execution(transaction, &self.plan, prelude)
                .await?;
        Ok(PreparedDeviceRevocationApplication {
            execution_id: self.execution_id,
            prepared,
        })
    }

    /// Consume the first-execution authority only after the private seal proves
    /// the exact prepared capsule was successfully applied.
    pub(crate) fn finish(
        self,
        applied: AppliedDeviceRevocationSeal,
    ) -> Result<AppliedDeviceRevocationMutation, DeviceRevocationFacadeError> {
        if applied.execution_id != self.execution_id
            || applied.transitions.len() != self.plan.conversations().len()
            || !self.response.validates_device(self.material.device())
        {
            return Err(DeviceRevocationFacadeError::Integrity);
        }
        Ok(AppliedDeviceRevocationMutation {
            authority: self.authority,
            scope: self.scope,
            completion: self.completion,
            material: self.material,
            response: self.response,
            _applied_transitions: applied.transitions,
        })
    }
}

#[must_use = "apply or explicitly roll back this G6 savepoint capsule"]
pub(crate) struct PreparedDeviceRevocationApplication<'transaction, 'plan> {
    execution_id: Uuid,
    prepared: PreparedDeviceRevocationBatchExecution<'transaction, 'plan>,
}

impl PreparedDeviceRevocationApplication<'_, '_> {
    pub(crate) async fn apply(
        self,
    ) -> Result<AppliedDeviceRevocationSeal, DeviceRevocationFacadeError> {
        let transitions = apply_device_revocation_batch_sequential(self.prepared).await?;
        Ok(AppliedDeviceRevocationSeal {
            execution_id: self.execution_id,
            transitions,
        })
    }

    pub(crate) async fn rollback(self) -> Result<(), DeviceRevocationFacadeError> {
        self.prepared.rollback().await?;
        Ok(())
    }
}

pub(crate) struct AppliedDeviceRevocationSeal {
    execution_id: Uuid,
    transitions: Vec<AppliedTransition>,
}

#[must_use]
pub(crate) struct AppliedDeviceRevocationMutation {
    authority: VerifiedChatDeviceRequest,
    scope: ScopeBoundBusinessAuthority,
    completion: OperationCompletionGuard,
    material: DeviceRevocationMaterial,
    response: CanonicalDeviceRevocationResponse,
    _applied_transitions: Vec<AppliedTransition>,
}

impl AppliedDeviceRevocationMutation {
    pub(crate) fn material(&self) -> &DeviceRevocationMaterial {
        &self.material
    }

    /// Persist the facade-owned canonical response receipt after the batch
    /// applied. No caller-authored bytes cross this boundary. This does not
    /// commit the caller-owned outer transaction and deliberately records no
    /// single/general revocation event position.
    pub(crate) async fn complete(
        self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<CompletedDeviceRevocationMutation, DeviceRevocationFacadeError> {
        if !self.response.validates_device(self.material.device()) {
            return Err(DeviceRevocationFacadeError::Integrity);
        }
        complete_operation(
            transaction,
            &self.authority,
            self.scope,
            self.completion,
            self.response.status,
            &self.response.body,
            None,
        )
        .await?;
        Ok(CompletedDeviceRevocationMutation {
            material: self.material,
            status: self.response.status,
            response_bytes: self.response.body,
        })
    }
}

/// Facade-owned result after the exact canonical bytes have been durably
/// recorded. Handlers may transmit these bytes but cannot influence them.
pub(crate) struct CompletedDeviceRevocationMutation {
    material: DeviceRevocationMaterial,
    status: i32,
    response_bytes: Vec<u8>,
}

impl CompletedDeviceRevocationMutation {
    pub(crate) fn material(&self) -> &DeviceRevocationMaterial {
        &self.material
    }

    pub(crate) fn status(&self) -> i32 {
        self.status
    }

    pub(crate) fn into_response_bytes(self) -> Vec<u8> {
        self.response_bytes
    }
}

/// Private response capability sealed to the repository-derived terminal
/// DeviceView. It is constructed before execution and carried linearly through
/// the apply seal, so completion cannot persist handler-selected bytes.
struct CanonicalDeviceRevocationResponse {
    status: i32,
    body: Vec<u8>,
    body_sha256: [u8; 32],
}

impl CanonicalDeviceRevocationResponse {
    fn from_device(device: &DeviceDirectoryView) -> Result<Self, DeviceRevocationFacadeError> {
        let output = chat_dto::revoke_device::RevokeDeviceOutput::<DefaultStr> {
            device: chat_dto::DeviceView {
                auth_generation: device.auth_generation,
                available_package_count: device.available_package_count,
                created_at: crate::sqlx_jacquard::chrono_to_datetime(device.created_at),
                device_id: SmolStr::from(device.device_id.to_string()),
                dpop_jkt: SmolStr::from(device.dpop_jkt.as_str()),
                key_id: SmolStr::from(device.key_id.as_str()),
                reserved_package_count: device.reserved_package_count,
                signature_public_key: Bytes::from(device.signing_public_key.clone()),
                status: SmolStr::from(device.status.as_str()),
                updated_at: crate::sqlx_jacquard::chrono_to_datetime(device.updated_at),
                extra_data: None,
            },
            extra_data: None,
        };
        let body =
            serde_json::to_vec(&output).map_err(|_| DeviceRevocationFacadeError::Integrity)?;
        let body_sha256 = Sha256::digest(&body).into();
        Ok(Self {
            status: 200,
            body,
            body_sha256,
        })
    }

    fn validates_device(&self, device: &DeviceDirectoryView) -> bool {
        let Ok(expected) = Self::from_device(device) else {
            return false;
        };
        self.status == expected.status
            && self.body_sha256 == expected.body_sha256
            && self.body == expected.body
    }
}

struct ExactRevocationInput {
    operation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: u64,
    target_did: String,
    target_device_id: Uuid,
    target_auth_generation: u64,
    signed_at: DateTime<Utc>,
    accepted_request_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: [u8; 32],
    accepted_request_sha256: [u8; 32],
    signature: [u8; 64],
}

fn exact_revocation_input(
    mutation: &VerifiedSignedMutation,
) -> Result<ExactRevocationInput, DeviceRevocationFacadeError> {
    let body = match mutation.projection() {
        VerifiedMutationProjection::DeviceRevocation(value) => value.body(),
        _ => return Err(DeviceRevocationFacadeError::Integrity),
    };
    let operation_id = match body.get("idempotencyKey") {
        Some(CanonicalValueRef::Uuid(value)) => Uuid::from_bytes(*value.as_bytes()),
        _ => return Err(DeviceRevocationFacadeError::Integrity),
    };
    let target_device_id = match body.get("targetDeviceId") {
        Some(CanonicalValueRef::Uuid(value)) => Uuid::from_bytes(*value.as_bytes()),
        _ => return Err(DeviceRevocationFacadeError::Integrity),
    };
    let target_auth_generation = match body.get("targetAuthGeneration") {
        Some(CanonicalValueRef::Integer(value)) => value,
        _ => return Err(DeviceRevocationFacadeError::Integrity),
    };
    let accepted_request_bytes = mutation
        .accepted_wrapper_bytes()
        .filter(|bytes| !bytes.is_empty())
        .ok_or(DeviceRevocationFacadeError::Integrity)?
        .to_vec();
    if operation_id.get_version_num() != 4
        || target_device_id.get_version_num() != 4
        || target_auth_generation == 0
        || mutation.kind() != SignedMutationKind::DeviceRevocation
    {
        return Err(DeviceRevocationFacadeError::Integrity);
    }
    Ok(ExactRevocationInput {
        operation_id,
        actor_did: mutation.actor_did().as_str().to_owned(),
        actor_device_id: Uuid::from_bytes(*mutation.actor_device_id().as_bytes()),
        actor_key_id: mutation.key_id().as_str().to_owned(),
        actor_auth_generation: mutation.auth_generation(),
        target_did: mutation.actor_did().as_str().to_owned(),
        target_device_id,
        target_auth_generation,
        signed_at: mutation.signed_at().datetime(),
        accepted_request_sha256: Sha256::digest(&accepted_request_bytes).into(),
        accepted_request_bytes,
        signing_transcript_bytes: mutation.transcript_bytes().to_vec(),
        request_digest: *mutation.request_digest(),
        signature: *mutation.signature(),
    })
}

/// Compose the complete G6 transaction. The only input capability is the
/// globally arbitrated ordinary signed operation; handlers cannot supply SQL
/// projections, fanout, registration facts, or execution artifacts.
pub(crate) async fn prepare_device_revocation(
    transaction: &mut Transaction<'_, Postgres>,
    operation: PreparedSignedOperation,
) -> Result<DeviceRevocationTransactionOutcome, DeviceRevocationFacadeError> {
    match operation {
        PreparedSignedOperation::First {
            authority,
            reservation,
        } => prepare_first_device_revocation(transaction, authority, reservation).await,
        PreparedSignedOperation::Replay { authority, replay } => {
            let locked =
                lock_signed_operation_replay_authority(transaction, authority, replay).await?;
            prepare_device_revocation_replay(transaction, locked).await
        }
    }
}

async fn prepare_first_device_revocation(
    transaction: &mut Transaction<'_, Postgres>,
    authority: VerifiedChatDeviceRequest,
    reservation: super::prelude::OperationReservationGuard,
) -> Result<DeviceRevocationTransactionOutcome, DeviceRevocationFacadeError> {
    if authority.endpoint().as_str() != REVOKE_DEVICE_NSID {
        return Err(DeviceRevocationFacadeError::Integrity);
    }
    let input = exact_revocation_input(
        authority
            .mutation()
            .ok_or(DeviceRevocationFacadeError::Integrity)?,
    )?;
    let (prepared, discovery) = prepare_g6_identity_scope(
        transaction,
        &authority,
        reservation,
        &input.target_did,
        input.target_device_id,
    )
    .await
    .map_err(|error| match error {
        // The admitted actor is already locked and every other audience device
        // was selected from live rows. The target is the only identity forced
        // into G6 discovery, so a missing device at this boundary is the
        // endpoint's declared target-not-found result.
        LockedG6PreludeError::Prelude(PreludeError::MissingDevice) => {
            DeviceRevocationFacadeError::TargetMissing
        }
        error => DeviceRevocationFacadeError::G6Prelude(error),
    })?;
    let prepared = prepared.verify_device_revocation_operation(
        input.operation_id,
        authority
            .mutation()
            .ok_or(DeviceRevocationFacadeError::Integrity)?,
    )?;
    let locked_device_view = lock_active_revocation_device_view(
        transaction,
        &input.target_did,
        input.target_device_id,
        input.target_auth_generation,
        prepared.scope_authority().trusted_instant(),
    )
    .await?;
    let scope = seal_g6_scope_authority(transaction, prepared.scope_authority(), discovery).await?;
    if locked_device_view.transaction_id() != scope.transaction_id() {
        return Err(DeviceRevocationFacadeError::Integrity);
    }
    let prehead = lock_g6_revocation_prehead_scope(transaction, scope).await?;
    let conversation_ids = prehead.conversation_ids().to_vec();
    let mut locked_conversations = Vec::with_capacity(conversation_ids.len());
    for conversation_id in conversation_ids {
        locked_conversations.push(
            hydrate_locked_conversation_state(
                transaction,
                conversation_id,
                prepared.scope_authority().trusted_instant(),
            )
            .await?,
        );
    }
    let fanout = prehead
        .seal_fanout(&locked_conversations)
        .map_err(LockedG6PreludeError::from)?;
    let repository_prelude =
        hydrate_locked_g6_prelude(transaction, prehead, &fanout, &locked_conversations).await?;
    let (g6_prelude, target, packages) = repository_prelude.into_parts();
    let actor_registration = HydrationAuthority::locked_global_registration_from_scope_authority(
        prepared.scope_authority(),
    )?;
    let planner_mutation = decode_and_verify_signed_mutation(
        &input.accepted_request_bytes,
        prepared
            .scope_authority()
            .actor_signing_public_key()
            .ok_or(DeviceRevocationFacadeError::Integrity)?,
    )
    .map_err(|_| DeviceRevocationFacadeError::Integrity)?;
    let plan = HydrationAuthority::plan_device_revocation_batch(
        planner_mutation,
        actor_registration,
        target,
        fanout,
        packages,
        locked_conversations,
    )?;
    let accepted_at = DateTime::from_timestamp_millis(plan.authority().accepted_at().unix_millis())
        .ok_or(DeviceRevocationFacadeError::Integrity)?;
    let device = locked_device_view.into_post_revocation_view(
        &input.target_did,
        input.target_device_id,
        input.target_auth_generation,
        accepted_at,
        plan.revoked_packages().len(),
    )?;
    if Uuid::from_bytes(*plan.authority().revocation_id()) != input.operation_id
        || plan.target_cas().transaction_id() != g6_prelude.transaction_id()
    {
        return Err(DeviceRevocationFacadeError::Integrity);
    }
    let (scope, completion) = prepared.into_execution_parts();
    let material = DeviceRevocationMaterial {
        revocation_id: input.operation_id,
        accepted_at,
        device,
    };
    let response = CanonicalDeviceRevocationResponse::from_device(material.device())?;
    Ok(DeviceRevocationTransactionOutcome::First(
        PreparedDeviceRevocationMutation {
            execution_id: Uuid::new_v4(),
            authority,
            scope,
            completion,
            plan,
            g6_prelude: Some(g6_prelude),
            material,
            response,
        },
    ))
}

#[derive(sqlx::FromRow)]
struct DurableDeviceRevocationRow {
    revocation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: i64,
    target_did: String,
    target_device_id: Uuid,
    target_auth_generation: i64,
    accepted_request_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    signed_at: DateTime<Utc>,
    accepted_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct RevokedTargetPostStateRow {
    device_id: Uuid,
    key_id: String,
    signing_public_key: Vec<u8>,
    auth_generation: i64,
    enrollment_auth_generation: i64,
    dpop_jkt: String,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    device_revoked_at: Option<DateTime<Utc>>,
    device_revocation_id: Option<Uuid>,
    key_revoked_at: Option<DateTime<Utc>>,
    key_revocation_id: Option<Uuid>,
    capabilities_json: String,
    available_package_count: i64,
    reserved_package_count: i64,
    open_recovery_request_count: i64,
    active_reservation_count: i64,
    pending_welcome_count: i64,
    pending_recovery_work_count: i64,
    invalid_package_terminal_count: i64,
    invalid_request_terminal_count: i64,
    invalid_reservation_terminal_count: i64,
    invalid_recovery_work_terminal_count: i64,
}

pub(in crate::chat_protocol::repository) struct DeviceRevocationReplayPostStateProof {
    transaction_id: Box<str>,
    operation_id: Uuid,
    principal_did: Box<str>,
    request_digest: [u8; 32],
    accepted_request_sha256: [u8; 32],
    signature: [u8; 64],
    accepted_at: DateTime<Utc>,
    device: DeviceDirectoryView,
    expected_response_sha256: [u8; 32],
    expected_status: i32,
    post_state_digest: [u8; 32],
}

impl DeviceRevocationReplayPostStateProof {
    pub(in crate::chat_protocol::repository) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(in crate::chat_protocol::repository) fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub(in crate::chat_protocol::repository) fn principal_did(&self) -> &str {
        &self.principal_did
    }

    pub(in crate::chat_protocol::repository) fn endpoint_nsid(&self) -> &str {
        REVOKE_DEVICE_NSID
    }

    pub(in crate::chat_protocol::repository) fn mutation_kind(&self) -> SignedMutationKind {
        SignedMutationKind::DeviceRevocation
    }

    pub(in crate::chat_protocol::repository) fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    pub(in crate::chat_protocol::repository) fn accepted_request_sha256(&self) -> &[u8; 32] {
        &self.accepted_request_sha256
    }

    pub(in crate::chat_protocol::repository) fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    pub(in crate::chat_protocol::repository) fn expected_response_sha256(&self) -> &[u8; 32] {
        &self.expected_response_sha256
    }

    pub(in crate::chat_protocol::repository) fn expected_status(&self) -> i32 {
        self.expected_status
    }

    pub(in crate::chat_protocol::repository) fn post_state_digest(&self) -> &[u8; 32] {
        &self.post_state_digest
    }

    pub(in crate::chat_protocol::repository) fn validates_seal(&self) -> bool {
        self.post_state_digest
            == device_revocation_replay_post_state_digest(
                &self.transaction_id,
                self.operation_id,
                &self.principal_did,
                &self.request_digest,
                &self.accepted_request_sha256,
                &self.signature,
                self.accepted_at,
                &self.device,
                self.expected_status,
                &self.expected_response_sha256,
            )
    }
}

#[allow(clippy::too_many_arguments)]
fn device_revocation_replay_post_state_digest(
    transaction_id: &str,
    operation_id: Uuid,
    principal_did: &str,
    request_digest: &[u8; 32],
    accepted_request_sha256: &[u8; 32],
    signature: &[u8; 64],
    accepted_at: DateTime<Utc>,
    device: &DeviceDirectoryView,
    expected_status: i32,
    expected_response_sha256: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(G6_REPLAY_POST_STATE_DOMAIN);
    for value in [transaction_id.as_bytes(), principal_did.as_bytes()] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(operation_id.as_bytes());
    digest.update(request_digest);
    digest.update(accepted_request_sha256);
    digest.update(signature);
    digest.update(accepted_at.timestamp_millis().to_be_bytes());
    digest.update(device.device_id.as_bytes());
    for value in [
        device.key_id.as_bytes(),
        device.signing_public_key.as_slice(),
        device.dpop_jkt.as_bytes(),
        device.status.as_bytes(),
        device.capabilities_json.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(device.auth_generation.to_be_bytes());
    digest.update(device.created_at.timestamp_millis().to_be_bytes());
    digest.update(device.updated_at.timestamp_millis().to_be_bytes());
    digest.update(device.available_package_count.to_be_bytes());
    digest.update(device.reserved_package_count.to_be_bytes());
    digest.update(expected_status.to_be_bytes());
    digest.update(expected_response_sha256);
    digest.finalize().into()
}

async fn prepare_device_revocation_replay(
    transaction: &mut Transaction<'_, Postgres>,
    locked: LockedSignedOperationReplayAuthority,
) -> Result<DeviceRevocationTransactionOutcome, DeviceRevocationFacadeError> {
    let authority = locked.authority();
    if authority.endpoint().as_str() != REVOKE_DEVICE_NSID {
        return Err(DeviceRevocationFacadeError::Integrity);
    }
    let input = exact_revocation_input(authority.mutation())?;
    if authority.subject().as_str() != input.actor_did
        || Uuid::from_bytes(*authority.device_id().as_bytes()) != input.actor_device_id
    {
        return Err(DeviceRevocationFacadeError::Integrity);
    }
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    let revocation: DurableDeviceRevocationRow = sqlx::query_as(
        r#"
        SELECT revocation_id,actor_did,actor_device_id,actor_key_id,
               actor_auth_generation,target_did,target_device_id,
               target_auth_generation,accepted_request_bytes,
               signing_transcript_bytes,request_digest,signature,
               signed_at,accepted_at
          FROM chat.device_revocations
         WHERE revocation_id=$1
         FOR UPDATE
        "#,
    )
    .bind(input.operation_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DeviceRevocationFacadeError::Integrity)?;
    let actor_auth_generation = i64::try_from(input.actor_auth_generation)
        .map_err(|_| DeviceRevocationFacadeError::Integrity)?;
    let target_auth_generation = i64::try_from(input.target_auth_generation)
        .map_err(|_| DeviceRevocationFacadeError::Integrity)?;
    if revocation.revocation_id != input.operation_id
        || revocation.actor_did != input.actor_did
        || revocation.actor_device_id != input.actor_device_id
        || revocation.actor_key_id != input.actor_key_id
        || revocation.actor_auth_generation != actor_auth_generation
        || revocation.target_did != input.target_did
        || revocation.target_device_id != input.target_device_id
        || revocation.target_auth_generation != target_auth_generation
        || revocation.accepted_request_bytes != input.accepted_request_bytes
        || revocation.signing_transcript_bytes != input.signing_transcript_bytes
        || revocation.request_digest.as_slice() != input.request_digest
        || revocation.signature.as_slice() != input.signature
        || revocation.signed_at != input.signed_at
    {
        return Err(DeviceRevocationFacadeError::Integrity);
    }
    let target: RevokedTargetPostStateRow = sqlx::query_as(
        r#"
        SELECT device.device_id,
               device_key.key_id,
               device_key.signing_public_key,
               device.auth_generation,
               device_key.enrollment_auth_generation,
               device.dpop_jkt,
               device.status,
               device.created_at,
               device.updated_at,
               device.revoked_at AS device_revoked_at,
               device.revocation_id AS device_revocation_id,
               device_key.revoked_at AS key_revoked_at,
               device_key.revocation_id AS key_revocation_id,
               device.capabilities::text AS capabilities_json,
               (SELECT count(*) FROM chat.key_packages package
                 WHERE package.owner_did=device.user_did
                   AND package.owner_device_id=device.device_id
                   AND package.status='available') AS available_package_count,
               (SELECT count(*) FROM chat.key_packages package
                 WHERE package.owner_did=device.user_did
                   AND package.owner_device_id=device.device_id
                   AND package.status='reserved') AS reserved_package_count,
               (SELECT count(*) FROM chat.leaf_recovery_requests request
                 WHERE request.requester_did=device.user_did
                   AND request.requester_device_id=device.device_id
                   AND request.status='open') AS open_recovery_request_count,
               (SELECT count(*) FROM chat.key_package_reservations reservation
                 WHERE reservation.recipient_did=device.user_did
                   AND reservation.recipient_device_id=device.device_id
                   AND reservation.status='active') AS active_reservation_count,
               (SELECT count(*) FROM chat.welcome_deliveries welcome
                 WHERE welcome.recipient_did=device.user_did
                   AND welcome.recipient_device_id=device.device_id
                   AND welcome.status='pending') AS pending_welcome_count,
               (SELECT count(*) FROM chat.recovery_work_items work
                 WHERE work.recipient_did=device.user_did
                   AND work.recipient_device_id=device.device_id
                   AND work.status='pending') AS pending_recovery_work_count,
               (SELECT count(*) FROM chat.key_packages package
                 WHERE package.owner_did=device.user_did
                   AND package.owner_device_id=device.device_id
                   AND package.terminal_revocation_id=$3
                   AND (package.status<>'revoked' OR package.terminal_at<>$4))
                   AS invalid_package_terminal_count,
               (SELECT count(*) FROM chat.leaf_recovery_requests request
                 WHERE request.requester_did=device.user_did
                   AND request.requester_device_id=device.device_id
                   AND request.terminal_revocation_id=$3
                   AND (request.status<>'superseded' OR request.terminal_at<>$4))
                   AS invalid_request_terminal_count,
               (SELECT count(*) FROM chat.key_package_reservations reservation
                 WHERE reservation.recipient_did=device.user_did
                   AND reservation.recipient_device_id=device.device_id
                   AND reservation.terminal_revocation_id=$3
                   AND (reservation.status<>'released' OR reservation.terminal_at<>$4))
                   AS invalid_reservation_terminal_count,
               (SELECT count(*) FROM chat.recovery_work_items work
                 WHERE work.recipient_did=device.user_did
                   AND work.recipient_device_id=device.device_id
                   AND work.terminal_revocation_id=$3
                   AND (work.status<>'superseded' OR work.terminal_at<>$4))
                   AS invalid_recovery_work_terminal_count
          FROM chat.devices device
          JOIN chat.device_keys device_key
            ON device_key.user_did=device.user_did
           AND device_key.device_id=device.device_id
         WHERE device.user_did=$1 AND device.device_id=$2
         FOR UPDATE OF device,device_key
        "#,
    )
    .bind(&input.target_did)
    .bind(input.target_device_id)
    .bind(input.operation_id)
    .bind(revocation.accepted_at)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DeviceRevocationFacadeError::Integrity)?;
    if target.device_id != input.target_device_id
        || target.auth_generation != target_auth_generation
        || target.enrollment_auth_generation <= 0
        || target.enrollment_auth_generation > target.auth_generation
        || target.status != "revoked"
        || target.device_revoked_at != Some(revocation.accepted_at)
        || target.device_revocation_id != Some(input.operation_id)
        || target.key_revoked_at != Some(revocation.accepted_at)
        || target.key_revocation_id != Some(input.operation_id)
        || target.signing_public_key.len() != 32
        || target.created_at > target.updated_at
        || target.updated_at != revocation.accepted_at
        || target.available_package_count != 0
        || target.reserved_package_count != 0
        || target.open_recovery_request_count != 0
        || target.active_reservation_count != 0
        || target.pending_welcome_count != 0
        || target.pending_recovery_work_count != 0
        || target.invalid_package_terminal_count != 0
        || target.invalid_request_terminal_count != 0
        || target.invalid_reservation_terminal_count != 0
        || target.invalid_recovery_work_terminal_count != 0
    {
        return Err(DeviceRevocationFacadeError::Integrity);
    }
    let device = DeviceDirectoryView {
        device_id: target.device_id,
        key_id: target.key_id,
        signing_public_key: target.signing_public_key,
        auth_generation: target.auth_generation,
        dpop_jkt: target.dpop_jkt,
        status: target.status,
        created_at: target.created_at,
        updated_at: target.updated_at,
        available_package_count: target.available_package_count,
        reserved_package_count: target.reserved_package_count,
        capabilities_json: target.capabilities_json,
    };
    let expected_response_sha256 =
        CanonicalDeviceRevocationResponse::from_device(&device)?.body_sha256;
    let post_state_digest = device_revocation_replay_post_state_digest(
        &transaction_id,
        input.operation_id,
        &input.actor_did,
        &input.request_digest,
        &input.accepted_request_sha256,
        &input.signature,
        revocation.accepted_at,
        &device,
        200,
        &expected_response_sha256,
    );
    let post_state = DeviceRevocationReplayPostStateProof {
        transaction_id: transaction_id.into_boxed_str(),
        operation_id: input.operation_id,
        principal_did: input.actor_did.clone().into_boxed_str(),
        request_digest: input.request_digest,
        accepted_request_sha256: input.accepted_request_sha256,
        signature: input.signature,
        accepted_at: revocation.accepted_at,
        device,
        expected_response_sha256,
        expected_status: 200,
        post_state_digest,
    };
    // Stored bytes cannot cross the prelude until every exact G6 durable fact
    // above has been locked and validated.
    let material = DeviceRevocationMaterial {
        revocation_id: post_state.operation_id,
        accepted_at: post_state.accepted_at,
        device: post_state.device.clone(),
    };
    let response = release_signed_operation_replay(
        transaction,
        locked,
        SignedOperationReplayPostStateProof::DeviceRevocation(post_state),
    )
    .await?;
    if response.status() != 200
        || response.event_position().is_some()
        || response.completed_at() != material.accepted_at
    {
        return Err(DeviceRevocationFacadeError::Integrity);
    }
    Ok(DeviceRevocationTransactionOutcome::Replay(
        CompletedDeviceRevocationReplay { material, response },
    ))
}

/// Real-library compiler witness for the complete production-only G6 facade.
#[cfg(feature = "chat-protocol-production-proof")]
#[allow(dead_code)]
fn production_g6_facade_typecheck() {
    let _ = prepare_device_revocation;
    let _ = PreparedDeviceRevocationMutation::prepare_application;
    let _ = PreparedDeviceRevocationApplication::apply;
    let _ = PreparedDeviceRevocationApplication::rollback;
    let _ = AppliedDeviceRevocationMutation::complete;
}
