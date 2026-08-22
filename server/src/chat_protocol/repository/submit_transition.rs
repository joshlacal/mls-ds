//! Transaction-bound composition for the non-Recovery `submitTransition` union.
//!
//! The public handler is deliberately kept outside this module. It may choose
//! this facade after global signed-operation arbitration, serialize the exact
//! returned bytes, and commit the caller-owned outer transaction. It may not
//! assemble planner inputs, executor artifacts, or replay bytes.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_atproto::generated::blue_catbird::chat as chat_dto;
use chrono::{DateTime, SecondsFormat, Utc};
use jacquard_common::DefaultStr;
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::chat_protocol::{
    dpop::VerifiedChatDeviceRequest,
    model::AuthPrimitiveError,
    relationship_policy::{PublicTransport, RelationshipAuthority},
    snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle, MAX_PROTOCOL_INTEGER},
    state_machine::{
        executor::AppliedTransition, ConversationPersistencePlan, ExecutorError,
        HydrationAuthority, StateChange, StateMachineError, WelcomeStatus, WelcomeWork,
    },
    transcript::{
        build_verified_control_entry, decode_and_verify_control_entry,
        decode_and_verify_signed_mutation, CanonicalControlEntryProducts,
        CanonicalControlServerFields, CanonicalValueRef, ClosedObjectRef, ControlEntryKind,
        SignedMutationKind, VerifiedMutationProjection, VerifiedSignedMutation,
    },
    validation::CanonicalUuidV4,
};

use super::{
    auth::{CompletedIdempotentResponse, RepositoryAuthorityClass},
    core::{
        hydrate_locked_conversation_state, hydrate_locked_invitation_quota,
        hydrate_locked_reserved_recovery_package, ConversationStateHydrationError,
        InvitationQuotaHydrationError, LockedConversationStateGuard, LockedRecoveryPackageGuard,
        RecoveryPackageHydrationError,
    },
    execution_context::{
        apply_prepared_submit_transition_execution, prepare_submit_transition_execution,
        ExecutionContextHydrationError,
    },
    prelude::{
        complete_operation, lock_signed_operation_replay_authority, prepare_identity_scope_prelude,
        release_signed_operation_replay, CanonicalDeviceIdentity, CanonicalLockScope,
        LockedSignedOperationReplayAuthority, OperationReservationGuard, PreludeError,
        PreparedSignedOperation, PreparedSignedOperationState, ScopeBoundBusinessAuthority,
    },
    relationship::{
        load_fallback_relationship_projection, seal_non_add_policy_no_pending_admission,
        seal_pending_add_fallback_scope, RelationshipRepositoryError,
    },
};

const SUBMIT_TRANSITION_ENDPOINT: &str = "blue.catbird.chat.submitTransition";
const SUBMIT_RESPONSE_DOMAIN: &[u8] = b"CATBIRD-CHAT-SUBMIT-TRANSITION-RESPONSE\0";
const SUBMIT_REPLAY_POST_STATE_DOMAIN: &[u8] =
    b"CATBIRD-CHAT-SUBMIT-TRANSITION-REPLAY-POST-STATE\0";
const SUBMIT_REPLAY_SEAL_DOMAIN: &[u8] = b"CATBIRD-CHAT-SUBMIT-TRANSITION-REPLAY-SEAL\0";
const COMPLETED_STATUS: i32 = 200;

#[derive(Debug)]
pub(crate) enum SubmitTransitionFacadeError {
    MissingMutation,
    UnsupportedMutation,
    InvalidCanonicalMaterial,
    CandidateScopeDrift,
    Prelude(PreludeError),
    Primitive(AuthPrimitiveError),
    StateMachine(StateMachineError),
    Conversation(ConversationStateHydrationError),
    RecoveryPackage(RecoveryPackageHydrationError),
    InvitationQuota(InvitationQuotaHydrationError),
    Relationship(RelationshipRepositoryError),
    ExecutionContext(ExecutionContextHydrationError),
    Executor(ExecutorError),
    Database(sqlx::Error),
}

macro_rules! facade_from {
    ($source:ty, $variant:ident) => {
        impl From<$source> for SubmitTransitionFacadeError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}

facade_from!(PreludeError, Prelude);
facade_from!(AuthPrimitiveError, Primitive);
facade_from!(StateMachineError, StateMachine);
facade_from!(ConversationStateHydrationError, Conversation);
facade_from!(RecoveryPackageHydrationError, RecoveryPackage);
facade_from!(InvitationQuotaHydrationError, InvitationQuota);
facade_from!(RelationshipRepositoryError, Relationship);
facade_from!(ExecutionContextHydrationError, ExecutionContext);
facade_from!(ExecutorError, Executor);
facade_from!(sqlx::Error, Database);

/// Generated-DTO-validated output bytes. The binding digest prevents accidental
/// replacement after the plan-derived response has been sealed.
#[derive(Debug)]
pub(crate) struct SubmitTransitionCanonicalResponse {
    bytes: Box<[u8]>,
    sha256: [u8; 32],
    binding_digest: [u8; 32],
}

impl SubmitTransitionCanonicalResponse {
    fn new(bytes: Vec<u8>) -> Result<Self, SubmitTransitionFacadeError> {
        if bytes.is_empty() {
            return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
        }
        let _: chat_dto::submit_transition::SubmitTransitionOutput<DefaultStr> =
            serde_json::from_slice(&bytes)
                .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
        let sha256: [u8; 32] = Sha256::digest(&bytes).into();
        let mut digest = Sha256::new();
        digest.update(SUBMIT_RESPONSE_DOMAIN);
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(&bytes);
        digest.update(sha256);
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            sha256,
            binding_digest: digest.finalize().into(),
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    fn validates(&self) -> bool {
        if self.bytes.is_empty() || <[u8; 32]>::from(Sha256::digest(&self.bytes)) != self.sha256 {
            return false;
        }
        let mut digest = Sha256::new();
        digest.update(SUBMIT_RESPONSE_DOMAIN);
        digest.update((self.bytes.len() as u64).to_be_bytes());
        digest.update(&self.bytes);
        digest.update(self.sha256);
        self.binding_digest == <[u8; 32]>::from(digest.finalize())
    }
}

/// Locked durable post-state for an exact completed non-Recovery transition.
///
/// Fields and construction are private. The operation foundation may only
/// consume the repository-visible exact-claim/status/SHA/seal accessors.
pub(in crate::chat_protocol::repository) struct SubmitTransitionReplayPostStateProof {
    transaction_id: Box<str>,
    operation_id: Uuid,
    principal_did: Box<str>,
    endpoint_nsid: Box<str>,
    mutation_kind: SignedMutationKind,
    request_digest: [u8; 32],
    accepted_request_sha256: [u8; 32],
    signature: [u8; 64],
    post_state_digest: [u8; 32],
    expected_response_sha256: [u8; 32],
    expected_status: i32,
    seal: [u8; 32],
}

impl SubmitTransitionReplayPostStateProof {
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
        &self.endpoint_nsid
    }

    pub(in crate::chat_protocol::repository) fn mutation_kind(&self) -> SignedMutationKind {
        self.mutation_kind
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

    pub(in crate::chat_protocol::repository) fn post_state_digest(&self) -> &[u8; 32] {
        &self.post_state_digest
    }

    pub(in crate::chat_protocol::repository) fn expected_response_sha256(&self) -> &[u8; 32] {
        &self.expected_response_sha256
    }

    pub(in crate::chat_protocol::repository) fn expected_status(&self) -> i32 {
        self.expected_status
    }

    pub(in crate::chat_protocol::repository) fn validates_seal(&self) -> bool {
        self.post_state_digest != [0; 32]
            && self.expected_response_sha256 != [0; 32]
            && self.expected_status == COMPLETED_STATUS
            && self.seal == self.rederive_seal()
    }

    fn rederive_seal(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(SUBMIT_REPLAY_SEAL_DOMAIN);
        bind_bytes(&mut digest, self.transaction_id.as_bytes());
        digest.update(self.operation_id.as_bytes());
        bind_bytes(&mut digest, self.principal_did.as_bytes());
        bind_bytes(&mut digest, self.endpoint_nsid.as_bytes());
        bind_bytes(&mut digest, self.mutation_kind.type_id().as_bytes());
        digest.update(self.request_digest);
        digest.update(self.accepted_request_sha256);
        digest.update(self.signature);
        digest.update(self.post_state_digest);
        digest.update(self.expected_response_sha256);
        digest.update(self.expected_status.to_be_bytes());
        digest.finalize().into()
    }
}

fn bind_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

/// Handler-safe completion material. Both first execution and replay expose
/// the same exact recorded status/body/event position shape.
pub(crate) struct SubmitTransitionTransactionOutcome {
    status: i32,
    response_bytes: Box<[u8]>,
    event_position: Option<i64>,
}

impl SubmitTransitionTransactionOutcome {
    pub(crate) fn status(&self) -> i32 {
        self.status
    }

    pub(crate) fn response_bytes(&self) -> &[u8] {
        &self.response_bytes
    }

    pub(crate) fn event_position(&self) -> Option<i64> {
        self.event_position
    }

    fn first(response: SubmitTransitionCanonicalResponse, event_position: Option<i64>) -> Self {
        Self {
            status: COMPLETED_STATUS,
            response_bytes: response.bytes,
            event_position,
        }
    }

    fn replay(response: CompletedIdempotentResponse) -> Self {
        Self {
            status: response.status(),
            response_bytes: response.response_bytes().to_vec().into_boxed_slice(),
            event_position: response.event_position(),
        }
    }
}

#[derive(Debug)]
struct ParsedSubmitTransition {
    transition_id: Uuid,
    prior: PublicGroupSnapshotCoordinate,
    add_principals: Vec<String>,
}

/// Consume one globally arbitrated signed `submitTransition` operation.
///
/// Recovery fulfillment is intentionally absent: its stronger request,
/// reservation, target-registration, relationship, and Welcome bindings live
/// in the dedicated Recovery bridge.
pub(crate) async fn execute_prepared_submit_transition<T: PublicTransport>(
    transaction: &mut Transaction<'_, Postgres>,
    prepared: PreparedSignedOperation,
    relationship_authority: &RelationshipAuthority<T>,
) -> Result<SubmitTransitionTransactionOutcome, SubmitTransitionFacadeError> {
    match prepared.into_state() {
        PreparedSignedOperationState::First {
            authority,
            reservation,
        } => {
            execute_first_submit_transition(
                transaction,
                authority,
                reservation,
                relationship_authority,
            )
            .await
        }
        PreparedSignedOperationState::Replay { authority, replay } => {
            let locked =
                lock_signed_operation_replay_authority(transaction, authority, replay).await?;
            let (proof, expected_response) =
                lock_submit_transition_replay_post_state(transaction, &locked).await?;
            let expected_sha256 = *proof.expected_response_sha256();
            let expected_status = proof.expected_status();
            let wrapped =
                super::prelude::SignedOperationReplayPostStateProof::SubmitTransition(proof);
            let completed = release_signed_operation_replay(transaction, locked, wrapped).await?;
            if completed.status() != expected_status
                || completed.response_sha256() != &expected_sha256
                || <[u8; 32]>::from(Sha256::digest(completed.response_bytes())) != expected_sha256
                || completed.response_bytes() != expected_response.as_bytes()
            {
                return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
            }
            Ok(SubmitTransitionTransactionOutcome::replay(completed))
        }
    }
}

async fn execute_first_submit_transition<T: PublicTransport>(
    transaction: &mut Transaction<'_, Postgres>,
    authority: VerifiedChatDeviceRequest,
    reservation: OperationReservationGuard,
    relationship_authority: &RelationshipAuthority<T>,
) -> Result<SubmitTransitionTransactionOutcome, SubmitTransitionFacadeError> {
    let admitted = authority
        .mutation()
        .ok_or(SubmitTransitionFacadeError::MissingMutation)?;
    let parsed = parse_submit_transition(admitted)?;
    let scope =
        discover_submit_transition_identity_scope(transaction, &authority, admitted, &parsed)
            .await?;
    let prelude =
        prepare_identity_scope_prelude(transaction, &authority, reservation, scope).await?;
    let mutation = {
        let scope_authority = prelude.scope_authority();
        validate_locked_scope(transaction, scope_authority, admitted, &parsed).await?;
        reverify_scope_mutation(scope_authority, admitted)?
    };
    let prelude = prelude.verify_submit_transition_operation(parsed.transition_id, &mutation)?;
    let scope_authority = prelude.scope_authority();

    let aggregate = hydrate_locked_conversation_state(
        transaction,
        Uuid::from_bytes(*parsed.prior.conversation_id()),
        scope_authority.trusted_instant(),
    )
    .await?;
    if aggregate.head().transaction_id() != scope_authority.transaction_id()
        || aggregate.head().prior_coordinate() != Some(&parsed.prior)
        || aggregate.state().coordinate() != &parsed.prior
        || parsed.prior.lifecycle() != PublicGroupSnapshotLifecycle::Active
    {
        return Err(SubmitTransitionFacadeError::CandidateScopeDrift);
    }

    let hydration = HydrationAuthority::from_locked_conversation(&aggregate)?;
    let registration = hydration.locked_registration_from_scope_authority(scope_authority)?;
    let terminal_packages = hydrate_terminal_recovery_packages(transaction, &aggregate).await?;
    let entry = build_verified_control_entry(
        mutation,
        authority.endpoint(),
        canonical_uuid_v4(parsed.transition_id)?,
        canonical_uuid_v4(Uuid::from_bytes(*parsed.prior.conversation_id()))?,
        aggregate.head().next_entry_seq(),
        authority.trusted_instant(),
        CanonicalControlServerFields::empty(control_kind(admitted.kind())?)?,
    )?;
    let products = CanonicalControlEntryProducts::mint(&entry)?;

    let planned = match admitted.kind() {
        SignedMutationKind::CommitTransition => {
            hydration.plan_commit_entry(&aggregate, entry, &registration, terminal_packages)?
        }
        SignedMutationKind::PolicyTransition if parsed.add_principals.is_empty() => {
            let quota = hydrate_locked_invitation_quota(
                transaction,
                std::str::from_utf8(registration.actor().principal().as_bytes())
                    .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?,
                &[],
                scope_authority.trusted_instant(),
            )
            .await?;
            let no_admission =
                seal_non_add_policy_no_pending_admission(&aggregate, &quota, &registration)?;
            hydration.plan_policy_without_pending_admission(
                &aggregate,
                entry,
                &registration,
                terminal_packages,
                quota,
                no_admission,
                authority.trusted_instant(),
            )?
        }
        SignedMutationKind::PolicyTransition => {
            let quota = hydrate_locked_invitation_quota(
                transaction,
                admitted.actor_did().as_str(),
                &parsed.add_principals,
                scope_authority.trusted_instant(),
            )
            .await?;
            let fallback_scope =
                seal_pending_add_fallback_scope(&aggregate, &quota, &registration)?;
            let (relationship, relationship_decision) = load_fallback_relationship_projection(
                transaction,
                fallback_scope,
                relationship_authority,
            )
            .await?
            .ok_or(SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
            hydration.plan_policy(
                &aggregate,
                entry,
                &registration,
                terminal_packages,
                &relationship,
                relationship_authority,
                quota,
                &relationship_decision,
                authority.trusted_instant(),
            )?
        }
        SignedMutationKind::MetadataTransition => {
            hydration.plan_metadata_entry(&aggregate, entry, registration, terminal_packages)?
        }
        SignedMutationKind::LeaveCommitFulfillment => hydration.plan_leave_fulfillment_entry(
            &aggregate,
            entry,
            &registration,
            terminal_packages,
        )?,
        _ => return Err(SubmitTransitionFacadeError::UnsupportedMutation),
    };
    let plan = planned.into_persistence_plan()?;
    let response = canonical_response_from_plan(&plan, products.canonical_response_json())?;
    if !response.validates() {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    let expected_entry_id = parsed.transition_id;
    let expected_seq = aggregate.head().next_entry_seq();
    let expected_coordinate = plan.successor_coordinate().copied();
    let accepted_control_entry_bytes = products.durable_json().to_vec();
    let response_sha256 = *response.sha256();

    let (scope_authority, completion) = prelude.into_execution_parts();
    let prepared_execution =
        prepare_submit_transition_execution(transaction, &plan, accepted_control_entry_bytes)
            .await?;
    let applied = apply_prepared_submit_transition_execution(prepared_execution).await?;
    validate_applied_transition(
        &applied,
        expected_entry_id,
        expected_seq,
        expected_coordinate.as_ref(),
    )?;
    let event_position = applied.event_positions.first().copied();
    complete_operation(
        transaction,
        &authority,
        scope_authority,
        completion,
        COMPLETED_STATUS,
        response.as_bytes(),
        event_position,
    )
    .await?;
    if response.sha256() != &response_sha256 {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    Ok(SubmitTransitionTransactionOutcome::first(
        response,
        event_position,
    ))
}

fn control_kind(kind: SignedMutationKind) -> Result<ControlEntryKind, SubmitTransitionFacadeError> {
    match kind {
        SignedMutationKind::CommitTransition => Ok(ControlEntryKind::Commit),
        SignedMutationKind::PolicyTransition => Ok(ControlEntryKind::Policy),
        SignedMutationKind::MetadataTransition => Ok(ControlEntryKind::Metadata),
        SignedMutationKind::LeaveCommitFulfillment => Ok(ControlEntryKind::LeaveCommitFulfillment),
        _ => Err(SubmitTransitionFacadeError::UnsupportedMutation),
    }
}

async fn hydrate_terminal_recovery_packages(
    transaction: &mut Transaction<'_, Postgres>,
    aggregate: &LockedConversationStateGuard,
) -> Result<Vec<LockedRecoveryPackageGuard>, SubmitTransitionFacadeError> {
    let mut request_ids = aggregate
        .state()
        .recovery_requests()
        .iter()
        .filter(|request| {
            request.status() == crate::chat_protocol::state_machine::RecoveryRequestStatus::Open
        })
        .map(|request| Uuid::from_bytes(*request.request_id()))
        .collect::<Vec<_>>();
    request_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let mut packages = Vec::with_capacity(request_ids.len());
    for request_id in request_ids {
        packages.push(
            hydrate_locked_reserved_recovery_package(transaction, aggregate.head(), request_id)
                .await?,
        );
    }
    Ok(packages)
}

fn validate_applied_transition(
    applied: &AppliedTransition,
    expected_entry_id: Uuid,
    expected_seq: u64,
    expected_coordinate: Option<&PublicGroupSnapshotCoordinate>,
) -> Result<(), SubmitTransitionFacadeError> {
    if applied.entry_id != expected_entry_id
        || applied.allocated_seq != expected_seq
        || applied.successor_coordinate.as_ref() != expected_coordinate
        || applied.event_positions.is_empty()
    {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    Ok(())
}

fn parse_submit_transition(
    mutation: &VerifiedSignedMutation,
) -> Result<ParsedSubmitTransition, SubmitTransitionFacadeError> {
    let (transition_id, prior, add_principals) = match mutation.projection() {
        VerifiedMutationProjection::CommitTransition(value) => (
            Uuid::from_bytes(*value.transition_id().as_bytes()),
            value.prior(),
            Vec::new(),
        ),
        VerifiedMutationProjection::PolicyTransition(value) => {
            let changes = match value.participant_changes() {
                CanonicalValueRef::Array(values) => values,
                _ => return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial),
            };
            let mut additions = Vec::new();
            for index in 0..changes.len() {
                let change = match changes.get(index) {
                    Some(CanonicalValueRef::Object(value)) => value,
                    _ => return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial),
                };
                match change.get("$type") {
                    Some(CanonicalValueRef::Text("blue.catbird.chat.defs#addParticipant")) => {
                        match change.get("userDid") {
                            Some(CanonicalValueRef::Did(value)) => {
                                additions.push(value.as_str().to_owned())
                            }
                            Some(CanonicalValueRef::Text(value)) => {
                                additions.push((*value).to_owned())
                            }
                            _ => return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial),
                        }
                    }
                    Some(CanonicalValueRef::Text("blue.catbird.chat.defs#removeParticipant"))
                    | Some(CanonicalValueRef::Text(
                        "blue.catbird.chat.defs#changeParticipantRole",
                    )) => {}
                    _ => return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial),
                }
            }
            (
                Uuid::from_bytes(*value.transition_id().as_bytes()),
                value.prior(),
                additions,
            )
        }
        VerifiedMutationProjection::MetadataTransition(value) => (
            Uuid::from_bytes(*value.transition_id().as_bytes()),
            value.prior(),
            Vec::new(),
        ),
        VerifiedMutationProjection::LeaveCommitFulfillment(value) => (
            Uuid::from_bytes(*value.transition_id().as_bytes()),
            value.prior(),
            Vec::new(),
        ),
        _ => return Err(SubmitTransitionFacadeError::UnsupportedMutation),
    };
    let idempotency_key = match mutation.projection() {
        VerifiedMutationProjection::CommitTransition(value) => value.body(),
        VerifiedMutationProjection::PolicyTransition(value) => value.body(),
        VerifiedMutationProjection::MetadataTransition(value) => value.body(),
        VerifiedMutationProjection::LeaveCommitFulfillment(value) => value.body(),
        _ => return Err(SubmitTransitionFacadeError::UnsupportedMutation),
    };
    let idempotency_key = match idempotency_key.get("idempotencyKey") {
        Some(CanonicalValueRef::Uuid(value)) => Uuid::from_bytes(*value.as_bytes()),
        _ => return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial),
    };
    if transition_id.get_version_num() != 4
        || idempotency_key != transition_id
        || mutation.accepted_wrapper_bytes().is_none()
        || add_principals
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    Ok(ParsedSubmitTransition {
        transition_id,
        prior: parse_coordinate(&prior)?,
        add_principals,
    })
}

fn parse_coordinate(
    value: &ClosedObjectRef<'_>,
) -> Result<PublicGroupSnapshotCoordinate, SubmitTransitionFacadeError> {
    let conversation_id = match value.get("conversationId") {
        Some(CanonicalValueRef::Uuid(value)) => *value.as_bytes(),
        _ => return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial),
    };
    let integer = |name| match value.get(name) {
        Some(CanonicalValueRef::Integer(value)) if value <= MAX_PROTOCOL_INTEGER => Ok(value),
        _ => Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial),
    };
    let bytes32 = |name| match value.get(name) {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial),
        _ => Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial),
    };
    let lifecycle = match value.get("lifecycle") {
        Some(CanonicalValueRef::Text("active")) => PublicGroupSnapshotLifecycle::Active,
        Some(CanonicalValueRef::Text("superseded")) => PublicGroupSnapshotLifecycle::Superseded,
        _ => return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial),
    };
    Ok(PublicGroupSnapshotCoordinate::new(
        conversation_id,
        integer("generation")?,
        integer("stateVersion")?,
        bytes32("groupId")?,
        integer("epoch")?,
        bytes32("groupContextHash")?,
        bytes32("confirmationTag")?,
        lifecycle,
    ))
}

async fn discover_submit_transition_identity_scope(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    mutation: &VerifiedSignedMutation,
    parsed: &ParsedSubmitTransition,
) -> Result<CanonicalLockScope, SubmitTransitionFacadeError> {
    if authority.endpoint().as_str() != SUBMIT_TRANSITION_ENDPOINT
        || authority.mutation().is_none_or(|value| {
            value.type_id() != mutation.type_id()
                || value.request_digest() != mutation.request_digest()
                || value.signature() != mutation.signature()
                || value.accepted_wrapper_bytes() != mutation.accepted_wrapper_bytes()
        })
    {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    discover_submit_transition_identity_scope_for_actor(
        transaction,
        Uuid::from_bytes(*parsed.prior.conversation_id()),
        mutation.actor_did().as_str(),
        Uuid::from_bytes(*mutation.actor_device_id().as_bytes()),
        &parsed.add_principals,
    )
    .await
}

async fn discover_submit_transition_identity_scope_for_actor(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    actor_did: &str,
    actor_device_id: Uuid,
    add_principals: &[String],
) -> Result<CanonicalLockScope, SubmitTransitionFacadeError> {
    let principals: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT user_did
          FROM (
            SELECT p.user_did
              FROM chat.participants p
             WHERE p.conversation_id=$1 AND p.current_membership
            UNION
            SELECT $2::text
            UNION
            SELECT unnest($3::text[])
            UNION
            SELECT wd.recipient_did
              FROM chat.welcome_bundles wb
              JOIN chat.welcome_deliveries wd ON wd.welcome_id=wb.welcome_id
             WHERE wb.conversation_id=$1 AND wd.status='pending'
          ) candidate_principals
        "#,
    )
    .bind(conversation_id)
    .bind(actor_did)
    .bind(add_principals)
    .fetch_all(&mut **transaction)
    .await?;
    let devices: Vec<(String, Uuid)> = sqlx::query_as(
        r#"
        SELECT user_did,device_id
          FROM (
            SELECT DISTINCT p.user_did,d.device_id
              FROM chat.participants p
              JOIN chat.devices d ON d.user_did=p.user_did
             WHERE p.conversation_id=$1 AND p.current_membership
            UNION
            SELECT $2::text,$3::uuid
            UNION
            SELECT wd.recipient_did,wd.recipient_device_id
              FROM chat.welcome_bundles wb
              JOIN chat.welcome_deliveries wd ON wd.welcome_id=wb.welcome_id
             WHERE wb.conversation_id=$1 AND wd.status='pending'
          ) candidate_devices
        "#,
    )
    .bind(conversation_id)
    .bind(actor_did)
    .bind(actor_device_id)
    .fetch_all(&mut **transaction)
    .await?;
    CanonicalLockScope::new(
        principals,
        devices
            .into_iter()
            .map(|(did, device_id)| CanonicalDeviceIdentity::new(did, device_id))
            .collect(),
    )
    .map_err(SubmitTransitionFacadeError::from)
}

async fn validate_locked_scope(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ScopeBoundBusinessAuthority,
    mutation: &VerifiedSignedMutation,
    parsed: &ParsedSubmitTransition,
) -> Result<(), SubmitTransitionFacadeError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    let discovered = discover_submit_transition_identity_scope_for_actor(
        transaction,
        Uuid::from_bytes(*parsed.prior.conversation_id()),
        mutation.actor_did().as_str(),
        Uuid::from_bytes(*mutation.actor_device_id().as_bytes()),
        &parsed.add_principals,
    )
    .await?;
    if transaction_id != scope.transaction_id()
        || scope.actor_class() != RepositoryAuthorityClass::ExistingDevice
        || scope.actor_did() != mutation.actor_did().as_str()
        || scope.actor_device_id() != Uuid::from_bytes(*mutation.actor_device_id().as_bytes())
        || scope.actor_key_id() != Some(mutation.key_id().as_str())
        || scope.actor_auth_generation() != i64::try_from(mutation.auth_generation()).ok()
        || scope.actor_signing_public_key().is_none()
        || scope.principals() != discovered.principals()
        || scope.devices().len() != discovered.devices().len()
        || !scope
            .devices()
            .iter()
            .zip(discovered.devices())
            .all(|(locked, expected)| {
                locked.user_did() == expected.did() && locked.device_id() == expected.device_id()
            })
    {
        return Err(SubmitTransitionFacadeError::CandidateScopeDrift);
    }
    Ok(())
}

fn reverify_scope_mutation(
    scope: &ScopeBoundBusinessAuthority,
    admitted: &VerifiedSignedMutation,
) -> Result<VerifiedSignedMutation, SubmitTransitionFacadeError> {
    let raw = admitted
        .accepted_wrapper_bytes()
        .ok_or(SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let key = scope
        .actor_signing_public_key()
        .ok_or(SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let verified = decode_and_verify_signed_mutation(raw, key)?;
    if verified.kind() != admitted.kind()
        || verified.type_id() != admitted.type_id()
        || verified.domain() != admitted.domain()
        || verified.canonical_projection() != admitted.canonical_projection()
        || verified.transcript_bytes() != admitted.transcript_bytes()
        || verified.request_digest() != admitted.request_digest()
        || verified.signature() != admitted.signature()
        || verified.accepted_wrapper_bytes() != admitted.accepted_wrapper_bytes()
        || verified.actor_did() != admitted.actor_did()
        || verified.actor_device_id() != admitted.actor_device_id()
        || verified.key_id() != admitted.key_id()
        || verified.auth_generation() != admitted.auth_generation()
        || verified.signed_at() != admitted.signed_at()
    {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    Ok(verified)
}

fn canonical_uuid_v4(value: Uuid) -> Result<CanonicalUuidV4, SubmitTransitionFacadeError> {
    CanonicalUuidV4::parse(&value.hyphenated().to_string())
        .map_err(SubmitTransitionFacadeError::from)
}

fn canonical_response_from_plan(
    plan: &ConversationPersistencePlan,
    canonical_response_entry: &[u8],
) -> Result<SubmitTransitionCanonicalResponse, SubmitTransitionFacadeError> {
    let successor = plan
        .successor_coordinate()
        .ok_or(SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    if successor.lifecycle() != PublicGroupSnapshotLifecycle::Active {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    let entry: JsonValue = serde_json::from_slice(canonical_response_entry)
        .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let welcomes = canonical_new_pending_welcomes(plan.effects().welcome_changes(), successor)?;
    let value = json!({
        "coordinates": coordinate_json(successor)?,
        "entry": entry,
        "welcomes": welcomes,
    });
    // `SubmitTransitionOutput<DefaultStr>` borrows string fields. `from_value`
    // cannot provide storage for those borrows; parse canonical JSON bytes.
    let value_bytes = serde_json::to_vec(&value)
        .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let output: chat_dto::submit_transition::SubmitTransitionOutput<DefaultStr> =
        serde_json::from_slice(&value_bytes)
            .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let bytes = serde_json::to_vec(&output)
        .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let round_trip: chat_dto::submit_transition::SubmitTransitionOutput<DefaultStr> =
        serde_json::from_slice(&bytes)
            .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    if round_trip != output {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    SubmitTransitionCanonicalResponse::new(bytes)
}

fn canonical_new_pending_welcomes(
    changes: &[StateChange<WelcomeWork>],
    successor: &PublicGroupSnapshotCoordinate,
) -> Result<Vec<JsonValue>, SubmitTransitionFacadeError> {
    let mut welcomes = changes
        .iter()
        .filter_map(|change| {
            (change.before().is_none())
                .then(|| change.after())
                .flatten()
        })
        .collect::<Vec<_>>();
    if changes.iter().any(|change| {
        change.before().is_none()
            && (change.after().is_none()
                || change
                    .after()
                    .is_some_and(|welcome| welcome.status() != WelcomeStatus::Pending))
    }) {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    welcomes.sort_by(|left, right| {
        left.recipient()
            .principal()
            .as_bytes()
            .cmp(right.recipient().principal().as_bytes())
            .then_with(|| {
                left.recipient()
                    .device_id()
                    .cmp(right.recipient().device_id())
            })
            .then_with(|| left.key_package_ref().cmp(right.key_package_ref()))
            .then_with(|| left.welcome_id().cmp(right.welcome_id()))
    });
    let mut prior_key: Option<(Vec<u8>, [u8; 16], [u8; 32], [u8; 16])> = None;
    let mut result = Vec::with_capacity(welcomes.len());
    for welcome in welcomes {
        if welcome.coordinate() != successor
            || welcome.status() != WelcomeStatus::Pending
            || welcome.opaque_welcome().is_empty()
            || welcome.sha256() != &<[u8; 32]>::from(Sha256::digest(welcome.opaque_welcome()))
            || welcome.transition_seq() == 0
        {
            return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
        }
        let did = std::str::from_utf8(welcome.recipient().principal().as_bytes())
            .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
        let expires_at = DateTime::<Utc>::from_timestamp_millis(welcome.expires_at().unix_millis())
            .ok_or(SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
        let key = (
            did.as_bytes().to_vec(),
            *welcome.recipient().device_id(),
            *welcome.key_package_ref(),
            *welcome.welcome_id(),
        );
        if prior_key.as_ref().is_some_and(|previous| previous >= &key) {
            return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
        }
        prior_key = Some(key);
        result.push(json!({
            "welcomeId": Uuid::from_bytes(*welcome.welcome_id()).hyphenated().to_string(),
            "conversationId":
                Uuid::from_bytes(*successor.conversation_id()).hyphenated().to_string(),
            "transitionSeq": i64::try_from(welcome.transition_seq())
                .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?,
            "coordinates": coordinate_json(successor)?,
            "status": "pending",
            "opaqueWelcome": STANDARD.encode(welcome.opaque_welcome()),
            "sha256": STANDARD.encode(welcome.sha256()),
            "recipientDid": did,
            "recipientDeviceId":
                Uuid::from_bytes(*welcome.recipient().device_id()).hyphenated().to_string(),
            "provenance": {
                "recoveryRequestId":
                    Uuid::from_bytes(*welcome.recovery_request_id()).hyphenated().to_string(),
                "keyPackageRef": STANDARD.encode(welcome.key_package_ref()),
            },
            "expiresAt": canonical_datetime(expires_at),
        }));
    }
    Ok(result)
}

fn coordinate_json(
    coordinate: &PublicGroupSnapshotCoordinate,
) -> Result<JsonValue, SubmitTransitionFacadeError> {
    super::coordinate::canonical_coordinate_json(coordinate)
        .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)
}

fn canonical_datetime(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[derive(Debug, FromRow)]
struct ReplayTransitionRow {
    transition_id: Uuid,
    conversation_id: Uuid,
    kind: String,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: i64,
    actor_role: String,
    actor_device_status: String,
    signed_request_bytes: Vec<u8>,
    unsigned_projection_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    prior_generation: Option<i64>,
    prior_state_version: Option<i64>,
    next_generation: Option<i64>,
    next_state_version: Option<i64>,
    retired_generation: Option<i64>,
    retired_state_version: Option<i64>,
    successor_generation: Option<i64>,
    successor_state_version: Option<i64>,
    reset_request_id: Option<Uuid>,
    close_transition_id: Option<Uuid>,
    metadata_snapshot_id: Option<Uuid>,
    entry_seq: i64,
    accepted_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct ReplayEntryRow {
    conversation_id: Uuid,
    seq: i64,
    entry_id: Uuid,
    entry_kind: String,
    accepted_payload_bytes: Vec<u8>,
    accepted_payload_sha256: Vec<u8>,
    signed_request_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    server_fields_bytes: Vec<u8>,
    outer_entry_fingerprint: Vec<u8>,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: i64,
    generation: Option<i64>,
    state_version: Option<i64>,
    transition_id: Option<Uuid>,
    message_id: Option<Uuid>,
    received_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct ReplaySuccessorRow {
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    group_id: Vec<u8>,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    lifecycle: String,
    state_kind: String,
    producing_transition_id: Uuid,
    snapshot_sha256: Vec<u8>,
    tree_summary_sha256: Vec<u8>,
    leaf_count: i64,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct ReplayWelcomeRow {
    welcome_id: Uuid,
    conversation_id: Uuid,
    transition_id: Uuid,
    entry_seq: i64,
    generation: i64,
    state_version: i64,
    group_id: Vec<u8>,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    wrapper_bytes: Vec<u8>,
    wrapper_sha256: Vec<u8>,
    created_at: DateTime<Utc>,
    recipient_did: String,
    recipient_device_id: Uuid,
    recovery_request_id: Uuid,
    key_package_ref: Vec<u8>,
    expires_at: DateTime<Utc>,
    status: String,
    terminal_at: Option<DateTime<Utc>>,
}

async fn lock_submit_transition_replay_post_state(
    transaction: &mut Transaction<'_, Postgres>,
    locked: &LockedSignedOperationReplayAuthority,
) -> Result<
    (
        SubmitTransitionReplayPostStateProof,
        SubmitTransitionCanonicalResponse,
    ),
    SubmitTransitionFacadeError,
> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    let replay_authority = locked.authority();
    if replay_authority.endpoint().as_str() != SUBMIT_TRANSITION_ENDPOINT {
        return Err(SubmitTransitionFacadeError::UnsupportedMutation);
    }
    let mutation = replay_authority.mutation();
    let parsed = parse_submit_transition(mutation)?;
    let transition: ReplayTransitionRow = sqlx::query_as(
        r#"
        SELECT transition_id,conversation_id,kind,actor_did,actor_device_id,
               actor_key_id,actor_auth_generation,actor_role,actor_device_status,
               signed_request_bytes,unsigned_projection_bytes,
               signing_transcript_bytes,request_digest,signature,
               prior_generation,prior_state_version,next_generation,
               next_state_version,retired_generation,retired_state_version,
               successor_generation,successor_state_version,reset_request_id,
               close_transition_id,metadata_snapshot_id,entry_seq,accepted_at
          FROM chat.transitions
         WHERE transition_id=$1
         FOR SHARE
        "#,
    )
    .bind(parsed.transition_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let entry: ReplayEntryRow = sqlx::query_as(
        r#"
        SELECT conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
               accepted_payload_sha256,signed_request_bytes,request_digest,
               signature,server_fields_bytes,outer_entry_fingerprint,
               actor_did,actor_device_id,actor_key_id,actor_auth_generation,
               generation,state_version,transition_id,message_id,received_at
          FROM chat.entries
         WHERE transition_id=$1
         FOR SHARE
        "#,
    )
    .bind(parsed.transition_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let signing_public_key: Vec<u8> = sqlx::query_scalar(
        r#"
        SELECT signing_public_key
          FROM chat.device_keys
         WHERE user_did=$1 AND device_id=$2 AND key_id=$3
         FOR SHARE
        "#,
    )
    .bind(&transition.actor_did)
    .bind(transition.actor_device_id)
    .bind(&transition.actor_key_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let successor: ReplaySuccessorRow = sqlx::query_as(
        r#"
        SELECT conversation_id,generation,state_version,group_id,epoch,
               group_context_hash,confirmation_tag,lifecycle,state_kind,
               producing_transition_id,snapshot_sha256,tree_summary_sha256,
               leaf_count,created_at
          FROM chat.generation_states
         WHERE producing_transition_id=$1
         FOR SHARE
        "#,
    )
    .bind(parsed.transition_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let mut welcomes: Vec<ReplayWelcomeRow> = sqlx::query_as(
        r#"
        SELECT wb.welcome_id,wb.conversation_id,wb.transition_id,wb.entry_seq,
               wb.generation,wb.state_version,wb.group_id,wb.epoch,
               wb.group_context_hash,wb.confirmation_tag,wb.wrapper_bytes,
               wb.wrapper_sha256,wb.created_at,wd.recipient_did,
               wd.recipient_device_id,wd.recovery_request_id,wd.key_package_ref,
               wd.expires_at,wd.status,wd.terminal_at
          FROM chat.welcome_bundles wb
          JOIN chat.welcome_deliveries wd ON wd.welcome_id=wb.welcome_id
         WHERE wb.transition_id=$1
         ORDER BY wd.recipient_did,uuid_send(wd.recipient_device_id),
                  wd.key_package_ref,uuid_send(wb.welcome_id)
         FOR SHARE OF wb,wd
        "#,
    )
    .bind(parsed.transition_id)
    .fetch_all(&mut **transaction)
    .await?;

    validate_replay_transition(
        replay_authority,
        mutation,
        &parsed,
        &transition,
        &entry,
        &successor,
        &signing_public_key,
    )?;
    let verified_entry =
        decode_and_verify_control_entry(&entry.accepted_payload_bytes, &signing_public_key)?;
    validate_replay_entry(&verified_entry, mutation, &transition, &entry)?;
    let products = CanonicalControlEntryProducts::mint(&verified_entry)?;
    let coordinate = replay_successor_coordinate(&successor)?;
    let welcome_json = replay_welcome_json(&mut welcomes, &transition, &coordinate)?;
    let response = canonical_response_from_replay_rows(
        &coordinate,
        products.canonical_response_json(),
        welcome_json,
    )?;
    let post_state_digest =
        submit_replay_post_state_digest(&transition, &entry, &successor, &welcomes, &response);
    let accepted_request = mutation
        .accepted_wrapper_bytes()
        .ok_or(SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let request_digest = *mutation.request_digest();
    let accepted_request_sha256: [u8; 32] = Sha256::digest(accepted_request).into();
    let signature = *mutation.signature();
    let expected_response_sha256 = *response.sha256();
    let mut proof = SubmitTransitionReplayPostStateProof {
        transaction_id: transaction_id.into_boxed_str(),
        operation_id: parsed.transition_id,
        principal_did: replay_authority
            .subject()
            .as_str()
            .to_owned()
            .into_boxed_str(),
        endpoint_nsid: SUBMIT_TRANSITION_ENDPOINT.to_owned().into_boxed_str(),
        mutation_kind: mutation.kind(),
        request_digest,
        accepted_request_sha256,
        signature,
        post_state_digest,
        expected_response_sha256,
        expected_status: COMPLETED_STATUS,
        seal: [0; 32],
    };
    proof.seal = proof.rederive_seal();
    if !proof.validates_seal() {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    Ok((proof, response))
}

fn validate_replay_transition(
    replay_authority: &super::auth::SignedOperationReplayAuthority,
    mutation: &VerifiedSignedMutation,
    parsed: &ParsedSubmitTransition,
    transition: &ReplayTransitionRow,
    entry: &ReplayEntryRow,
    successor: &ReplaySuccessorRow,
    signing_public_key: &[u8],
) -> Result<(), SubmitTransitionFacadeError> {
    let reverified =
        decode_and_verify_signed_mutation(&transition.signed_request_bytes, signing_public_key)?;
    let expected_kind = persisted_transition_kind(mutation.kind())?;
    let expected_state_kind = match mutation.kind() {
        SignedMutationKind::CommitTransition | SignedMutationKind::LeaveCommitFulfillment => {
            "commit"
        }
        SignedMutationKind::PolicyTransition => "policy",
        SignedMutationKind::MetadataTransition => "metadata",
        _ => return Err(SubmitTransitionFacadeError::UnsupportedMutation),
    };
    let prior_generation = i64::try_from(parsed.prior.generation())
        .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let prior_state_version = i64::try_from(parsed.prior.state_version())
        .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    if transition.transition_id != parsed.transition_id
        || transition.conversation_id != Uuid::from_bytes(*parsed.prior.conversation_id())
        || transition.kind != expected_kind
        || transition.actor_did != mutation.actor_did().as_str()
        || transition.actor_device_id != Uuid::from_bytes(*mutation.actor_device_id().as_bytes())
        || transition.actor_key_id != mutation.key_id().as_str()
        || u64::try_from(transition.actor_auth_generation).ok() != Some(mutation.auth_generation())
        || transition.actor_device_status != "active"
        || !matches!(transition.actor_role.as_str(), "admin" | "member")
        || transition.signed_request_bytes
            != mutation
                .accepted_wrapper_bytes()
                .ok_or(SubmitTransitionFacadeError::InvalidCanonicalMaterial)?
        || transition.unsigned_projection_bytes != mutation.canonical_projection()
        || transition.signing_transcript_bytes != mutation.transcript_bytes()
        || transition.request_digest != mutation.request_digest().as_slice()
        || transition.signature != mutation.signature().as_slice()
        || transition.prior_generation != Some(prior_generation)
        || transition.prior_state_version != Some(prior_state_version)
        || transition.next_generation != Some(successor.generation)
        || transition.next_state_version != Some(successor.state_version)
        || transition.retired_generation.is_some()
        || transition.retired_state_version.is_some()
        || transition.successor_generation.is_some()
        || transition.successor_state_version.is_some()
        || transition.reset_request_id.is_some()
        || transition.close_transition_id.is_some()
        || transition.entry_seq != entry.seq
        || transition.accepted_at != entry.received_at
        || successor.conversation_id != transition.conversation_id
        || successor.producing_transition_id != transition.transition_id
        || successor.state_kind != expected_state_kind
        || successor.created_at != transition.accepted_at
        || replay_authority.subject().as_str() != transition.actor_did
        || replay_authority.device_id().as_bytes() != transition.actor_device_id.as_bytes()
        || reverified.kind() != mutation.kind()
        || reverified.canonical_projection() != mutation.canonical_projection()
        || reverified.request_digest() != mutation.request_digest()
        || reverified.signature() != mutation.signature()
    {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    Ok(())
}

fn validate_replay_entry(
    verified: &crate::chat_protocol::transcript::VerifiedControlEntry,
    mutation: &VerifiedSignedMutation,
    transition: &ReplayTransitionRow,
    row: &ReplayEntryRow,
) -> Result<(), SubmitTransitionFacadeError> {
    if row.conversation_id != transition.conversation_id
        || row.seq != transition.entry_seq
        || row.entry_id != transition.transition_id
        || row.entry_kind != control_kind(mutation.kind())?.type_id()
        || row.accepted_payload_bytes.is_empty()
        || row.accepted_payload_sha256.len() != 32
        || Sha256::digest(&row.accepted_payload_bytes).as_slice() != row.accepted_payload_sha256
        || row.request_digest.len() != 32
        || row.signature.len() != 64
        || row.server_fields_bytes.is_empty()
        || row.outer_entry_fingerprint.len() != 32
        || row.signed_request_bytes != transition.signed_request_bytes
        || row.request_digest != transition.request_digest
        || row.signature != transition.signature
        || row.actor_did != transition.actor_did
        || row.actor_device_id != transition.actor_device_id
        || row.actor_key_id != transition.actor_key_id
        || row.actor_auth_generation != transition.actor_auth_generation
        || row.generation != transition.next_generation
        || row.state_version != transition.next_state_version
        || row.transition_id != Some(transition.transition_id)
        || row.message_id.is_some()
        || verified.entry_id().as_bytes() != row.entry_id.as_bytes()
        || verified.conversation_id().as_bytes() != row.conversation_id.as_bytes()
        || i64::try_from(verified.seq()).ok() != Some(row.seq)
        || verified.received_at().as_str() != canonical_datetime(row.received_at)
        || verified.kind().type_id() != row.entry_kind
        || verified.mutation().request_digest() != mutation.request_digest()
        || verified.mutation().signature() != mutation.signature()
        || verified.server_fields_dag_cbor()? != row.server_fields_bytes
        || verified.outer_control_fingerprint().as_slice() != row.outer_entry_fingerprint
    {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    Ok(())
}

fn persisted_transition_kind(
    kind: SignedMutationKind,
) -> Result<&'static str, SubmitTransitionFacadeError> {
    match kind {
        SignedMutationKind::CommitTransition => Ok("commit"),
        SignedMutationKind::PolicyTransition => Ok("policy"),
        SignedMutationKind::MetadataTransition => Ok("metadata"),
        SignedMutationKind::LeaveCommitFulfillment => Ok("leaveCommit"),
        _ => Err(SubmitTransitionFacadeError::UnsupportedMutation),
    }
}

fn replay_successor_coordinate(
    row: &ReplaySuccessorRow,
) -> Result<PublicGroupSnapshotCoordinate, SubmitTransitionFacadeError> {
    let generation = protocol_u64(row.generation)?;
    let state_version = protocol_u64(row.state_version)?;
    let epoch = protocol_u64(row.epoch)?;
    if row.conversation_id.get_version_num() != 4
        || row.producing_transition_id.get_version_num() != 4
        || !matches!(row.lifecycle.as_str(), "active" | "superseded")
        || !matches!(
            row.state_kind.as_str(),
            "commit" | "policy" | "metadata" | "leavePolicy"
        )
        || row.snapshot_sha256.len() != 32
        || row.tree_summary_sha256.len() != 32
        || !(1..=100).contains(&row.leaf_count)
        || row.created_at.timestamp_subsec_nanos() % 1_000_000 != 0
    {
        return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
    }
    Ok(PublicGroupSnapshotCoordinate::new(
        *row.conversation_id.as_bytes(),
        generation,
        state_version,
        row.group_id
            .as_slice()
            .try_into()
            .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?,
        epoch,
        row.group_context_hash
            .as_slice()
            .try_into()
            .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?,
        row.confirmation_tag
            .as_slice()
            .try_into()
            .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?,
        PublicGroupSnapshotLifecycle::Active,
    ))
}

fn replay_welcome_json(
    rows: &mut [ReplayWelcomeRow],
    transition: &ReplayTransitionRow,
    successor: &PublicGroupSnapshotCoordinate,
) -> Result<Vec<JsonValue>, SubmitTransitionFacadeError> {
    rows.sort_by(|left, right| {
        left.recipient_did
            .as_bytes()
            .cmp(right.recipient_did.as_bytes())
            .then_with(|| {
                left.recipient_device_id
                    .as_bytes()
                    .cmp(right.recipient_device_id.as_bytes())
            })
            .then_with(|| left.key_package_ref.cmp(&right.key_package_ref))
            .then_with(|| left.welcome_id.as_bytes().cmp(right.welcome_id.as_bytes()))
    });
    let mut output = Vec::with_capacity(rows.len());
    for row in rows.iter() {
        let terminal_shape = match row.status.as_str() {
            "pending" => row.terminal_at.is_none(),
            "expired" => row.terminal_at == Some(row.expires_at),
            "acknowledged" | "rejected" | "superseded" => {
                row.terminal_at.is_some_and(|value| value < row.expires_at)
            }
            _ => false,
        };
        if row.welcome_id.get_version_num() != 4
            || row.conversation_id != transition.conversation_id
            || row.transition_id != transition.transition_id
            || row.entry_seq != transition.entry_seq
            || Some(row.generation) != transition.next_generation
            || Some(row.state_version) != transition.next_state_version
            || row.group_id.as_slice() != successor.group_id()
            || protocol_u64(row.epoch)? != successor.epoch()
            || row.group_context_hash.as_slice() != successor.group_context_hash()
            || row.confirmation_tag.as_slice() != successor.confirmation_tag()
            || row.wrapper_bytes.is_empty()
            || Sha256::digest(&row.wrapper_bytes).as_slice() != row.wrapper_sha256
            || row.created_at != transition.accepted_at
            || row.recipient_device_id.get_version_num() != 4
            || row.recovery_request_id.get_version_num() != 4
            || row.key_package_ref.len() != 32
            || row.expires_at.timestamp_subsec_nanos() % 1_000_000 != 0
            || !terminal_shape
        {
            return Err(SubmitTransitionFacadeError::InvalidCanonicalMaterial);
        }
        output.push(json!({
            "welcomeId": row.welcome_id.hyphenated().to_string(),
            "conversationId": row.conversation_id.hyphenated().to_string(),
            "transitionSeq": row.entry_seq,
            "coordinates": coordinate_json(successor)?,
            "status": "pending",
            "opaqueWelcome": STANDARD.encode(&row.wrapper_bytes),
            "sha256": STANDARD.encode(&row.wrapper_sha256),
            "recipientDid": row.recipient_did,
            "recipientDeviceId": row.recipient_device_id.hyphenated().to_string(),
            "provenance": {
                "recoveryRequestId": row.recovery_request_id.hyphenated().to_string(),
                "keyPackageRef": STANDARD.encode(&row.key_package_ref),
            },
            "expiresAt": canonical_datetime(row.expires_at),
        }));
    }
    Ok(output)
}

fn canonical_response_from_replay_rows(
    coordinate: &PublicGroupSnapshotCoordinate,
    entry: &[u8],
    welcomes: Vec<JsonValue>,
) -> Result<SubmitTransitionCanonicalResponse, SubmitTransitionFacadeError> {
    let value = json!({
        "coordinates": coordinate_json(coordinate)?,
        "entry": serde_json::from_slice::<JsonValue>(entry)
            .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?,
        "welcomes": welcomes,
    });
    let output: chat_dto::submit_transition::SubmitTransitionOutput<DefaultStr> =
        serde_json::from_value(value)
            .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    let bytes = serde_json::to_vec(&output)
        .map_err(|_| SubmitTransitionFacadeError::InvalidCanonicalMaterial)?;
    SubmitTransitionCanonicalResponse::new(bytes)
}

fn submit_replay_post_state_digest(
    transition: &ReplayTransitionRow,
    entry: &ReplayEntryRow,
    successor: &ReplaySuccessorRow,
    welcomes: &[ReplayWelcomeRow],
    response: &SubmitTransitionCanonicalResponse,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SUBMIT_REPLAY_POST_STATE_DOMAIN);
    digest.update(transition.transition_id.as_bytes());
    digest.update(transition.conversation_id.as_bytes());
    for bytes in [
        transition.kind.as_bytes(),
        transition.actor_did.as_bytes(),
        transition.actor_device_id.as_bytes(),
        transition.actor_key_id.as_bytes(),
        transition.actor_role.as_bytes(),
        transition.actor_device_status.as_bytes(),
        &transition.signed_request_bytes,
        &transition.unsigned_projection_bytes,
        &transition.signing_transcript_bytes,
        &transition.request_digest,
        &transition.signature,
        &entry.accepted_payload_bytes,
        &entry.accepted_payload_sha256,
        &entry.server_fields_bytes,
        &entry.outer_entry_fingerprint,
        &successor.group_id,
        &successor.group_context_hash,
        &successor.confirmation_tag,
        &successor.snapshot_sha256,
        &successor.tree_summary_sha256,
    ] {
        bind_bytes(&mut digest, bytes);
    }
    digest.update(transition.actor_auth_generation.to_be_bytes());
    bind_optional_i64(&mut digest, transition.prior_generation);
    bind_optional_i64(&mut digest, transition.prior_state_version);
    bind_optional_i64(&mut digest, transition.next_generation);
    bind_optional_i64(&mut digest, transition.next_state_version);
    bind_optional_i64(&mut digest, transition.retired_generation);
    bind_optional_i64(&mut digest, transition.retired_state_version);
    bind_optional_i64(&mut digest, transition.successor_generation);
    bind_optional_i64(&mut digest, transition.successor_state_version);
    bind_optional_uuid(&mut digest, transition.reset_request_id);
    bind_optional_uuid(&mut digest, transition.close_transition_id);
    bind_optional_uuid(&mut digest, transition.metadata_snapshot_id);
    digest.update(transition.entry_seq.to_be_bytes());
    digest.update(transition.accepted_at.timestamp_millis().to_be_bytes());
    digest.update(entry.conversation_id.as_bytes());
    digest.update(entry.seq.to_be_bytes());
    digest.update(entry.entry_id.as_bytes());
    bind_bytes(&mut digest, entry.entry_kind.as_bytes());
    for bytes in [
        &entry.signed_request_bytes,
        &entry.request_digest,
        &entry.signature,
        entry.actor_did.as_bytes(),
        entry.actor_device_id.as_bytes(),
        entry.actor_key_id.as_bytes(),
    ] {
        bind_bytes(&mut digest, bytes);
    }
    digest.update(entry.actor_auth_generation.to_be_bytes());
    bind_optional_i64(&mut digest, entry.generation);
    bind_optional_i64(&mut digest, entry.state_version);
    bind_optional_uuid(&mut digest, entry.transition_id);
    bind_optional_uuid(&mut digest, entry.message_id);
    digest.update(entry.received_at.timestamp_millis().to_be_bytes());
    digest.update(successor.conversation_id.as_bytes());
    digest.update(successor.generation.to_be_bytes());
    digest.update(successor.state_version.to_be_bytes());
    digest.update(successor.epoch.to_be_bytes());
    bind_bytes(&mut digest, successor.lifecycle.as_bytes());
    bind_bytes(&mut digest, successor.state_kind.as_bytes());
    digest.update(successor.producing_transition_id.as_bytes());
    digest.update(successor.leaf_count.to_be_bytes());
    digest.update(successor.created_at.timestamp_millis().to_be_bytes());
    for row in welcomes {
        digest.update(row.welcome_id.as_bytes());
        digest.update(row.conversation_id.as_bytes());
        digest.update(row.transition_id.as_bytes());
        digest.update(row.entry_seq.to_be_bytes());
        digest.update(row.generation.to_be_bytes());
        digest.update(row.state_version.to_be_bytes());
        digest.update(row.epoch.to_be_bytes());
        digest.update(row.created_at.timestamp_millis().to_be_bytes());
        for bytes in [
            &row.group_id,
            &row.group_context_hash,
            &row.confirmation_tag,
            &row.wrapper_bytes,
            &row.wrapper_sha256,
            row.recipient_did.as_bytes(),
            row.recipient_device_id.as_bytes(),
            row.recovery_request_id.as_bytes(),
            &row.key_package_ref,
            row.status.as_bytes(),
        ] {
            bind_bytes(&mut digest, bytes);
        }
        digest.update(row.expires_at.timestamp_millis().to_be_bytes());
        match row.terminal_at {
            Some(value) => {
                digest.update([1]);
                digest.update(value.timestamp_millis().to_be_bytes());
            }
            None => digest.update([0]),
        }
    }
    bind_bytes(&mut digest, response.as_bytes());
    digest.update(response.sha256());
    digest.finalize().into()
}

fn bind_optional_i64(digest: &mut Sha256, value: Option<i64>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
        None => digest.update([0]),
    }
}

fn bind_optional_uuid(digest: &mut Sha256, value: Option<Uuid>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.as_bytes());
        }
        None => digest.update([0]),
    }
}

fn protocol_u64(value: i64) -> Result<u64, SubmitTransitionFacadeError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(SubmitTransitionFacadeError::InvalidCanonicalMaterial)
}
