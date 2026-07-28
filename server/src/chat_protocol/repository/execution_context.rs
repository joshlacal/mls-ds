// Production ExecutionContext hydration for the clean-chat transition executor.
//
// The executor intentionally accepts an already-frozen audience. This module is
// the only production derivation layer for that input: it combines the sealed
// persistence plan with rows observed while the caller's transaction holds the
// conversation/authentication locks. Handlers provide only exact serialized
// artifacts that are not retained by the plan (the accepted public control row,
// event payloads, and creation/reset GroupInfo bytes); they never provide
// recipients, period identifiers, actor columns, or event-chain predecessors.

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Acquire, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use super::core::LockedG6Prelude;
use super::delivery::{
    EntryEntitlementKind, EventEntitlementKind, EventKind, OutboxWorkKind, WelcomeRejectionReason,
};
use super::recovery::PreparedRecoveryExecutionGraph;
use super::transition::{ResetReason, TransitionActorRole};
use crate::chat_protocol::public_state::encode_public_tree_summary;
#[cfg(test)]
use crate::chat_protocol::state_machine::apply_device_revocation_batch_unscoped_for_test as apply_device_revocation_contexts_unscoped_for_test;
use crate::chat_protocol::state_machine::executor::ExecutionContext;
use crate::chat_protocol::state_machine::{
    apply_prepared_device_revocation_members, apply_prepared_device_revocation_prefix,
    batch_transaction_bindings_match, plan_transaction_bindings_match,
    prepare_device_revocation_batch_members, AppliedTransition, ControlEntryContent,
    ConversationPersistencePlan, DeviceIdentity, DeviceRevocationBatchPersistencePlan,
    EventChainCursorError, EventFanout, ExecutionActor, ExecutionAuthority, ExecutorError,
    LeafPersistenceColumns, LeafRecoveryKind, MetadataAuthorColumns, ParticipantRole,
    PlanAuthority, PlanKind, PreparedConversationExecution, PreparedDeviceRevocationBatchMembers,
    PrincipalId, RecoveryOpenContext, RecoverySource, ResetRequestRow, ServerTimestamp,
    SpineArtifacts, WelcomeDispositionInput, WelcomeExpiryContext, WelcomeRejectionWork,
    WelcomeResponseContext, WelcomeStatus,
};
use crate::chat_protocol::transcript::{
    decode_and_verify_control_entry, decode_and_verify_signed_mutation, CanonicalValueRef,
    SignedMutationKind, VerifiedMutationProjection, VerifiedSignedMutation,
};

const STREAM_OUTBOX_COUNT: usize = 1;

/// Exact serialized products that the state-machine plan deliberately does not
/// retain. These values are re-verified against the plan under the transaction;
/// no identity, audience, period UUID, predecessor, or timestamp is accepted
/// from this input.
#[derive(Clone, Debug, Default)]
pub(crate) struct ExecutionContextArtifacts {
    /// Required exactly for an entry-bearing plan. This is the full closed
    /// `conversationEntry` JSON that `decode_and_verify_control_entry` accepts.
    pub(crate) accepted_control_entry_bytes: Option<Vec<u8>>,
    /// Required exactly for creation/reset activation. Its SHA-256 must equal
    /// the already-verified GroupInfo digest retained by the successor state.
    pub(crate) genesis_group_info_bytes: Option<Vec<u8>>,
    /// Payload for the plan's primary event. Absent exactly when the plan has no
    /// primary event (device revocation with only per-Welcome dispositions).
    pub(crate) primary_event_payload: Option<Vec<u8>>,
    /// One exact payload for every Pending -> Superseded Welcome delta, keyed by
    /// immutable Welcome ID. The facade derives the recipient and event kind.
    pub(crate) welcome_disposition_event_payloads: Vec<(Uuid, Vec<u8>)>,
}

/// Caller-supplied serialized artifacts keyed by the exact conversation whose
/// sealed revocation plan consumes them. Keeping this as a sequence preserves
/// duplicate detection; orchestration converts it to a map only after validating
/// the complete set.
#[derive(Clone, Debug)]
pub(crate) struct ConversationExecutionArtifacts {
    conversation_id: Uuid,
    artifacts: ExecutionContextArtifacts,
}

impl ConversationExecutionArtifacts {
    pub(crate) fn new(conversation_id: Uuid, artifacts: ExecutionContextArtifacts) -> Self {
        Self {
            conversation_id,
            artifacts,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum SequentialDeviceRevocationError {
    #[error("device revocation artifacts are missing for conversation {0}")]
    MissingConversationArtifacts(Uuid),
    #[error("device revocation artifacts repeat conversation {0}")]
    DuplicateConversationArtifacts(Uuid),
    #[error("device revocation artifacts include extra conversation {0}")]
    ExtraConversationArtifacts(Uuid),
    #[error("device revocation execution-context hydration failed")]
    Hydration(ExecutionContextHydrationError),
    #[error("device revocation G6 prelude does not match the sealed batch")]
    PreludeMismatch,
    #[error("device revocation event schedule does not match the locked G6 audience")]
    EventChain(#[from] EventChainCursorError),
    #[error("device revocation persistence execution failed")]
    Executor(ExecutorError),
    #[error("device revocation savepoint begin failed")]
    SavepointBegin(sqlx::Error),
    #[error("device revocation live transaction identity read failed")]
    TransactionIdentity(sqlx::Error),
    #[error("device revocation savepoint release failed")]
    SavepointRelease(sqlx::Error),
    #[error("device revocation explicit savepoint rollback failed")]
    ExplicitRollback(sqlx::Error),
    #[error("device revocation operation and savepoint rollback both failed")]
    SavepointRollback {
        operation: Box<SequentialDeviceRevocationError>,
        rollback: sqlx::Error,
    },
}

impl SequentialDeviceRevocationError {
    /// Savepoint infrastructure failures require abandonment or rollback of the
    /// caller-owned outer transaction before it can be reused.
    pub(crate) fn requires_outer_abort(&self) -> bool {
        matches!(
            self,
            Self::SavepointBegin(_)
                | Self::TransactionIdentity(_)
                | Self::SavepointRelease(_)
                | Self::ExplicitRollback(_)
                | Self::SavepointRollback { .. }
        ) || matches!(self, Self::Executor(error) if error.requires_outer_abort())
    }
}

impl From<ExecutionContextHydrationError> for SequentialDeviceRevocationError {
    fn from(error: ExecutionContextHydrationError) -> Self {
        Self::Hydration(error)
    }
}

impl From<ExecutorError> for SequentialDeviceRevocationError {
    fn from(error: ExecutorError) -> Self {
        Self::Executor(error)
    }
}

#[derive(Debug, Error)]
pub(crate) enum ExecutionContextHydrationError {
    #[error("clean-chat execution-context database read failed")]
    Database(#[from] sqlx::Error),
    #[error("clean-chat execution plan lacks sealed authority")]
    MissingAuthority,
    #[error("clean-chat execution authority does not match its locked database rows")]
    AuthorityMismatch,
    #[error("clean-chat accepted control entry does not match the sealed plan")]
    ControlEntryMismatch,
    #[error("clean-chat execution artifact set does not match the sealed plan")]
    ArtifactMismatch,
    #[error("clean-chat execution audience could not be derived")]
    AudienceMismatch,
    #[error("clean-chat execution period mapping could not be derived")]
    PeriodMismatch,
    #[error("clean-chat execution value is outside the protocol domain")]
    OutOfDomain,
}

#[derive(Clone)]
struct AuthorityFacts {
    actor: DeviceIdentity,
    expected_key_id: Option<[u8; 32]>,
    expected_auth_generation: Option<u64>,
    signed_kind: Option<SignedMutationKind>,
    operation_id: Uuid,
    applied_at: DateTime<Utc>,
    signed_request_bytes: Vec<u8>,
    unsigned_projection_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    outer_control_projection_bytes: Vec<u8>,
    server_fields_bytes: Vec<u8>,
    outer_entry_fingerprint: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct LockedActorRow {
    user_did: String,
    device_id: Uuid,
    status: String,
    auth_generation: i64,
    key_id: String,
    signing_public_key: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct GenerationSpineRow {
    public_snapshot_bytes: Vec<u8>,
    snapshot_sha256: Vec<u8>,
    tree_summary_bytes: Vec<u8>,
    tree_summary_sha256: Vec<u8>,
    leaf_count: i64,
}

fn server_instant(value: ServerTimestamp) -> Result<DateTime<Utc>, ExecutionContextHydrationError> {
    DateTime::<Utc>::from_timestamp_millis(value.unix_millis())
        .ok_or(ExecutionContextHydrationError::OutOfDomain)
}

fn device_identity(
    did: String,
    device_id: Uuid,
) -> Result<DeviceIdentity, ExecutionContextHydrationError> {
    DeviceIdentity::new(
        PrincipalId::new(did.into_bytes())
            .map_err(|_| ExecutionContextHydrationError::OutOfDomain)?,
        *device_id.as_bytes(),
    )
    .map_err(|_| ExecutionContextHydrationError::OutOfDomain)
}

fn device_did(device: &DeviceIdentity) -> Result<String, ExecutionContextHydrationError> {
    String::from_utf8(device.principal().as_bytes().to_vec())
        .map_err(|_| ExecutionContextHydrationError::OutOfDomain)
}

fn device_uuid(device: &DeviceIdentity) -> Uuid {
    Uuid::from_bytes(*device.device_id())
}

fn authority_facts(
    plan: &ConversationPersistencePlan,
) -> Result<AuthorityFacts, ExecutionContextHydrationError> {
    let authority = plan
        .effects()
        .authority()
        .ok_or(ExecutionContextHydrationError::MissingAuthority)?;
    match authority {
        PlanAuthority::Transition(evidence) => {
            let signed = evidence
                .signed_authority()
                .ok_or(ExecutionContextHydrationError::MissingAuthority)?;
            Ok(AuthorityFacts {
                actor: signed.actor().clone(),
                expected_key_id: Some(*signed.key_id()),
                expected_auth_generation: Some(signed.auth_generation()),
                signed_kind: Some(signed.kind()),
                operation_id: Uuid::from_bytes(*evidence.transition_id()),
                applied_at: server_instant(evidence.received_at())?,
                signed_request_bytes: signed.signed_request_bytes().to_vec(),
                unsigned_projection_bytes: signed.canonical_projection().to_vec(),
                signing_transcript_bytes: signed.transcript_bytes().to_vec(),
                request_digest: signed.request_digest().to_vec(),
                signature: signed.signature().to_vec(),
                outer_control_projection_bytes: evidence.outer_control_projection().to_vec(),
                server_fields_bytes: evidence.server_fields_dag_cbor().to_vec(),
                outer_entry_fingerprint: evidence.outer_entry_fingerprint().to_vec(),
            })
        }
        PlanAuthority::Request(evidence) => {
            let signed = evidence
                .signed_authority()
                .ok_or(ExecutionContextHydrationError::MissingAuthority)?;
            Ok(AuthorityFacts {
                actor: signed.actor().clone(),
                expected_key_id: Some(*signed.key_id()),
                expected_auth_generation: Some(signed.auth_generation()),
                signed_kind: Some(signed.kind()),
                operation_id: Uuid::from_bytes(*evidence.request_id()),
                applied_at: server_instant(evidence.received_at())?,
                signed_request_bytes: signed.signed_request_bytes().to_vec(),
                unsigned_projection_bytes: signed.canonical_projection().to_vec(),
                signing_transcript_bytes: signed.transcript_bytes().to_vec(),
                request_digest: signed.request_digest().to_vec(),
                signature: signed.signature().to_vec(),
                outer_control_projection_bytes: evidence
                    .control_outer_projection()
                    .unwrap_or_default()
                    .to_vec(),
                server_fields_bytes: evidence
                    .control_server_fields_dag_cbor()
                    .unwrap_or_default()
                    .to_vec(),
                outer_entry_fingerprint: evidence
                    .control_outer_entry_fingerprint()
                    .copied()
                    .unwrap_or(*evidence.durable_row_digest())
                    .to_vec(),
            })
        }
        PlanAuthority::DeviceRevocation(evidence) => Ok(AuthorityFacts {
            actor: evidence.actor().clone(),
            expected_key_id: Some(*evidence.actor_key_id()),
            expected_auth_generation: Some(evidence.actor_auth_generation()),
            signed_kind: Some(SignedMutationKind::DeviceRevocation),
            operation_id: Uuid::from_bytes(*evidence.revocation_id()),
            applied_at: server_instant(evidence.accepted_at())?,
            signed_request_bytes: evidence.signed_request_bytes().to_vec(),
            unsigned_projection_bytes: Vec::new(),
            signing_transcript_bytes: evidence.signing_transcript_bytes().to_vec(),
            request_digest: evidence.request_digest().to_vec(),
            signature: evidence.signature().to_vec(),
            outer_control_projection_bytes: Vec::new(),
            server_fields_bytes: Vec::new(),
            outer_entry_fingerprint: evidence.durable_row_digest().to_vec(),
        }),
        PlanAuthority::RecoveryExpiry(evidence) => Ok(AuthorityFacts {
            actor: evidence.requester().clone(),
            expected_key_id: None,
            expected_auth_generation: None,
            signed_kind: None,
            operation_id: Uuid::from_bytes(*evidence.request_id()),
            applied_at: server_instant(evidence.terminal_at())?,
            signed_request_bytes: Vec::new(),
            unsigned_projection_bytes: Vec::new(),
            signing_transcript_bytes: Vec::new(),
            request_digest: Vec::new(),
            signature: Vec::new(),
            outer_control_projection_bytes: Vec::new(),
            server_fields_bytes: Vec::new(),
            outer_entry_fingerprint: evidence.locked_read_set_digest().to_vec(),
        }),
        PlanAuthority::WelcomeExpiry(evidence) => Ok(AuthorityFacts {
            actor: evidence.recipient().clone(),
            expected_key_id: None,
            expected_auth_generation: None,
            signed_kind: None,
            operation_id: Uuid::from_bytes(*evidence.welcome_id()),
            applied_at: server_instant(evidence.terminal_at())?,
            signed_request_bytes: Vec::new(),
            unsigned_projection_bytes: Vec::new(),
            signing_transcript_bytes: Vec::new(),
            request_digest: Vec::new(),
            signature: Vec::new(),
            outer_control_projection_bytes: Vec::new(),
            server_fields_bytes: Vec::new(),
            outer_entry_fingerprint: Vec::new(),
        }),
    }
}

async fn lock_actor(
    transaction: &mut Transaction<'_, Postgres>,
    facts: &AuthorityFacts,
) -> Result<LockedActorRow, ExecutionContextHydrationError> {
    let did = device_did(&facts.actor)?;
    let row = sqlx::query_as::<_, LockedActorRow>(
        r#"
        SELECT d.user_did,d.device_id,d.status,d.auth_generation,
               dk.key_id,dk.signing_public_key
          FROM chat.devices AS d
          JOIN chat.device_keys AS dk
            ON dk.user_did=d.user_did AND dk.device_id=d.device_id
         WHERE d.user_did=$1 AND d.device_id=$2
         FOR SHARE OF d,dk
        "#,
    )
    .bind(&did)
    .bind(device_uuid(&facts.actor))
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ExecutionContextHydrationError::AuthorityMismatch)?;

    if row.user_did != did
        || row.device_id != device_uuid(&facts.actor)
        || facts
            .expected_auth_generation
            .is_some_and(|expected| i64::try_from(expected).ok() != Some(row.auth_generation))
    {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    if let Some(expected) = facts.expected_key_id {
        let decoded: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&row.key_id)
            .ok()
            .and_then(|value| value.try_into().ok())
            .ok_or(ExecutionContextHydrationError::AuthorityMismatch)?;
        if decoded != expected {
            return Err(ExecutionContextHydrationError::AuthorityMismatch);
        }
    }
    Ok(row)
}

fn g6_actor(
    plan: &ConversationPersistencePlan,
    facts: &AuthorityFacts,
    prelude: &LockedG6Prelude,
) -> Result<LockedActorRow, ExecutionContextHydrationError> {
    let actor_did = device_did(&facts.actor)?;
    let actor_device_id = device_uuid(&facts.actor);
    let actor_fact = prelude
        .devices()
        .iter()
        .find(|fact| fact.device() == &facts.actor)
        .ok_or(ExecutionContextHydrationError::AuthorityMismatch)?;
    let expected_key_id = facts
        .expected_key_id
        .ok_or(ExecutionContextHydrationError::MissingAuthority)?;
    let locked_key_id: [u8; 32] = URL_SAFE_NO_PAD
        .decode(prelude.actor_key_id())
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(ExecutionContextHydrationError::AuthorityMismatch)?;
    if plan.effects().kind() != PlanKind::DeviceRevocation
        || prelude.actor_did() != actor_did
        || prelude.actor_device_id() != actor_device_id
        || prelude.actor_auth_generation() <= 0
        || u64::try_from(prelude.actor_auth_generation()).ok() != facts.expected_auth_generation
        || locked_key_id != expected_key_id
        || prelude.actor_signing_public_key().is_empty()
        || actor_fact.status() != "active"
        || actor_fact.dpop_jkt() != prelude.actor_dpop_jkt()
        || actor_fact.auth_generation() != prelude.actor_auth_generation()
    {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    Ok(LockedActorRow {
        user_did: actor_did,
        device_id: actor_device_id,
        status: actor_fact.status().to_owned(),
        auth_generation: prelude.actor_auth_generation(),
        key_id: prelude.actor_key_id().to_owned(),
        signing_public_key: prelude.actor_signing_public_key().to_vec(),
    })
}

fn validate_g6_hydration_shape(
    plan: &ConversationPersistencePlan,
    artifacts: &ExecutionContextArtifacts,
) -> Result<(), ExecutionContextHydrationError> {
    let effects = plan.effects();
    let head = effects
        .head_cas()
        .ok_or(ExecutionContextHydrationError::MissingAuthority)?;
    if effects.kind() != PlanKind::DeviceRevocation
        || !matches!(
            effects.authority(),
            Some(PlanAuthority::DeviceRevocation(_))
        )
        || head.allocated_entry_id().is_some()
        || primary_event_kind(plan).is_some()
        || artifacts.accepted_control_entry_bytes.is_some()
        || artifacts.genesis_group_info_bytes.is_some()
        || artifacts.primary_event_payload.is_some()
        || !artifacts.welcome_disposition_event_payloads.is_empty()
        || !effects.participant_changes().is_empty()
        || !effects.leaf_changes().is_empty()
        || !effects.interval_changes().is_empty()
        || !effects.terminal_proof_changes().is_empty()
        || !effects.reset_request_changes().is_empty()
        || !effects.leave_request_changes().is_empty()
        || !effects.recovery_package_cas().is_empty()
        || effects.metadata_change().is_some()
        || effects.welcome_cas().is_some()
        || effects.revocation_target_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    Ok(())
}

fn g6_spine_artifacts(
    plan: &ConversationPersistencePlan,
) -> Result<SpineArtifacts, ExecutionContextHydrationError> {
    Ok(SpineArtifacts {
        public_snapshot_bytes: Vec::new(),
        public_snapshot_sha256: Vec::new(),
        tree_summary_bytes: Vec::new(),
        tree_summary_sha256: Vec::new(),
        leaf_count: i64::try_from(plan.state().leaves.len())
            .map_err(|_| ExecutionContextHydrationError::OutOfDomain)?,
        genesis_group_info_bytes: Vec::new(),
        genesis_group_info_sha256: Vec::new(),
    })
}

fn planned_actor_role(
    plan: &ConversationPersistencePlan,
    actor: &DeviceIdentity,
) -> Result<TransitionActorRole, ExecutionContextHydrationError> {
    let participant = plan
        .state()
        .participants
        .iter()
        .find(|participant| participant.principal.as_bytes() == actor.principal().as_bytes())
        .ok_or(ExecutionContextHydrationError::AuthorityMismatch)?;
    Ok(match participant.role {
        ParticipantRole::Member => TransitionActorRole::Member,
        ParticipantRole::Admin => TransitionActorRole::Admin,
    })
}

async fn actor_role(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
    actor: &DeviceIdentity,
) -> Result<TransitionActorRole, ExecutionContextHydrationError> {
    let role: Option<String> = sqlx::query_scalar(
        r#"
        SELECT role
          FROM chat.participants
         WHERE conversation_id=$1 AND user_did=$2
           AND current_membership
         FOR SHARE
        "#,
    )
    .bind(Uuid::from_bytes(*plan.state().coordinate.conversation_id()))
    .bind(device_did(actor)?)
    .fetch_optional(&mut **transaction)
    .await?;
    match role.as_deref() {
        Some("member") => Ok(TransitionActorRole::Member),
        Some("admin") => Ok(TransitionActorRole::Admin),
        None if plan.effects().kind() == PlanKind::Creation => {
            let participant = plan
                .state()
                .participants
                .iter()
                .find(|participant| {
                    participant.principal.as_bytes() == actor.principal().as_bytes()
                })
                .ok_or(ExecutionContextHydrationError::AuthorityMismatch)?;
            Ok(match participant.role {
                ParticipantRole::Member => TransitionActorRole::Member,
                ParticipantRole::Admin => TransitionActorRole::Admin,
            })
        }
        _ => Err(ExecutionContextHydrationError::AuthorityMismatch),
    }
}

fn verify_signed_mutation(
    mutation: &VerifiedSignedMutation,
    facts: &AuthorityFacts,
    actor: &LockedActorRow,
    require_retained_wrapper: bool,
) -> Result<(), ExecutionContextHydrationError> {
    if facts.signed_kind != Some(mutation.kind())
        || mutation.actor_did().as_str() != actor.user_did
        || mutation.actor_device_id().as_bytes() != actor.device_id.as_bytes()
        || mutation.key_id().as_str() != actor.key_id
        || i64::try_from(mutation.auth_generation()).ok() != Some(actor.auth_generation)
        || (require_retained_wrapper
            && mutation.accepted_wrapper_bytes() != Some(facts.signed_request_bytes.as_slice()))
        || mutation.canonical_projection() != facts.unsigned_projection_bytes
        || mutation.transcript_bytes() != facts.signing_transcript_bytes
        || mutation.request_digest().as_slice() != facts.request_digest
        || mutation.signature().as_slice() != facts.signature
    {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    Ok(())
}

fn verify_device_revocation_mutation(
    mutation: &VerifiedSignedMutation,
    facts: &AuthorityFacts,
    actor: &LockedActorRow,
) -> Result<(), ExecutionContextHydrationError> {
    if facts.signed_kind != Some(SignedMutationKind::DeviceRevocation)
        || mutation.kind() != SignedMutationKind::DeviceRevocation
        || mutation.actor_did().as_str() != actor.user_did
        || mutation.actor_device_id().as_bytes() != actor.device_id.as_bytes()
        || mutation.key_id().as_str() != actor.key_id
        || i64::try_from(mutation.auth_generation()).ok() != Some(actor.auth_generation)
        || mutation.accepted_wrapper_bytes() != Some(facts.signed_request_bytes.as_slice())
        || mutation.transcript_bytes() != facts.signing_transcript_bytes
        || mutation.request_digest().as_slice() != facts.request_digest
        || mutation.signature().as_slice() != facts.signature
    {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    Ok(())
}

fn build_execution_authority(
    plan: &ConversationPersistencePlan,
    facts: &AuthorityFacts,
    actor: &LockedActorRow,
    artifacts: &ExecutionContextArtifacts,
) -> Result<(ExecutionAuthority, Option<VerifiedSignedMutation>), ExecutionContextHydrationError> {
    let head = plan
        .effects()
        .head_cas()
        .ok_or(ExecutionContextHydrationError::MissingAuthority)?;
    if let Some(entry_id) = head.allocated_entry_id() {
        let bytes = artifacts
            .accepted_control_entry_bytes
            .as_deref()
            .ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
        let entry = decode_and_verify_control_entry(bytes, &actor.signing_public_key)
            .map_err(|_| ExecutionContextHydrationError::ControlEntryMismatch)?;
        // A public control row contains the signed object, not the separately
        // retained exact wrapper bytes, so compare its full canonical signed
        // projection here and verify the retained wrapper independently below.
        verify_signed_mutation(entry.mutation(), facts, actor, false)?;
        if entry.entry_id().as_bytes() != entry_id
            || entry.conversation_id().as_bytes() != plan.state().coordinate.conversation_id()
            || Some(entry.seq()) != head.allocated_seq()
            || entry.outer_control_projection() != facts.outer_control_projection_bytes
            || entry.outer_control_fingerprint() != facts.outer_entry_fingerprint.as_slice()
            || entry
                .server_fields_dag_cbor()
                .map_err(|_| ExecutionContextHydrationError::ControlEntryMismatch)?
                != facts.server_fields_bytes
        {
            return Err(ExecutionContextHydrationError::ControlEntryMismatch);
        }
        let mutation = decode_and_verify_signed_mutation(
            &facts.signed_request_bytes,
            &actor.signing_public_key,
        )
        .map_err(|_| ExecutionContextHydrationError::AuthorityMismatch)?;
        verify_signed_mutation(&mutation, facts, actor, true)?;
        let content = ControlEntryContent {
            entry_id: Uuid::from_bytes(*entry_id),
            entry_kind: entry.kind().type_id().to_owned(),
            accepted_payload_bytes: bytes.to_vec(),
            accepted_payload_sha256: Sha256::digest(bytes).to_vec(),
            signed_request_bytes: facts.signed_request_bytes.clone(),
            unsigned_projection_bytes: facts.unsigned_projection_bytes.clone(),
            signing_transcript_bytes: facts.signing_transcript_bytes.clone(),
            request_digest: facts.request_digest.clone(),
            signature: facts.signature.clone(),
            server_fields_bytes: facts.server_fields_bytes.clone(),
            outer_entry_fingerprint: facts.outer_entry_fingerprint.clone(),
        };
        Ok((ExecutionAuthority::ControlEntry(content), Some(mutation)))
    } else {
        if artifacts.accepted_control_entry_bytes.is_some() {
            return Err(ExecutionContextHydrationError::ArtifactMismatch);
        }
        let mutation = match facts.signed_kind {
            Some(_) => {
                let mutation = decode_and_verify_signed_mutation(
                    &facts.signed_request_bytes,
                    &actor.signing_public_key,
                )
                .map_err(|_| ExecutionContextHydrationError::AuthorityMismatch)?;
                if facts.unsigned_projection_bytes.is_empty()
                    && facts.signed_kind == Some(SignedMutationKind::DeviceRevocation)
                {
                    // The revocation evidence retains the transcript but not the
                    // unsigned projection; recover it from the reverified wrapper
                    // while still binding every retained authority field.
                    verify_device_revocation_mutation(&mutation, facts, actor)?;
                } else {
                    verify_signed_mutation(&mutation, facts, actor, true)?;
                }
                Some(mutation)
            }
            None => None,
        };
        if matches!(
            plan.effects().kind(),
            PlanKind::WelcomeExpiry | PlanKind::RecoveryExpiry | PlanKind::DeviceRevocation
        ) {
            return Ok((
                ExecutionAuthority::Entryless {
                    operation_id: facts.operation_id,
                },
                mutation,
            ));
        }
        let mutation = mutation.ok_or(ExecutionContextHydrationError::MissingAuthority)?;
        let kind = mutation.type_id().to_owned();
        let unsigned_projection = mutation.canonical_projection().to_vec();
        Ok((
            ExecutionAuthority::ControlEntry(ControlEntryContent {
                entry_id: facts.operation_id,
                entry_kind: kind,
                accepted_payload_bytes: facts.signed_request_bytes.clone(),
                accepted_payload_sha256: Sha256::digest(&facts.signed_request_bytes).to_vec(),
                signed_request_bytes: facts.signed_request_bytes.clone(),
                unsigned_projection_bytes: unsigned_projection,
                signing_transcript_bytes: facts.signing_transcript_bytes.clone(),
                request_digest: facts.request_digest.clone(),
                signature: facts.signature.clone(),
                server_fields_bytes: facts.server_fields_bytes.clone(),
                outer_entry_fingerprint: facts.outer_entry_fingerprint.clone(),
            }),
            Some(mutation),
        ))
    }
}

async fn standard_audience(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
    actor: &DeviceIdentity,
) -> Result<Vec<DeviceIdentity>, ExecutionContextHydrationError> {
    let conversation_id = Uuid::from_bytes(*plan.state().coordinate.conversation_id());
    let actor_did = device_did(actor)?;
    let actor_device_id = device_uuid(actor);
    let successor_dids = plan
        .state()
        .participants
        .iter()
        .map(|participant| {
            String::from_utf8(participant.principal.as_bytes().to_vec())
                .map_err(|_| ExecutionContextHydrationError::OutOfDomain)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let rows: Vec<(String, Uuid, bool)> = sqlx::query_as(
        r#"
        WITH entitled_dids AS (
            SELECT unnest($2::text[]) AS user_did
            UNION
            SELECT p.user_did
              FROM chat.participants AS p
             WHERE p.conversation_id=$1
               AND p.current_membership
        )
        SELECT d.user_did,
               d.device_id,
               d.status='active' AND e.user_did IS NOT NULL AS entitled
          FROM chat.devices AS d
          LEFT JOIN entitled_dids AS e ON e.user_did=d.user_did
         WHERE (d.status='active' AND e.user_did IS NOT NULL)
            OR (
               d.user_did=$3
               AND d.device_id=$4
           )
         ORDER BY convert_to(d.user_did,'UTF8'),uuid_send(d.device_id)
         FOR UPDATE OF d
        "#,
    )
    .bind(conversation_id)
    .bind(&successor_dids)
    .bind(&actor_did)
    .bind(actor_device_id)
    .fetch_all(&mut **transaction)
    .await?;
    rows.into_iter()
        .filter(|(_, _, entitled)| *entitled)
        .map(|(did, device, _)| device_identity(did, device))
        .collect()
}

async fn historical_schedule_audience(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    actor: &DeviceIdentity,
) -> Result<Vec<DeviceIdentity>, ExecutionContextHydrationError> {
    let actor_did = device_did(actor)?;
    let actor_device_id = device_uuid(actor);
    let rows: Vec<(String, Uuid, bool)> = sqlx::query_as(
        r#"
        WITH schedules AS (
            SELECT recipient_did,recipient_device_id
              FROM chat.application_intervals
             WHERE conversation_id=$1
            UNION
            SELECT recipient_did,recipient_device_id
             FROM chat.application_schedule_terminal_proofs
             WHERE conversation_id=$1
        )
        SELECT d.user_did,
               d.device_id,
               s.recipient_did IS NOT NULL AS entitled
          FROM chat.devices AS d
          LEFT JOIN schedules AS s
            ON d.user_did=s.recipient_did AND d.device_id=s.recipient_device_id
         WHERE s.recipient_did IS NOT NULL
            OR (
               d.user_did=$2
               AND d.device_id=$3
           )
         ORDER BY convert_to(d.user_did,'UTF8'),uuid_send(d.device_id)
         FOR UPDATE OF d
        "#,
    )
    .bind(conversation_id)
    .bind(&actor_did)
    .bind(actor_device_id)
    .fetch_all(&mut **transaction)
    .await?;
    rows.into_iter()
        .filter(|(_, _, entitled)| *entitled)
        .map(|(did, device, _)| device_identity(did, device))
        .collect()
}

async fn closing_leaf_periods(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
) -> Result<Vec<(DeviceIdentity, Uuid)>, ExecutionContextHydrationError> {
    let conversation_id = Uuid::from_bytes(*plan.state().coordinate.conversation_id());
    let mut devices = BTreeSet::new();
    devices.extend(plan.effects().closed_intervals().iter().cloned());
    for change in plan.effects().leaf_changes() {
        if let (Some(before), None) = (change.before(), change.after()) {
            devices.insert(before.device().clone());
        }
    }
    let mut periods = Vec::with_capacity(devices.len());
    for device in devices {
        let period: Uuid = sqlx::query_scalar(
            r#"
            SELECT leaf_period_id
              FROM chat.member_devices
             WHERE conversation_id=$1 AND user_did=$2 AND device_id=$3 AND active
             FOR SHARE
            "#,
        )
        .bind(conversation_id)
        .bind(device_did(&device)?)
        .bind(device_uuid(&device))
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(ExecutionContextHydrationError::PeriodMismatch)?;
        periods.push((device, period));
    }
    Ok(periods)
}

async fn closing_participant_periods(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
) -> Result<Vec<(PrincipalId, Uuid)>, ExecutionContextHydrationError> {
    let conversation_id = Uuid::from_bytes(*plan.state().coordinate.conversation_id());
    let mut periods = Vec::new();
    for change in plan.effects().participant_changes() {
        let (Some(before), None) = (change.before(), change.after()) else {
            continue;
        };
        let did = String::from_utf8(before.principal().as_bytes().to_vec())
            .map_err(|_| ExecutionContextHydrationError::OutOfDomain)?;
        let period_id: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT participant_period_id
              FROM chat.participants
             WHERE conversation_id=$1 AND user_did=$2 AND current_membership
             FOR SHARE
            "#,
        )
        .bind(conversation_id)
        .bind(&did)
        .fetch_optional(&mut **transaction)
        .await?;
        let period_id = period_id.ok_or(ExecutionContextHydrationError::PeriodMismatch)?;
        periods.push((before.principal().clone(), period_id));
    }
    periods.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(periods)
}

async fn participant_period_ids(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
) -> Result<Vec<Uuid>, ExecutionContextHydrationError> {
    let needs_full_mapping = matches!(
        plan.effects().kind(),
        PlanKind::Creation | PlanKind::ResetActivation
    ) || !plan.effects().opened_intervals().is_empty();
    if !needs_full_mapping {
        if plan.effects().kind() != PlanKind::Policy {
            return Ok(Vec::new());
        }
        return Ok(plan
            .effects()
            .participant_changes()
            .iter()
            .filter(|change| change.before().is_none() && change.after().is_some())
            .map(|_| Uuid::new_v4())
            .collect());
    }
    let conversation_id = Uuid::from_bytes(*plan.state().coordinate.conversation_id());
    let mut ids = Vec::with_capacity(plan.state().participants.len());
    for participant in &plan.state().participants {
        let did = String::from_utf8(participant.principal.as_bytes().to_vec())
            .map_err(|_| ExecutionContextHydrationError::OutOfDomain)?;
        let existing: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT participant_period_id
              FROM chat.participants
             WHERE conversation_id=$1 AND user_did=$2 AND current_membership
             FOR SHARE
            "#,
        )
        .bind(conversation_id)
        .bind(did)
        .fetch_optional(&mut **transaction)
        .await?;
        ids.push(existing.unwrap_or_else(Uuid::new_v4));
    }
    Ok(ids)
}

async fn opened_leaf_columns(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
) -> Result<(Vec<LeafPersistenceColumns>, Vec<Uuid>), ExecutionContextHydrationError> {
    let mut columns = Vec::new();
    for device in plan.effects().opened_intervals() {
        let _after = plan
            .effects()
            .leaf_changes()
            .iter()
            .find_map(|change| change.after().filter(|leaf| leaf.device() == device))
            .ok_or(ExecutionContextHydrationError::PeriodMismatch)?;
        let hydration = plan
            .state()
            .leaves
            .iter()
            .find(|leaf| leaf.device == *device)
            .ok_or(ExecutionContextHydrationError::PeriodMismatch)?;
        let row: Option<(String, i64, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT key_id,enrollment_auth_generation,signing_public_key
              FROM chat.device_keys
             WHERE user_did=$1 AND device_id=$2
             FOR SHARE
            "#,
        )
        .bind(device_did(device)?)
        .bind(device_uuid(device))
        .fetch_optional(&mut **transaction)
        .await?;
        let (key_id, auth_generation, signing_public_key) =
            row.ok_or(ExecutionContextHydrationError::AuthorityMismatch)?;
        if signing_public_key != hydration.signature_key || auth_generation < 1 {
            return Err(ExecutionContextHydrationError::AuthorityMismatch);
        }
        columns.push(LeafPersistenceColumns {
            device: device.clone(),
            leaf_key_id: key_id,
            leaf_auth_generation: auth_generation,
        });
    }
    let ids = (0..columns.len()).map(|_| Uuid::new_v4()).collect();
    Ok((columns, ids))
}

async fn metadata_author(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
    facts: &AuthorityFacts,
    actor: &LockedActorRow,
) -> Result<Option<MetadataAuthorColumns>, ExecutionContextHydrationError> {
    let Some(metadata) = plan
        .effects()
        .metadata_change()
        .and_then(|change| change.after())
    else {
        return Ok(None);
    };
    let author_did = device_did(metadata.author())?;
    let author_device = device_uuid(metadata.author());
    let author_key_id = URL_SAFE_NO_PAD.encode(metadata.author_key_id());
    let current_origin =
        metadata.author_origin_transition_id() == plan.state().producer.transition_id();
    let (role, status, key_id, public_key, auth_generation) = if current_origin {
        (
            match actor_role(transaction, plan, &facts.actor).await? {
                TransitionActorRole::Admin => "admin".to_owned(),
                TransitionActorRole::Member => "member".to_owned(),
            },
            actor.status.clone(),
            actor.key_id.clone(),
            actor.signing_public_key.clone(),
            actor.auth_generation,
        )
    } else {
        sqlx::query_as::<_, (String, String, String, Vec<u8>, i64)>(
            r#"
            SELECT t.actor_role,t.actor_device_status,t.actor_key_id,
                   dk.signing_public_key,t.actor_auth_generation
              FROM chat.transitions AS t
              JOIN chat.device_keys AS dk
                ON dk.user_did=t.actor_did
               AND dk.device_id=t.actor_device_id
               AND dk.key_id=t.actor_key_id
             WHERE t.transition_id=$1
               AND t.entry_seq=$2
               AND t.actor_did=$3
               AND t.actor_device_id=$4
             FOR SHARE OF t,dk
            "#,
        )
        .bind(Uuid::from_bytes(*metadata.author_origin_transition_id()))
        .bind(
            i64::try_from(metadata.author_origin_seq())
                .map_err(|_| ExecutionContextHydrationError::OutOfDomain)?,
        )
        .bind(&author_did)
        .bind(author_device)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(ExecutionContextHydrationError::AuthorityMismatch)?
    };
    if role != "admin"
        || status != "active"
        || key_id != author_key_id
        || public_key != metadata.signature_public_key()
        || u64::try_from(auth_generation).ok() != Some(metadata.author_auth_generation_at_origin())
    {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    Ok(Some(MetadataAuthorColumns {
        author_role: role,
        author_device_status: status,
        author_public_key: public_key,
        author_key_id: key_id,
        metadata_snapshot_id: Uuid::new_v4(),
    }))
}

async fn spine_artifacts(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
    artifacts: &ExecutionContextArtifacts,
) -> Result<SpineArtifacts, ExecutionContextHydrationError> {
    let Some(public_state) = plan.state().public_state.as_ref() else {
        if artifacts.genesis_group_info_bytes.is_some() {
            return Err(ExecutionContextHydrationError::ArtifactMismatch);
        }
        if plan.effects().kind() == PlanKind::Close {
            let prior = plan
                .expected_prior()
                .ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
            let row: Option<GenerationSpineRow> = sqlx::query_as(
                r#"
                SELECT public_snapshot_bytes,snapshot_sha256,
                       tree_summary_bytes,tree_summary_sha256,leaf_count
                  FROM chat.generation_states
                 WHERE conversation_id=$1 AND generation=$2 AND state_version=$3
                 FOR SHARE
                "#,
            )
            .bind(Uuid::from_bytes(*prior.conversation_id()))
            .bind(
                i64::try_from(prior.generation())
                    .map_err(|_| ExecutionContextHydrationError::OutOfDomain)?,
            )
            .bind(
                i64::try_from(prior.state_version())
                    .map_err(|_| ExecutionContextHydrationError::OutOfDomain)?,
            )
            .fetch_optional(&mut **transaction)
            .await?;
            let row = row.ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
            if Sha256::digest(&row.public_snapshot_bytes).as_slice() != row.snapshot_sha256
                || Sha256::digest(&row.tree_summary_bytes).as_slice() != row.tree_summary_sha256
                || row.leaf_count < 1
            {
                return Err(ExecutionContextHydrationError::ArtifactMismatch);
            }
            return Ok(SpineArtifacts {
                public_snapshot_bytes: row.public_snapshot_bytes,
                public_snapshot_sha256: row.snapshot_sha256,
                tree_summary_bytes: row.tree_summary_bytes,
                tree_summary_sha256: row.tree_summary_sha256,
                leaf_count: row.leaf_count,
                genesis_group_info_bytes: Vec::new(),
                genesis_group_info_sha256: Vec::new(),
            });
        }
        return Ok(SpineArtifacts {
            public_snapshot_bytes: Vec::new(),
            public_snapshot_sha256: Vec::new(),
            tree_summary_bytes: Vec::new(),
            tree_summary_sha256: Vec::new(),
            leaf_count: 0,
            genesis_group_info_bytes: Vec::new(),
            genesis_group_info_sha256: Vec::new(),
        });
    };
    let tree = encode_public_tree_summary(public_state.binding().tree_summary())
        .map_err(|_| ExecutionContextHydrationError::ArtifactMismatch)?;
    let expected_group_info = public_state.verified_group_info_sha256();
    let group_info = artifacts.genesis_group_info_bytes.as_deref();
    match (expected_group_info, group_info) {
        (Some(expected), Some(bytes)) if Sha256::digest(bytes).as_slice() == expected => {}
        (None, None) => {}
        _ => return Err(ExecutionContextHydrationError::ArtifactMismatch),
    }
    if plan.effects().kind() == PlanKind::ResetActivation {
        let prior = plan
            .expected_prior()
            .ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
        let row: Option<GenerationSpineRow> = sqlx::query_as(
            r#"
            SELECT public_snapshot_bytes,snapshot_sha256,
                   tree_summary_bytes,tree_summary_sha256,leaf_count
              FROM chat.generation_states
             WHERE conversation_id=$1 AND generation=$2 AND state_version=$3
               AND group_id=$4 AND epoch=$5
               AND group_context_hash=$6 AND confirmation_tag=$7
               AND lifecycle='active'
             FOR SHARE
            "#,
        )
        .bind(Uuid::from_bytes(*prior.conversation_id()))
        .bind(
            i64::try_from(prior.generation())
                .map_err(|_| ExecutionContextHydrationError::OutOfDomain)?,
        )
        .bind(
            i64::try_from(prior.state_version())
                .map_err(|_| ExecutionContextHydrationError::OutOfDomain)?,
        )
        .bind(prior.group_id().to_vec())
        .bind(
            i64::try_from(prior.epoch())
                .map_err(|_| ExecutionContextHydrationError::OutOfDomain)?,
        )
        .bind(prior.group_context_hash().to_vec())
        .bind(prior.confirmation_tag().to_vec())
        .fetch_optional(&mut **transaction)
        .await?;
        let row = row.ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
        if Sha256::digest(&row.public_snapshot_bytes).as_slice() != row.snapshot_sha256
            || Sha256::digest(&row.tree_summary_bytes).as_slice() != row.tree_summary_sha256
            || row.leaf_count < 1
        {
            return Err(ExecutionContextHydrationError::ArtifactMismatch);
        }
        return Ok(SpineArtifacts {
            public_snapshot_bytes: row.public_snapshot_bytes,
            public_snapshot_sha256: row.snapshot_sha256,
            tree_summary_bytes: row.tree_summary_bytes,
            tree_summary_sha256: row.tree_summary_sha256,
            leaf_count: row.leaf_count,
            genesis_group_info_bytes: group_info
                .expect("Reset GroupInfo presence was verified above")
                .to_vec(),
            genesis_group_info_sha256: expected_group_info
                .expect("Reset successor retains its verified GroupInfo digest")
                .to_vec(),
        });
    }
    Ok(SpineArtifacts {
        public_snapshot_bytes: public_state.snapshot().to_vec(),
        public_snapshot_sha256: public_state.snapshot_sha256().to_vec(),
        tree_summary_bytes: tree.bytes().to_vec(),
        tree_summary_sha256: tree.sha256().to_vec(),
        leaf_count: i64::try_from(public_state.binding().tree_summary().leaves().len())
            .map_err(|_| ExecutionContextHydrationError::OutOfDomain)?,
        genesis_group_info_bytes: group_info.unwrap_or_default().to_vec(),
        genesis_group_info_sha256: group_info
            .map(|bytes| Sha256::digest(bytes).to_vec())
            .unwrap_or_default(),
    })
}

fn primary_event_kind(plan: &ConversationPersistencePlan) -> Option<EventKind> {
    match plan.effects().kind() {
        PlanKind::DeviceRevocation
        | PlanKind::WelcomeAcknowledgement
        | PlanKind::WelcomeRejection
        | PlanKind::WelcomeExpiry => None,
        PlanKind::RecoveryRequest | PlanKind::RecoveryCancellation | PlanKind::RecoveryExpiry => {
            Some(EventKind::LeafRecovery)
        }
        PlanKind::Close => Some(EventKind::ConversationClosed),
        PlanKind::ResetRequest => Some(EventKind::ResetRequested),
        PlanKind::LeaveRequest | PlanKind::LeaveCancellation => Some(EventKind::LeaveRequest),
        PlanKind::Commit => match plan.effects().authority() {
            Some(PlanAuthority::Transition(evidence)) => match evidence
                .signed_authority()
                .map(|authority| authority.kind())
            {
                Some(SignedMutationKind::LeafRecoveryFulfillment) => {
                    Some(EventKind::WelcomeAvailable)
                }
                Some(SignedMutationKind::LeaveCommitFulfillment) => Some(EventKind::LeaveRequest),
                _ => Some(EventKind::ConversationChanged),
            },
            _ => Some(EventKind::ConversationChanged),
        },
        _ => Some(EventKind::ConversationChanged),
    }
}

fn canonical_recovery_primary_event_payload(
    plan: &ConversationPersistencePlan,
) -> Result<Vec<u8>, ExecutionContextHydrationError> {
    match plan.effects().kind() {
        PlanKind::RecoveryRequest => {
            let request = plan
                .effects()
                .recovery_request_changes()
                .iter()
                .find_map(|change| match (change.before(), change.after()) {
                    (None, Some(after))
                        if after.status()
                            == crate::chat_protocol::state_machine::RecoveryRequestStatus::Open =>
                    {
                        Some(after)
                    }
                    _ => None,
                })
                .ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
            Ok(super::delivery::canonical_leaf_recovery_event_payload(
                Uuid::from_bytes(*request.request_id()),
                Uuid::from_bytes(*request.bound_coordinate().conversation_id()),
                super::delivery::LeafRecoveryEventStatus::Open,
            ))
        }
        PlanKind::RecoveryCancellation => {
            let request = plan
                .effects()
                .recovery_request_changes()
                .iter()
                .find_map(|change| match (change.before(), change.after()) {
                    (Some(before), Some(after))
                        if before.status()
                            == crate::chat_protocol::state_machine::RecoveryRequestStatus::Open
                            && after.status()
                                == crate::chat_protocol::state_machine::RecoveryRequestStatus::Cancelled =>
                    {
                        Some(after)
                    }
                    _ => None,
                })
                .ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
            Ok(super::delivery::canonical_leaf_recovery_event_payload(
                Uuid::from_bytes(*request.request_id()),
                Uuid::from_bytes(*request.bound_coordinate().conversation_id()),
                super::delivery::LeafRecoveryEventStatus::Cancelled,
            ))
        }
        PlanKind::RecoveryExpiry => {
            let request = plan
                .effects()
                .recovery_request_changes()
                .iter()
                .find_map(|change| match (change.before(), change.after()) {
                    (Some(before), Some(after))
                        if before.status()
                            == crate::chat_protocol::state_machine::RecoveryRequestStatus::Open
                            && after.status()
                                == crate::chat_protocol::state_machine::RecoveryRequestStatus::Expired =>
                    {
                        Some(after)
                    }
                    _ => None,
                })
                .ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
            Ok(super::delivery::canonical_leaf_recovery_event_payload(
                Uuid::from_bytes(*request.request_id()),
                Uuid::from_bytes(*request.bound_coordinate().conversation_id()),
                super::delivery::LeafRecoveryEventStatus::Expired,
            ))
        }
        PlanKind::Commit
            if matches!(
                plan.effects().authority(),
                Some(PlanAuthority::Transition(evidence))
                    if evidence
                        .signed_authority()
                        .is_some_and(|authority| {
                            authority.kind() == SignedMutationKind::LeafRecoveryFulfillment
                        })
            ) =>
        {
            let welcome = plan
                .effects()
                .welcome_changes()
                .iter()
                .find_map(|change| match (change.before(), change.after()) {
                    (None, Some(after)) if after.status() == WelcomeStatus::Pending => Some(after),
                    _ => None,
                })
                .ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
            Ok(super::delivery::canonical_welcome_available_event_payload(
                Uuid::from_bytes(*welcome.welcome_id()),
                Uuid::from_bytes(*welcome.coordinate().conversation_id()),
            ))
        }
        _ => Err(ExecutionContextHydrationError::ArtifactMismatch),
    }
}

async fn predecessor(
    transaction: &mut Transaction<'_, Postgres>,
    device: &DeviceIdentity,
) -> Result<Option<i64>, ExecutionContextHydrationError> {
    Ok(sqlx::query_scalar(
        r#"
        SELECT max(event_position)
          FROM chat.event_recipients
         WHERE user_did=$1 AND device_id=$2
        "#,
    )
    .bind(device_did(device)?)
    .bind(device_uuid(device))
    .fetch_one(&mut **transaction)
    .await?)
}

async fn event(
    transaction: &mut Transaction<'_, Postgres>,
    kind: EventKind,
    payload: Vec<u8>,
    recipients: Vec<(DeviceIdentity, EventEntitlementKind)>,
) -> Result<EventFanout, ExecutionContextHydrationError> {
    if payload.is_empty() {
        return Err(ExecutionContextHydrationError::ArtifactMismatch);
    }
    let mut canonical = recipients;
    canonical.sort_by(|left, right| left.0.cmp(&right.0));
    if canonical.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ExecutionContextHydrationError::AudienceMismatch);
    }
    let mut with_predecessors = Vec::with_capacity(canonical.len());
    for (device, entitlement) in canonical {
        // The event chain is device-global, not conversation-local. Lock the
        // exact device row in canonical order before reading its predecessor so
        // concurrent events in different conversations cannot both select the
        // same chain tail.
        sqlx::query("SELECT 1 FROM chat.devices WHERE user_did=$1 AND device_id=$2 FOR UPDATE")
            .bind(device_did(&device)?)
            .bind(device_uuid(&device))
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(ExecutionContextHydrationError::AudienceMismatch)?;
        let prior = predecessor(transaction, &device).await?;
        with_predecessors.push((device, entitlement, prior));
    }
    Ok(EventFanout {
        event_id: Uuid::new_v4(),
        event_kind: kind,
        payload_bytes: payload,
        recipients: with_predecessors,
        outbox: (0..STREAM_OUTBOX_COUNT)
            .map(|_| (Uuid::new_v4(), OutboxWorkKind::Stream))
            .collect(),
    })
}

fn g6_event(
    prelude: &LockedG6Prelude,
    kind: EventKind,
    payload: Vec<u8>,
    recipients: Vec<(DeviceIdentity, EventEntitlementKind)>,
) -> Result<EventFanout, ExecutionContextHydrationError> {
    if payload.is_empty() {
        return Err(ExecutionContextHydrationError::ArtifactMismatch);
    }
    let mut canonical = recipients;
    canonical.sort_by(|left, right| left.0.cmp(&right.0));
    if canonical.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ExecutionContextHydrationError::AudienceMismatch);
    }
    let with_predecessors = canonical
        .into_iter()
        .map(|(device, entitlement)| {
            let predecessor = prelude
                .devices()
                .iter()
                .find(|fact| fact.device() == &device)
                .map(|fact| fact.initial_event_tail())
                .ok_or(ExecutionContextHydrationError::AudienceMismatch)?;
            Ok((device, entitlement, predecessor))
        })
        .collect::<Result<Vec<_>, ExecutionContextHydrationError>>()?;
    Ok(EventFanout {
        event_id: Uuid::new_v4(),
        event_kind: kind,
        payload_bytes: payload,
        recipients: with_predecessors,
        outbox: (0..STREAM_OUTBOX_COUNT)
            .map(|_| (Uuid::new_v4(), OutboxWorkKind::Stream))
            .collect(),
    })
}

fn reset_reason(
    mutation: Option<&VerifiedSignedMutation>,
) -> Result<ResetReason, ExecutionContextHydrationError> {
    let Some(VerifiedMutationProjection::ResetRequest(request)) =
        mutation.map(VerifiedSignedMutation::projection)
    else {
        return Err(ExecutionContextHydrationError::ArtifactMismatch);
    };
    match request.reason() {
        "localStateLost" => Ok(ResetReason::LocalStateLost),
        "poisonedState" => Ok(ResetReason::PoisonedState),
        "epochDivergence" => Ok(ResetReason::EpochDivergence),
        "manualRecovery" => Ok(ResetReason::ManualRecovery),
        _ => Err(ExecutionContextHydrationError::ArtifactMismatch),
    }
}

fn rejection_reason(
    mutation: Option<&VerifiedSignedMutation>,
) -> Result<WelcomeRejectionReason, ExecutionContextHydrationError> {
    let Some(VerifiedMutationProjection::WelcomeRejection(rejection)) =
        mutation.map(VerifiedSignedMutation::projection)
    else {
        return Err(ExecutionContextHydrationError::ArtifactMismatch);
    };
    let body = rejection.body();
    let reason = match body.get("reason") {
        Some(CanonicalValueRef::Text(value)) => value,
        _ => return Err(ExecutionContextHydrationError::ArtifactMismatch),
    };
    match reason {
        "noMatchingKeyPackage" => Ok(WelcomeRejectionReason::NoMatchingKeyPackage),
        "invalidWelcome" => Ok(WelcomeRejectionReason::InvalidWelcome),
        "unsupportedCipherSuite" => Ok(WelcomeRejectionReason::UnsupportedCipherSuite),
        "coordinateMismatch" => Ok(WelcomeRejectionReason::CoordinateMismatch),
        "localStateConflict" => Ok(WelcomeRejectionReason::LocalStateConflict),
        _ => Err(ExecutionContextHydrationError::ArtifactMismatch),
    }
}

async fn recovery_open(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
) -> Result<Option<RecoveryOpenContext>, ExecutionContextHydrationError> {
    let Some(request) = plan
        .effects()
        .recovery_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (None, Some(after))
                if after.status()
                    == crate::chat_protocol::state_machine::RecoveryRequestStatus::Open =>
            {
                Some(after)
            }
            _ => None,
        })
    else {
        return Ok(None);
    };
    let package = plan
        .effects()
        .recovery_package_cas()
        .iter()
        .find(|binding| binding.key_package_ref() == request.key_package_ref())
        .ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
    let participant_period_id = if request.source() == RecoverySource::Acceptance {
        Some(
            sqlx::query_scalar(
                r#"
                SELECT participant_period_id
                  FROM chat.participants
                 WHERE conversation_id=$1 AND user_did=$2 AND current_membership
                 FOR SHARE
                "#,
            )
            .bind(Uuid::from_bytes(
                *request.bound_coordinate().conversation_id(),
            ))
            .bind(device_did(request.target())?)
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(ExecutionContextHydrationError::PeriodMismatch)?,
        )
    } else {
        None
    };
    let replaced_leaf_period_id = if request.kind() == LeafRecoveryKind::Replace {
        Some(
            sqlx::query_scalar(
                r#"
                SELECT leaf_period_id
                  FROM chat.member_devices
                 WHERE conversation_id=$1 AND user_did=$2 AND device_id=$3 AND active
                 FOR SHARE
                "#,
            )
            .bind(Uuid::from_bytes(
                *request.bound_coordinate().conversation_id(),
            ))
            .bind(device_did(request.target())?)
            .bind(device_uuid(request.target()))
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(ExecutionContextHydrationError::PeriodMismatch)?,
        )
    } else {
        None
    };
    Ok(Some(RecoveryOpenContext {
        participant_period_id,
        package_not_after: server_instant(package.package_not_after())?,
        replaced_leaf_period_id,
    }))
}

/// Hydrate the executor's complete context while the caller-owned transaction
/// remains open. The caller must have produced `plan` from guards acquired in
/// this same transaction. Generic plans additionally row-lock every mutable
/// actor/audience/period fact they project. G6 instead consumes the actor,
/// exact device audience, and predecessor tails already sealed by its
/// pre-head-lock `LockedG6Prelude`; it must not reacquire identity locks here.
///
/// A caller applying more than one plan in the same transaction must hydrate
/// each context immediately before applying that plan. Event predecessors are
/// intentionally frozen from the device-global chain tail visible at hydration
/// time; pre-hydrating a batch could assign the same predecessor to two later
/// events for one device. G6 is the deliberate exception: its prelude freezes
/// initial tails before any head lock and its single-use state-machine cursor
/// advances them across the completely preflighted batch.
async fn hydrate_execution_context_inner_with_g6(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
    artifacts: ExecutionContextArtifacts,
    g6_prelude: Option<&LockedG6Prelude>,
) -> Result<ExecutionContext, ExecutionContextHydrationError> {
    if g6_prelude.is_some() {
        // This SQL-free shape gate runs before the first transaction query.
        // It makes every generic identity-reading family unreachable for G6,
        // including opened-leaf key lookup and metadata-author role/key lookup.
        validate_g6_hydration_shape(plan, &artifacts)?;
    }
    let facts = authority_facts(plan)?;
    if g6_prelude.is_some() && plan.effects().kind() != PlanKind::DeviceRevocation {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    let head = plan
        .effects()
        .head_cas()
        .ok_or(ExecutionContextHydrationError::MissingAuthority)?;
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if transaction_id != head.transaction_id() {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    if !matches!(
        plan.effects().kind(),
        PlanKind::WelcomeExpiry | PlanKind::RecoveryExpiry
    ) && server_instant(head.locked_at())? != facts.applied_at
    {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    let conversation_id = Uuid::from_bytes(*plan.state().coordinate.conversation_id());
    // Device rows are the device-global event-chain serialization point. Lock
    // the complete relevant audience once, in canonical order, before locking
    // the actor/key or reading any predecessor. Close deliberately uses only
    // the historical schedule audience; mixing a separate current-audience
    // phase could invert device lock order across two conversations.
    let terminal_welcome = matches!(
        plan.effects().kind(),
        PlanKind::WelcomeAcknowledgement | PlanKind::WelcomeRejection | PlanKind::WelcomeExpiry
    );
    let (normal_audience, historical_audience) = if g6_prelude.is_some() {
        // G6 locked the exact device-global scope before conversation heads.
        // Device revocation is entryless and has no broad primary event, so its
        // only recipients are the pending-Welcome recipients projected below.
        (Vec::new(), Vec::new())
    } else if plan.effects().kind() == PlanKind::Close {
        (
            Vec::new(),
            historical_schedule_audience(transaction, conversation_id, &facts.actor).await?,
        )
    } else if terminal_welcome {
        // A terminal Welcome event has one historical recipient fixed by the
        // locked Welcome itself. Do not relock the conversation's broad current
        // audience: `event()` below takes the exact recipient's device-global
        // serialization lock before reading its predecessor.
        (Vec::new(), Vec::new())
    } else {
        (
            standard_audience(transaction, plan, &facts.actor).await?,
            Vec::new(),
        )
    };
    let actor_row = match g6_prelude {
        Some(prelude) => g6_actor(plan, &facts, prelude)?,
        None => lock_actor(transaction, &facts).await?,
    };
    if actor_row.status != "active"
        && !matches!(
            plan.effects().kind(),
            PlanKind::WelcomeExpiry | PlanKind::RecoveryExpiry | PlanKind::DeviceRevocation
        )
    {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    let role = match g6_prelude {
        Some(_) => planned_actor_role(plan, &facts.actor)?,
        None => actor_role(transaction, plan, &facts.actor).await?,
    };
    let (authority, mutation) = build_execution_authority(plan, &facts, &actor_row, &artifacts)?;

    let protocol_instance_id: Uuid = sqlx::query_scalar(
        "SELECT protocol_instance_id FROM chat.protocol_instances WHERE singleton FOR SHARE",
    )
    .fetch_one(&mut **transaction)
    .await?;

    let closing_leaf_periods = if g6_prelude.is_some() {
        Vec::new()
    } else {
        closing_leaf_periods(transaction, plan).await?
    };
    let closing_devices = closing_leaf_periods
        .iter()
        .map(|(device, _)| device.clone())
        .collect::<BTreeSet<_>>();
    let entry_recipients = if plan
        .effects()
        .head_cas()
        .and_then(|head| head.allocated_entry_id())
        .is_none()
    {
        Vec::new()
    } else if plan.effects().kind() == PlanKind::Close {
        historical_audience
            .iter()
            .cloned()
            .map(|device| (device, EntryEntitlementKind::ScheduleTerminal))
            .collect()
    } else {
        normal_audience
            .iter()
            .cloned()
            .map(|device| {
                let kind = if closing_devices.contains(&device) {
                    EntryEntitlementKind::IntervalClose
                } else {
                    EntryEntitlementKind::Control
                };
                (device, kind)
            })
            .collect()
    };

    if !artifacts.welcome_disposition_event_payloads.is_empty() {
        // Supersession disposition payloads are repository-owned canonical
        // protocol projections. Accepting caller bytes here lets append-time
        // and historical terminal-graph verification disagree.
        return Err(ExecutionContextHydrationError::ArtifactMismatch);
    }
    let superseded = plan
        .effects()
        .welcome_changes()
        .iter()
        .filter_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == WelcomeStatus::Pending
                    && after.status() == WelcomeStatus::Superseded =>
            {
                Some(after)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let disposition_recipients = superseded
        .iter()
        .map(|welcome| welcome.recipient().clone())
        .collect::<BTreeSet<_>>();
    if disposition_recipients.len() != superseded.len() {
        return Err(ExecutionContextHydrationError::AudienceMismatch);
    }
    let mut welcome_dispositions = Vec::with_capacity(superseded.len());
    for welcome in superseded {
        let welcome_id = Uuid::from_bytes(*welcome.welcome_id());
        let payload =
            super::delivery::canonical_welcome_disposition_event_payload(welcome_id, "superseded");
        let recipients = vec![(welcome.recipient().clone(), EventEntitlementKind::Welcome)];
        let event = match g6_prelude {
            Some(prelude) => g6_event(prelude, EventKind::WelcomeDisposition, payload, recipients)?,
            None => {
                event(
                    transaction,
                    EventKind::WelcomeDisposition,
                    payload,
                    recipients,
                )
                .await?
            }
        };
        welcome_dispositions.push(WelcomeDispositionInput { welcome_id, event });
    }

    let primary_kind = primary_event_kind(plan);
    let events = match (primary_kind, artifacts.primary_event_payload.clone()) {
        (Some(kind), Some(payload)) => {
            let recipients = if kind == EventKind::ConversationClosed {
                historical_audience
                    .iter()
                    .cloned()
                    .map(|device| (device, EventEntitlementKind::HistoricalSchedule))
                    .collect()
            } else {
                normal_audience
                    .iter()
                    .filter(|device| !disposition_recipients.contains(*device))
                    .cloned()
                    .map(|device| (device, EventEntitlementKind::Participant))
                    .collect()
            };
            vec![event(transaction, kind, payload, recipients).await?]
        }
        (None, None) => Vec::new(),
        _ => return Err(ExecutionContextHydrationError::ArtifactMismatch),
    };

    let terminal_welcome_changes = plan
        .effects()
        .welcome_changes()
        .iter()
        .filter_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == WelcomeStatus::Pending
                    && matches!(
                        after.status(),
                        WelcomeStatus::Acknowledged
                            | WelcomeStatus::Rejected
                            | WelcomeStatus::Expired
                    ) =>
            {
                Some(after)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let welcome_change = match plan.effects().kind() {
        PlanKind::WelcomeAcknowledgement | PlanKind::WelcomeRejection | PlanKind::WelcomeExpiry
            if terminal_welcome_changes.len() == 1 =>
        {
            terminal_welcome_changes.first().copied()
        }
        PlanKind::WelcomeAcknowledgement | PlanKind::WelcomeRejection | PlanKind::WelcomeExpiry => {
            return Err(ExecutionContextHydrationError::ArtifactMismatch);
        }
        _ if terminal_welcome_changes.is_empty() => None,
        _ => return Err(ExecutionContextHydrationError::ArtifactMismatch),
    };
    let (welcome_expiry, welcome_response) = match plan.effects().kind() {
        PlanKind::WelcomeExpiry => {
            let welcome = welcome_change.ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
            if artifacts.primary_event_payload.is_some() {
                return Err(ExecutionContextHydrationError::ArtifactMismatch);
            }
            let welcome_id = Uuid::from_bytes(*welcome.welcome_id());
            let payload =
                super::delivery::canonical_welcome_disposition_event_payload(welcome_id, "expired");
            (
                Some(WelcomeExpiryContext {
                    recovery_work_id: Uuid::new_v4(),
                    event: event(
                        transaction,
                        EventKind::WelcomeDisposition,
                        payload,
                        vec![(welcome.recipient().clone(), EventEntitlementKind::Welcome)],
                    )
                    .await?,
                }),
                None,
            )
        }
        PlanKind::WelcomeAcknowledgement | PlanKind::WelcomeRejection => {
            let welcome = welcome_change.ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
            if artifacts.primary_event_payload.is_some() {
                return Err(ExecutionContextHydrationError::ArtifactMismatch);
            }
            let welcome_id = Uuid::from_bytes(*welcome.welcome_id());
            let status = if plan.effects().kind() == PlanKind::WelcomeAcknowledgement {
                "acknowledged"
            } else {
                "rejected"
            };
            let payload =
                super::delivery::canonical_welcome_disposition_event_payload(welcome_id, status);
            let rejection = if plan.effects().kind() == PlanKind::WelcomeRejection {
                Some(WelcomeRejectionWork {
                    recovery_work_id: Uuid::new_v4(),
                    reason: rejection_reason(mutation.as_ref())?,
                })
            } else {
                None
            };
            (
                None,
                Some(WelcomeResponseContext {
                    event: event(
                        transaction,
                        EventKind::WelcomeDisposition,
                        payload,
                        vec![(welcome.recipient().clone(), EventEntitlementKind::Welcome)],
                    )
                    .await?,
                    rejection,
                }),
            )
        }
        _ => (None, None),
    };

    let reset_request_row = if plan.effects().kind() == PlanKind::ResetRequest {
        let request = plan
            .effects()
            .reset_request_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (None, Some(after))
                    if after.status()
                        == crate::chat_protocol::state_machine::ResetRequestStatus::Pending =>
                {
                    Some(after)
                }
                _ => None,
            })
            .ok_or(ExecutionContextHydrationError::ArtifactMismatch)?;
        Some(ResetRequestRow {
            reset_request_id: facts.operation_id,
            reason: reset_reason(mutation.as_ref())?,
            signed_request_bytes: facts.signed_request_bytes.clone(),
            signing_transcript_bytes: facts.signing_transcript_bytes.clone(),
            request_digest: facts.request_digest.clone(),
            signature: facts.signature.clone(),
            expires_at: server_instant(*request.expires_at())?,
        })
    } else {
        None
    };

    let (
        opened_leaves,
        leaf_period_ids,
        participant_period_ids,
        closing_participant_periods,
        metadata_author,
        spine,
        recovery_open,
    ) = if g6_prelude.is_some() {
        (
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            g6_spine_artifacts(plan)?,
            None,
        )
    } else {
        let (opened_leaves, leaf_period_ids) = opened_leaf_columns(transaction, plan).await?;
        (
            opened_leaves,
            leaf_period_ids,
            participant_period_ids(transaction, plan).await?,
            closing_participant_periods(transaction, plan).await?,
            metadata_author(transaction, plan, &facts, &actor_row).await?,
            spine_artifacts(transaction, plan, &artifacts).await?,
            recovery_open(transaction, plan).await?,
        )
    };

    Ok(ExecutionContext {
        protocol_instance_id,
        applied_at: facts.applied_at,
        actor: ExecutionActor {
            user_did: actor_row.user_did,
            device_id: actor_row.device_id,
            key_id: actor_row.key_id,
            auth_generation: actor_row.auth_generation,
            role,
            device_status: actor_row.status,
        },
        authority,
        spine,
        opened_leaves,
        metadata_author,
        participant_period_ids,
        leaf_period_ids,
        entry_recipients,
        events,
        closing_leaf_periods,
        closing_participant_periods,
        reset_request_row,
        recovery_open,
        welcome_expiry,
        welcome_response,
        welcome_dispositions,
    })
}

async fn hydrate_execution_context_inner(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
    artifacts: ExecutionContextArtifacts,
) -> Result<ExecutionContext, ExecutionContextHydrationError> {
    hydrate_execution_context_inner_with_g6(transaction, plan, artifacts, None).await
}

async fn hydrate_g6_execution_context_inner(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
    artifacts: ExecutionContextArtifacts,
    prelude: &LockedG6Prelude,
) -> Result<ExecutionContext, ExecutionContextHydrationError> {
    hydrate_execution_context_inner_with_g6(transaction, plan, artifacts, Some(prelude)).await
}

/// Unforgeable proof that execution-context hydration completed inside the
/// transaction exclusively borrowed by `PreparedConversationExecution`.
pub(crate) struct ExecutionContextHydrationProof {
    _minted_here: (),
}

/// Unforgeable witness that the repository layer hydrated the complete G6
/// member set under the capsule-owned savepoint. The state-machine executor
/// requires this token before it will mint opaque prepared members; no caller
/// can assemble a raw plan/context/cursor execution surface.
pub(crate) struct RevocationBatchHydrationProof {
    _minted_here: (),
}

/// Production hydration returns a single-use capsule that exclusively retains
/// the caller's transaction until apply consumes it. No raw context escapes
/// this module in production builds.
pub(crate) async fn hydrate_execution_context<'borrow, 'connection, 'plan>(
    transaction: &'borrow mut Transaction<'connection, Postgres>,
    plan: &'plan ConversationPersistencePlan,
    artifacts: ExecutionContextArtifacts,
) -> Result<
    PreparedConversationExecution<'borrow, 'connection, 'plan>,
    ExecutionContextHydrationError,
> {
    let expected_transaction_id = plan
        .effects()
        .head_cas()
        .ok_or(ExecutionContextHydrationError::MissingAuthority)?
        .transaction_id()
        .to_owned();
    if !plan_transaction_bindings_match(plan, &expected_transaction_id) {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    let context = hydrate_execution_context_inner(transaction, plan, artifacts).await?;
    Ok(PreparedConversationExecution::from_hydrated_parts(
        transaction,
        plan,
        context,
        expected_transaction_id.into_boxed_str(),
        ExecutionContextHydrationProof { _minted_here: () },
    ))
}

/// Welcome-only production capsule constructor. It accepts no caller-supplied
/// artifacts: every response/expiry event and recipient is derived from the
/// sealed plan under the already-held transaction locks.
pub(crate) async fn prepare_welcome_terminal_execution<'borrow, 'connection, 'plan>(
    transaction: &'borrow mut Transaction<'connection, Postgres>,
    plan: &'plan ConversationPersistencePlan,
) -> Result<
    PreparedConversationExecution<'borrow, 'connection, 'plan>,
    ExecutionContextHydrationError,
> {
    if !matches!(
        plan.effects().kind(),
        PlanKind::WelcomeAcknowledgement | PlanKind::WelcomeRejection | PlanKind::WelcomeExpiry
    ) {
        return Err(ExecutionContextHydrationError::ArtifactMismatch);
    }
    hydrate_execution_context(transaction, plan, ExecutionContextArtifacts::default()).await
}

/// Recovery-only production capsule constructor. Route callers cannot supply
/// event or disposition payloads: those are derived from the sealed plan. The
/// optional accepted control row is itself minted by the Recovery composition
/// facade and is required only for fulfillment.
pub(in crate::chat_protocol) async fn prepare_recovery_execution<'borrow, 'connection, 'plan>(
    transaction: &'borrow mut Transaction<'connection, Postgres>,
    graph: &'plan PreparedRecoveryExecutionGraph,
) -> Result<
    PreparedConversationExecution<'borrow, 'connection, 'plan>,
    ExecutionContextHydrationError,
> {
    let plan = graph.plan();
    let valid = matches!(
        plan.effects().kind(),
        PlanKind::RecoveryRequest | PlanKind::RecoveryCancellation | PlanKind::RecoveryExpiry
    ) || matches!(
        plan.effects().authority(),
        Some(PlanAuthority::Transition(evidence))
            if evidence
                .signed_authority()
                .is_some_and(|authority| {
                    authority.kind() == SignedMutationKind::LeafRecoveryFulfillment
                })
    );
    if !valid {
        return Err(ExecutionContextHydrationError::ArtifactMismatch);
    }
    graph
        .persistence_witness()
        .validate_prewrite(transaction, plan)
        .await?;
    let primary_event_payload = canonical_recovery_primary_event_payload(plan)?;
    hydrate_execution_context(
        transaction,
        plan,
        ExecutionContextArtifacts {
            accepted_control_entry_bytes: graph.accepted_control_entry_bytes(),
            genesis_group_info_bytes: None,
            primary_event_payload: Some(primary_event_payload),
            welcome_disposition_event_payloads: Vec::new(),
        },
    )
    .await
    .map(|prepared| prepared.with_recovery_witness(graph.persistence_witness()))
}

pub(in crate::chat_protocol) async fn apply_prepared_recovery_execution(
    prepared: PreparedConversationExecution<'_, '_, '_>,
) -> Result<AppliedTransition, ExecutorError> {
    crate::chat_protocol::state_machine::executor::apply_conversation_persistence_plan(prepared)
        .await
}

pub(crate) async fn apply_prepared_welcome_terminal_execution(
    prepared: PreparedConversationExecution<'_, '_, '_>,
) -> Result<AppliedTransition, ExecutorError> {
    crate::chat_protocol::state_machine::executor::apply_conversation_persistence_plan(prepared)
        .await
}

/// cfg(test) mutation harnesses retain raw contexts so they can corrupt one
/// family at a time. Production builds do not compile this separable seam.
#[cfg(test)]
pub(crate) async fn hydrate_execution_context_unscoped_for_test(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
    artifacts: ExecutionContextArtifacts,
) -> Result<ExecutionContext, ExecutionContextHydrationError> {
    hydrate_execution_context_inner(transaction, plan, artifacts).await
}

/// Test-only constructor for exercising the exact production capsule and
/// savepoint executor with a mutation-harness context. It never rewrites a
/// plan binding: the live transaction must already match every retained
/// transaction-bound effect.
#[cfg(test)]
pub(crate) async fn prepare_execution_context_for_test<'borrow, 'connection, 'plan>(
    transaction: &'borrow mut Transaction<'connection, Postgres>,
    plan: &'plan ConversationPersistencePlan,
    context: ExecutionContext,
) -> Result<
    PreparedConversationExecution<'borrow, 'connection, 'plan>,
    ExecutionContextHydrationError,
> {
    let live_transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if !plan_transaction_bindings_match(plan, &live_transaction_id) {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    Ok(PreparedConversationExecution::from_hydrated_parts(
        transaction,
        plan,
        context,
        live_transaction_id.into_boxed_str(),
        ExecutionContextHydrationProof { _minted_here: () },
    ))
}

/// Legacy test-harness preflight for one conversation's entryless revocation
/// authority.
///
/// This deliberately verifies only the authority needed before the batch's
/// first writer: it locks the durable actor registration/key, re-verifies the
/// exact retained signed DeviceRevocation wrapper, and binds its entryless
/// operation ID to the global batch revocation ID. It never derives audiences or
/// predecessors and never constructs an `ExecutionContext`; full hydration still
/// occurs immediately before each later apply.
#[cfg(test)]
async fn preflight_device_revocation_execution_authority(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ConversationPersistencePlan,
    batch_revocation_id: Uuid,
) -> Result<(), ExecutionContextHydrationError> {
    if plan.effects().kind() != PlanKind::DeviceRevocation {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    let facts = authority_facts(plan)?;
    if facts.operation_id != batch_revocation_id {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    let head = plan
        .effects()
        .head_cas()
        .ok_or(ExecutionContextHydrationError::MissingAuthority)?;
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if transaction_id != head.transaction_id() {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    if server_instant(head.locked_at())? != facts.applied_at {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }

    let actor = lock_actor(transaction, &facts).await?;
    if actor.status != "active" {
        return Err(ExecutionContextHydrationError::AuthorityMismatch);
    }
    let (authority, _) =
        build_execution_authority(plan, &facts, &actor, &ExecutionContextArtifacts::default())?;
    match authority {
        ExecutionAuthority::Entryless { operation_id } if operation_id == batch_revocation_id => {
            Ok(())
        }
        _ => Err(ExecutionContextHydrationError::AuthorityMismatch),
    }
}

pub(crate) fn validate_g6_prelude_binding(
    plan: &DeviceRevocationBatchPersistencePlan,
    prelude: &LockedG6Prelude,
) -> Result<(), SequentialDeviceRevocationError> {
    let authority = plan.authority();
    let actor = authority.actor();
    let target = authority.target();
    let (prelude_target_did, prelude_target_device_id, prelude_target_generation) =
        prelude.target();
    let conversation_ids = plan
        .conversations()
        .iter()
        .map(|conversation| Uuid::from_bytes(*conversation.state().coordinate.conversation_id()))
        .collect::<Vec<_>>();
    let head_digests = plan
        .conversations()
        .iter()
        .map(|conversation| {
            conversation
                .effects()
                .head_cas()
                .map(|head| *head.locked_head_digest())
                .ok_or(SequentialDeviceRevocationError::PreludeMismatch)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if prelude.transaction_id() != plan.target_cas().transaction_id()
        || !batch_transaction_bindings_match(plan, prelude.transaction_id())
        || prelude.fanout_digest() != plan.fanout_manifest_digest()
        || prelude.conversation_ids() != conversation_ids
        || prelude.head_digests() != head_digests
        || prelude.trusted_instant().timestamp_millis() != authority.accepted_at().unix_millis()
        || prelude.actor_did().as_bytes() != actor.principal().as_bytes()
        || prelude.actor_device_id().as_bytes() != actor.device_id()
        || u64::try_from(prelude.actor_auth_generation()).ok()
            != Some(authority.actor_auth_generation())
        || prelude.authority_scope_digest() == &[0; 32]
        || prelude.authority_scope_digest() != plan.authority_scope_digest()
        || prelude.scope_digest() == &[0; 32]
        || prelude_target_did.as_bytes() != target.principal().as_bytes()
        || prelude_target_device_id.as_bytes() != target.device_id()
        || prelude_target_generation != authority.expected_target_auth_generation()
    {
        return Err(SequentialDeviceRevocationError::PreludeMismatch);
    }
    Ok(())
}

async fn prepare_device_revocation_contexts(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &DeviceRevocationBatchPersistencePlan,
    prelude: &LockedG6Prelude,
    artifact_inputs: Vec<ConversationExecutionArtifacts>,
) -> Result<Vec<ExecutionContext>, SequentialDeviceRevocationError> {
    let live_transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await
        .map_err(SequentialDeviceRevocationError::TransactionIdentity)?;
    if !batch_transaction_bindings_match(plan, &live_transaction_id) {
        return Err(SequentialDeviceRevocationError::Hydration(
            ExecutionContextHydrationError::AuthorityMismatch,
        ));
    }
    let mut expected_ids = BTreeSet::new();
    for conversation in plan.conversations() {
        let conversation_id = Uuid::from_bytes(*conversation.state().coordinate.conversation_id());
        if !expected_ids.insert(conversation_id) {
            return Err(SequentialDeviceRevocationError::Executor(
                ExecutorError::InconsistentPlan("device revocation batch repeats a conversation"),
            ));
        }
    }
    let mut artifacts_by_id = BTreeMap::new();
    for input in artifact_inputs {
        if !expected_ids.contains(&input.conversation_id) {
            return Err(SequentialDeviceRevocationError::ExtraConversationArtifacts(
                input.conversation_id,
            ));
        }
        if artifacts_by_id
            .insert(input.conversation_id, input.artifacts)
            .is_some()
        {
            return Err(
                SequentialDeviceRevocationError::DuplicateConversationArtifacts(
                    input.conversation_id,
                ),
            );
        }
    }
    for conversation_id in &expected_ids {
        if !artifacts_by_id.contains_key(conversation_id) {
            return Err(
                SequentialDeviceRevocationError::MissingConversationArtifacts(*conversation_id),
            );
        }
    }
    let mut contexts = Vec::with_capacity(plan.conversations().len());
    for conversation in plan.conversations() {
        let conversation_id = Uuid::from_bytes(*conversation.state().coordinate.conversation_id());
        let artifacts = artifacts_by_id
            .remove(&conversation_id)
            .expect("complete artifact set was preflighted");
        contexts.push(
            hydrate_g6_execution_context_inner(transaction, conversation, artifacts, prelude)
                .await?,
        );
    }
    Ok(contexts)
}

fn g6_capsule_scope_binding(
    transaction_id: &str,
    authority_scope_digest: &[u8; 32],
    prelude_scope_digest: &[u8; 32],
    prepared_members_digest: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-G6-EXECUTION-CAPSULE\0");
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update(authority_scope_digest);
    digest.update(prelude_scope_digest);
    digest.update(prepared_members_digest);
    digest.finalize().into()
}

/// Opaque, savepoint-owning G6 execution. Construction freezes every context
/// and event shape before the prefix can write; application can only consume
/// this exact plan/prelude/context set once. The capsule separately retains
/// both the shared canonical authority-scope digest and the complete G6 scope
/// digest so neither authority nor event-chain scope can be detached.
#[must_use = "a prepared revocation batch must be consumed or explicitly rolled back"]
pub(crate) struct PreparedDeviceRevocationBatchExecution<'transaction, 'plan> {
    savepoint: Transaction<'transaction, Postgres>,
    members: PreparedDeviceRevocationBatchMembers<'plan>,
    expected_transaction_id: Box<str>,
    authority_scope_digest: [u8; 32],
    prelude_scope_digest: [u8; 32],
    prepared_members_digest: [u8; 32],
    scope_binding_digest: [u8; 32],
    #[cfg(test)]
    cancellation_hook: Option<DeviceRevocationCancellationHook>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeviceRevocationCancellationPoint {
    BeforePrefix,
    AfterPrefix,
    BeforeRelease,
    AfterRelease,
}

#[cfg(test)]
type DeviceRevocationCancellationHook = Box<
    dyn FnMut(
            DeviceRevocationCancellationPoint,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send,
>;

impl PreparedDeviceRevocationBatchExecution<'_, '_> {
    /// Explicitly unwind the capsule savepoint before returning the borrowed
    /// outer transaction to its owner.
    pub(crate) async fn rollback(self) -> Result<(), SequentialDeviceRevocationError> {
        self.savepoint
            .rollback()
            .await
            .map_err(SequentialDeviceRevocationError::ExplicitRollback)
    }

    /// Capsule-local deterministic cancellation seam. It is test-only and
    /// travels with this one prepared batch; there is no process-global hook.
    #[cfg(test)]
    pub(crate) fn set_cancellation_hook(&mut self, hook: DeviceRevocationCancellationHook) {
        self.cancellation_hook = Some(hook);
    }
}

/// Mutation-harness constructor for the exact production capsule. It bypasses
/// SQL hydration only so a test can corrupt a later raw context and prove the
/// complete pure preflight rejects it before the prefix. The returned type and
/// application path are identical to production.
#[cfg(test)]
pub(crate) async fn prepare_device_revocation_batch_execution_from_contexts_for_test<
    'transaction,
    'connection,
    'plan,
>(
    transaction: &'transaction mut Transaction<'connection, Postgres>,
    plan: &'plan DeviceRevocationBatchPersistencePlan,
    prelude: LockedG6Prelude,
    contexts: Vec<ExecutionContext>,
) -> Result<
    PreparedDeviceRevocationBatchExecution<'transaction, 'plan>,
    SequentialDeviceRevocationError,
> {
    validate_g6_prelude_binding(plan, &prelude)?;
    let expected_transaction_id = prelude.transaction_id().to_owned().into_boxed_str();
    let authority_scope_digest = *prelude.authority_scope_digest();
    let prelude_scope_digest = *prelude.scope_digest();
    let savepoint = transaction
        .begin()
        .await
        .map_err(SequentialDeviceRevocationError::SavepointBegin)?;
    let devices = prelude
        .devices()
        .iter()
        .map(|fact| fact.device().clone())
        .collect();
    let initial_tails = prelude
        .devices()
        .iter()
        .map(|fact| fact.initial_event_tail())
        .collect();
    let operation = prepare_device_revocation_batch_members(
        plan,
        contexts,
        *prelude.scope_digest(),
        devices,
        initial_tails,
        RevocationBatchHydrationProof { _minted_here: () },
    )
    .map_err(SequentialDeviceRevocationError::Executor);
    match operation {
        Ok(members) => {
            let prepared_members_digest = *members.binding_digest();
            let scope_binding_digest = g6_capsule_scope_binding(
                &expected_transaction_id,
                &authority_scope_digest,
                &prelude_scope_digest,
                &prepared_members_digest,
            );
            Ok(PreparedDeviceRevocationBatchExecution {
                savepoint,
                members,
                expected_transaction_id,
                authority_scope_digest,
                prelude_scope_digest,
                prepared_members_digest,
                scope_binding_digest,
                cancellation_hook: None,
            })
        }
        Err(operation) => match savepoint.rollback().await {
            Ok(()) => Err(operation),
            Err(rollback) => Err(SequentialDeviceRevocationError::SavepointRollback {
                operation: Box::new(operation),
                rollback,
            }),
        },
    }
}

pub(crate) async fn prepare_device_revocation_batch_execution<'transaction, 'connection, 'plan>(
    transaction: &'transaction mut Transaction<'connection, Postgres>,
    plan: &'plan DeviceRevocationBatchPersistencePlan,
    prelude: LockedG6Prelude,
    artifact_inputs: Vec<ConversationExecutionArtifacts>,
) -> Result<
    PreparedDeviceRevocationBatchExecution<'transaction, 'plan>,
    SequentialDeviceRevocationError,
> {
    validate_g6_prelude_binding(plan, &prelude)?;
    let expected_transaction_id = prelude.transaction_id().to_owned().into_boxed_str();
    let authority_scope_digest = *prelude.authority_scope_digest();
    let prelude_scope_digest = *prelude.scope_digest();
    let mut savepoint = transaction
        .begin()
        .await
        .map_err(SequentialDeviceRevocationError::SavepointBegin)?;
    let operation = async {
        let contexts =
            prepare_device_revocation_contexts(&mut savepoint, plan, &prelude, artifact_inputs)
                .await?;
        let devices = prelude
            .devices()
            .iter()
            .map(|fact| fact.device().clone())
            .collect();
        let initial_tails = prelude
            .devices()
            .iter()
            .map(|fact| fact.initial_event_tail())
            .collect();
        prepare_device_revocation_batch_members(
            plan,
            contexts,
            *prelude.scope_digest(),
            devices,
            initial_tails,
            RevocationBatchHydrationProof { _minted_here: () },
        )
        .map_err(SequentialDeviceRevocationError::Executor)
    }
    .await;
    match operation {
        Ok(members) => {
            let prepared_members_digest = *members.binding_digest();
            let scope_binding_digest = g6_capsule_scope_binding(
                &expected_transaction_id,
                &authority_scope_digest,
                &prelude_scope_digest,
                &prepared_members_digest,
            );
            Ok(PreparedDeviceRevocationBatchExecution {
                savepoint,
                members,
                expected_transaction_id,
                authority_scope_digest,
                prelude_scope_digest,
                prepared_members_digest,
                scope_binding_digest,
                #[cfg(test)]
                cancellation_hook: None,
            })
        }
        Err(operation) => match savepoint.rollback().await {
            Ok(()) => Err(operation),
            Err(rollback) => Err(SequentialDeviceRevocationError::SavepointRollback {
                operation: Box::new(operation),
                rollback,
            }),
        },
    }
}

/// Test compatibility for legacy mutation harnesses. Production does not
/// compile this separable plan/context execution seam.
#[cfg(test)]
async fn apply_device_revocation_batch_unscoped_for_test_inner(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &DeviceRevocationBatchPersistencePlan,
    artifact_inputs: Vec<ConversationExecutionArtifacts>,
) -> Result<Vec<AppliedTransition>, SequentialDeviceRevocationError> {
    let live_transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await
        .map_err(ExecutionContextHydrationError::from)?;
    if !batch_transaction_bindings_match(plan, &live_transaction_id) {
        return Err(SequentialDeviceRevocationError::Hydration(
            ExecutionContextHydrationError::AuthorityMismatch,
        ));
    }
    let mut expected_ids = BTreeSet::new();
    for conversation in plan.conversations() {
        let conversation_id = Uuid::from_bytes(*conversation.state().coordinate.conversation_id());
        if !expected_ids.insert(conversation_id) {
            return Err(SequentialDeviceRevocationError::Executor(
                ExecutorError::InconsistentPlan("device revocation batch repeats a conversation"),
            ));
        }
    }

    let mut artifacts_by_id = BTreeMap::new();
    for input in artifact_inputs {
        if !expected_ids.contains(&input.conversation_id) {
            return Err(SequentialDeviceRevocationError::ExtraConversationArtifacts(
                input.conversation_id,
            ));
        }
        if artifacts_by_id
            .insert(input.conversation_id, input.artifacts)
            .is_some()
        {
            return Err(
                SequentialDeviceRevocationError::DuplicateConversationArtifacts(
                    input.conversation_id,
                ),
            );
        }
    }
    for conversation in plan.conversations() {
        let conversation_id = Uuid::from_bytes(*conversation.state().coordinate.conversation_id());
        if !artifacts_by_id.contains_key(&conversation_id) {
            return Err(
                SequentialDeviceRevocationError::MissingConversationArtifacts(conversation_id),
            );
        }
    }

    let batch_revocation_id = Uuid::from_bytes(*plan.authority().revocation_id());
    for conversation in plan.conversations() {
        preflight_device_revocation_execution_authority(
            transaction,
            conversation,
            batch_revocation_id,
        )
        .await?;
    }

    let mut contexts = Vec::with_capacity(plan.conversations().len());
    for conversation in plan.conversations() {
        let conversation_id = Uuid::from_bytes(*conversation.state().coordinate.conversation_id());
        let artifacts = artifacts_by_id
            .remove(&conversation_id)
            .expect("complete artifact set was preflighted");
        let context =
            hydrate_execution_context_unscoped_for_test(transaction, conversation, artifacts)
                .await?;
        contexts.push(context);
    }
    apply_device_revocation_contexts_unscoped_for_test(transaction, plan, &contexts)
        .await
        .map_err(SequentialDeviceRevocationError::Executor)
}

#[cfg(test)]
pub(crate) async fn apply_device_revocation_batch_unscoped_for_test(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &DeviceRevocationBatchPersistencePlan,
    artifact_inputs: Vec<ConversationExecutionArtifacts>,
) -> Result<Vec<AppliedTransition>, SequentialDeviceRevocationError> {
    let mut savepoint = transaction
        .begin()
        .await
        .map_err(SequentialDeviceRevocationError::SavepointBegin)?;
    let operation = apply_device_revocation_batch_unscoped_for_test_inner(
        &mut savepoint,
        plan,
        artifact_inputs,
    )
    .await;
    match operation {
        Ok(applied) => {
            savepoint
                .commit()
                .await
                .map_err(SequentialDeviceRevocationError::SavepointRelease)?;
            Ok(applied)
        }
        Err(operation) => match savepoint.rollback().await {
            Ok(()) => Err(operation),
            Err(rollback) => Err(SequentialDeviceRevocationError::SavepointRollback {
                operation: Box::new(operation),
                rollback,
            }),
        },
    }
}

/// Consume the opaque G6 batch. No SQL hydration or audience read occurs after
/// the prefix; only sealed writes and cursor-resolved event predecessors remain.
///
/// Cancellation contract: once application starts, dropping or aborting this
/// future makes the savepoint outcome commit-unknown. In particular, PostgreSQL
/// may have completed `RELEASE SAVEPOINT` before cancellation becomes visible
/// to Rust. The caller MUST therefore roll back the outer transaction and MUST
/// NOT drain the connection and continue using that transaction. A caller that
/// decides not to apply a still-owned capsule should instead call
/// `PreparedDeviceRevocationBatchExecution::rollback`, which explicitly awaits
/// the savepoint rollback before returning the outer transaction.
pub(crate) async fn apply_device_revocation_batch_sequential(
    prepared: PreparedDeviceRevocationBatchExecution<'_, '_>,
) -> Result<Vec<AppliedTransition>, SequentialDeviceRevocationError> {
    let PreparedDeviceRevocationBatchExecution {
        mut savepoint,
        members,
        expected_transaction_id,
        authority_scope_digest,
        prelude_scope_digest,
        prepared_members_digest,
        scope_binding_digest,
        #[cfg(test)]
        mut cancellation_hook,
    } = prepared;
    let operation = async {
        if !members.binding_is_intact()
            || members.binding_digest() != &prepared_members_digest
            || scope_binding_digest
                != g6_capsule_scope_binding(
                    &expected_transaction_id,
                    &authority_scope_digest,
                    &prelude_scope_digest,
                    &prepared_members_digest,
                )
        {
            return Err(SequentialDeviceRevocationError::PreludeMismatch);
        }
        let live_transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
            .fetch_one(&mut *savepoint)
            .await
            .map_err(SequentialDeviceRevocationError::TransactionIdentity)?;
        if live_transaction_id != expected_transaction_id.as_ref()
            || authority_scope_digest == [0; 32]
            || prelude_scope_digest == [0; 32]
            || prepared_members_digest == [0; 32]
        {
            return Err(SequentialDeviceRevocationError::PreludeMismatch);
        }
        #[cfg(test)]
        if let Some(hook) = cancellation_hook.as_mut() {
            hook(DeviceRevocationCancellationPoint::BeforePrefix).await;
        }
        let prefixed = apply_prepared_device_revocation_prefix(&mut savepoint, members).await?;
        #[cfg(test)]
        if let Some(hook) = cancellation_hook.as_mut() {
            hook(DeviceRevocationCancellationPoint::AfterPrefix).await;
        }
        let applied = apply_prepared_device_revocation_members(&mut savepoint, prefixed).await?;
        #[cfg(test)]
        if let Some(hook) = cancellation_hook.as_mut() {
            hook(DeviceRevocationCancellationPoint::BeforeRelease).await;
        }
        Ok(applied)
    }
    .await;
    match operation {
        Ok(applied) => {
            savepoint
                .commit()
                .await
                .map_err(SequentialDeviceRevocationError::SavepointRelease)?;
            #[cfg(test)]
            if let Some(hook) = cancellation_hook.as_mut() {
                hook(DeviceRevocationCancellationPoint::AfterRelease).await;
            }
            Ok(applied)
        }
        Err(operation) => match savepoint.rollback().await {
            Ok(()) => Err(operation),
            Err(rollback) => Err(SequentialDeviceRevocationError::SavepointRollback {
                operation: Box::new(operation),
                rollback,
            }),
        },
    }
}

/// Feature-gated compiler witness for the production-only G6 chain. Integration
/// harnesses compile source modules with `cfg(test)`, which intentionally omits
/// the production batch planner; this witness is compiled in the real library
/// configuration and keeps every opaque stage reachable as one typed path.
#[cfg(feature = "chat-protocol-production-proof")]
#[allow(dead_code)]
fn g6_scope_bound_production_pipeline_typecheck() {
    let _ = super::core::prepare_g6_identity_scope;
    let _ = super::core::seal_g6_scope_authority;
    let _ = super::core::lock_g6_revocation_prehead_scope;
    let _ = super::core::LockedG6PreheadScope::seal_fanout;
    let _ = super::core::hydrate_locked_g6_prelude;
    let _ = crate::chat_protocol::state_machine::HydrationAuthority::plan_device_revocation_batch;
    let _ = prepare_device_revocation_batch_execution;
    let _ = apply_device_revocation_batch_sequential;
}
