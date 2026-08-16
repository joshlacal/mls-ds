//! Repository facade for the clean-chat leave/close mutation family.
//!
//! The facade owns the complete transaction: operation arbitration, canonical
//! identity locking, state-machine planning, durable execution, and replay
//! post-state validation.  It deliberately keeps the HTTP layer unaware of
//! planners, SQL rows, and operation-completion capabilities.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{SecondsFormat, TimeZone, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::chat_protocol::{
    dpop::VerifiedChatDeviceRequest,
    repository::{
        core::{hydrate_locked_conversation_state, ConversationStateHydrationError},
        execution_context::{
            apply_prepared_leave_lifecycle_execution, prepare_leave_lifecycle_execution,
            ExecutionContextHydrationError,
        },
        prelude::{
            lock_signed_operation_replay_authority, release_signed_operation_replay,
            CanonicalDeviceIdentity, CanonicalLockScope, LockedSignedOperationReplayAuthority,
            OperationReservationGuard, PreludeError, PreparedSignedOperation,
            PreparedSignedOperationState, ScopeBoundBusinessAuthority,
            SignedOperationReplayPostStateProof,
        },
        transition::TransitionRepositoryError,
    },
    snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle},
    state_machine::{ConversationKind, HydrationAuthority, LeaveRequestStatus, StateMachineError},
    transcript::{
        build_verified_control_entry, CanonicalControlEntryProducts, CanonicalControlServerFields,
        CanonicalValueRef, ControlEntryKind, SignedMutationKind, VerifiedMutationProjection,
        VerifiedSignedMutation,
    },
    validation::CanonicalUuidV4,
};

const OK: i32 = 200;

#[derive(Debug)]
pub(crate) enum LeaveFacadeError {
    MissingMutation,
    UnsupportedMutation,
    InvalidCanonicalMaterial,
    Prelude(PreludeError),
    Conversation(ConversationStateHydrationError),
    StateMachine(StateMachineError),
    ExecutionContext(ExecutionContextHydrationError),
    Executor(crate::chat_protocol::state_machine::executor::ExecutorError),
    Transition(TransitionRepositoryError),
    Database(sqlx::Error),
    Authorization(crate::chat_protocol::repository::auth::AuthRepositoryError),
}

macro_rules! from_err {
    ($($ty:path => $variant:ident),+ $(,)?) => {
        $(
        impl From<$ty> for LeaveFacadeError { fn from(value: $ty) -> Self { Self::$variant(value) } }
        )+
    };
}
from_err!(
    PreludeError => Prelude,
    ConversationStateHydrationError => Conversation,
    StateMachineError => StateMachine,
    ExecutionContextHydrationError => ExecutionContext,
    crate::chat_protocol::state_machine::executor::ExecutorError => Executor,
    TransitionRepositoryError => Transition,
    sqlx::Error => Database,
    crate::chat_protocol::repository::auth::AuthRepositoryError => Authorization,
);

pub(crate) struct LeaveTransactionOutcome {
    pub(crate) response_bytes: Vec<u8>,
    pub(crate) status: i32,
    pub(crate) event_position: Option<i64>,
    pub(crate) completion: Option<LeaveCompletion>,
}

pub(crate) struct LeaveCompletion {
    authority: VerifiedChatDeviceRequest,
    scope_authority: ScopeBoundBusinessAuthority,
    completion: crate::chat_protocol::repository::prelude::OperationCompletionGuard,
}

impl LeaveCompletion {
    pub(crate) fn into_parts(
        self,
    ) -> (
        VerifiedChatDeviceRequest,
        ScopeBoundBusinessAuthority,
        crate::chat_protocol::repository::prelude::OperationCompletionGuard,
    ) {
        (self.authority, self.scope_authority, self.completion)
    }
}

pub(crate) async fn execute_prepared_leave(
    transaction: &mut Transaction<'_, Postgres>,
    prepared: PreparedSignedOperation,
) -> Result<LeaveTransactionOutcome, LeaveFacadeError> {
    match prepared.into_state() {
        PreparedSignedOperationState::First {
            authority,
            reservation,
        } => execute_first(transaction, authority, reservation).await,
        PreparedSignedOperationState::Replay { authority, replay } => {
            // Replay remains byte-opaque until the operation row, actor rows,
            // retained entry, and terminal status are all locked in this tx.
            let locked =
                lock_signed_operation_replay_authority(transaction, authority, replay).await?;
            let proof = lock_leave_replay_post_state(transaction, &locked).await?;
            let expected_status = proof.expected_response_status();
            let expected_sha = *proof.expected_response_sha256();
            let completed = release_signed_operation_replay(
                transaction,
                locked,
                SignedOperationReplayPostStateProof::Leave(proof),
            )
            .await?;
            if completed.status() != expected_status
                || completed.response_sha256() != &expected_sha
                || <[u8; 32]>::from(Sha256::digest(completed.response_bytes())) != expected_sha
            {
                return Err(LeaveFacadeError::InvalidCanonicalMaterial);
            }
            Ok(LeaveTransactionOutcome {
                response_bytes: completed.response_bytes().to_vec(),
                status: completed.status(),
                event_position: completed.event_position(),
                completion: None,
            })
        }
    }
}

async fn execute_first(
    transaction: &mut Transaction<'_, Postgres>,
    authority: VerifiedChatDeviceRequest,
    reservation: OperationReservationGuard,
) -> Result<LeaveTransactionOutcome, LeaveFacadeError> {
    let mutation = authority
        .mutation()
        .ok_or(LeaveFacadeError::MissingMutation)?;
    let parsed = ParsedMutation::parse(mutation)?;
    let initial_scope = discover_scope(transaction, &authority, parsed.conversation_id).await?;
    let prepared = super::prelude::prepare_identity_scope_prelude(
        transaction,
        &authority,
        reservation,
        initial_scope.clone(),
    )
    .await?;
    // The first discovery happens before row locks. Re-discover after all
    // principal/device locks and require exact equality so an inserted or
    // removed zero-leaf participant device cannot escape the authority scope.
    let locked_scope = discover_scope(transaction, &authority, parsed.conversation_id).await?;
    if locked_scope != initial_scope {
        return Err(LeaveFacadeError::Prelude(PreludeError::ScopeDrift));
    }
    let scope_authority = prepared.scope_authority();
    let aggregate = hydrate_locked_conversation_state(
        transaction,
        parsed.conversation_id,
        scope_authority.trusted_instant(),
    )
    .await?;
    if aggregate.head().transaction_id() != scope_authority.transaction_id()
        || aggregate.head().prior_coordinate() != Some(aggregate.state().coordinate())
        || parsed
            .prior
            .is_some_and(|prior| aggregate.state().coordinate() != &prior)
    {
        return Err(LeaveFacadeError::InvalidCanonicalMaterial);
    }
    let registration = HydrationAuthority::from_locked_conversation(&aggregate)?
        .locked_registration_from_scope_authority(scope_authority)?;
    let entry_id = CanonicalUuidV4::parse(&Uuid::new_v4().hyphenated().to_string())
        .map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)?;
    let entry = build_entry(
        &authority,
        mutation,
        &aggregate,
        parsed,
        entry_id,
        scope_authority
            .actor_signing_public_key()
            .ok_or(LeaveFacadeError::InvalidCanonicalMaterial)?,
    )?;
    let products = CanonicalControlEntryProducts::mint(&entry)
        .map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)?;
    let planned = match parsed.kind {
        SignedMutationKind::LeaveRequest => {
            hydration_plan_request(&aggregate, entry, registration)?
        }
        SignedMutationKind::ZeroLeafLeave => HydrationAuthority::from_locked_conversation(
            &aggregate,
        )?
        .plan_zero_leaf_leave_entry(&aggregate, entry, &registration, Vec::new())?,
        SignedMutationKind::LeaveCancellation => {
            HydrationAuthority::from_locked_conversation(&aggregate)?
                .plan_leave_cancellation_entry(&aggregate, entry, registration)?
        }
        SignedMutationKind::ConversationClose => HydrationAuthority::from_locked_conversation(
            &aggregate,
        )?
        .plan_close_entry(&aggregate, entry, &registration, Vec::new())?,
        _ => return Err(LeaveFacadeError::UnsupportedMutation),
    };
    let plan = planned.into_persistence_plan()?;
    let response_bytes = response_for_plan(&plan, products.canonical_response_json(), parsed)?;
    let (scope_authority, completion) = prepared.into_execution_parts();
    let execution =
        prepare_leave_lifecycle_execution(transaction, &plan, products.durable_json().to_vec())
            .await?;
    let applied = apply_prepared_leave_lifecycle_execution(execution).await?;
    let event_position = applied.event_positions.first().copied();
    if event_position.is_none() {
        return Err(LeaveFacadeError::InvalidCanonicalMaterial);
    }
    Ok(LeaveTransactionOutcome {
        response_bytes,
        status: OK,
        event_position,
        completion: Some(LeaveCompletion {
            authority,
            scope_authority,
            completion,
        }),
    })
}

fn hydration_plan_request(
    aggregate: &crate::chat_protocol::repository::core::LockedConversationStateGuard,
    entry: crate::chat_protocol::transcript::VerifiedControlEntry,
    registration: crate::chat_protocol::state_machine::LockedRegistrationProjection,
) -> Result<crate::chat_protocol::state_machine::PlannedTransition, LeaveFacadeError> {
    HydrationAuthority::from_locked_conversation(aggregate)?
        .plan_leave_request_entry(aggregate, entry, registration)
        .map_err(Into::into)
}

#[derive(Clone, Copy)]
struct ParsedMutation {
    kind: SignedMutationKind,
    conversation_id: Uuid,
    prior: Option<PublicGroupSnapshotCoordinate>,
    leave_request_id: Option<Uuid>,
}

impl ParsedMutation {
    fn parse(mutation: &VerifiedSignedMutation) -> Result<Self, LeaveFacadeError> {
        let body = match mutation.projection() {
            VerifiedMutationProjection::LeaveRequest(v) => v.body(),
            VerifiedMutationProjection::ZeroLeafLeave(v) => v.body(),
            VerifiedMutationProjection::LeaveCancellation(v) => v.body(),
            VerifiedMutationProjection::ConversationClose(v) => v.body(),
            _ => return Err(LeaveFacadeError::UnsupportedMutation),
        };
        let conversation_id = if mutation.kind() == SignedMutationKind::LeaveCancellation {
            uuid_field(&body, "conversationId")?
        } else {
            uuid_field(&object_field(&body, "prior")?, "conversationId")?
        };
        let prior = (mutation.kind() != SignedMutationKind::LeaveCancellation)
            .then(|| coordinate_field(&body, "prior"))
            .transpose()?;
        let leave_request_id = (mutation.kind() == SignedMutationKind::LeaveCancellation)
            .then(|| uuid_field(&body, "leaveRequestId"))
            .transpose()?;
        Ok(Self {
            kind: mutation.kind(),
            conversation_id,
            prior,
            leave_request_id,
        })
    }
}

async fn discover_scope(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    conversation_id: Uuid,
) -> Result<CanonicalLockScope, LeaveFacadeError> {
    let actor_did = authority.subject().as_str();
    let actor_device = Uuid::from_bytes(*authority.device_id().as_bytes());
    let principals: Vec<String> = sqlx::query_scalar(
        "SELECT user_did FROM chat.participants WHERE conversation_id=$1 AND current_membership ORDER BY convert_to(user_did,'UTF8')",
    ).bind(conversation_id).fetch_all(&mut **transaction).await?;
    let devices: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT device.user_did, device.device_id FROM chat.devices device JOIN chat.participants p ON p.user_did=device.user_did WHERE p.conversation_id=$1 AND p.current_membership UNION SELECT $2::text,$3::uuid ORDER BY 1,2",
    ).bind(conversation_id).bind(actor_did).bind(actor_device).fetch_all(&mut **transaction).await?;
    CanonicalLockScope::new(
        principals,
        devices
            .into_iter()
            .map(|(did, device_id)| CanonicalDeviceIdentity::new(did, device_id))
            .collect(),
    )
    .map_err(Into::into)
}

fn uuid_field(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<Uuid, LeaveFacadeError> {
    match object.get(name) {
        Some(CanonicalValueRef::Uuid(value)) => {
            Uuid::parse_str(value.as_str()).map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)
        }
        _ => Err(LeaveFacadeError::InvalidCanonicalMaterial),
    }
}

fn object_field<'a>(
    object: &'a crate::chat_protocol::transcript::ClosedObjectRef<'a>,
    name: &str,
) -> Result<crate::chat_protocol::transcript::ClosedObjectRef<'a>, LeaveFacadeError> {
    match object.get(name) {
        Some(CanonicalValueRef::Object(value)) => Ok(value),
        _ => Err(LeaveFacadeError::InvalidCanonicalMaterial),
    }
}

fn coordinate_field(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<PublicGroupSnapshotCoordinate, LeaveFacadeError> {
    let value = object_field(object, name)?;
    let bytes = |field| -> Result<[u8; 32], LeaveFacadeError> {
        match value.get(field) {
            Some(CanonicalValueRef::Bytes(v)) => v
                .try_into()
                .map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial),
            _ => Err(LeaveFacadeError::InvalidCanonicalMaterial),
        }
    };
    let integer = |field| -> Result<u64, LeaveFacadeError> {
        match value.get(field) {
            Some(CanonicalValueRef::Integer(v)) => Ok(v),
            _ => Err(LeaveFacadeError::InvalidCanonicalMaterial),
        }
    };
    let lifecycle = match value.get("lifecycle") {
        Some(CanonicalValueRef::Text("active")) => PublicGroupSnapshotLifecycle::Active,
        Some(CanonicalValueRef::Text("superseded")) => PublicGroupSnapshotLifecycle::Superseded,
        _ => return Err(LeaveFacadeError::InvalidCanonicalMaterial),
    };
    Ok(PublicGroupSnapshotCoordinate::new(
        uuid_field(&value, "conversationId")?.into_bytes(),
        integer("generation")?,
        integer("stateVersion")?,
        bytes("groupId")?,
        integer("epoch")?,
        bytes("groupContextHash")?,
        bytes("confirmationTag")?,
        lifecycle,
    ))
}

fn build_entry(
    authority: &VerifiedChatDeviceRequest,
    mutation: &VerifiedSignedMutation,
    aggregate: &crate::chat_protocol::repository::core::LockedConversationStateGuard,
    parsed: ParsedMutation,
    entry_id: CanonicalUuidV4,
    signing_key: &[u8],
) -> Result<crate::chat_protocol::transcript::VerifiedControlEntry, LeaveFacadeError> {
    let server_fields = if parsed.kind == SignedMutationKind::ConversationClose {
        let tombstone = json!({"$type":"blue.catbird.chat.defs#conversationCloseTombstone","closedAt":authority.trusted_instant().as_canonical().as_str(),"closedByDeviceId":authority.device_id().as_str(),"closedByDid":authority.subject().as_str(),"conversationId":parsed.conversation_id.hyphenated().to_string(),"conversationKind":match aggregate.state().kind(){ConversationKind::Direct=>"direct",ConversationKind::Group=>"group"},"retired":coordinate_json(aggregate.state().coordinate())?,"terminalSeq":aggregate.head().next_entry_seq()});
        CanonicalControlServerFields::decode(
            ControlEntryKind::ConversationClose,
            serde_json::to_vec(&json!({"tombstone":tombstone}))
                .map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)?
                .as_slice(),
        )
        .map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)?
    } else {
        CanonicalControlServerFields::empty(match parsed.kind {
            SignedMutationKind::LeaveRequest => ControlEntryKind::LeaveRequest,
            SignedMutationKind::ZeroLeafLeave => ControlEntryKind::ZeroLeafLeave,
            SignedMutationKind::LeaveCancellation => ControlEntryKind::LeaveCancellation,
            _ => return Err(LeaveFacadeError::UnsupportedMutation),
        })
        .map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)?
    };
    let verified = crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
        mutation
            .accepted_wrapper_bytes()
            .ok_or(LeaveFacadeError::InvalidCanonicalMaterial)?,
        signing_key,
    )
    .map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)?;
    build_verified_control_entry(
        verified,
        authority.endpoint(),
        entry_id,
        CanonicalUuidV4::parse(&parsed.conversation_id.hyphenated().to_string())
            .map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)?,
        aggregate.head().next_entry_seq(),
        authority.trusted_instant(),
        server_fields,
    )
    .map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)
}

fn coordinate_json(coordinate: &PublicGroupSnapshotCoordinate) -> Result<Value, LeaveFacadeError> {
    Ok(
        json!({"conversationId":Uuid::from_bytes(*coordinate.conversation_id()).hyphenated().to_string(),"generation":coordinate.generation(),"stateVersion":coordinate.state_version(),"groupId":STANDARD.encode(coordinate.group_id()),"epoch":coordinate.epoch(),"groupContextHash":STANDARD.encode(coordinate.group_context_hash()),"confirmationTag":STANDARD.encode(coordinate.confirmation_tag()),"lifecycle":match coordinate.lifecycle(){PublicGroupSnapshotLifecycle::Active=>"active",PublicGroupSnapshotLifecycle::Superseded=>"superseded"}}),
    )
}

fn response_for_plan(
    plan: &crate::chat_protocol::state_machine::ConversationPersistencePlan,
    entry_json: &[u8],
    parsed: ParsedMutation,
) -> Result<Vec<u8>, LeaveFacadeError> {
    let entry: Value = serde_json::from_slice(entry_json)
        .map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)?;
    let body = match parsed.kind {
        SignedMutationKind::LeaveRequest => {
            let request = plan.effects().leave_request_changes().iter().find_map(|change| matches!((change.before(),change.after()),(None,Some(after)) if after.status()==LeaveRequestStatus::Pending).then(||change.after()).flatten()).ok_or(LeaveFacadeError::InvalidCanonicalMaterial)?;
            json!({"result":{"$type":"blue.catbird.chat.defs#durableLeaveRequestResult","leaveRequest":leave_view_json(parsed.conversation_id,request)?,"entry":entry}})
        }
        SignedMutationKind::LeaveCancellation => {
            let request = plan.effects().leave_request_changes().iter().find_map(|change| matches!((change.before(),change.after()),(Some(before),Some(after)) if before.status()==LeaveRequestStatus::Pending && after.status()==LeaveRequestStatus::Cancelled).then(||change.after()).flatten()).ok_or(LeaveFacadeError::InvalidCanonicalMaterial)?;
            json!({"leaveRequest":leave_view_json(parsed.conversation_id,request)?,"entry":entry})
        }
        SignedMutationKind::ZeroLeafLeave => {
            json!({"result":{"$type":"blue.catbird.chat.defs#zeroLeafLeaveResult","coordinates":coordinate_json(plan.successor_coordinate().ok_or(LeaveFacadeError::InvalidCanonicalMaterial)?)?,"entry":entry}})
        }
        SignedMutationKind::ConversationClose => {
            json!({"result":{"tombstone":entry.get("tombstone").ok_or(LeaveFacadeError::InvalidCanonicalMaterial)?,"entry":entry}})
        }
        _ => return Err(LeaveFacadeError::UnsupportedMutation),
    };
    let bytes =
        serde_json::to_vec(&body).map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)?;
    let valid = match parsed.kind {
        SignedMutationKind::LeaveRequest | SignedMutationKind::ZeroLeafLeave => serde_json::from_slice::<catbird_atproto::generated::blue_catbird::chat::request_leave::RequestLeaveOutput>(&bytes).and_then(|v|serde_json::to_vec(&v)),
        SignedMutationKind::LeaveCancellation => serde_json::from_slice::<catbird_atproto::generated::blue_catbird::chat::cancel_leave::CancelLeaveOutput>(&bytes).and_then(|v|serde_json::to_vec(&v)),
        SignedMutationKind::ConversationClose => serde_json::from_slice::<catbird_atproto::generated::blue_catbird::chat::close_conversation::CloseConversationOutput>(&bytes).and_then(|v|serde_json::to_vec(&v)),
        _ => return Err(LeaveFacadeError::UnsupportedMutation),
    }.map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)?;
    if valid != bytes {
        return Err(LeaveFacadeError::InvalidCanonicalMaterial);
    }
    Ok(bytes)
}

fn leave_view_json(
    conversation_id: Uuid,
    request: &crate::chat_protocol::state_machine::LeaveRequest,
) -> Result<Value, LeaveFacadeError> {
    let requester = request.requester();
    let requester_did = std::str::from_utf8(requester.principal().as_bytes())
        .map_err(|_| LeaveFacadeError::InvalidCanonicalMaterial)?;
    let at = |millis| {
        Utc.timestamp_millis_opt(millis)
            .single()
            .ok_or(LeaveFacadeError::InvalidCanonicalMaterial)
    };
    Ok(
        json!({"leaveRequestId":Uuid::from_bytes(*request.request_id()).hyphenated().to_string(),"conversationId":conversation_id.hyphenated().to_string(),"requesterDid":requester_did,"requesterDeviceId":Uuid::from_bytes(*requester.device_id()).hyphenated().to_string(),"prior":coordinate_json(request.bound_coordinate())?,"status":match request.status(){LeaveRequestStatus::Pending=>"pending",LeaveRequestStatus::Fulfilled=>"fulfilled",LeaveRequestStatus::Cancelled=>"cancelled",LeaveRequestStatus::Expired=>"expired",LeaveRequestStatus::Stale=>"stale"},"requestedAt":at(request.received_at().unix_millis())?.to_rfc3339_opts(SecondsFormat::Millis,true),"expiresAt":at(request.expires_at().unix_millis())?.to_rfc3339_opts(SecondsFormat::Millis,true)}),
    )
}

#[cfg(not(test))]
async fn lock_leave_replay_post_state(
    transaction: &mut Transaction<'_, Postgres>,
    locked: &LockedSignedOperationReplayAuthority,
) -> Result<LeaveReplayPostStateProof, LeaveFacadeError> {
    let mutation = locked.authority().mutation();
    let parsed = ParsedMutation::parse(mutation)?;
    let accepted = mutation
        .accepted_wrapper_bytes()
        .ok_or(LeaveFacadeError::InvalidCanonicalMaterial)?;
    let entry: Option<(Uuid,i64)> = sqlx::query_as("SELECT entry_id,seq FROM chat.entries WHERE conversation_id=$1 AND signed_request_bytes=$2 FOR SHARE").bind(parsed.conversation_id).bind(accepted).fetch_optional(&mut **transaction).await?;
    let (entry_id, seq) = entry.ok_or(LeaveFacadeError::InvalidCanonicalMaterial)?;
    let head: Option<(String,i64,i64,i64)> = sqlx::query_as("SELECT lifecycle,current_generation,current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1 FOR SHARE").bind(parsed.conversation_id).fetch_optional(&mut **transaction).await?;
    let (lifecycle, generation, state_version, next_seq) =
        head.ok_or(LeaveFacadeError::InvalidCanonicalMaterial)?;
    let expected_lifecycle = if parsed.kind == SignedMutationKind::ConversationClose {
        "superseded"
    } else {
        "active"
    };
    if lifecycle != expected_lifecycle || seq <= 0 || next_seq <= seq {
        return Err(LeaveFacadeError::InvalidCanonicalMaterial);
    }
    if let Some(request_id) = parsed
        .leave_request_id
        .or_else(|| match mutation.projection() {
            VerifiedMutationProjection::LeaveRequest(value) => {
                Uuid::parse_str(value.leave_request_id().as_str()).ok()
            }
            _ => None,
        })
    {
        let row: Option<(Uuid, Uuid, String)> = sqlx::query_as(
            "SELECT leave_request_id, conversation_id, status FROM chat.leave_requests WHERE leave_request_id=$1 FOR SHARE",
        )
        .bind(request_id)
        .fetch_optional(&mut **transaction)
        .await?;
        let (stored_id, stored_conversation, status) =
            row.ok_or(LeaveFacadeError::InvalidCanonicalMaterial)?;
        if stored_id != request_id
            || stored_conversation != parsed.conversation_id
            || !matches!(
                status.as_str(),
                "pending" | "fulfilled" | "cancelled" | "expired" | "stale"
            )
            || (parsed.kind == SignedMutationKind::LeaveCancellation && status != "cancelled")
        {
            return Err(LeaveFacadeError::InvalidCanonicalMaterial);
        }
    }
    let completed =
        super::auth::load_signed_operation_replay_completion(transaction, locked.authority())
            .await?
            .ok_or(LeaveFacadeError::InvalidCanonicalMaterial)?;
    LeaveReplayPostStateProof::new(locked, &completed, entry_id, seq, generation, state_version)
        .ok_or(LeaveFacadeError::InvalidCanonicalMaterial)
}

#[cfg(not(test))]
pub(in crate::chat_protocol::repository) struct LeaveReplayPostStateProof {
    transaction_id: Box<str>,
    operation_id: Uuid,
    principal_did: Box<str>,
    endpoint_nsid: Box<str>,
    mutation_kind: SignedMutationKind,
    request_digest: [u8; 32],
    accepted_request_sha256: [u8; 32],
    signature: [u8; 64],
    post_state_digest: [u8; 32],
    expected_status: i32,
    expected_response_sha256: [u8; 32],
    seal: [u8; 32],
}

#[cfg(not(test))]
impl LeaveReplayPostStateProof {
    fn new(
        locked: &LockedSignedOperationReplayAuthority,
        completed: &super::auth::CompletedIdempotentResponse,
        entry_id: Uuid,
        seq: i64,
        generation: i64,
        state_version: i64,
    ) -> Option<Self> {
        let authority = locked.authority();
        let operation_id = authority.repository_receipt().operation_id()?;
        let mut digest = Sha256::new();
        digest.update(b"CATBIRD-CHAT-LEAVE-REPLAY-POST-STATE\0");
        digest.update(completed.response_bytes());
        digest.update(entry_id.as_bytes());
        digest.update(seq.to_be_bytes());
        digest.update(generation.to_be_bytes());
        digest.update(state_version.to_be_bytes());
        let post = digest.finalize().into();
        let mut seal = Sha256::new();
        seal.update(b"CATBIRD-CHAT-LEAVE-REPLAY-SEAL\0");
        seal.update(locked.transaction_id().as_bytes());
        seal.update(operation_id.as_bytes());
        seal.update(post);
        seal.update(completed.status().to_be_bytes());
        seal.update(completed.response_sha256());
        Some(Self {
            transaction_id: locked.transaction_id().to_owned().into_boxed_str(),
            operation_id,
            principal_did: authority.subject().as_str().to_owned().into_boxed_str(),
            endpoint_nsid: authority.endpoint().as_str().to_owned().into_boxed_str(),
            mutation_kind: authority.mutation().kind(),
            request_digest: *authority.mutation().request_digest(),
            accepted_request_sha256: <[u8; 32]>::from(Sha256::digest(
                authority.mutation().accepted_wrapper_bytes()?,
            )),
            signature: *authority.mutation().signature(),
            post_state_digest: post,
            expected_status: completed.status(),
            expected_response_sha256: *completed.response_sha256(),
            seal: seal.finalize().into(),
        })
    }
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
    pub(in crate::chat_protocol::repository) fn expected_response_status(&self) -> i32 {
        self.expected_status
    }
    pub(in crate::chat_protocol::repository) fn expected_response_sha256(&self) -> &[u8; 32] {
        &self.expected_response_sha256
    }
    pub(in crate::chat_protocol::repository) fn validates_seal(&self) -> bool {
        self.seal != [0; 32]
    }
}
