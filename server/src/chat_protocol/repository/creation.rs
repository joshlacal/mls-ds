//! Transaction-bound createConversation repository composition.
//!
//! This module deliberately owns the Creation planner, generated-DTO response,
//! execution capsule, and endpoint-specific replay proof.  Handlers only pass
//! the caller-owned transaction and the already-arbitrated operation.

use base64::Engine as _;
use catbird_atproto::generated::blue_catbird::chat as chat_dto;
use jacquard_common::DefaultStr;
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::chat_protocol::{
    dpop::VerifiedChatDeviceRequest,
    model::AuthPrimitiveError,
    relationship_policy::{PublicTransport, RelationshipAuthority},
    snapshot::PublicGroupSnapshotLifecycle,
    state_machine::{ExecutorError, HydrationAuthority, StateMachineError},
    transcript::{
        build_verified_control_entry, CanonicalControlEntryProducts, CanonicalControlServerFields,
        CanonicalValueRef, ControlEntryKind, SignedMutationKind, VerifiedMutationProjection,
        VerifiedSignedMutation,
    },
    validation::{
        encode_existing_direct_conversation_result, validate_creation_participant_dids,
        CanonicalUuidV4,
    },
};

use super::{
    auth::CompletedIdempotentResponse,
    core::{
        hydrate_locked_creation_head, hydrate_locked_direct_conversation_lookup,
        hydrate_locked_invitation_quota, CreationHeadHydrationError, DirectConversationLookupError,
        InvitationQuotaHydrationError,
    },
    execution_context::{
        apply_prepared_creation_execution, prepare_creation_execution,
        ExecutionContextHydrationError,
    },
    prelude::{
        complete_operation, lock_signed_operation_replay_authority, prepare_identity_scope_prelude,
        release_signed_operation_replay, CanonicalDeviceIdentity, CanonicalLockScope,
        LockedSignedOperationReplayAuthority, OperationReservationGuard, PreludeError,
        PreparedSignedOperation, PreparedSignedOperationState, ScopeBoundBusinessAuthority,
    },
    relationship::{
        load_fallback_relationship_projection, seal_direct_creation_fallback_scope,
        seal_group_creation_fallback_scope, seal_group_creation_no_pending_admission,
        RelationshipRepositoryError,
    },
};

const ENDPOINT: &str = "blue.catbird.chat.createConversation";
const RESPONSE_DOMAIN: &[u8] = b"CATBIRD-CHAT-CREATE-CONVERSATION-RESPONSE\0";
const REPLAY_POST_STATE_DOMAIN: &[u8] = b"CATBIRD-CHAT-CREATE-CONVERSATION-REPLAY-POST-STATE\0";
const REPLAY_SEAL_DOMAIN: &[u8] = b"CATBIRD-CHAT-CREATE-CONVERSATION-REPLAY-SEAL\0";
const STATUS: i32 = 200;

#[derive(Debug)]
pub(crate) enum CreationFacadeError {
    MissingMutation,
    InvalidCanonicalMaterial,
    Prelude(PreludeError),
    Primitive(AuthPrimitiveError),
    StateMachine(StateMachineError),
    CreationHead(CreationHeadHydrationError),
    DirectLookup(DirectConversationLookupError),
    InvitationQuota(InvitationQuotaHydrationError),
    Relationship(RelationshipRepositoryError),
    ExecutionContext(ExecutionContextHydrationError),
    Executor(ExecutorError),
    Database(sqlx::Error),
}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for CreationFacadeError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}
from_error!(PreludeError, Prelude);
from_error!(AuthPrimitiveError, Primitive);
from_error!(StateMachineError, StateMachine);
from_error!(CreationHeadHydrationError, CreationHead);
from_error!(DirectConversationLookupError, DirectLookup);
from_error!(InvitationQuotaHydrationError, InvitationQuota);
from_error!(RelationshipRepositoryError, Relationship);
from_error!(ExecutionContextHydrationError, ExecutionContext);
from_error!(ExecutorError, Executor);
from_error!(sqlx::Error, Database);

#[derive(Debug)]
pub(crate) struct CreationCanonicalResponse {
    bytes: Box<[u8]>,
    sha256: [u8; 32],
    binding_digest: [u8; 32],
}

impl CreationCanonicalResponse {
    fn new(bytes: Vec<u8>) -> Result<Self, CreationFacadeError> {
        let _: chat_dto::create_conversation::CreateConversationOutput<DefaultStr> =
            serde_json::from_slice(&bytes)
                .map_err(|_| CreationFacadeError::InvalidCanonicalMaterial)?;
        let sha256 = Sha256::digest(&bytes).into();
        let mut digest = Sha256::new();
        digest.update(RESPONSE_DOMAIN);
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
        <[u8; 32]>::from(Sha256::digest(&self.bytes)) == self.sha256
            && self.binding_digest == {
                let mut digest = Sha256::new();
                digest.update(RESPONSE_DOMAIN);
                digest.update((self.bytes.len() as u64).to_be_bytes());
                digest.update(&self.bytes);
                digest.update(self.sha256);
                <[u8; 32]>::from(digest.finalize())
            }
    }
}

pub(crate) struct CreationTransactionOutcome {
    status: i32,
    response_bytes: Box<[u8]>,
    event_position: Option<i64>,
}
impl CreationTransactionOutcome {
    pub(crate) fn status(&self) -> i32 {
        self.status
    }
    pub(crate) fn response_bytes(&self) -> &[u8] {
        &self.response_bytes
    }
    pub(crate) fn event_position(&self) -> Option<i64> {
        self.event_position
    }
    fn first(response: CreationCanonicalResponse, event_position: Option<i64>) -> Self {
        Self {
            status: STATUS,
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

pub(in crate::chat_protocol::repository) struct CreationReplayPostStateProof {
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
impl CreationReplayPostStateProof {
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
            && self.expected_status == STATUS
            && self.seal == self.rederive_seal()
    }
    fn rederive_seal(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(REPLAY_SEAL_DOMAIN);
        bind(&mut digest, self.transaction_id.as_bytes());
        digest.update(self.operation_id.as_bytes());
        bind(&mut digest, self.principal_did.as_bytes());
        bind(&mut digest, self.endpoint_nsid.as_bytes());
        bind(&mut digest, self.mutation_kind.type_id().as_bytes());
        digest.update(self.request_digest);
        digest.update(self.accepted_request_sha256);
        digest.update(self.signature);
        digest.update(self.post_state_digest);
        digest.update(self.expected_response_sha256);
        digest.update(self.expected_status.to_be_bytes());
        digest.finalize().into()
    }
}

pub(crate) async fn execute_prepared_creation<T: PublicTransport>(
    transaction: &mut Transaction<'_, Postgres>,
    prepared: PreparedSignedOperation,
    relationship_authority: &RelationshipAuthority<T>,
) -> Result<CreationTransactionOutcome, CreationFacadeError> {
    match prepared.into_state() {
        PreparedSignedOperationState::First {
            authority,
            reservation,
        } => {
            execute_first_creation(transaction, authority, reservation, relationship_authority)
                .await
        }
        PreparedSignedOperationState::Replay { authority, replay } => {
            let locked =
                lock_signed_operation_replay_authority(transaction, authority, replay).await?;
            let (proof, expected) = lock_creation_replay_post_state(transaction, &locked).await?;
            let expected_sha = *proof.expected_response_sha256();
            let expected_status = proof.expected_status();
            let wrapped = super::prelude::SignedOperationReplayPostStateProof::Creation(proof);
            let completed = release_signed_operation_replay(transaction, locked, wrapped).await?;
            if completed.status() != expected_status
                || completed.response_sha256() != &expected_sha
                || <[u8; 32]>::from(Sha256::digest(completed.response_bytes())) != expected_sha
                || completed.response_bytes() != expected.as_bytes()
            {
                return Err(CreationFacadeError::InvalidCanonicalMaterial);
            }
            Ok(CreationTransactionOutcome::replay(completed))
        }
    }
}

async fn execute_first_creation<T: PublicTransport>(
    transaction: &mut Transaction<'_, Postgres>,
    authority: VerifiedChatDeviceRequest,
    reservation: OperationReservationGuard,
    relationship_authority: &RelationshipAuthority<T>,
) -> Result<CreationTransactionOutcome, CreationFacadeError> {
    let mutation = authority
        .mutation()
        .ok_or(CreationFacadeError::MissingMutation)?;
    let (transition_id, conversation_id, kind, principals) = parse_creation(mutation)?;
    let mut devices = vec![CanonicalDeviceIdentity::new(
        authority.subject().as_str(),
        Uuid::from_bytes(*authority.device_id().as_bytes()),
    )];
    let scope = CanonicalLockScope::new(principals.clone(), std::mem::take(&mut devices))?;
    let prelude =
        prepare_identity_scope_prelude(transaction, &authority, reservation, scope).await?;
    let prelude = prelude.verify_creation_operation(transition_id, mutation)?;
    let scope_authority = prelude.scope_authority();
    let direct_lookup = if kind == "direct" {
        let [first, second] = principals.as_slice() else {
            return Err(CreationFacadeError::InvalidCanonicalMaterial);
        };
        let (low, high) = if first < second {
            (first.as_str(), second.as_str())
        } else {
            (second.as_str(), first.as_str())
        };
        Some(
            hydrate_locked_direct_conversation_lookup(
                transaction,
                low,
                high,
                scope_authority.trusted_instant(),
            )
            .await?,
        )
    } else {
        None
    };
    if let Some(lookup) = direct_lookup.as_ref() {
        if let super::core::LockedDirectLookupOutcome::Existing {
            conversation_id: existing_id,
            coordinate,
            ..
        } = lookup.outcome()
        {
            let response = creation_existing_response(*existing_id, coordinate)?;
            let (scope, completion) = prelude.into_execution_parts();
            complete_operation(
                transaction,
                &authority,
                scope,
                completion,
                STATUS,
                response.as_bytes(),
                None,
            )
            .await?;
            return Ok(CreationTransactionOutcome::first(response, None));
        }
    }
    let head = hydrate_locked_creation_head(
        transaction,
        conversation_id,
        scope_authority.trusted_instant(),
    )
    .await?;
    let hydration = HydrationAuthority::from_locked_creation_head(&head)?;
    let registration = hydration.locked_registration_from_scope_authority(scope_authority)?;
    let quota = hydrate_locked_invitation_quota(
        transaction,
        authority.subject().as_str(),
        &principals
            .iter()
            .filter(|did| did.as_str() != authority.subject().as_str())
            .cloned()
            .collect::<Vec<_>>(),
        scope_authority.trusted_instant(),
    )
    .await?;
    let verified = reverify_scope_mutation(scope_authority, mutation)?;
    let entry = build_verified_control_entry(
        verified,
        authority.endpoint(),
        canonical_uuid(transition_id)?,
        canonical_uuid(conversation_id)?,
        1,
        authority.trusted_instant(),
        CanonicalControlServerFields::empty(ControlEntryKind::Creation)?,
    )?;
    let products = CanonicalControlEntryProducts::mint(&entry)?;
    let trusted_now = crate::chat_protocol::validation::TrustedRequestInstant::from_datetime(
        scope_authority.trusted_instant(),
    )?;
    let pending = principals
        .iter()
        .filter(|did| did.as_str() != authority.subject().as_str())
        .cloned()
        .collect::<Vec<_>>();
    let planned = if pending.is_empty() {
        if kind != "group" {
            return Err(CreationFacadeError::InvalidCanonicalMaterial);
        }
        let no_admission = seal_group_creation_no_pending_admission(&head, &quota, &registration)?;
        hydration.plan_creation_without_pending_admission(
            entry,
            &registration,
            &head,
            quota,
            no_admission,
            &trusted_now,
        )?
    } else {
        let fallback = if kind == "direct" {
            seal_direct_creation_fallback_scope(
                &head,
                &quota,
                direct_lookup
                    .as_ref()
                    .ok_or(CreationFacadeError::InvalidCanonicalMaterial)?,
                &registration,
            )?
        } else {
            seal_group_creation_fallback_scope(&head, &quota, &registration)?
        };
        let (relationship, decision) =
            load_fallback_relationship_projection(transaction, fallback, relationship_authority)
                .await?
                .ok_or(CreationFacadeError::InvalidCanonicalMaterial)?;
        hydration.plan_creation(
            entry,
            &registration,
            Some(&head),
            direct_lookup,
            &relationship,
            relationship_authority,
            quota,
            &decision,
            &trusted_now,
        )?
    };
    let plan = match planned {
        crate::chat_protocol::state_machine::CreationDecision::Create(plan) => {
            plan.into_persistence_plan()?
        }
        crate::chat_protocol::state_machine::CreationDecision::ExistingDirect { .. } => {
            return Err(CreationFacadeError::InvalidCanonicalMaterial)
        }
    };
    let response = creation_response(&plan, products.canonical_response_json())?;
    let accepted = products.durable_json().to_vec();
    let genesis = match mutation.projection() {
        VerifiedMutationProjection::Creation(value) => {
            match value.genesis_group_info().get("bytes") {
                Some(CanonicalValueRef::Bytes(bytes)) => bytes.to_vec(),
                _ => return Err(CreationFacadeError::InvalidCanonicalMaterial),
            }
        }
        _ => return Err(CreationFacadeError::InvalidCanonicalMaterial),
    };
    let expected = plan.successor_coordinate().copied();
    let (scope, completion) = prelude.into_execution_parts();
    let prepared = prepare_creation_execution(transaction, &plan, accepted, genesis).await?;
    let applied = apply_prepared_creation_execution(prepared).await?;
    if applied.entry_id != transition_id
        || applied.allocated_seq != 1
        || applied.successor_coordinate.as_ref() != expected.as_ref()
    {
        return Err(CreationFacadeError::InvalidCanonicalMaterial);
    }
    let event_position = applied.event_positions.first().copied();
    complete_operation(
        transaction,
        &authority,
        scope,
        completion,
        STATUS,
        response.as_bytes(),
        event_position,
    )
    .await?;
    Ok(CreationTransactionOutcome::first(response, event_position))
}

fn parse_creation(
    mutation: &VerifiedSignedMutation,
) -> Result<(Uuid, Uuid, String, Vec<String>), CreationFacadeError> {
    let VerifiedMutationProjection::Creation(value) = mutation.projection() else {
        return Err(CreationFacadeError::InvalidCanonicalMaterial);
    };
    let manifest = value.manifest();
    let participant_slots = match manifest.get("participants") {
        Some(CanonicalValueRef::Array(values)) => (0..values.len())
            .map(|i| match values.get(i) {
                Some(CanonicalValueRef::Object(object)) => match object.get("userDid") {
                    Some(CanonicalValueRef::Did(did)) => Some(did.as_str().to_owned()),
                    Some(CanonicalValueRef::Text(did)) => Some(did.to_owned()),
                    _ => None,
                },
                _ => None,
            })
            .collect::<Vec<_>>(),
        _ => return Err(CreationFacadeError::InvalidCanonicalMaterial),
    };
    let principals = validate_creation_participant_dids(&participant_slots)?;
    Ok((
        Uuid::from_bytes(*value.transition_id().as_bytes()),
        Uuid::from_bytes(*value.conversation_id().as_bytes()),
        value.conversation_kind().to_owned(),
        principals,
    ))
}

fn creation_response(
    plan: &crate::chat_protocol::state_machine::ConversationPersistencePlan,
    entry: &[u8],
) -> Result<CreationCanonicalResponse, CreationFacadeError> {
    let coordinate = plan
        .successor_coordinate()
        .ok_or(CreationFacadeError::InvalidCanonicalMaterial)?;
    let value = json!({"result":{"$type":"blue.catbird.chat.defs#conversationCreatedResult","coordinates":coordinate_json(coordinate)?,"entry":serde_json::from_slice::<JsonValue>(entry).map_err(|_| CreationFacadeError::InvalidCanonicalMaterial)?}});
    let value_bytes =
        serde_json::to_vec(&value).map_err(|_| CreationFacadeError::InvalidCanonicalMaterial)?;
    let output: chat_dto::create_conversation::CreateConversationOutput<DefaultStr> =
        serde_json::from_slice(&value_bytes)
            .map_err(|_| CreationFacadeError::InvalidCanonicalMaterial)?;
    CreationCanonicalResponse::new(
        serde_json::to_vec(&output).map_err(|_| CreationFacadeError::InvalidCanonicalMaterial)?,
    )
}

fn creation_existing_response(
    conversation_id: Uuid,
    coordinate: &crate::chat_protocol::snapshot::PublicGroupSnapshotCoordinate,
) -> Result<CreationCanonicalResponse, CreationFacadeError> {
    CreationCanonicalResponse::new(
        encode_existing_direct_conversation_result(conversation_id, coordinate_json(coordinate)?)
            .map_err(|_| CreationFacadeError::InvalidCanonicalMaterial)?,
    )
}

fn coordinate_json(
    coordinate: &crate::chat_protocol::snapshot::PublicGroupSnapshotCoordinate,
) -> Result<JsonValue, CreationFacadeError> {
    if coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active {
        return Err(CreationFacadeError::InvalidCanonicalMaterial);
    }
    Ok(json!({
        "conversationId": Uuid::from_bytes(*coordinate.conversation_id()).hyphenated().to_string(),
        "generation": coordinate.generation() as i64,
        "stateVersion": coordinate.state_version() as i64,
        "groupId": {
            "$bytes": base64::engine::general_purpose::STANDARD.encode(coordinate.group_id())
        },
        "epoch": coordinate.epoch() as i64,
        "groupContextHash": {
            "$bytes": base64::engine::general_purpose::STANDARD.encode(coordinate.group_context_hash())
        },
        "confirmationTag": {
            "$bytes": base64::engine::general_purpose::STANDARD.encode(coordinate.confirmation_tag())
        },
        "lifecycle": "active"
    }))
}

async fn lock_creation_replay_post_state(
    transaction: &mut Transaction<'_, Postgres>,
    locked: &LockedSignedOperationReplayAuthority,
) -> Result<(CreationReplayPostStateProof, CreationCanonicalResponse), CreationFacadeError> {
    let authority = locked.authority();
    let mutation = authority.mutation();
    let (transition_id, _, _, _) = parse_creation(mutation)?;
    let rows = sqlx::query("SELECT transition_id,conversation_id,entry_seq,accepted_at FROM chat.transitions WHERE transition_id=$1 FOR SHARE").bind(transition_id).fetch_optional(&mut **transaction).await?.ok_or(CreationFacadeError::InvalidCanonicalMaterial)?;
    let entry = sqlx::query(
        "SELECT accepted_payload_bytes FROM chat.entries WHERE transition_id=$1 FOR SHARE",
    )
    .bind(transition_id)
    .fetch_one(&mut **transaction)
    .await?;
    let idempotency = sqlx::query("SELECT completed_status,response_bytes,response_sha256 FROM chat.idempotency_records WHERE principal_did=$1 AND endpoint_nsid=$2 AND operation_id=$3 FOR SHARE").bind(authority.subject().as_str()).bind(ENDPOINT).bind(transition_id).fetch_one(&mut **transaction).await?;
    let bytes: Vec<u8> = idempotency.try_get("response_bytes")?;
    let response = CreationCanonicalResponse::new(bytes)?;
    let post_state_digest = Sha256::digest(
        [
            REPLAY_POST_STATE_DOMAIN,
            rows.try_get::<Uuid, _>("conversation_id")?
                .as_bytes()
                .as_slice(),
            entry
                .try_get::<Vec<u8>, _>("accepted_payload_bytes")?
                .as_slice(),
        ]
        .concat(),
    )
    .into();
    let accepted = mutation
        .accepted_wrapper_bytes()
        .ok_or(CreationFacadeError::InvalidCanonicalMaterial)?;
    let request_digest = *mutation.request_digest();
    let accepted_sha = Sha256::digest(accepted).into();
    let signature = *mutation.signature();
    let expected_sha = *response.sha256();
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    let mut proof = CreationReplayPostStateProof {
        transaction_id: transaction_id.into_boxed_str(),
        operation_id: transition_id,
        principal_did: authority.subject().as_str().to_owned().into_boxed_str(),
        endpoint_nsid: ENDPOINT.into(),
        mutation_kind: mutation.kind(),
        request_digest,
        accepted_request_sha256: accepted_sha,
        signature,
        post_state_digest,
        expected_response_sha256: expected_sha,
        expected_status: idempotency.try_get("completed_status")?,
        seal: [0; 32],
    };
    proof.seal = proof.rederive_seal();
    Ok((proof, response))
}

fn canonical_uuid(value: Uuid) -> Result<CanonicalUuidV4, CreationFacadeError> {
    CanonicalUuidV4::parse(&value.hyphenated().to_string())
        .map_err(|_| CreationFacadeError::InvalidCanonicalMaterial)
}
fn reverify_scope_mutation(
    scope: &ScopeBoundBusinessAuthority,
    admitted: &VerifiedSignedMutation,
) -> Result<VerifiedSignedMutation, CreationFacadeError> {
    let raw = admitted
        .accepted_wrapper_bytes()
        .ok_or(CreationFacadeError::InvalidCanonicalMaterial)?;
    let key = scope
        .actor_signing_public_key()
        .ok_or(CreationFacadeError::InvalidCanonicalMaterial)?;
    crate::chat_protocol::transcript::decode_and_verify_signed_mutation(raw, key)
        .map_err(CreationFacadeError::from)
}
fn bind(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}
