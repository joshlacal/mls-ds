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

#[derive(Debug)]
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
            let is_member: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS (
                    SELECT 1
                      FROM chat.participants
                     WHERE conversation_id = $1
                       AND user_did = $2
                       AND current_membership
                       AND status = 'active'
                )
                "#,
            )
            .bind(existing_id)
            .bind(authority.subject().as_str())
            .fetch_one(&mut **transaction)
            .await?;

            if !is_member {
                return Err(CreationFacadeError::CreationHead(
                    CreationHeadHydrationError::ConversationExists,
                ));
            }
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
    super::coordinate::canonical_active_coordinate_json(coordinate)
        .map_err(|_| CreationFacadeError::InvalidCanonicalMaterial)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_protocol::dpop;
    use crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority;
    use crate::chat_protocol::repository::auth::creation_existing_device_receipt_for_test;
    use crate::chat_protocol::repository::prelude::{
        arbitrate_operation, OperationArbitration, PreparedSignedOperation,
    };
    use crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard;
    use crate::chat_protocol::snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle};
    use crate::chat_protocol::transcript::decode_canonical_signed_mutation;
    use crate::chat_protocol::validation::ed25519_key_id;
    use chrono::{DateTime, SecondsFormat, Utc};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;
    use sqlx::PgPool;
    async fn test_pool() -> PgPool {
        let url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722".to_string());
        PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("PostgreSQL test database connection is required for behavioral creation tests")
    }
    fn random_test_did(prefix: &str) -> String {
        let bytes = Uuid::new_v4();
        let raw = bytes.as_bytes();
        let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
        let prefix_bytes = prefix.as_bytes();
        let mut suffix = String::with_capacity(24);
        for i in 0..24 {
            let b = if i < prefix_bytes.len() {
                prefix_bytes[i]
            } else {
                raw[i % 16]
            };
            let ch = alphabet[((b as usize) + i) % 32] as char;
            suffix.push(ch);
        }
        format!("did:plc:{suffix}")
    }

    struct TestActor {
        did: String,
        device_id: Uuid,
        dpop_jkt: String,
        signing_key: SigningKey,
        public_key_bytes: Vec<u8>,
        key_id: String,
    }

    fn new_test_actor(did_prefix: &str) -> TestActor {
        let mut seed = [0u8; 32];
        let id_bytes = Uuid::new_v4();
        seed[..16].copy_from_slice(id_bytes.as_bytes());
        seed[16..].copy_from_slice(id_bytes.as_bytes());
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let key_id = ed25519_key_id(&public_key_bytes).unwrap().as_str().to_owned();
        let did = random_test_did(did_prefix);
        let device_id = Uuid::new_v4();
        let dpop_jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
        TestActor {
            did,
            device_id,
            dpop_jkt,
            signing_key,
            public_key_bytes,
            key_id,
        }
    }

    fn build_signed_direct_creation_request(
        actor: &TestActor,
        first_did: &str,
        second_did: &str,
        trusted_at: DateTime<Utc>,
    ) -> VerifiedChatDeviceRequest {
        let (low_did, high_did) = if first_did < second_did {
            (first_did, second_did)
        } else {
            (second_did, first_did)
        };
        let cid = Uuid::new_v4();
        let transition_id = Uuid::new_v4();
        let signed_at = (trusted_at - chrono::Duration::milliseconds(500))
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        let group_id = [0x42u8; 32];
        let group_context_hash = [0x43u8; 32];
        let confirmation_tag_32 = [0x44u8; 32];
        let metadata_ciphertext = [0x99u8; 32];

        let body = json!({
            "$type": "blue.catbird.chat.defs#creationBody",
            "signatureDomain": "CATBIRD-CHAT-CREATE\u{0000}",
            "conversationId": cid.hyphenated().to_string(),
            "transitionId": transition_id.hyphenated().to_string(),
            "conversationKind": "direct",
            "absence": true,
            "actorDid": &actor.did,
            "actorDeviceId": actor.device_id.hyphenated().to_string(),
            "authGeneration": 1,
            "idempotencyKey": transition_id.hyphenated().to_string(),
            "keyId": &actor.key_id,
            "signedAt": &signed_at,
            "manifest": {
                "actorLeaf": {
                    "userDid": &actor.did,
                    "deviceId": actor.device_id.hyphenated().to_string(),
                    "leafOrigin": "genesis"
                },
                "participants": [
                    {
                        "userDid": low_did,
                        "status": "active",
                        "role": "admin"
                    },
                    {
                        "userDid": high_did,
                        "status": "active",
                        "role": "admin"
                    }
                ]
            },
            "genesisGroupInfo": {
                "framing": "mlsMessage",
                "contentType": "groupInfo",
                "bytes": base64::engine::general_purpose::STANDARD.encode(&[0x42u8; 32]),
                "sha256": base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&[0x42u8; 32]))
            },
            "next": {
                "conversationId": cid.hyphenated().to_string(),
                "generation": 0,
                "stateVersion": 0,
                "groupId": base64::engine::general_purpose::STANDARD.encode(group_id),
                "epoch": 0,
                "groupContextHash": base64::engine::general_purpose::STANDARD.encode(group_context_hash),
                "confirmationTag": base64::engine::general_purpose::STANDARD.encode(confirmation_tag_32),
                "lifecycle": "active"
            },
            "metadataSnapshot": {
                "coordinate": {
                    "conversationId": base64::engine::general_purpose::STANDARD.encode(cid.as_bytes()),
                    "generation": 0,
                    "groupId": base64::engine::general_purpose::STANDARD.encode(group_id),
                    "epoch": 0,
                    "groupContextHash": base64::engine::general_purpose::STANDARD.encode(group_context_hash),
                    "confirmationTag": base64::engine::general_purpose::STANDARD.encode(confirmation_tag_32),
                },
                "originTransitionId": transition_id.hyphenated().to_string(),
                "metadataVersion": 1,
                "nonce": base64::engine::general_purpose::STANDARD.encode([0x73_u8; 12]),
                "ciphertext": base64::engine::general_purpose::STANDARD.encode(metadata_ciphertext),
                "ciphertextSha256": base64::engine::general_purpose::STANDARD.encode(Sha256::digest(metadata_ciphertext)),
                "ciphertextSize": metadata_ciphertext.len(),
                "authorProof": {
                    "authorDid": &actor.did,
                    "authorDeviceId": actor.device_id.hyphenated().to_string(),
                    "authorKeyId": &actor.key_id,
                    "signaturePublicKey": base64::engine::general_purpose::STANDARD.encode(&actor.public_key_bytes),
                    "authGenerationAtOrigin": 1,
                    "originTransitionId": transition_id.hyphenated().to_string(),
                    "originSeq": 1,
                    "roleAtOrigin": "admin",
                    "deviceStatusAtOrigin": "active",
                },
            }
        });

        let mut wrapper = json!({
            "body": body,
            "signature": base64::engine::general_purpose::STANDARD.encode([0_u8; 64]),
        });
        let unsigned = serde_json::to_vec(&wrapper).unwrap();
        let canonical = decode_canonical_signed_mutation(&unsigned).expect("canonicalize creation body");
        let signature = actor.signing_key.sign(canonical.transcript_bytes());
        wrapper["signature"] = json!(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()));

        let signed_raw = serde_json::to_vec(&wrapper).unwrap();
        let canonical = decode_canonical_signed_mutation(&signed_raw).expect("canonicalize signed creation body");
        let pre_replay = dpop::repository_test_evidence::ordinary_device_with_binding(
            Uuid::new_v4(),
            *Uuid::new_v4().as_bytes().first_chunk::<12>().unwrap(),
            "blue.catbird.chat.createConversation",
            &trusted_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            &actor.did,
            actor.device_id,
            &actor.dpop_jkt,
        );
        let receipt = creation_existing_device_receipt_for_test(
            &crate::chat_protocol::transcript::decode_and_verify_signed_mutation(&signed_raw, &actor.public_key_bytes).unwrap(),
            &actor.dpop_jkt,
            &actor.public_key_bytes,
        ).unwrap();
        dpop::mint_signed_repository_authority(pre_replay, canonical, &actor.public_key_bytes, receipt).unwrap()
    }

    async fn seed_test_direct_environment(
        tx: &mut Transaction<'_, Postgres>,
        alice: &TestActor,
        bob_did: &str,
        charlie: &TestActor,
        existing_convo_id: Uuid,
        now: DateTime<Utc>,
    ) {
        let (low_did, high_did) = if alice.did.as_str() < bob_did {
            (alice.did.as_str(), bob_did)
        } else {
            (bob_did, alice.did.as_str())
        };

        // Seed principals
        for did in [&alice.did, &bob_did.to_string(), &charlie.did] {
            sqlx::query("INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(did)
                .bind(now)
                .execute(&mut **tx)
                .await
                .unwrap();
        }

        // Seed devices and device_keys for Alice and Charlie
        for actor in [alice, charlie] {
            sqlx::query(
                "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
                 VALUES ($1, $2, 'Test Device', 'active', $3, 1, chat.protocol_capabilities(), $4, $4) ON CONFLICT DO NOTHING"
            )
            .bind(&actor.did)
            .bind(actor.device_id)
            .bind(&actor.dpop_jkt)
            .bind(now)
            .execute(&mut **tx)
            .await
            .unwrap();

            sqlx::query(
                "INSERT INTO chat.device_keys (user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at) \
                 VALUES ($1, $2, $3, $4, 1, $5) ON CONFLICT DO NOTHING"
            )
            .bind(&actor.did)
            .bind(actor.device_id)
            .bind(&actor.key_id)
            .bind(&actor.public_key_bytes)
            .bind(now)
            .execute(&mut **tx)
            .await
            .unwrap();
        }
        // Seed active direct conversation between Alice and Bob
        sqlx::query(
            "INSERT INTO chat.conversations (conversation_id, kind, lifecycle, direct_did_low, direct_did_high, current_generation, current_state_version, next_entry_seq, created_at) \
             VALUES ($1, 'direct', 'active', $2, $3, 1, 1, 2, $4)"
        )
        .bind(existing_convo_id)
        .bind(low_did)
        .bind(high_did)
        .bind(now)
        .execute(&mut **tx)
        .await
        .unwrap();

        let genesis_bytes = vec![0x11u8; 32];
        let genesis_sha = Sha256::digest(&genesis_bytes).to_vec();
        sqlx::query(
            "INSERT INTO chat.generations (conversation_id, generation, group_id, lifecycle, genesis_group_info_bytes, genesis_group_info_sha256, current_state_version, activated_seq, activated_at) \
             VALUES ($1, 1, $2, 'active', $3, $4, 1, 1, $5)"
        )
        .bind(existing_convo_id)
        .bind(&[0x42u8; 32])
        .bind(&genesis_bytes)
        .bind(&genesis_sha)
        .bind(now)
        .execute(&mut **tx)
        .await
        .unwrap();

        let snapshot_bytes = vec![0x55u8; 32];
        let snapshot_sha = Sha256::digest(&snapshot_bytes).to_vec();
        let tree_bytes = vec![0x66u8; 32];
        let tree_sha = Sha256::digest(&tree_bytes).to_vec();
        sqlx::query(
            "INSERT INTO chat.generation_states (conversation_id, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, lifecycle, state_kind, producing_transition_id, public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count, created_at) \
             VALUES ($1, 1, 1, $2, 1, $3, $4, 'active', 'creation', $5, $6, $7, $8, $9, 2, $10)"
        )
        .bind(existing_convo_id)
        .bind(&[0x42u8; 32])
        .bind(&[0x43u8; 32])
        .bind(&[0x44u8; 32])
        .bind(Uuid::new_v4())
        .bind(&snapshot_bytes)
        .bind(&snapshot_sha)
        .bind(&tree_bytes)
        .bind(&tree_sha)
        .bind(now)
        .execute(&mut **tx)
        .await
        .unwrap();
        for did in [&alice.did, &bob_did.to_string()] {
            sqlx::query(
                "INSERT INTO chat.participants (participant_period_id, conversation_id, user_did, status, role, role_transition_id, role_changed_at, created_by_did, created_by_device_id, current_membership, created_at) \
                 VALUES ($1, $2, $3, 'active', 'admin', $4, $5, $6, $7, true, $5)"
            )
            .bind(Uuid::new_v4())
            .bind(existing_convo_id)
            .bind(did)
            .bind(Uuid::new_v4())
            .bind(now)
            .bind(&alice.did)
            .bind(alice.device_id)
            .execute(&mut **tx)
            .await
            .unwrap();
        }
    }


    #[tokio::test]
    async fn direct_dedup_member_caller_returns_existing_conversation_and_preserves_wire_contract() {
        let pool = test_pool().await;
        let mut tx = pool.begin().await.expect("begin transaction");
        let trusted_at: DateTime<Utc> = sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&mut *tx)
            .await
            .unwrap();

        let alice = new_test_actor("alice");
        let bob_did = random_test_did("bob");
        let charlie = new_test_actor("charlie");
        let existing_convo_id = Uuid::new_v4();

        seed_test_direct_environment(&mut tx, &alice, &bob_did, &charlie, existing_convo_id, trusted_at).await;

        let request = build_signed_direct_creation_request(&alice, &alice.did, &bob_did, trusted_at);
        let reservation = match arbitrate_operation(&mut tx, &request).await.expect("arbitrate operation") {
            OperationArbitration::First(res) => res,
            OperationArbitration::Replay(_) => panic!("unexpected replay"),
        };

        let guard = load_fixed_relationship_authority_startup_guard().unwrap();
        let rel_auth = ProductionRelationshipAuthority::from_startup_guard(guard);

        let prepared = PreparedSignedOperation::first_for_test(request, reservation);
        let outcome = execute_prepared_creation(&mut tx, prepared, &rel_auth)
            .await
            .expect("member creation on existing direct conversation must succeed");

        // 1. Assert status is HTTP 200
        assert_eq!(outcome.status(), 200);

        // 2. Assert exact wire response bytes match canonical creation_existing_response
        let expected_coord = PublicGroupSnapshotCoordinate::new(
            *existing_convo_id.as_bytes(),
            1,
            1,
            [0x42; 32],
            1,
            [0x43; 32],
            [0x44; 32],
            PublicGroupSnapshotLifecycle::Active,
        );
        let expected_response = creation_existing_response(existing_convo_id, &expected_coord)
            .expect("encode expected existing response");
        assert_eq!(
            outcome.response_bytes(),
            expected_response.as_bytes(),
            "wire response bytes must be byte-identical to creation_existing_response"
        );


        // 4. Assert decoded JSON payload fields
        let parsed: serde_json::Value =
            serde_json::from_slice(outcome.response_bytes()).expect("parse canonical json response");
        assert_eq!(
            parsed["result"]["$type"],
            "blue.catbird.chat.defs#existingDirectConversationResult"
        );
        assert_eq!(
            parsed["result"]["conversationId"],
            existing_convo_id.to_string()
        );
        assert_eq!(parsed["result"]["conversationKind"], "direct");
        assert_eq!(parsed["result"]["coordinates"]["epoch"], 1);

        // 5. Ensure exact conversation and participant row values are preserved
        let (kind, lifecycle, did_low, did_high, cur_gen, cur_state_ver, next_seq): (
            String,
            String,
            String,
            String,
            i64,
            i64,
            i64,
        ) = sqlx::query_as(
            "SELECT kind, lifecycle, direct_did_low, direct_did_high, current_generation, current_state_version, next_entry_seq \
             FROM chat.conversations WHERE conversation_id = $1",
        )
        .bind(existing_convo_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(kind, "direct");
        assert_eq!(lifecycle, "active");
        assert_eq!(cur_gen, 1);
        assert_eq!(cur_state_ver, 1);
        assert_eq!(next_seq, 2);

        let participants: Vec<(String, String, String, bool)> = sqlx::query_as(
            "SELECT user_did, status, role, current_membership \
             FROM chat.participants WHERE conversation_id = $1 ORDER BY user_did",
        )
        .bind(existing_convo_id)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        assert_eq!(participants.len(), 2);
        for (_did, status, role, current_membership) in &participants {
            assert_eq!(status, "active");
            assert_eq!(role, "admin");
            assert!(current_membership);
        }

        let idempotency_records: Vec<(i32, Vec<u8>)> = sqlx::query_as(
            "SELECT completed_status, response_bytes \
             FROM chat.idempotency_records WHERE principal_did = $1",
        )
        .bind(&alice.did)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        assert_eq!(idempotency_records.len(), 1);
        assert_eq!(idempotency_records[0].0, 200);
        assert_eq!(
            idempotency_records[0].1.as_slice(),
            expected_response.as_bytes()
        );

        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn direct_dedup_non_member_caller_rejects_with_conversation_already_exists_and_no_mutation() {
        let pool = test_pool().await;
        let mut tx = pool.begin().await.expect("begin transaction");
        let trusted_at: DateTime<Utc> = sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let alice = new_test_actor("alice");
        let bob_did = random_test_did("bob");
        let charlie = new_test_actor("charlie");
        let existing_convo_id = Uuid::new_v4();

        seed_test_direct_environment(&mut tx, &alice, &bob_did, &charlie, existing_convo_id, trusted_at).await;

        // Baseline conversation and participant state
        let (kind_before, lifecycle_before, cur_gen_before, cur_ver_before, next_seq_before): (
            String,
            String,
            i64,
            i64,
            i64,
        ) = sqlx::query_as(
            "SELECT kind, lifecycle, current_generation, current_state_version, next_entry_seq \
             FROM chat.conversations WHERE conversation_id = $1",
        )
        .bind(existing_convo_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        let total_convos_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.conversations")
            .fetch_one(&mut *tx)
            .await
            .unwrap();

        // Charlie (non-member) tries to create direct conversation for pair (alice, bob)
        let request = build_signed_direct_creation_request(&charlie, &alice.did, &bob_did, trusted_at);
        let operation_id = match request.mutation().expect("creation mutation").projection() {
            crate::chat_protocol::transcript::VerifiedMutationProjection::Creation(c) => {
                Uuid::from_bytes(*c.transition_id().as_bytes())
            }
            _ => panic!("expected creation projection"),
        };

        let reservation = match arbitrate_operation(&mut tx, &request).await.expect("arbitrate operation") {
            OperationArbitration::First(res) => res,
            OperationArbitration::Replay(_) => panic!("unexpected replay"),
        };

        let guard = load_fixed_relationship_authority_startup_guard().unwrap();
        let rel_auth = ProductionRelationshipAuthority::from_startup_guard(guard);

        let prepared = PreparedSignedOperation::first_for_test(request, reservation);
        let err = execute_prepared_creation(&mut tx, prepared, &rel_auth)
            .await
            .expect_err("non-member creation on existing direct conversation must be rejected");

        // 1. Assert repository-level error
        assert!(
            matches!(
                err,
                CreationFacadeError::CreationHead(CreationHeadHydrationError::ConversationExists)
            ),
            "non-member must be rejected with CreationHeadHydrationError::ConversationExists, got: {err:?}"
        );


        // 3. Assert database state inside transaction before rollback
        let (kind_after, lifecycle_after, cur_gen_after, cur_ver_after, next_seq_after): (
            String,
            String,
            i64,
            i64,
            i64,
        ) = sqlx::query_as(
            "SELECT kind, lifecycle, current_generation, current_state_version, next_entry_seq \
             FROM chat.conversations WHERE conversation_id = $1",
        )
        .bind(existing_convo_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(kind_after, kind_before);
        assert_eq!(lifecycle_after, lifecycle_before);
        assert_eq!(cur_gen_after, cur_gen_before);
        assert_eq!(cur_ver_after, cur_ver_before);
        assert_eq!(next_seq_after, next_seq_before);

        let total_convos_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.conversations")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(total_convos_after, total_convos_before, "no new conversation row created");

        let participants: Vec<(String, String, bool)> = sqlx::query_as(
            "SELECT user_did, status, current_membership \
             FROM chat.participants WHERE conversation_id = $1 ORDER BY user_did",
        )
        .bind(existing_convo_id)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        assert_eq!(participants.len(), 2, "no new participant row created");
        for (did, status, current_membership) in &participants {
            assert!(did == &alice.did || did == &bob_did);
            assert_eq!(status, "active");
            assert!(current_membership);
        }

        let idempotency_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM chat.idempotency_records WHERE principal_did = $1",
        )
        .bind(&charlie.did)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(idempotency_count, 0, "no idempotency record in transaction");

        // 4. Roll back transaction and verify no state persists in the database
        tx.rollback().await.unwrap();

        let operation_claims_in_db: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM chat.operation_claims WHERE operation_id = $1",
        )
        .bind(operation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            operation_claims_in_db, 0,
            "operation claim must be rolled back on rejection"
        );

        let charlie_idempotency_in_db: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM chat.idempotency_records WHERE principal_did = $1",
        )
        .bind(&charlie.did)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            charlie_idempotency_in_db, 0,
            "no idempotency record persisted in database"
        );
    }

    #[test]
    fn creation_existing_response_encodes_direct_result_without_state_mutation() {
        let convo_id = Uuid::parse_str("f55a5ece-b653-43f3-950a-ab72b4a5c075").unwrap();
        let coord = PublicGroupSnapshotCoordinate::new(
            *convo_id.as_bytes(),
            1,
            1,
            [0x42; 32],
            1,
            [0x43; 32],
            [0x44; 32],
            PublicGroupSnapshotLifecycle::Active,
        );
        let response = creation_existing_response(convo_id, &coord).expect("encode existing response");
        assert!(response.validates(), "canonical response digest must validate");

        let parsed: serde_json::Value =
            serde_json::from_slice(response.as_bytes()).expect("parse canonical json");
        assert_eq!(
            parsed["result"]["$type"],
            "blue.catbird.chat.defs#existingDirectConversationResult"
        );
        assert_eq!(
            parsed["result"]["conversationId"],
            "f55a5ece-b653-43f3-950a-ab72b4a5c075"
        );
        assert_eq!(parsed["result"]["conversationKind"], "direct");
        assert_eq!(parsed["result"]["coordinates"]["epoch"], 1);
    }
}
