//! Transaction-bound acceptConversation repository composition.
//!
//! Acceptance owns the locked aggregate, exact successor KeyPackage
//! reservation, recovery server-fields projection, canonical output, and its
//! endpoint-specific replay post-state proof.  The handler never receives a
//! raw planner or execution-artifact seam.

use base64::Engine as _;
use catbird_atproto::generated::blue_catbird::chat as chat_dto;
use jacquard_common::DefaultStr;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::chat_protocol::{
    dpop::VerifiedChatDeviceRequest,
    model::AuthPrimitiveError,
    relationship_policy::{PublicTransport, RelationshipAuthority},
    snapshot::PublicGroupSnapshotLifecycle,
    state_machine::HydrationAuthority,
    state_machine::{ExecutorError, StateMachineError},
    transcript::{
        build_verified_control_entry, CanonicalControlEntryProducts, CanonicalControlServerFields,
        CanonicalValueRef, ControlEntryKind, SignedMutationKind, VerifiedMutationProjection,
    },
};

use super::{
    auth::CompletedIdempotentResponse,
    execution_context::{
        apply_prepared_acceptance_execution, prepare_acceptance_execution,
        ExecutionContextHydrationError,
    },
    prelude::{
        complete_operation, lock_signed_operation_replay_authority, prepare_identity_scope_prelude,
        release_signed_operation_replay, CanonicalDeviceIdentity, CanonicalLockScope,
        LockedSignedOperationReplayAuthority, OperationReservationGuard, PreludeError,
        PreparedSignedOperation, PreparedSignedOperationState,
    },
};

const ENDPOINT: &str = "blue.catbird.chat.acceptConversation";
const RESPONSE_DOMAIN: &[u8] = b"CATBIRD-CHAT-ACCEPT-CONVERSATION-RESPONSE\0";
const REPLAY_POST_STATE_DOMAIN: &[u8] = b"CATBIRD-CHAT-ACCEPT-CONVERSATION-REPLAY-POST-STATE\0";
const REPLAY_SEAL_DOMAIN: &[u8] = b"CATBIRD-CHAT-ACCEPT-CONVERSATION-REPLAY-SEAL\0";
const STATUS: i32 = 200;

#[derive(Debug)]
pub(crate) enum AcceptanceFacadeError {
    MissingMutation,
    InvalidCanonicalMaterial,
    Prelude(PreludeError),
    Primitive(AuthPrimitiveError),
    StateMachine(StateMachineError),
    Conversation(super::core::ConversationStateHydrationError),
    RecoveryPackage(super::core::RecoveryPackageHydrationError),
    Relationship(super::relationship::RelationshipRepositoryError),
    ExecutionContext(ExecutionContextHydrationError),
    Executor(ExecutorError),
    Database(sqlx::Error),
}
macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for AcceptanceFacadeError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}
from_error!(PreludeError, Prelude);
from_error!(AuthPrimitiveError, Primitive);
from_error!(StateMachineError, StateMachine);
from_error!(super::core::ConversationStateHydrationError, Conversation);
from_error!(super::core::RecoveryPackageHydrationError, RecoveryPackage);
from_error!(
    super::relationship::RelationshipRepositoryError,
    Relationship
);
from_error!(ExecutionContextHydrationError, ExecutionContext);
from_error!(ExecutorError, Executor);
from_error!(sqlx::Error, Database);

#[derive(Debug)]
pub(crate) struct AcceptanceCanonicalResponse {
    bytes: Box<[u8]>,
    sha256: [u8; 32],
    binding_digest: [u8; 32],
}
impl AcceptanceCanonicalResponse {
    fn new(bytes: Vec<u8>) -> Result<Self, AcceptanceFacadeError> {
        let _: chat_dto::accept_conversation::AcceptConversationOutput<DefaultStr> =
            serde_json::from_slice(&bytes)
                .map_err(|_| AcceptanceFacadeError::InvalidCanonicalMaterial)?;
        let sha256 = <[u8; 32]>::from(Sha256::digest(&bytes));
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
            && self.binding_digest != [0; 32]
    }
}

pub(crate) struct AcceptanceTransactionOutcome {
    status: i32,
    response_bytes: Box<[u8]>,
    event_position: Option<i64>,
}
impl AcceptanceTransactionOutcome {
    pub(crate) fn status(&self) -> i32 {
        self.status
    }
    pub(crate) fn response_bytes(&self) -> &[u8] {
        &self.response_bytes
    }
    pub(crate) fn event_position(&self) -> Option<i64> {
        self.event_position
    }
    fn replay(response: CompletedIdempotentResponse) -> Self {
        Self {
            status: response.status(),
            response_bytes: response.response_bytes().to_vec().into_boxed_slice(),
            event_position: response.event_position(),
        }
    }
}

pub(in crate::chat_protocol::repository) struct AcceptanceReplayPostStateProof {
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
impl AcceptanceReplayPostStateProof {
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

pub(crate) async fn execute_prepared_acceptance<T: PublicTransport>(
    transaction: &mut Transaction<'_, Postgres>,
    prepared: PreparedSignedOperation,
    _relationship_authority: &RelationshipAuthority<T>,
) -> Result<AcceptanceTransactionOutcome, AcceptanceFacadeError> {
    match prepared.into_state() {
        PreparedSignedOperationState::First {
            authority,
            reservation,
        } => {
            execute_first_acceptance(transaction, authority, reservation, _relationship_authority)
                .await
        }
        PreparedSignedOperationState::Replay { authority, replay } => {
            let locked =
                lock_signed_operation_replay_authority(transaction, authority, replay).await?;
            let (proof, expected) = lock_acceptance_replay_post_state(transaction, &locked).await?;
            let expected_sha = *proof.expected_response_sha256();
            let expected_status = proof.expected_status();
            let completed = release_signed_operation_replay(
                transaction,
                locked,
                super::prelude::SignedOperationReplayPostStateProof::Acceptance(proof),
            )
            .await?;
            if completed.status() != expected_status
                || completed.response_sha256() != &expected_sha
                || <[u8; 32]>::from(Sha256::digest(completed.response_bytes())) != expected_sha
                || completed.response_bytes() != expected.as_bytes()
            {
                return Err(AcceptanceFacadeError::InvalidCanonicalMaterial);
            }
            Ok(AcceptanceTransactionOutcome::replay(completed))
        }
    }
}

async fn execute_first_acceptance<T: PublicTransport>(
    transaction: &mut Transaction<'_, Postgres>,
    authority: VerifiedChatDeviceRequest,
    reservation: OperationReservationGuard,
    relationship_authority: &RelationshipAuthority<T>,
) -> Result<AcceptanceTransactionOutcome, AcceptanceFacadeError> {
    let mutation = authority
        .mutation()
        .ok_or(AcceptanceFacadeError::MissingMutation)?;
    let VerifiedMutationProjection::ParticipantAcceptance(value) = mutation.projection() else {
        return Err(AcceptanceFacadeError::InvalidCanonicalMaterial);
    };
    let transition_id = Uuid::from_bytes(*value.transition_id().as_bytes());
    let conversation_id = match value.prior().get("conversationId") {
        Some(CanonicalValueRef::Uuid(id)) => Uuid::from_bytes(*id.as_bytes()),
        _ => return Err(AcceptanceFacadeError::InvalidCanonicalMaterial),
    };
    let scope = CanonicalLockScope::new(
        vec![authority.subject().as_str().to_owned()],
        vec![CanonicalDeviceIdentity::new(
            authority.subject().as_str(),
            Uuid::from_bytes(*authority.device_id().as_bytes()),
        )],
    )?;
    let prelude = prepare_identity_scope_prelude(transaction, &authority, reservation, scope)
        .await?
        .verify_acceptance_operation(transition_id, mutation)?;
    let scope_authority = prelude.scope_authority();
    let aggregate = super::core::hydrate_locked_conversation_state(
        transaction,
        conversation_id,
        scope_authority.trusted_instant(),
    )
    .await?;
    let hydration = HydrationAuthority::from_locked_conversation(&aggregate)?;
    let registration = hydration.locked_registration_from_scope_authority(scope_authority)?;
    let actor_did = String::from_utf8(registration.actor().principal().as_bytes().to_vec())
        .map_err(|_| AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let actor_device_id = Uuid::from_bytes(*registration.actor().device_id());
    let actor_key_id =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(registration.key_id());
    let package = super::core::hydrate_locked_available_acceptance_package(
        transaction,
        aggregate.head(),
        Uuid::from_bytes(*value.recovery_request_id().as_bytes()),
        &actor_did,
        actor_device_id,
        &actor_key_id,
        i64::try_from(registration.auth_generation())
            .map_err(|_| AcceptanceFacadeError::InvalidCanonicalMaterial)?,
    )
    .await?;
    let recovery_reservation = hydration.locked_recovery_reservation(package, &registration)?;
    let fallback = super::relationship::seal_acceptance_fallback_scope(&aggregate, &registration)?;
    let (relationship, decision) = super::relationship::load_fallback_relationship_projection(
        transaction,
        fallback,
        relationship_authority,
    )
    .await?
    .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let server_fields = acceptance_server_fields(
        &recovery_reservation,
        &aggregate,
        &registration,
        &value,
        transaction,
        scope_authority.trusted_instant(),
    )
    .await?;
    let verified = crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
        mutation
            .accepted_wrapper_bytes()
            .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?,
        scope_authority
            .actor_signing_public_key()
            .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?,
    )?;
    let entry = build_verified_control_entry(
        verified,
        authority.endpoint(),
        canonical_uuid(transition_id)?,
        canonical_uuid(conversation_id)?,
        aggregate.head().next_entry_seq(),
        authority.trusted_instant(),
        server_fields,
    )?;
    let products = CanonicalControlEntryProducts::mint(&entry)?;
    let terminal_packages = Vec::new();
    let trusted_now = crate::chat_protocol::validation::TrustedRequestInstant::from_datetime(
        scope_authority.trusted_instant(),
    )?;
    let plan = hydration
        .plan_acceptance_entry(
            &aggregate,
            entry,
            registration,
            recovery_reservation,
            terminal_packages,
            &relationship,
            relationship_authority,
            &decision,
            &trusted_now,
        )?
        .into_persistence_plan()?;
    let response = acceptance_response(&plan, products.canonical_response_json())?;
    let (scope, completion) = prelude.into_execution_parts();
    let prepared =
        prepare_acceptance_execution(transaction, &plan, products.durable_json().to_vec()).await?;
    let applied = apply_prepared_acceptance_execution(prepared).await?;
    if applied.entry_id != transition_id {
        return Err(AcceptanceFacadeError::InvalidCanonicalMaterial);
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
    Ok(AcceptanceTransactionOutcome {
        status: STATUS,
        response_bytes: response.bytes,
        event_position,
    })
}

async fn acceptance_server_fields(
    reservation: &crate::chat_protocol::state_machine::LockedRecoveryReservationProjection,
    _aggregate: &super::core::LockedConversationStateGuard,
    _registration: &crate::chat_protocol::state_machine::LockedRegistrationProjection,
    value: &crate::chat_protocol::transcript::ParticipantAcceptanceProjection<'_>,
    _transaction: &mut Transaction<'_, Postgres>,
    _trusted_at: chrono::DateTime<chrono::Utc>,
) -> Result<CanonicalControlServerFields, AcceptanceFacadeError> {
    let target = reservation.target();
    let requester_did = std::str::from_utf8(target.principal().as_bytes())
        .map_err(|_| AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let request_id = Uuid::from_bytes(*reservation.request_id());
    let conversation_id = Uuid::from_bytes(*reservation.conversation_id());
    let bound_coordinate = coordinate_json(reservation.bound_coordinate())?;
    let expires_at = reservation
        .claimed_at()
        .unix_millis()
        .checked_add(300_000)
        .map(|ttl| ttl.min(reservation.package_not_after().unix_millis()))
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let claimed_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        reservation.claimed_at().unix_millis(),
    )
    .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let key_package_ref =
        base64::engine::general_purpose::STANDARD.encode(reservation.key_package_ref());
    let wrapper_sha256 =
        base64::engine::general_purpose::STANDARD.encode(reservation.key_package_wrapper_sha256());
    let wrapper_bytes =
        base64::engine::general_purpose::STANDARD.encode(reservation.key_package_wrapper());
    let recovery = serde_json::json!({
        "recoveryRequestId": request_id.hyphenated().to_string(),
        "conversationId": conversation_id.hyphenated().to_string(),
        "requesterDid": requester_did,
        "requesterDeviceId": Uuid::from_bytes(*target.device_id()).hyphenated().to_string(),
        "recoveryKind": "add",
        "boundCoordinate": bound_coordinate,
        "reservation": {
            "recoveryRequestId": request_id.hyphenated().to_string(),
            "conversationId": conversation_id.hyphenated().to_string(),
            "boundCoordinate": coordinate_json(reservation.bound_coordinate())?,
            "requesterDid": requester_did,
            "requesterDeviceId": Uuid::from_bytes(*target.device_id()).hyphenated().to_string(),
            "requesterKeyId": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(reservation.target_key_id()),
            "requesterAuthGeneration": i64::try_from(reservation.target_auth_generation())
                .map_err(|_| AcceptanceFacadeError::InvalidCanonicalMaterial)?,
            "keyPackageRef": key_package_ref,
            "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
            "purpose": "leafRecovery",
            "status": "active",
            "expiresAt": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "keyPackage": {
                "framing": "mlsMessage",
                "contentType": "keyPackage",
                "bytes": wrapper_bytes,
                "sha256": wrapper_sha256,
                "keyPackageRef": base64::engine::general_purpose::STANDARD.encode(reservation.key_package_ref()),
            }
        },
        "status": "open",
        "requestedAt": claimed_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "expiresAt": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    if Uuid::from_bytes(*value.recovery_request_id().as_bytes()) != request_id {
        return Err(AcceptanceFacadeError::InvalidCanonicalMaterial);
    }
    CanonicalControlServerFields::decode(
        ControlEntryKind::ParticipantAcceptance,
        &serde_json::to_vec(&serde_json::json!({ "recovery": recovery }))
            .map_err(|_| AcceptanceFacadeError::InvalidCanonicalMaterial)?,
    )
    .map_err(AcceptanceFacadeError::from)
}

fn acceptance_response(
    plan: &crate::chat_protocol::state_machine::ConversationPersistencePlan,
    entry: &[u8],
) -> Result<AcceptanceCanonicalResponse, AcceptanceFacadeError> {
    let coordinate = plan
        .successor_coordinate()
        .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let entry_value = serde_json::from_slice::<serde_json::Value>(entry)
        .map_err(|_| AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let recovery = entry_value
        .get("recovery")
        .cloned()
        .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let value = serde_json::json!({
        "coordinates": coordinate_json(coordinate)?,
        "entry": entry_value,
        "recovery": recovery
    });
    let value_bytes =
        serde_json::to_vec(&value).map_err(|_| AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let output: chat_dto::accept_conversation::AcceptConversationOutput<DefaultStr> =
        serde_json::from_slice(&value_bytes)
            .map_err(|_| AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    AcceptanceCanonicalResponse::new(
        serde_json::to_vec(&output).map_err(|_| AcceptanceFacadeError::InvalidCanonicalMaterial)?,
    )
}

fn coordinate_json(
    coordinate: &crate::chat_protocol::snapshot::PublicGroupSnapshotCoordinate,
) -> Result<serde_json::Value, AcceptanceFacadeError> {
    if coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active {
        return Err(AcceptanceFacadeError::InvalidCanonicalMaterial);
    }
    Ok(serde_json::json!({
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
fn canonical_uuid(
    value: Uuid,
) -> Result<crate::chat_protocol::validation::CanonicalUuidV4, AcceptanceFacadeError> {
    crate::chat_protocol::validation::CanonicalUuidV4::parse(&value.hyphenated().to_string())
        .map_err(|_| AcceptanceFacadeError::InvalidCanonicalMaterial)
}

async fn lock_acceptance_replay_post_state(
    transaction: &mut Transaction<'_, Postgres>,
    locked: &LockedSignedOperationReplayAuthority,
) -> Result<(AcceptanceReplayPostStateProof, AcceptanceCanonicalResponse), AcceptanceFacadeError> {
    let authority = locked.authority();
    let mutation = authority.mutation();
    if mutation.kind() != SignedMutationKind::ParticipantAcceptance {
        return Err(AcceptanceFacadeError::InvalidCanonicalMaterial);
    }
    let operation_id = match mutation.projection() {
        crate::chat_protocol::transcript::VerifiedMutationProjection::ParticipantAcceptance(
            value,
        ) => Uuid::from_bytes(*value.transition_id().as_bytes()),
        _ => return Err(AcceptanceFacadeError::InvalidCanonicalMaterial),
    };
    let transition = sqlx::query(
        r#"
        SELECT conversation_id,kind,actor_did,actor_device_id,actor_key_id,
               actor_auth_generation,next_generation,next_state_version,
               signed_request_bytes,request_digest,signature
          FROM chat.transitions
         WHERE transition_id=$1
         FOR SHARE
        "#,
    )
    .bind(operation_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let transition_kind: String = transition.try_get("kind")?;
    let transition_actor: String = transition.try_get("actor_did")?;
    let transition_actor_device: Uuid = transition.try_get("actor_device_id")?;
    let transition_actor_key: String = transition.try_get("actor_key_id")?;
    let transition_actor_auth_generation: i64 = transition.try_get("actor_auth_generation")?;
    let transition_next_generation: Option<i64> = transition.try_get("next_generation")?;
    let transition_next_state_version: Option<i64> = transition.try_get("next_state_version")?;
    let transition_request: Vec<u8> = transition.try_get("request_digest")?;
    let transition_signature: Vec<u8> = transition.try_get("signature")?;
    let accepted = mutation
        .accepted_wrapper_bytes()
        .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    if transition_kind != "acceptConversation"
        || transition_actor != authority.subject().as_str()
        || transition_request.as_slice() != mutation.request_digest()
        || transition_signature.as_slice() != mutation.signature()
        || transition
            .try_get::<Vec<u8>, _>("signed_request_bytes")?
            .as_slice()
            != accepted
    {
        return Err(AcceptanceFacadeError::InvalidCanonicalMaterial);
    }
    let transition_row_digest: Vec<u8> = sqlx::query_scalar(
        "SELECT digest(row_to_json(t)::text, 'sha256') FROM (SELECT * FROM chat.transitions WHERE transition_id=$1 FOR SHARE) t",
    )
    .bind(operation_id)
    .fetch_one(&mut **transaction)
    .await?;
    let conversation_id: Uuid = transition.try_get("conversation_id")?;
    let entry = sqlx::query(
        r#"
        SELECT conversation_id,entry_kind,accepted_payload_bytes,
               accepted_payload_sha256,request_digest,signature,transition_id
          FROM chat.entries
         WHERE transition_id=$1
         FOR SHARE
        "#,
    )
    .bind(operation_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let accepted_payload: Vec<u8> = entry.try_get("accepted_payload_bytes")?;
    let payload_hash: Vec<u8> = entry.try_get("accepted_payload_sha256")?;
    if entry.try_get::<Uuid, _>("conversation_id")? != conversation_id
        || entry.try_get::<String, _>("entry_kind")?
            != "blue.catbird.chat.defs#participantAcceptanceEntry"
        || entry.try_get::<Uuid, _>("transition_id")? != operation_id
        || entry.try_get::<Vec<u8>, _>("request_digest")?.as_slice() != mutation.request_digest()
        || entry.try_get::<Vec<u8>, _>("signature")?.as_slice() != mutation.signature()
        || payload_hash.as_slice() != Sha256::digest(&accepted_payload).as_slice()
    {
        return Err(AcceptanceFacadeError::InvalidCanonicalMaterial);
    }
    let entry_row_digest: Vec<u8> = sqlx::query_scalar(
        "SELECT digest(row_to_json(t)::text, 'sha256') FROM (SELECT * FROM chat.entries WHERE transition_id=$1 FOR SHARE) t",
    )
    .bind(operation_id)
    .fetch_one(&mut **transaction)
    .await?;
    let recovery_request_id = match mutation.projection() {
        crate::chat_protocol::transcript::VerifiedMutationProjection::ParticipantAcceptance(
            value,
        ) => Uuid::from_bytes(*value.recovery_request_id().as_bytes()),
        _ => return Err(AcceptanceFacadeError::InvalidCanonicalMaterial),
    };
    let recovery = sqlx::query(
        r#"
        SELECT conversation_id,generation,source,status,reservation_request_id,
               fulfilling_transition_id,requester_did,requester_device_id,
               requester_key_id,requester_auth_generation,bound_state_version,
               bound_group_id,bound_epoch,bound_group_context_hash,
               bound_confirmation_tag,signed_request_bytes,request_digest,signature,
               terminal_transition_id,terminal_revocation_id,terminal_at
          FROM chat.leaf_recovery_requests
         WHERE recovery_request_id=$1
         FOR SHARE
        "#,
    )
    .bind(recovery_request_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let recovery_status: String = recovery.try_get("status")?;
    let recovery_fulfilling_transition: Option<Uuid> =
        recovery.try_get("fulfilling_transition_id")?;
    let recovery_terminal_transition: Option<Uuid> = recovery.try_get("terminal_transition_id")?;
    let recovery_terminal_revocation: Option<Uuid> = recovery.try_get("terminal_revocation_id")?;
    let recovery_bound_state_version: i64 = recovery.try_get("bound_state_version")?;
    let recovery_bound_epoch: i64 = recovery.try_get("bound_epoch")?;
    let recovery_bound_group_id: Vec<u8> = recovery.try_get("bound_group_id")?;
    let recovery_bound_group_context_hash: Vec<u8> =
        recovery.try_get("bound_group_context_hash")?;
    let recovery_bound_confirmation_tag: Vec<u8> = recovery.try_get("bound_confirmation_tag")?;
    if recovery.try_get::<Uuid, _>("conversation_id")? != conversation_id
        || recovery.try_get::<String, _>("source")? != "acceptConversation"
        || recovery.try_get::<Uuid, _>("reservation_request_id")? != recovery_request_id
        || recovery.try_get::<String, _>("requester_did")? != transition_actor
        || recovery.try_get::<Uuid, _>("requester_device_id")? != transition_actor_device
        || recovery.try_get::<String, _>("requester_key_id")? != transition_actor_key
        || recovery.try_get::<i64, _>("requester_auth_generation")?
            != transition_actor_auth_generation
        || !crate::chat_protocol::validation::acceptance_replay_coordinate_matches_successor(
            transition_next_generation,
            transition_next_state_version,
            recovery.try_get("generation")?,
            recovery_bound_state_version,
        )
        || recovery
            .try_get::<Vec<u8>, _>("signed_request_bytes")?
            .as_slice()
            != accepted
        || recovery.try_get::<Vec<u8>, _>("request_digest")?.as_slice() != mutation.request_digest()
        || recovery.try_get::<Vec<u8>, _>("signature")?.as_slice() != mutation.signature()
    {
        return Err(AcceptanceFacadeError::InvalidCanonicalMaterial);
    }
    let recovery_row_digest: Vec<u8> = sqlx::query_scalar(
        "SELECT digest(row_to_json(t)::text, 'sha256') FROM (SELECT * FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1 FOR SHARE) t",
    )
    .bind(recovery_request_id)
    .fetch_one(&mut **transaction)
    .await?;
    let reservation = sqlx::query(
        r#"
        SELECT key_package_ref,conversation_id,requester_did,requester_device_id,
               requester_key_id,requester_auth_generation,recipient_did,
               recipient_device_id,bound_state_version,bound_group_id,bound_epoch,
               bound_group_context_hash,bound_confirmation_tag,purpose,status,
               consumed_transition_id,terminal_transition_id,terminal_revocation_id,
               terminal_request_digest,terminal_at
          FROM chat.key_package_reservations
         WHERE recovery_request_id=$1
         FOR SHARE
        "#,
    )
    .bind(recovery_request_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let reservation_status: String = reservation.try_get("status")?;
    let reservation_consumed_transition: Option<Uuid> =
        reservation.try_get("consumed_transition_id")?;
    let reservation_terminal_transition: Option<Uuid> =
        reservation.try_get("terminal_transition_id")?;
    let reservation_terminal_revocation: Option<Uuid> =
        reservation.try_get("terminal_revocation_id")?;
    if reservation.try_get::<Uuid, _>("conversation_id")? != conversation_id
        || reservation.try_get::<String, _>("requester_did")? != transition_actor
        || reservation.try_get::<Uuid, _>("requester_device_id")? != transition_actor_device
        || reservation.try_get::<String, _>("requester_key_id")? != transition_actor_key
        || reservation.try_get::<i64, _>("requester_auth_generation")?
            != transition_actor_auth_generation
        || reservation.try_get::<String, _>("recipient_did")? != transition_actor
        || reservation.try_get::<Uuid, _>("recipient_device_id")? != transition_actor_device
        || reservation.try_get::<i64, _>("bound_state_version")? != recovery_bound_state_version
        || reservation.try_get::<i64, _>("bound_epoch")? != recovery_bound_epoch
        || reservation.try_get::<Vec<u8>, _>("bound_group_id")? != recovery_bound_group_id
        || reservation.try_get::<Vec<u8>, _>("bound_group_context_hash")?
            != recovery_bound_group_context_hash
        || reservation.try_get::<Vec<u8>, _>("bound_confirmation_tag")?
            != recovery_bound_confirmation_tag
        || reservation.try_get::<String, _>("purpose")? != "leafRecovery"
        || !recovery_terminal_state_is_consistent(
            &recovery_status,
            &reservation_status,
            reservation_consumed_transition,
            reservation_terminal_transition,
            reservation_terminal_revocation,
        )
        || recovery_fulfilling_transition != reservation_consumed_transition
        || recovery_terminal_transition != reservation_terminal_transition
        || recovery_terminal_revocation != reservation_terminal_revocation
    {
        return Err(AcceptanceFacadeError::InvalidCanonicalMaterial);
    }
    let reservation_row_digest: Vec<u8> = sqlx::query_scalar(
        "SELECT digest(row_to_json(t)::text, 'sha256') FROM (SELECT * FROM chat.key_package_reservations WHERE recovery_request_id=$1 FOR SHARE) t",
    )
    .bind(recovery_request_id)
    .fetch_one(&mut **transaction)
    .await?;
    let key_package_ref: Vec<u8> = reservation.try_get("key_package_ref")?;
    let package = sqlx::query(
        r#"
        SELECT wrapper_bytes,wrapper_sha256,status,owner_did,owner_device_id,
               owner_key_id,owner_auth_generation,terminal_transition_id,
               terminal_revocation_id,terminal_at
          FROM chat.key_packages
         WHERE key_package_ref=$1
         FOR SHARE
        "#,
    )
    .bind(&key_package_ref)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AcceptanceFacadeError::InvalidCanonicalMaterial)?;
    let wrapper_bytes: Vec<u8> = package.try_get("wrapper_bytes")?;
    let wrapper_sha256: Vec<u8> = package.try_get("wrapper_sha256")?;
    let package_status: String = package.try_get("status")?;
    if package.try_get::<String, _>("owner_did")? != transition_actor
        || package.try_get::<Uuid, _>("owner_device_id")? != transition_actor_device
        || package.try_get::<String, _>("owner_key_id")? != transition_actor_key
        || package.try_get::<i64, _>("owner_auth_generation")? != transition_actor_auth_generation
        || !recovery_package_terminal_state_is_consistent(
            &recovery_status,
            &reservation_status,
            &package_status,
            reservation_consumed_transition,
            package.try_get("terminal_transition_id")?,
            package.try_get("terminal_revocation_id")?,
            reservation_terminal_transition,
            reservation_terminal_revocation,
        )
        || wrapper_sha256.as_slice() != Sha256::digest(&wrapper_bytes).as_slice()
    {
        return Err(AcceptanceFacadeError::InvalidCanonicalMaterial);
    }
    let package_row_digest: Vec<u8> = sqlx::query_scalar(
        "SELECT digest(row_to_json(t)::text, 'sha256') FROM (SELECT * FROM chat.key_packages WHERE key_package_ref=$1 FOR SHARE) t",
    )
    .bind(&key_package_ref)
    .fetch_one(&mut **transaction)
    .await?;
    let response_bytes: Vec<u8> = sqlx::query_scalar("SELECT response_bytes FROM chat.idempotency_records WHERE principal_did=$1 AND endpoint_nsid=$2 AND operation_id=$3 FOR SHARE").bind(authority.subject().as_str()).bind(ENDPOINT).bind(operation_id).fetch_one(&mut **transaction).await?;
    let response = AcceptanceCanonicalResponse::new(response_bytes)?;
    let mut post_state = Sha256::new();
    post_state.update(REPLAY_POST_STATE_DOMAIN);
    bind(&mut post_state, &operation_id.as_bytes()[..]);
    bind(&mut post_state, &accepted_payload);
    bind(&mut post_state, &wrapper_bytes);
    bind(&mut post_state, &wrapper_sha256);
    bind(&mut post_state, &key_package_ref);
    bind(&mut post_state, recovery_request_id.as_bytes());
    bind(&mut post_state, &transition_row_digest);
    bind(&mut post_state, &entry_row_digest);
    bind(&mut post_state, &recovery_row_digest);
    bind(&mut post_state, &reservation_row_digest);
    bind(&mut post_state, &package_row_digest);
    let post_state_digest = post_state.finalize().into();
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    let mut proof = AcceptanceReplayPostStateProof {
        transaction_id: transaction_id.into_boxed_str(),
        operation_id,
        principal_did: authority.subject().as_str().to_owned().into_boxed_str(),
        endpoint_nsid: ENDPOINT.into(),
        mutation_kind: mutation.kind(),
        request_digest: *mutation.request_digest(),
        accepted_request_sha256: Sha256::digest(accepted).into(),
        signature: *mutation.signature(),
        post_state_digest,
        expected_response_sha256: *response.sha256(),
        expected_status: STATUS,
        seal: [0; 32],
    };
    proof.seal = proof.rederive_seal();
    Ok((proof, response))
}

fn bind(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn recovery_terminal_state_is_consistent(
    recovery_status: &str,
    reservation_status: &str,
    consumed_transition_id: Option<Uuid>,
    terminal_transition_id: Option<Uuid>,
    terminal_revocation_id: Option<Uuid>,
) -> bool {
    let package_status = match recovery_status {
        "open" => "reserved",
        "fulfilled" => "consumed",
        "cancelled" => "available",
        "superseded" if terminal_revocation_id.is_some() => "revoked",
        "superseded" => "available",
        "expired" => "expired",
        _ => "invalid",
    };
    if !crate::chat_protocol::validation::acceptance_replay_terminal_state_allowed(
        recovery_status,
        reservation_status,
        package_status,
    ) {
        return false;
    }
    match recovery_status {
        "open" => {
            reservation_status == "active"
                && consumed_transition_id.is_none()
                && terminal_transition_id.is_none()
                && terminal_revocation_id.is_none()
        }
        "fulfilled" => {
            reservation_status == "consumed"
                && consumed_transition_id.is_some()
                && terminal_transition_id.is_none()
                && terminal_revocation_id.is_none()
        }
        "superseded" | "cancelled" => {
            reservation_status == "released"
                && consumed_transition_id.is_none()
                && if recovery_status == "superseded" {
                    terminal_transition_id.is_some() ^ terminal_revocation_id.is_some()
                } else {
                    terminal_transition_id.is_none() && terminal_revocation_id.is_none()
                }
        }
        "expired" => {
            reservation_status == "expired"
                && consumed_transition_id.is_none()
                && terminal_transition_id.is_none()
                && terminal_revocation_id.is_none()
        }
        _ => false,
    }
}

fn recovery_package_terminal_state_is_consistent(
    recovery_status: &str,
    reservation_status: &str,
    package_status: &str,
    consumed_transition_id: Option<Uuid>,
    package_terminal_transition_id: Option<Uuid>,
    package_terminal_revocation_id: Option<Uuid>,
    reservation_terminal_transition_id: Option<Uuid>,
    reservation_terminal_revocation_id: Option<Uuid>,
) -> bool {
    if !crate::chat_protocol::validation::acceptance_replay_terminal_state_allowed(
        recovery_status,
        reservation_status,
        package_status,
    ) {
        return false;
    }
    match recovery_status {
        "open" => reservation_status == "active" && package_status == "reserved",
        "fulfilled" => {
            reservation_status == "consumed"
                && package_status == "consumed"
                && consumed_transition_id.is_some()
                && package_terminal_transition_id == consumed_transition_id
                && package_terminal_revocation_id.is_none()
        }
        "superseded" | "cancelled" => {
            reservation_status == "released"
                && if recovery_status == "cancelled" {
                    package_status == "available"
                        && package_terminal_transition_id.is_none()
                        && package_terminal_revocation_id.is_none()
                } else if reservation_terminal_transition_id.is_some() {
                    package_status == "available"
                        && package_terminal_transition_id.is_none()
                        && package_terminal_revocation_id.is_none()
                } else {
                    package_status == "revoked"
                        && package_terminal_transition_id.is_none()
                        && package_terminal_revocation_id == reservation_terminal_revocation_id
                }
        }
        "expired" => {
            reservation_status == "expired"
                && (package_status == "available" || package_status == "expired")
                && package_terminal_transition_id.is_none()
                && package_terminal_revocation_id.is_none()
        }
        _ => false,
    }
}
