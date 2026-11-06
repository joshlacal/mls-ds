// Business admission for the clean application-send and typing procedures.
//
// This module is deliberately transaction-scoped: authentication and the
// operation prelude have already consumed replay evidence and locked the
// actor authority before either function is called.  Conversation state and
// the actor's concrete MLS interval are then read under the same transaction
// and all coordinate fields are compared, rather than comparing only a
// generation or state version.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::{delivery, prelude::ScopeBoundBusinessAuthority};
use crate::chat_protocol::{
    relationship_policy::{PublicTransport, RelationshipAuthority},
    state_machine::{
        FederatedOperationAdmission, HydrationAuthority, LockedRegistrationProjection,
        StateMachineError,
    },
    transcript::{self, CanonicalValueRef, VerifiedSignedMutation},
    validation::CanonicalUuidV4,
};

#[derive(Debug)]
pub(crate) enum MessageDeliveryError {
    Database(sqlx::Error),
    InvalidApplicationMessage,
    InvalidCoordinates,
    ConversationNotFound,
    ConversationNotAccepted,
    NotAuthorized,
    DeviceNotLeaf,
    RecipientNotReady,
    RelationshipPolicyUnavailable,
    /// A relationship source could not answer now: nothing was decided.
    RelationshipSourceUnavailable,
    BlockedRelationship,
    RateLimited,
    BlobNotFound,
    BlobBindingConflict,
    IdempotencyConflict,
    Invariant,
}

impl From<sqlx::Error> for MessageDeliveryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Clone, Copy)]
struct Coordinate {
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    group_id: [u8; 32],
    epoch: i64,
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
}

struct Head {
    coordinate: Coordinate,
    next_seq: u64,
    kind: String,
    direct_did_low: Option<String>,
    direct_did_high: Option<String>,
    is_remote: bool,
    sequencer_ds: Option<String>,
    sequencer_term: i64,
}

fn uuid(value: Option<CanonicalValueRef<'_>>) -> Result<Uuid, MessageDeliveryError> {
    match value {
        Some(CanonicalValueRef::Uuid(value)) => Ok(Uuid::from_bytes(*value.as_bytes())),
        _ => Err(MessageDeliveryError::InvalidCoordinates),
    }
}
fn integer(value: Option<CanonicalValueRef<'_>>) -> Result<i64, MessageDeliveryError> {
    match value {
        Some(CanonicalValueRef::Integer(value)) => {
            i64::try_from(value).map_err(|_| MessageDeliveryError::InvalidCoordinates)
        }
        _ => Err(MessageDeliveryError::InvalidCoordinates),
    }
}
fn bytes32(value: Option<CanonicalValueRef<'_>>) -> Result<[u8; 32], MessageDeliveryError> {
    match value {
        Some(CanonicalValueRef::Bytes(value)) if value.len() == 32 => {
            Ok(value.try_into().expect("length checked"))
        }
        _ => Err(MessageDeliveryError::InvalidCoordinates),
    }
}

fn coordinate(object: transcript::ClosedObjectRef<'_>) -> Result<Coordinate, MessageDeliveryError> {
    Ok(Coordinate {
        conversation_id: uuid(object.get("conversationId"))?,
        generation: integer(object.get("generation"))?,
        state_version: integer(object.get("stateVersion"))?,
        group_id: bytes32(object.get("groupId"))?,
        epoch: integer(object.get("epoch"))?,
        group_context_hash: bytes32(object.get("groupContextHash"))?,
        confirmation_tag: bytes32(object.get("confirmationTag"))?,
    })
}

fn same(a: Coordinate, b: Coordinate) -> bool {
    a.conversation_id == b.conversation_id
        && a.generation == b.generation
        && a.state_version == b.state_version
        && a.group_id == b.group_id
        && a.epoch == b.epoch
        && a.group_context_hash == b.group_context_hash
        && a.confirmation_tag == b.confirmation_tag
}

async fn lock_head(
    tx: &mut Transaction<'_, Postgres>,
    expected: Coordinate,
) -> Result<Head, MessageDeliveryError> {
    let row = sqlx::query(
        "SELECT c.kind, c.direct_did_low, c.direct_did_high, c.next_entry_seq, c.current_generation, c.current_state_version, \
                c.is_remote, c.sequencer_ds, c.sequencer_term, \
                g.group_id, s.epoch, s.group_context_hash, s.confirmation_tag, c.lifecycle \
           FROM chat.conversations c \
           JOIN chat.generations g ON g.conversation_id=c.conversation_id AND g.generation=c.current_generation \
           JOIN chat.generation_states s ON s.conversation_id=c.conversation_id AND s.generation=c.current_generation AND s.state_version=c.current_state_version \
          WHERE c.conversation_id=$1 FOR UPDATE",
    )
    .bind(expected.conversation_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(MessageDeliveryError::ConversationNotFound)?;
    let lifecycle: String = row.try_get("lifecycle")?;
    let current = Coordinate {
        conversation_id: expected.conversation_id,
        generation: row.try_get("current_generation")?,
        state_version: row.try_get("current_state_version")?,
        group_id: row
            .try_get::<Vec<u8>, _>("group_id")?
            .try_into()
            .map_err(|_| MessageDeliveryError::Invariant)?,
        epoch: row.try_get("epoch")?,
        group_context_hash: row
            .try_get::<Vec<u8>, _>("group_context_hash")?
            .try_into()
            .map_err(|_| MessageDeliveryError::Invariant)?,
        confirmation_tag: row
            .try_get::<Vec<u8>, _>("confirmation_tag")?
            .try_into()
            .map_err(|_| MessageDeliveryError::Invariant)?,
    };
    if lifecycle != "active" || !same(current, expected) {
        return Err(MessageDeliveryError::InvalidCoordinates);
    }
    if super::core::is_conversation_quarantined(tx, expected.conversation_id).await? {
        return Err(MessageDeliveryError::IdempotencyConflict);
    }
    let next_seq: i64 = row.try_get("next_entry_seq")?;
    Ok(Head {
        coordinate: current,
        next_seq: u64::try_from(next_seq).map_err(|_| MessageDeliveryError::Invariant)?,
        kind: row.try_get("kind")?,
        direct_did_low: row.try_get("direct_did_low")?,
        direct_did_high: row.try_get("direct_did_high")?,
        is_remote: row.try_get("is_remote")?,
        sequencer_ds: row.try_get("sequencer_ds")?,
        sequencer_term: row.try_get("sequencer_term")?,
    })
}

async fn require_current_leaf(
    tx: &mut Transaction<'_, Postgres>,
    coordinate: Coordinate,
    authority: &ScopeBoundBusinessAuthority,
) -> Result<(), MessageDeliveryError> {
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.application_intervals \
          WHERE conversation_id=$1 AND generation=$2 AND recipient_did=$3 AND recipient_device_id=$4 \
            AND start_seq <= (SELECT next_entry_seq-1 FROM chat.conversations WHERE conversation_id=$1) \
            AND (terminal_seq IS NULL OR terminal_seq >= (SELECT next_entry_seq-1 FROM chat.conversations WHERE conversation_id=$1)) \
            AND opening_state_version <= $5)",
    )
    .bind(coordinate.conversation_id)
    .bind(coordinate.generation)
    .bind(authority.actor_did())
    .bind(authority.actor_device_id())
    .bind(coordinate.state_version)
    .fetch_one(&mut **tx)
    .await?;
    if present {
        Ok(())
    } else {
        Err(MessageDeliveryError::DeviceNotLeaf)
    }
}

/// The head is already locked and its full signed coordinate validated. Do
/// not discover and acquire additional device locks here: an audience absent
/// from the canonical pre-head scope must reject before any business write.
async fn require_locked_application_audience(
    tx: &mut Transaction<'_, Postgres>,
    coordinate: Coordinate,
    seq: u64,
    scope: &ScopeBoundBusinessAuthority,
) -> Result<(), MessageDeliveryError> {
    let seq = i64::try_from(seq).map_err(|_| MessageDeliveryError::Invariant)?;
    let audience: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT recipient_did,recipient_device_id FROM chat.application_intervals \
         WHERE conversation_id=$1 AND generation=$2 AND start_seq<=$3 \
           AND (terminal_seq IS NULL OR terminal_seq>=$3) \
         ORDER BY convert_to(recipient_did,'UTF8'),uuid_send(recipient_device_id) LIMIT 101",
    )
    .bind(coordinate.conversation_id)
    .bind(coordinate.generation)
    .bind(seq)
    .fetch_all(&mut **tx)
    .await?;
    if audience.is_empty()
        || audience.len() > 100
        || audience.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(MessageDeliveryError::InvalidCoordinates);
    }
    if !audience
        .iter()
        .any(|(did, id)| did == scope.actor_did() && *id == scope.actor_device_id())
    {
        return Err(MessageDeliveryError::DeviceNotLeaf);
    }
    if audience.iter().any(|(did, id)| {
        !scope
            .devices()
            .iter()
            .any(|locked| locked.user_did() == did && locked.device_id() == *id)
    }) {
        return Err(MessageDeliveryError::InvalidCoordinates);
    }
    Ok(())
}

async fn require_recipient_ready(
    tx: &mut Transaction<'_, Postgres>,
    coordinate: Coordinate,
    authority: &ScopeBoundBusinessAuthority,
    head: &Head,
) -> Result<(), MessageDeliveryError> {
    // A sender must never be able to publish to a conversation with no other
    // concrete leaf.  Direct conversations require the peer; groups require
    // one current recipient leaf (remaining leaves may continue after removal).
    let direct_recipient = if head.kind == "direct" {
        let low = head
            .direct_did_low
            .as_deref()
            .ok_or(MessageDeliveryError::Invariant)?;
        let high = head
            .direct_did_high
            .as_deref()
            .ok_or(MessageDeliveryError::Invariant)?;
        let actor = authority.actor_did();
        Some(
            if actor == low {
                high
            } else if actor == high {
                low
            } else {
                return Err(MessageDeliveryError::ConversationNotAccepted);
            }
            .to_owned(),
        )
    } else {
        None
    };
    let ready: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.participants actor_p \
          WHERE actor_p.conversation_id=$1 AND actor_p.user_did=$3 \
            AND actor_p.current_membership AND actor_p.status='active' AND \
                (actor_p.role IN ('member','admin')) AND \
            EXISTS (SELECT 1 FROM chat.application_intervals i \
              JOIN chat.participants recipient_p ON recipient_p.conversation_id=i.conversation_id \
                AND recipient_p.user_did=i.recipient_did \
              WHERE i.conversation_id=$1 AND i.generation=$2 \
                AND recipient_p.current_membership AND recipient_p.status='active' \
                AND (recipient_p.accepted_at IS NOT NULL OR recipient_p.invitation_transition_id IS NULL) \
                AND (($4::text IS NULL AND i.recipient_did <> $3) OR ($4::text IS NOT NULL AND i.recipient_did = $4)) \
                AND i.start_seq <= (SELECT next_entry_seq-1 FROM chat.conversations WHERE conversation_id=$1) \
                AND (i.terminal_seq IS NULL OR i.terminal_seq >= (SELECT next_entry_seq-1 FROM chat.conversations WHERE conversation_id=$1))))",
    )
    .bind(coordinate.conversation_id)
    .bind(coordinate.generation)
    .bind(authority.actor_did())
    .bind(direct_recipient)
    .fetch_one(&mut **tx)
    .await?;
    if ready {
        Ok(())
    } else {
        Err(MessageDeliveryError::RecipientNotReady)
    }
}

async fn require_relationship_policy<T: PublicTransport>(
    tx: &mut Transaction<'_, Postgres>,
    authority: &ScopeBoundBusinessAuthority,
    coordinate: Coordinate,
    relationship_authority: &RelationshipAuthority<T>,
) -> Result<(), MessageDeliveryError> {
    require_traffic_policy(
        tx,
        coordinate.conversation_id,
        authority.trusted_instant(),
        relationship_authority,
        |hydration| hydration.locked_registration_from_scope_authority(authority),
    )
    .await
}

/// [`send`]'s traffic check for a group application send its member's home
/// `caller_ds` relayed here: the actor is `mutation`'s verified signer, bound
/// to this transaction, which already locked the head and that member's
/// device. The caller writes nothing before it passes.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn require_relayed_traffic_policy<T: PublicTransport>(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    caller_ds: &str,
    mutation: &VerifiedSignedMutation,
    message_id: Uuid,
    entry_id: Uuid,
    signed_bytes: &[u8],
    trusted_now: DateTime<Utc>,
    relationship_authority: &RelationshipAuthority<T>,
) -> Result<(), MessageDeliveryError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **tx)
        .await?;
    let admission = FederatedOperationAdmission::seal(
        mutation.actor_did().clone(),
        mutation.actor_device_id().clone(),
        mutation.key_id().clone(),
        *mutation.historical_public_key(),
        mutation.auth_generation(),
        trusted_now,
        transaction_id,
        crate::identity::canonical_did(caller_ds).to_owned(),
        conversation_id,
        entry_id,
        Sha256::digest(signed_bytes).into(),
        message_id,
        "blue.catbird.chat.sendMessage".to_owned(),
        *mutation.request_digest(),
        *mutation.signature(),
    )
    .map_err(|error| {
        tracing::error!(?error, "relayed traffic admission failed");
        MessageDeliveryError::RelationshipPolicyUnavailable
    })?;
    require_traffic_policy(
        tx,
        conversation_id,
        trusted_now,
        relationship_authority,
        |hydration| hydration.locked_registration_from_federated_admission(&admission),
    )
    .await
}

/// The traffic relationship check of the actor `registration` binds, over the
/// conversation whose head this transaction locked: a block is
/// `BlockedRelationship`.
async fn require_traffic_policy<T: PublicTransport>(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    locked_at: DateTime<Utc>,
    relationship_authority: &RelationshipAuthority<T>,
    registration: impl FnOnce(
        &HydrationAuthority,
    ) -> Result<LockedRegistrationProjection, StateMachineError>,
) -> Result<(), MessageDeliveryError> {
    let aggregate = super::core::hydrate_locked_conversation_state(tx, conversation_id, locked_at)
        .await
        .map_err(hydration_failure)?;
    let hydration = HydrationAuthority::from_locked_conversation(&aggregate).map_err(|error| {
        tracing::error!(?error, "traffic hydration authority failed");
        MessageDeliveryError::RelationshipPolicyUnavailable
    })?;
    let registration = registration(&hydration).map_err(|error| {
        tracing::error!(?error, "traffic registration authority failed");
        MessageDeliveryError::RelationshipPolicyUnavailable
    })?;
    let fallback = super::relationship::seal_traffic_fallback_scope(&aggregate, &registration)
        .map_err(relationship_failure)?;
    let (projection, decision) =
        super::relationship::load_fallback_traffic_projection(tx, fallback, relationship_authority)
            .await
            .map_err(relationship_failure)?
            .ok_or(MessageDeliveryError::RelationshipPolicyUnavailable)?;
    super::relationship::consume_locked_traffic_projection(
        &projection,
        &decision,
        &aggregate,
        &registration,
        relationship_authority,
    )
    .map_err(|error| match error {
        super::relationship::RelationshipConsumptionError::PolicyDenied => {
            MessageDeliveryError::BlockedRelationship
        }
        super::relationship::RelationshipConsumptionError::InvalidWitness => {
            MessageDeliveryError::RelationshipPolicyUnavailable
        }
    })
}

/// The traffic check's conversation hydration failed. This DS's store failing,
/// at any depth, is storage; anything else leaves the policy unevaluated.
fn hydration_failure(error: super::core::ConversationStateHydrationError) -> MessageDeliveryError {
    use super::core::{
        ConversationHeadHydrationError as Head, ConversationStateHydrationError as State,
        IntervalHydrationError as Intervals, LeafHydrationError as Leaves,
        MetadataHydrationError as Metadata, ParticipantHydrationError as Participants,
        ProducerHydrationError as Producer, PublicStateHydrationError as PublicState,
        RecoveryHydrationError as Recovery, ResetLeaveHydrationError as ResetLeave,
        TerminalProofHydrationError as TerminalProofs, WelcomeHydrationError as Welcomes,
    };
    match error {
        State::Database(error)
        | State::Head(Head::Database(error))
        | State::PublicState(PublicState::Database(error))
        | State::Producer(Producer::Database(error))
        | State::Metadata(Metadata::Database(error))
        | State::Participants(Participants::Database(error))
        | State::Leaves(Leaves::Database(error))
        | State::Intervals(Intervals::Database(error))
        | State::RecoveryWork(Recovery::Database(error))
        | State::ResetWork(ResetLeave::Database(error))
        | State::LeaveWork(ResetLeave::Database(error))
        | State::Welcomes(Welcomes::Database(error))
        | State::TerminalProofs(TerminalProofs::Database(error)) => {
            MessageDeliveryError::Database(error)
        }
        error => {
            tracing::error!(?error, "traffic conversation hydration failed");
            MessageDeliveryError::RelationshipPolicyUnavailable
        }
    }
}

/// Sealing or loading the traffic projection failed. This DS's store failing
/// is storage; a source that could not answer now decided nothing; anything
/// else leaves the policy unevaluated.
fn relationship_failure(
    error: super::relationship::RelationshipRepositoryError,
) -> MessageDeliveryError {
    use super::relationship::RelationshipRepositoryError as R;
    match error {
        R::Database(error) => MessageDeliveryError::Database(error),
        R::Unavailable => MessageDeliveryError::RelationshipSourceUnavailable,
        error @ (R::InvalidProjection | R::InvalidAuthorityConfiguration(_)) => {
            tracing::error!(?error, "traffic relationship policy could not be evaluated");
            MessageDeliveryError::RelationshipPolicyUnavailable
        }
    }
}

fn validate_application_message(
    projection: &transcript::ApplicationSendProjection<'_>,
) -> Result<(), MessageDeliveryError> {
    let message = projection.application_message();
    let bytes = match message.get("bytes") {
        Some(CanonicalValueRef::Bytes(v)) => v,
        _ => return Err(MessageDeliveryError::InvalidApplicationMessage),
    };
    let hash = match message.get("sha256") {
        Some(CanonicalValueRef::Bytes(v)) if v.len() == 32 => v,
        _ => return Err(MessageDeliveryError::InvalidApplicationMessage),
    };
    if Sha256::digest(bytes).as_slice() != hash
        || !matches!(
            message.get("framing"),
            Some(CanonicalValueRef::Text("mlsMessage"))
        )
        || !matches!(
            message.get("contentType"),
            Some(CanonicalValueRef::Text("privateMessageApplication"))
        )
    {
        return Err(MessageDeliveryError::InvalidApplicationMessage);
    }
    Ok(())
}

fn validate_artifacts(
    projection: &transcript::ApplicationSendProjection<'_>,
    coordinate: Coordinate,
    message_id: Uuid,
    expected_sender_did: &str,
    expected_sender_device_id: Uuid,
    expected_sender_public_key: &[u8],
) -> Result<Option<transcript::VerifiedApplicationArchive>, MessageDeliveryError> {
    let aad = projection.aad();
    let aad_conversation = match aad.get("conversationId") {
        Some(CanonicalValueRef::Bytes(v)) if v.len() == 16 => {
            Uuid::from_slice(v).map_err(|_| MessageDeliveryError::InvalidApplicationMessage)?
        }
        _ => return Err(MessageDeliveryError::InvalidApplicationMessage),
    };
    let aad_message = match aad.get("messageId") {
        Some(CanonicalValueRef::Bytes(v)) if v.len() == 16 => {
            Uuid::from_slice(v).map_err(|_| MessageDeliveryError::InvalidApplicationMessage)?
        }
        _ => return Err(MessageDeliveryError::InvalidApplicationMessage),
    };
    let aad_prior = match aad.get("prior") {
        Some(CanonicalValueRef::Object(value)) => value,
        _ => return Err(MessageDeliveryError::InvalidApplicationMessage),
    };
    let prior_conversation = match aad_prior.get("conversationId") {
        Some(CanonicalValueRef::Bytes(v)) if v.len() == 16 => {
            Uuid::from_slice(v).map_err(|_| MessageDeliveryError::InvalidApplicationMessage)?
        }
        _ => return Err(MessageDeliveryError::InvalidApplicationMessage),
    };
    let prior = Coordinate {
        conversation_id: prior_conversation,
        generation: integer(aad_prior.get("generation"))?,
        state_version: integer(aad_prior.get("stateVersion"))?,
        group_id: bytes32(aad_prior.get("groupId"))?,
        epoch: integer(aad_prior.get("epoch"))?,
        group_context_hash: bytes32(aad_prior.get("groupContextHash"))?,
        confirmation_tag: bytes32(aad_prior.get("confirmationTag"))?,
    };
    if !matches!(
        aad.get("protocolVersion"),
        Some(CanonicalValueRef::Text("1"))
    ) || aad_conversation != coordinate.conversation_id
        || aad_message != message_id
        || integer(aad.get("generation"))? != coordinate.generation
        || !matches!(
            aad_prior.get("lifecycle"),
            Some(CanonicalValueRef::Text("active"))
        )
        || !same(prior, coordinate)
    {
        return Err(MessageDeliveryError::InvalidApplicationMessage);
    }
    if !projection.blob_bindings().is_empty() {
        return Err(MessageDeliveryError::BlobNotFound);
    }
    transcript::verify_application_archive_attestation(
        aad,
        expected_sender_did,
        expected_sender_device_id,
        expected_sender_public_key,
        coordinate.conversation_id,
        message_id,
    )
    .map_err(|_| MessageDeliveryError::InvalidApplicationMessage)
}

fn verified_mutation(
    authority: &crate::chat_protocol::dpop::VerifiedChatDeviceRequest,
    scope: &ScopeBoundBusinessAuthority,
) -> Result<VerifiedSignedMutation, MessageDeliveryError> {
    let bytes = authority
        .mutation()
        .and_then(|m| m.accepted_wrapper_bytes())
        .ok_or(MessageDeliveryError::Invariant)?;
    let key = scope
        .actor_signing_public_key()
        .ok_or(MessageDeliveryError::Invariant)?;
    transcript::decode_and_verify_signed_mutation(bytes, key)
        .map_err(|_| MessageDeliveryError::InvalidApplicationMessage)
}

#[allow(dead_code)]
pub(crate) async fn send<T: PublicTransport>(
    tx: &mut Transaction<'_, Postgres>,
    authority: &crate::chat_protocol::dpop::VerifiedChatDeviceRequest,
    scope: &ScopeBoundBusinessAuthority,
    relationship_authority: &RelationshipAuthority<T>,
) -> Result<(Vec<u8>, Option<i64>), MessageDeliveryError> {
    send_with_receipt_signer(tx, authority, scope, relationship_authority, None).await
}

pub(crate) async fn send_with_receipt_signer<T: PublicTransport>(
    tx: &mut Transaction<'_, Postgres>,
    authority: &crate::chat_protocol::dpop::VerifiedChatDeviceRequest,
    scope: &ScopeBoundBusinessAuthority,
    relationship_authority: &RelationshipAuthority<T>,
    i13_signer: Option<&crate::federation::receipt::I13ReceiptSigner>,
) -> Result<(Vec<u8>, Option<i64>), MessageDeliveryError> {
    let mutation = verified_mutation(&authority, &scope)?;
    let projection = match mutation.projection() {
        transcript::VerifiedMutationProjection::ApplicationSend(p) => p,
        _ => return Err(MessageDeliveryError::Invariant),
    };
    let expected = coordinate(projection.prior())?;
    let head = lock_head(tx, expected).await?;
    require_current_leaf(tx, head.coordinate, &scope).await?;
    // A replica cannot allocate an authoritative group sequence. Its ordinary
    // federation outbox is intentionally disabled, so fail before any append.
    if head.kind == "group" && head.is_remote {
        return Err(MessageDeliveryError::NotAuthorized);
    }
    require_locked_application_audience(tx, head.coordinate, head.next_seq, scope).await?;
    require_recipient_ready(tx, head.coordinate, &scope, &head).await?;
    require_relationship_policy(tx, scope, head.coordinate, relationship_authority).await?;
    let message_id = Uuid::from_bytes(*projection.message_id().as_bytes());
    validate_application_message(&projection)?;
    let actor_signing_public_key = scope
        .actor_signing_public_key()
        .ok_or(MessageDeliveryError::Invariant)?;
    let archive = validate_artifacts(
        &projection,
        expected,
        message_id,
        scope.actor_did(),
        scope.actor_device_id(),
        actor_signing_public_key,
    )?;
    let minted_entry_uuid = crate::sim_hooks::mint_entry_uuid_v4(
        b"chat.sendMessage",
        &[
            expected.conversation_id.as_bytes(),
            &head.next_seq.to_be_bytes(),
            message_id.as_bytes(),
        ],
    );
    let entry_id = CanonicalUuidV4::parse(&minted_entry_uuid.to_string())
        .map_err(|_| MessageDeliveryError::Invariant)?;
    let conversation_id = CanonicalUuidV4::parse(&expected.conversation_id.to_string())
        .map_err(|_| MessageDeliveryError::Invariant)?;
    let entry_id_text = entry_id.as_str().to_owned();
    let conversation_id_text = conversation_id.as_str().to_owned();
    let entry = transcript::build_verified_application_entry(
        verified_mutation(&authority, &scope)?,
        entry_id,
        conversation_id,
        head.next_seq,
        authority.trusted_instant(),
    )
    .map_err(|_| MessageDeliveryError::Invariant)?;
    let signed_request = serde_json::from_slice::<serde_json::Value>(
        authority
            .mutation()
            .and_then(|m| m.accepted_wrapper_bytes())
            .ok_or(MessageDeliveryError::Invariant)?,
    )
    .map_err(|_| MessageDeliveryError::Invariant)?;
    let i13_receipt_json = match (archive, i13_signer) {
        (Some(archive), Some(signer)) => {
            let epoch_u64 =
                u64::try_from(expected.epoch).map_err(|_| MessageDeliveryError::Invariant)?;
            let generation_u64 =
                u64::try_from(expected.generation).map_err(|_| MessageDeliveryError::Invariant)?;
            let sender_device_text = scope.actor_device_id().to_string();
            let signed_receipt = signer
                .sign_application_receipt(
                    &conversation_id_text,
                    &head.coordinate.group_id,
                    epoch_u64,
                    scope.actor_did(),
                    &sender_device_text,
                    &entry_id_text,
                    archive.commitment(),
                    head.next_seq,
                    scope.trusted_instant().timestamp_millis(),
                )
                .map_err(|_| MessageDeliveryError::Invariant)?;
            Some(
                crate::federation::receipt::I13ReceiptSigner::receipt_wire_json(
                    &signed_receipt,
                    generation_u64,
                    scope.actor_did(),
                    &sender_device_text,
                ),
            )
        }
        _ => None,
    };
    let mut entry_obj = json!({
        "entryId": entry_id_text,
        "conversationId": conversation_id_text,
        "seq": head.next_seq,
        "signedRequest": signed_request,
        "receivedAt": authority.trusted_instant().as_str()
    });
    let mut response = json!({ "entry": entry_obj });
    if let Some(rcpt) = &i13_receipt_json {
        entry_obj["sequencerReceipt"] = rcpt.clone();
        response = json!({
            "entry": entry_obj,
            "sequencerReceipt": rcpt.clone(),
        });
    }
    let response_bytes = serde_json::to_vec(&response).map_err(|e| {
        tracing::error!("response serde error: {:?}", e);
        MessageDeliveryError::Invariant
    })?;
    let append = delivery::AppendEntry {
        conversation_id: expected.conversation_id,
        entry_id: Uuid::from_bytes(*entry.entry_id().as_bytes()),
        entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
        accepted_payload_bytes: entry.canonical_entry_bytes().to_vec(),
        accepted_payload_sha256: entry.accepted_payload_sha256().to_vec(),
        signed_request_bytes: authority
            .mutation()
            .and_then(|m| m.accepted_wrapper_bytes())
            .ok_or(MessageDeliveryError::Invariant)?
            .to_vec(),
        request_digest: entry.mutation().request_digest().to_vec(),
        signature: entry.mutation().signature().to_vec(),
        server_fields_bytes: serde_ipld_dagcbor::to_vec(&std::collections::BTreeMap::<
            String,
            String,
        >::new())
        .map_err(|_| MessageDeliveryError::Invariant)?,
        outer_entry_fingerprint: entry.outer_application_fingerprint().to_vec(),
        actor_did: scope.actor_did().to_owned(),
        actor_device_id: scope.actor_device_id(),
        actor_key_id: scope
            .actor_key_id()
            .ok_or(MessageDeliveryError::Invariant)?
            .to_owned(),
        actor_auth_generation: scope
            .actor_auth_generation()
            .ok_or(MessageDeliveryError::Invariant)?,
        generation: Some(expected.generation),
        state_version: Some(expected.state_version),
        transition_id: None,
        message_id: Some(message_id),
        received_at: scope.trusted_instant(),
    };
    let outcome = delivery::resolve_application_send(
        tx,
        &delivery::ApplicationSend {
            entry: append.clone(),
            signing_transcript_bytes: entry.mutation().transcript_bytes().to_vec(),
            outcome_bytes: response_bytes.clone(),
        },
        delivery::ApplicationSendDisposition::Accept,
    )
    .await
    .map_err(|e| match e {
        delivery::DeliveryRepositoryError::Database(e) => MessageDeliveryError::Database(e),
        delivery::DeliveryRepositoryError::MessageSendConflict => {
            MessageDeliveryError::IdempotencyConflict
        }
        _ => MessageDeliveryError::Invariant,
    })?;
    let seq = match outcome {
        delivery::ApplicationSendOutcome::Accepted { seq } => seq,
        delivery::ApplicationSendOutcome::Stale => {
            return Err(MessageDeliveryError::InvalidCoordinates)
        }
    };
    if seq != head.next_seq {
        return Err(MessageDeliveryError::Invariant);
    }
    if let Some(rcpt) = &i13_receipt_json {
        let rcpt_bytes = serde_json::to_vec(rcpt).map_err(|_| MessageDeliveryError::Invariant)?;
        delivery::set_entry_sequencer_receipt(tx, expected.conversation_id, seq, &rcpt_bytes)
            .await
            .map_err(|e| match e {
                delivery::DeliveryRepositoryError::Database(e) => MessageDeliveryError::Database(e),
                _ => MessageDeliveryError::Invariant,
            })?;
    }
    // A group's remote homes receive every entry, application ones included,
    // through the ordered `deliverGroupEntry` stream its handler queues; only
    // direct conversations replicate applications through `deliverMessage`.
    if !head.is_remote && head.kind != "group" {
        let _ =
            crate::chat_protocol::repository::federation::enqueue_clean_federation_message_jobs(
                tx,
                expected.conversation_id,
                &append,
                seq,
                head.sequencer_term as u64,
            )
            .await
            .map_err(|e| {
                tracing::error!(?e, "failed to enqueue clean federation message jobs");
                MessageDeliveryError::Invariant
            })?;
    }
    let event_position = delivery::append_message_available_event(
        tx,
        expected.conversation_id,
        expected.generation,
        seq,
        scope.trusted_instant(),
    )
    .await
    .map_err(|error| match error {
        delivery::DeliveryRepositoryError::Database(error) => MessageDeliveryError::Database(error),
        _ => MessageDeliveryError::Invariant,
    })?;
    Ok((response_bytes, Some(event_position)))
}

static TYPING_LAST: OnceLock<Mutex<HashMap<(Uuid, Uuid), (bool, DateTime<Utc>)>>> = OnceLock::new();
static TYPING_RATE: OnceLock<Mutex<HashMap<(Uuid, String, Uuid), DateTime<Utc>>>> = OnceLock::new();

fn admit_typing(
    conversation_id: Uuid,
    typing_id: Uuid,
    actor_did: &str,
    actor_device_id: Uuid,
    state: bool,
    now: DateTime<Utc>,
) -> Result<(), MessageDeliveryError> {
    // Ephemeral abuse/idempotency caches are a production optimization. A
    // deterministic worker must neither consult nor alter another worker's state.
    if crate::sim_hooks::is_deterministic_clock_active() {
        return Ok(());
    }
    let key = (conversation_id, typing_id);
    let rate_key = (conversation_id, actor_did.to_owned(), actor_device_id);
    let guard = TYPING_LAST.get_or_init(|| Mutex::new(HashMap::new()));
    let mut values = guard.lock().map_err(|_| MessageDeliveryError::Invariant)?;
    values.retain(|_, (_, sent_at)| now.signed_duration_since(*sent_at) < Duration::minutes(10));
    if let Some((previous, sent_at)) = values.get(&key) {
        if *previous != state {
            return Err(MessageDeliveryError::IdempotencyConflict);
        }
        if *previous == state && now.signed_duration_since(*sent_at) < Duration::seconds(1) {
            return Err(MessageDeliveryError::RateLimited);
        }
    }
    let rate_guard = TYPING_RATE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut rates = rate_guard
        .lock()
        .map_err(|_| MessageDeliveryError::Invariant)?;
    rates.retain(|_, sent_at| now.signed_duration_since(*sent_at) < Duration::minutes(10));
    if let Some(sent_at) = rates.get(&rate_key) {
        if now.signed_duration_since(*sent_at) < Duration::milliseconds(250) {
            return Err(MessageDeliveryError::RateLimited);
        }
    }
    values.insert(key, (state, now));
    rates.insert(rate_key, now);
    Ok(())
}

pub(crate) async fn typing<T: PublicTransport>(
    tx: &mut Transaction<'_, Postgres>,
    authority: &crate::chat_protocol::dpop::VerifiedChatDeviceRequest,
    scope: &ScopeBoundBusinessAuthority,
    relationship_authority: &RelationshipAuthority<T>,
) -> Result<Vec<u8>, MessageDeliveryError> {
    let mutation = verified_mutation(authority, scope)?;
    let projection = match mutation.projection() {
        transcript::VerifiedMutationProjection::Typing(p) => p,
        _ => return Err(MessageDeliveryError::Invariant),
    };
    let expected = coordinate(projection.coordinates())?;
    let head = lock_head(tx, expected).await?;
    require_current_leaf(tx, head.coordinate, scope).await?;
    require_recipient_ready(tx, head.coordinate, scope, &head).await?;
    require_relationship_policy(tx, scope, head.coordinate, relationship_authority).await?;
    let now = scope.trusted_instant();
    let state = projection.is_typing();
    admit_typing(
        expected.conversation_id,
        Uuid::from_bytes(*projection.typing_id().as_bytes()),
        scope.actor_did(),
        scope.actor_device_id(),
        state,
        now,
    )?;
    let expires = now + Duration::seconds(8);
    let response = json!({"typing": {"typingId": projection.typing_id().as_str(), "conversationId": expected.conversation_id.to_string(), "actorDid": scope.actor_did(), "actorDeviceId": scope.actor_device_id(), "isTyping": state, "expiresAt": expires.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)}});
    serde_json::to_vec(&response).map_err(|_| MessageDeliveryError::Invariant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_typing_does_not_consult_or_mutate_process_state() {
        use crate::sim_hooks::{with_ds_clock, ManualDsClock};
        use std::sync::Arc;

        let now = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let conversation = Uuid::new_v4();
        let typing = Uuid::new_v4();
        let device = Uuid::new_v4();
        let did = "did:plc:typing-cache-isolation";
        assert!(admit_typing(conversation, typing, did, device, false, now).is_ok());
        with_ds_clock(Arc::new(ManualDsClock::new(now)), || {
            assert!(admit_typing(conversation, typing, did, device, true, now).is_ok());
            assert!(admit_typing(conversation, typing, did, device, true, now).is_ok());
        });
        assert!(matches!(
            admit_typing(conversation, typing, did, device, true, now),
            Err(MessageDeliveryError::IdempotencyConflict)
        ));
        assert!(matches!(
            admit_typing(conversation, typing, did, device, false, now),
            Err(MessageDeliveryError::RateLimited)
        ));
    }

    /// The traffic check's own store failing, at any hydration depth or while
    /// loading its projection, is storage; a relationship source that could
    /// not answer now is its own retryable failure.
    #[test]
    fn traffic_policy_failures_keep_their_class() {
        use super::super::core::{
            ConversationHeadHydrationError as Head, ConversationStateHydrationError as State,
            ParticipantHydrationError as Participants,
        };
        use super::super::relationship::RelationshipRepositoryError as R;
        for error in [
            State::Head(Head::Database(sqlx::Error::PoolTimedOut)),
            State::Participants(Participants::Database(sqlx::Error::PoolTimedOut)),
        ] {
            assert!(matches!(
                hydration_failure(error),
                MessageDeliveryError::Database(_)
            ));
        }
        assert!(matches!(
            hydration_failure(State::ReadSetMismatch),
            MessageDeliveryError::RelationshipPolicyUnavailable
        ));
        assert!(matches!(
            relationship_failure(R::Database(sqlx::Error::PoolTimedOut)),
            MessageDeliveryError::Database(_)
        ));
        assert!(matches!(
            relationship_failure(R::Unavailable),
            MessageDeliveryError::RelationshipSourceUnavailable
        ));
        assert!(matches!(
            relationship_failure(R::InvalidProjection),
            MessageDeliveryError::RelationshipPolicyUnavailable
        ));
    }
}
