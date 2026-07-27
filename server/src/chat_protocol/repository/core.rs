// Non-forgeable lock witnesses for clean-chat state planning.
//
// Constructors intentionally remain private to this module. The production SQL
// hydrators below construct these values only from rows read under `FOR UPDATE`
// in the caller-owned transaction and must retain that transaction through
// application of the resulting persistence plan.
//
// Regular `//` comments (not `//!`) so the `include!`-based integration harness
// (`tests/chat_protocol_conversation_substrate.rs`) can inline this file as a
// module, matching the sibling repository writers.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use super::super::transcript::{
    decode_and_verify_signed_mutation, decode_canonical_signed_mutation, CanonicalValueRef,
    SignedMutationKind, VerifiedMutationProjection,
};
use super::super::{
    snapshot::{
        PublicGroupSnapshotBinding, PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle,
    },
    state_machine::{
        acceptance_recovery_package_artifact_matches, classify_acceptance, classify_invitation,
        classify_role_producer, hydrate_conversation_state, metadata_binding_of_transition,
        recovery_fulfillment_terminal_matches, CloseKind, ConversationKind, ConversationState,
        ConversationStateHydration, DeviceIdentity, HistoricalRehydrationAuthority,
        HydrationAuthority, IntervalEndHydrationRow, IntervalHydrationRow, LeafHydrationRow,
        LeafRecoveryKind, LeaveRequestHydrationRow, LeaveRequestStatus, MetadataSnapshotBinding,
        OpeningKind, ParticipantHydrationRow, ParticipantRemovalEvidence, ParticipantRole,
        ParticipantStatus, PersistedControlAuthority, PrincipalId, RecoveryOriginHydrationRow,
        RecoveryRequestHydrationRow, RecoveryRequestStatus, RecoveryReservationHydrationRow,
        RecoverySource, RequestEntryKind, RequestEvidence, ReservationStatus,
        ResetRequestHydrationRow, ResetRequestStatus, ServerTimestamp, StateMachineError,
        TerminalProofHydrationRow, TransitionEvidence, WelcomeHydrationRow, WelcomeStatus,
        WorkTerminalHydrationRow,
    },
    validation::{BareDid, KeyThumbprint},
    wire::{validate_key_package, KeyPackageValidationPolicy, MAX_KEY_PACKAGE_WIRE_BYTES},
};

const MAX_PROTOCOL_INTEGER: u64 = 9_007_199_254_740_991;

/// One exact relationship-projection allocation minted by PostgreSQL. The
/// opaque UUID identifies the durable allocation claim while the sequence
/// value supplies global ordering. This pair is deliberately non-cloneable and
/// must survive collection until it is consumed by the persistence seal.
#[derive(Debug)]
pub(crate) struct AllocatedProjectionRevisionGuard {
    allocation_id: Uuid,
    projection_revision: u64,
}

impl AllocatedProjectionRevisionGuard {
    pub(super) fn from_database_allocation(
        allocation_id: Uuid,
        projection_revision: i64,
    ) -> Option<Self> {
        let projection_revision = u64::try_from(projection_revision)
            .ok()
            .filter(|value| (1..=MAX_PROTOCOL_INTEGER).contains(value))?;
        if !uuid_is_canonical_v4(allocation_id) {
            return None;
        }
        Some(Self {
            allocation_id,
            projection_revision,
        })
    }

    pub(crate) fn projection_revision(&self) -> u64 {
        self.projection_revision
    }

    pub(crate) fn into_allocation(self) -> (Uuid, u64) {
        (self.allocation_id, self.projection_revision)
    }

    #[cfg(test)]
    pub(crate) fn for_test(value: u64) -> Self {
        Self::from_database_allocation(
            Uuid::new_v4(),
            i64::try_from(value).expect("test revision fits i64"),
        )
        .expect("valid test projection allocation")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LockedRecoveryPackageStatus {
    Available,
    Reserved,
    Consumed,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LockedRecoveryPackageUse {
    AvailableSelection,
    ReservedFulfillment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LockedRevocationTargetStatus {
    Active,
    Revoked,
}

/// Transaction-bound invitation quota snapshot for one exact inviter and
/// exact newly-pending recipient set. Handlers cannot substitute a boolean or
/// reuse the projection for another roster.
#[derive(Debug)]
pub(crate) struct LockedInvitationQuotaGuard {
    transaction_id: String,
    inviter_did: String,
    new_recipient_dids: Vec<String>,
    current_pending: u64,
    quota_limit: u64,
    locked_at: DateTime<Utc>,
    durable_row_digest: [u8; 32],
}

impl LockedInvitationQuotaGuard {
    fn from_locked_row(
        transaction_id: String,
        inviter_did: String,
        new_recipient_dids: Vec<String>,
        current_pending: u64,
        quota_limit: u64,
        locked_at: DateTime<Utc>,
        durable_row_digest: [u8; 32],
    ) -> Option<Self> {
        if !canonical_transaction_id(&transaction_id)
            || BareDid::parse(&inviter_did).is_err()
            || new_recipient_dids
                .iter()
                .any(|did| BareDid::parse(did).is_err())
            || new_recipient_dids.windows(2).any(|pair| pair[0] >= pair[1])
            || quota_limit == 0
            || quota_limit > MAX_PROTOCOL_INTEGER
            || current_pending > MAX_PROTOCOL_INTEGER
            || locked_at.timestamp_millis() < 0
            || locked_at.timestamp_subsec_nanos() % 1_000_000 != 0
            || durable_row_digest
                != invitation_quota_guard_digest(
                    &transaction_id,
                    &inviter_did,
                    &new_recipient_dids,
                    current_pending,
                    quota_limit,
                    locked_at,
                )
        {
            return None;
        }
        Some(Self {
            transaction_id,
            inviter_did,
            new_recipient_dids,
            current_pending,
            quota_limit,
            locked_at,
            durable_row_digest,
        })
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn inviter_did(&self) -> &str {
        &self.inviter_did
    }
    pub(crate) fn new_recipient_dids(&self) -> &[String] {
        &self.new_recipient_dids
    }
    pub(crate) fn current_pending(&self) -> u64 {
        self.current_pending
    }
    pub(crate) fn quota_limit(&self) -> u64 {
        self.quota_limit
    }
    pub(crate) fn locked_at(&self) -> DateTime<Utc> {
        self.locked_at
    }
    pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
        &self.durable_row_digest
    }
    pub(crate) fn would_exceed(&self) -> bool {
        self.current_pending
            .checked_add(self.new_recipient_dids.len() as u64)
            .is_none_or(|next| next > self.quota_limit)
    }
}

fn invitation_quota_guard_digest(
    transaction_id: &str,
    inviter_did: &str,
    new_recipient_dids: &[String],
    current_pending: u64,
    quota_limit: u64,
    locked_at: DateTime<Utc>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-INVITATION-QUOTA\0");
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update((inviter_did.len() as u64).to_be_bytes());
    digest.update(inviter_did.as_bytes());
    digest.update((new_recipient_dids.len() as u64).to_be_bytes());
    for did in new_recipient_dids {
        digest.update((did.len() as u64).to_be_bytes());
        digest.update(did.as_bytes());
    }
    digest.update(current_pending.to_be_bytes());
    digest.update(quota_limit.to_be_bytes());
    digest.update(locked_at.timestamp_millis().to_be_bytes());
    digest.finalize().into()
}

/// Exact pending Welcome row locked after the conversation head in the same
/// transaction. The constructor accepts only the persisted Pending state;
/// terminal rows can never authorize acknowledgement, rejection, or expiry.
#[derive(Debug)]
pub(crate) struct LockedWelcomeGuard {
    transaction_id: String,
    conversation_id: Uuid,
    welcome_id: Uuid,
    recipient_did: String,
    recipient_device_id: Uuid,
    transition_seq: u64,
    coordinate: PublicGroupSnapshotCoordinate,
    recovery_request_id: Uuid,
    key_package_ref: [u8; 32],
    opaque_welcome: Vec<u8>,
    opaque_welcome_sha256: [u8; 32],
    expires_at: DateTime<Utc>,
    locked_at: DateTime<Utc>,
    durable_row_digest: [u8; 32],
}

impl LockedWelcomeGuard {
    #[allow(clippy::too_many_arguments)]
    fn from_locked_pending_row(
        transaction_id: String,
        conversation_id: Uuid,
        welcome_id: Uuid,
        recipient_did: String,
        recipient_device_id: Uuid,
        transition_seq: u64,
        coordinate: PublicGroupSnapshotCoordinate,
        recovery_request_id: Uuid,
        key_package_ref: [u8; 32],
        opaque_welcome: Vec<u8>,
        opaque_welcome_sha256: [u8; 32],
        expires_at: DateTime<Utc>,
        locked_at: DateTime<Utc>,
        durable_row_digest: [u8; 32],
    ) -> Option<Self> {
        if !canonical_transaction_id(&transaction_id)
            || !uuid_is_canonical_v4(conversation_id)
            || !uuid_is_canonical_v4(welcome_id)
            || !uuid_is_canonical_v4(recipient_device_id)
            || !uuid_is_canonical_v4(recovery_request_id)
            || BareDid::parse(&recipient_did).is_err()
            || !(1..=MAX_PROTOCOL_INTEGER).contains(&transition_seq)
            || coordinate.conversation_id() != conversation_id.as_bytes()
            || key_package_ref == [0; 32]
            || opaque_welcome.is_empty()
            || <[u8; 32]>::from(Sha256::digest(&opaque_welcome)) != opaque_welcome_sha256
            || expires_at.timestamp_millis() < 0
            || expires_at.timestamp_subsec_nanos() % 1_000_000 != 0
            || locked_at.timestamp_millis() < 0
            || locked_at.timestamp_subsec_nanos() % 1_000_000 != 0
            || durable_row_digest
                != locked_welcome_digest(
                    &transaction_id,
                    conversation_id,
                    welcome_id,
                    &recipient_did,
                    recipient_device_id,
                    transition_seq,
                    &coordinate,
                    recovery_request_id,
                    &key_package_ref,
                    &opaque_welcome,
                    &opaque_welcome_sha256,
                    expires_at,
                    locked_at,
                )
        {
            return None;
        }
        Some(Self {
            transaction_id,
            conversation_id,
            welcome_id,
            recipient_did,
            recipient_device_id,
            transition_seq,
            coordinate,
            recovery_request_id,
            key_package_ref,
            opaque_welcome,
            opaque_welcome_sha256,
            expires_at,
            locked_at,
            durable_row_digest,
        })
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn conversation_id(&self) -> Uuid {
        self.conversation_id
    }
    pub(crate) fn welcome_id(&self) -> Uuid {
        self.welcome_id
    }
    pub(crate) fn recipient_did(&self) -> &str {
        &self.recipient_did
    }
    pub(crate) fn recipient_device_id(&self) -> Uuid {
        self.recipient_device_id
    }
    pub(crate) fn transition_seq(&self) -> u64 {
        self.transition_seq
    }
    pub(crate) fn coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.coordinate
    }
    pub(crate) fn recovery_request_id(&self) -> Uuid {
        self.recovery_request_id
    }
    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }
    pub(crate) fn opaque_welcome(&self) -> &[u8] {
        &self.opaque_welcome
    }
    pub(crate) fn opaque_welcome_sha256(&self) -> &[u8; 32] {
        &self.opaque_welcome_sha256
    }
    pub(crate) fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    pub(crate) fn locked_at(&self) -> DateTime<Utc> {
        self.locked_at
    }
    pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
        &self.durable_row_digest
    }
}

#[allow(clippy::too_many_arguments)]
fn locked_welcome_digest(
    transaction_id: &str,
    conversation_id: Uuid,
    welcome_id: Uuid,
    recipient_did: &str,
    recipient_device_id: Uuid,
    transition_seq: u64,
    coordinate: &PublicGroupSnapshotCoordinate,
    recovery_request_id: Uuid,
    key_package_ref: &[u8; 32],
    opaque_welcome: &[u8],
    opaque_welcome_sha256: &[u8; 32],
    expires_at: DateTime<Utc>,
    locked_at: DateTime<Utc>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-PENDING-WELCOME\0");
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update(conversation_id.as_bytes());
    digest.update(welcome_id.as_bytes());
    digest.update((recipient_did.len() as u64).to_be_bytes());
    digest.update(recipient_did.as_bytes());
    digest.update(recipient_device_id.as_bytes());
    digest.update(transition_seq.to_be_bytes());
    digest.update(coordinate.generation().to_be_bytes());
    digest.update(coordinate.state_version().to_be_bytes());
    digest.update(coordinate.group_id());
    digest.update(coordinate.epoch().to_be_bytes());
    digest.update(coordinate.group_context_hash());
    digest.update(coordinate.confirmation_tag());
    digest.update([match coordinate.lifecycle() {
        super::super::snapshot::PublicGroupSnapshotLifecycle::Active => 1,
        super::super::snapshot::PublicGroupSnapshotLifecycle::Superseded => 2,
    }]);
    digest.update(recovery_request_id.as_bytes());
    digest.update(key_package_ref);
    digest.update((opaque_welcome.len() as u64).to_be_bytes());
    digest.update(opaque_welcome);
    digest.update(opaque_welcome_sha256);
    digest.update([1]); // exact persisted Pending status
    digest.update(expires_at.timestamp_millis().to_be_bytes());
    digest.update(locked_at.timestamp_millis().to_be_bytes());
    digest.finalize().into()
}

/// Exact target registration row locked for a device-revocation decision.
/// This witness is consumed by state planning and cannot be cloned or minted
/// by a handler from loose identity/generation/status fields.
#[derive(Debug)]
pub(crate) struct LockedRevocationTargetGuard {
    transaction_id: String,
    target_did: String,
    target_device_id: Uuid,
    target_auth_generation: u64,
    status: LockedRevocationTargetStatus,
    locked_at: DateTime<Utc>,
    durable_row_digest: [u8; 32],
}

impl LockedRevocationTargetGuard {
    #[allow(clippy::too_many_arguments)]
    fn from_locked_row(
        transaction_id: String,
        target_did: String,
        target_device_id: Uuid,
        target_auth_generation: i64,
        status: LockedRevocationTargetStatus,
        locked_at: DateTime<Utc>,
        durable_row_digest: [u8; 32],
    ) -> Option<Self> {
        let target_auth_generation = u64::try_from(target_auth_generation)
            .ok()
            .filter(|value| (1..=MAX_PROTOCOL_INTEGER).contains(value))?;
        if !canonical_transaction_id(&transaction_id)
            || BareDid::parse(&target_did).is_err()
            || !uuid_is_canonical_v4(target_device_id)
            || locked_at.timestamp_millis() < 0
            || locked_at.timestamp_subsec_nanos() % 1_000_000 != 0
            || durable_row_digest
                != revocation_target_guard_digest(
                    &transaction_id,
                    &target_did,
                    target_device_id,
                    target_auth_generation,
                    status,
                    locked_at,
                )
        {
            return None;
        }
        Some(Self {
            transaction_id,
            target_did,
            target_device_id,
            target_auth_generation,
            status,
            locked_at,
            durable_row_digest,
        })
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn target_did(&self) -> &str {
        &self.target_did
    }
    pub(crate) fn target_device_id(&self) -> Uuid {
        self.target_device_id
    }
    pub(crate) fn target_auth_generation(&self) -> u64 {
        self.target_auth_generation
    }
    pub(crate) fn status(&self) -> LockedRevocationTargetStatus {
        self.status
    }
    pub(crate) fn locked_at(&self) -> DateTime<Utc> {
        self.locked_at
    }
    pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
        &self.durable_row_digest
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        transaction_id: String,
        target_did: String,
        target_device_id: Uuid,
        target_auth_generation: u64,
        status: LockedRevocationTargetStatus,
        locked_at: DateTime<Utc>,
    ) -> Self {
        let digest = revocation_target_guard_digest(
            &transaction_id,
            &target_did,
            target_device_id,
            target_auth_generation,
            status,
            locked_at,
        );
        Self::from_locked_row(
            transaction_id,
            target_did,
            target_device_id,
            i64::try_from(target_auth_generation).expect("test generation fits i64"),
            status,
            locked_at,
            digest,
        )
        .expect("valid test revocation target guard")
    }
}

fn revocation_target_guard_digest(
    transaction_id: &str,
    target_did: &str,
    target_device_id: Uuid,
    target_auth_generation: u64,
    status: LockedRevocationTargetStatus,
    locked_at: DateTime<Utc>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-REVOCATION-TARGET\0");
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update((target_did.len() as u64).to_be_bytes());
    digest.update(target_did.as_bytes());
    digest.update(target_device_id.as_bytes());
    digest.update(target_auth_generation.to_be_bytes());
    digest.update([match status {
        LockedRevocationTargetStatus::Active => 1,
        LockedRevocationTargetStatus::Revoked => 2,
    }]);
    digest.update(locked_at.timestamp_millis().to_be_bytes());
    digest.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LockedRevocationPackageManifest {
    key_package_ref: [u8; 32],
    status: LockedRecoveryPackageStatus,
    conversation_id: Option<Uuid>,
    request_id: Option<Uuid>,
    locked_row_digest: [u8; 32],
}

impl LockedRevocationPackageManifest {
    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }
    pub(crate) fn status(&self) -> LockedRecoveryPackageStatus {
        self.status
    }
    pub(crate) fn conversation_id(&self) -> Option<Uuid> {
        self.conversation_id
    }
    pub(crate) fn request_id(&self) -> Option<Uuid> {
        self.request_id
    }
    pub(crate) fn locked_row_digest(&self) -> &[u8; 32] {
        &self.locked_row_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LockedRevocationConversationManifest {
    conversation_id: Uuid,
    locked_head_digest: [u8; 32],
    open_recovery_request_ids: Vec<Uuid>,
    pending_welcome_ids: Vec<Uuid>,
    reserved_package_refs: Vec<[u8; 32]>,
}

impl LockedRevocationConversationManifest {
    pub(crate) fn conversation_id(&self) -> Uuid {
        self.conversation_id
    }
    pub(crate) fn locked_head_digest(&self) -> &[u8; 32] {
        &self.locked_head_digest
    }
    pub(crate) fn open_recovery_request_ids(&self) -> &[Uuid] {
        &self.open_recovery_request_ids
    }
    pub(crate) fn pending_welcome_ids(&self) -> &[Uuid] {
        &self.pending_welcome_ids
    }
    pub(crate) fn reserved_package_refs(&self) -> &[[u8; 32]] {
        &self.reserved_package_refs
    }
}

/// Exact live KeyPackage row locked target-first for a global revocation.
/// Available rows have no reservation provenance; Reserved rows bind the
/// owning conversation/request. Both become terminal Revoked with immutable
/// revocation provenance in the batch persistence plan.
#[derive(Debug)]
pub(crate) struct LockedRevocationPackageGuard {
    transaction_id: String,
    target_did: String,
    target_device_id: Uuid,
    target_key_id: String,
    target_auth_generation: u64,
    key_package_ref: [u8; 32],
    wrapper_sha256: [u8; 32],
    not_after: DateTime<Utc>,
    status: LockedRecoveryPackageStatus,
    conversation_id: Option<Uuid>,
    request_id: Option<Uuid>,
    locked_at: DateTime<Utc>,
    durable_row_digest: [u8; 32],
}

impl LockedRevocationPackageGuard {
    #[allow(clippy::too_many_arguments)]
    fn from_locked_row(
        transaction_id: String,
        target_did: String,
        target_device_id: Uuid,
        target_key_id: String,
        target_auth_generation: u64,
        key_package_ref: [u8; 32],
        wrapper_sha256: [u8; 32],
        not_after: DateTime<Utc>,
        status: LockedRecoveryPackageStatus,
        conversation_id: Option<Uuid>,
        request_id: Option<Uuid>,
        locked_at: DateTime<Utc>,
        durable_row_digest: [u8; 32],
    ) -> Option<Self> {
        let reservation_shape = match status {
            LockedRecoveryPackageStatus::Available => {
                conversation_id.is_none() && request_id.is_none()
            }
            LockedRecoveryPackageStatus::Reserved => {
                conversation_id.is_some_and(uuid_is_canonical_v4)
                    && request_id.is_some_and(uuid_is_canonical_v4)
            }
            _ => false,
        };
        if !canonical_transaction_id(&transaction_id)
            || BareDid::parse(&target_did).is_err()
            || !uuid_is_canonical_v4(target_device_id)
            || KeyThumbprint::parse(&target_key_id).is_err()
            || !(1..=MAX_PROTOCOL_INTEGER).contains(&target_auth_generation)
            || key_package_ref == [0; 32]
            || wrapper_sha256 == [0; 32]
            || !reservation_shape
            || not_after <= locked_at
            || not_after.timestamp_subsec_nanos() % 1_000_000 != 0
            || locked_at.timestamp_millis() < 0
            || locked_at.timestamp_subsec_nanos() % 1_000_000 != 0
            || durable_row_digest
                != revocation_package_guard_digest(
                    &transaction_id,
                    &target_did,
                    target_device_id,
                    &target_key_id,
                    target_auth_generation,
                    &key_package_ref,
                    &wrapper_sha256,
                    not_after,
                    status,
                    conversation_id,
                    request_id,
                    locked_at,
                )
        {
            return None;
        }
        Some(Self {
            transaction_id,
            target_did,
            target_device_id,
            target_key_id,
            target_auth_generation,
            key_package_ref,
            wrapper_sha256,
            not_after,
            status,
            conversation_id,
            request_id,
            locked_at,
            durable_row_digest,
        })
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn target_did(&self) -> &str {
        &self.target_did
    }
    pub(crate) fn target_device_id(&self) -> Uuid {
        self.target_device_id
    }
    pub(crate) fn target_key_id(&self) -> &str {
        &self.target_key_id
    }
    pub(crate) fn target_auth_generation(&self) -> u64 {
        self.target_auth_generation
    }
    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }
    pub(crate) fn wrapper_sha256(&self) -> &[u8; 32] {
        &self.wrapper_sha256
    }
    pub(crate) fn not_after(&self) -> DateTime<Utc> {
        self.not_after
    }
    pub(crate) fn status(&self) -> LockedRecoveryPackageStatus {
        self.status
    }
    pub(crate) fn conversation_id(&self) -> Option<Uuid> {
        self.conversation_id
    }
    pub(crate) fn request_id(&self) -> Option<Uuid> {
        self.request_id
    }
    pub(crate) fn locked_at(&self) -> DateTime<Utc> {
        self.locked_at
    }
    pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
        &self.durable_row_digest
    }
}

#[allow(clippy::too_many_arguments)]
fn revocation_package_guard_digest(
    transaction_id: &str,
    target_did: &str,
    target_device_id: Uuid,
    target_key_id: &str,
    target_auth_generation: u64,
    key_package_ref: &[u8; 32],
    wrapper_sha256: &[u8; 32],
    not_after: DateTime<Utc>,
    status: LockedRecoveryPackageStatus,
    conversation_id: Option<Uuid>,
    request_id: Option<Uuid>,
    locked_at: DateTime<Utc>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-REVOCATION-PACKAGE\0");
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update((target_did.len() as u64).to_be_bytes());
    digest.update(target_did.as_bytes());
    digest.update(target_device_id.as_bytes());
    digest.update((target_key_id.len() as u64).to_be_bytes());
    digest.update(target_key_id.as_bytes());
    digest.update(target_auth_generation.to_be_bytes());
    digest.update(key_package_ref);
    digest.update(wrapper_sha256);
    digest.update(not_after.timestamp_millis().to_be_bytes());
    digest.update([match status {
        LockedRecoveryPackageStatus::Available => 1,
        LockedRecoveryPackageStatus::Reserved => 2,
        LockedRecoveryPackageStatus::Consumed => 3,
        LockedRecoveryPackageStatus::Expired => 4,
        LockedRecoveryPackageStatus::Revoked => 5,
    }]);
    if let (Some(conversation_id), Some(request_id)) = (conversation_id, request_id) {
        digest.update([1]);
        digest.update(conversation_id.as_bytes());
        digest.update(request_id.as_bytes());
    } else {
        digest.update([0]);
    }
    digest.update(locked_at.timestamp_millis().to_be_bytes());
    digest.finalize().into()
}

/// Repository proof that the target-first fanout query covered every open
/// recovery request, reserved KeyPackage, and pending Welcome for the target.
/// Conversations are in UUID byte order and all child identities are sorted;
/// an empty manifest is the only valid proof of an empty fanout.
#[derive(Debug)]
pub(crate) struct LockedRevocationFanoutGuard {
    transaction_id: String,
    target_did: String,
    target_device_id: Uuid,
    locked_at: DateTime<Utc>,
    conversations: Vec<LockedRevocationConversationManifest>,
    live_packages: Vec<LockedRevocationPackageManifest>,
    durable_manifest_digest: [u8; 32],
}

impl LockedRevocationFanoutGuard {
    fn from_locked_manifest(
        transaction_id: String,
        target_did: String,
        target_device_id: Uuid,
        locked_at: DateTime<Utc>,
        conversations: Vec<LockedRevocationConversationManifest>,
        live_packages: Vec<LockedRevocationPackageManifest>,
        durable_manifest_digest: [u8; 32],
    ) -> Option<Self> {
        if !canonical_transaction_id(&transaction_id)
            || BareDid::parse(&target_did).is_err()
            || !uuid_is_canonical_v4(target_device_id)
            || locked_at.timestamp_millis() < 0
            || locked_at.timestamp_subsec_nanos() % 1_000_000 != 0
            || conversations.windows(2).any(|pair| {
                pair[0].conversation_id.as_bytes() >= pair[1].conversation_id.as_bytes()
            })
            || conversations.iter().any(|entry| {
                !uuid_is_canonical_v4(entry.conversation_id)
                    || entry.locked_head_digest == [0; 32]
                    || !sorted_unique_uuid_v4(&entry.open_recovery_request_ids)
                    || !sorted_unique_uuid_v4(&entry.pending_welcome_ids)
                    || entry
                        .reserved_package_refs
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
            })
            || live_packages
                .windows(2)
                .any(|pair| pair[0].key_package_ref >= pair[1].key_package_ref)
            || live_packages.iter().any(|package| {
                package.key_package_ref == [0; 32]
                    || package.locked_row_digest == [0; 32]
                    || !matches!(
                        (package.status, package.conversation_id, package.request_id),
                        (LockedRecoveryPackageStatus::Available, None, None)
                            | (LockedRecoveryPackageStatus::Reserved, Some(_), Some(_))
                    )
            })
            || conversations
                .iter()
                .flat_map(|entry| entry.reserved_package_refs.iter())
                .any(|key_package_ref| {
                    !live_packages.iter().any(|package| {
                        package.status == LockedRecoveryPackageStatus::Reserved
                            && &package.key_package_ref == key_package_ref
                    })
                })
            || durable_manifest_digest
                != revocation_fanout_manifest_digest(
                    &transaction_id,
                    &target_did,
                    target_device_id,
                    locked_at,
                    &conversations,
                    &live_packages,
                )
        {
            return None;
        }
        Some(Self {
            transaction_id,
            target_did,
            target_device_id,
            locked_at,
            conversations,
            live_packages,
            durable_manifest_digest,
        })
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn target_did(&self) -> &str {
        &self.target_did
    }
    pub(crate) fn target_device_id(&self) -> Uuid {
        self.target_device_id
    }
    pub(crate) fn locked_at(&self) -> DateTime<Utc> {
        self.locked_at
    }
    pub(crate) fn conversations(&self) -> &[LockedRevocationConversationManifest] {
        &self.conversations
    }
    pub(crate) fn live_packages(&self) -> &[LockedRevocationPackageManifest] {
        &self.live_packages
    }
    pub(crate) fn durable_manifest_digest(&self) -> &[u8; 32] {
        &self.durable_manifest_digest
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        transaction_id: String,
        target_did: String,
        target_device_id: Uuid,
        locked_at: DateTime<Utc>,
        conversations: Vec<LockedRevocationConversationManifest>,
        live_packages: Vec<LockedRevocationPackageManifest>,
    ) -> Self {
        let digest = revocation_fanout_manifest_digest(
            &transaction_id,
            &target_did,
            target_device_id,
            locked_at,
            &conversations,
            &live_packages,
        );
        Self::from_locked_manifest(
            transaction_id,
            target_did,
            target_device_id,
            locked_at,
            conversations,
            live_packages,
            digest,
        )
        .expect("valid test revocation fanout")
    }
}

fn sorted_unique_uuid_v4(values: &[Uuid]) -> bool {
    values.iter().all(|value| uuid_is_canonical_v4(*value))
        && values
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
}

fn revocation_fanout_manifest_digest(
    transaction_id: &str,
    target_did: &str,
    target_device_id: Uuid,
    locked_at: DateTime<Utc>,
    conversations: &[LockedRevocationConversationManifest],
    live_packages: &[LockedRevocationPackageManifest],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-REVOCATION-FANOUT\0");
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update((target_did.len() as u64).to_be_bytes());
    digest.update(target_did.as_bytes());
    digest.update(target_device_id.as_bytes());
    digest.update(locked_at.timestamp_millis().to_be_bytes());
    digest.update((conversations.len() as u64).to_be_bytes());
    for entry in conversations {
        digest.update(entry.conversation_id.as_bytes());
        digest.update(entry.locked_head_digest);
        digest.update((entry.open_recovery_request_ids.len() as u64).to_be_bytes());
        for request_id in &entry.open_recovery_request_ids {
            digest.update(request_id.as_bytes());
        }
        digest.update((entry.pending_welcome_ids.len() as u64).to_be_bytes());
        for welcome_id in &entry.pending_welcome_ids {
            digest.update(welcome_id.as_bytes());
        }
        digest.update((entry.reserved_package_refs.len() as u64).to_be_bytes());
        for key_package_ref in &entry.reserved_package_refs {
            digest.update(key_package_ref);
        }
    }
    digest.update((live_packages.len() as u64).to_be_bytes());
    for package in live_packages {
        digest.update(package.key_package_ref);
        digest.update([match package.status {
            LockedRecoveryPackageStatus::Available => 1,
            LockedRecoveryPackageStatus::Reserved => 2,
            LockedRecoveryPackageStatus::Consumed => 3,
            LockedRecoveryPackageStatus::Expired => 4,
            LockedRecoveryPackageStatus::Revoked => 5,
        }]);
        if let (Some(conversation_id), Some(request_id)) =
            (package.conversation_id, package.request_id)
        {
            digest.update([1]);
            digest.update(conversation_id.as_bytes());
            digest.update(request_id.as_bytes());
        } else {
            digest.update([0]);
        }
        digest.update(package.locked_row_digest);
    }
    digest.finalize().into()
}

/// Exact conversation-head row locked by the current database transaction.
/// Absence is represented by `prior_coordinate == None`, `next_entry_seq == 1`
/// and is valid only for creation.
#[derive(Debug)]
pub(crate) struct LockedConversationHeadGuard {
    transaction_id: String,
    conversation_id: Uuid,
    prior_coordinate: Option<PublicGroupSnapshotCoordinate>,
    next_entry_seq: u64,
    locked_at: DateTime<Utc>,
    durable_row_digest: [u8; 32],
}

impl LockedConversationHeadGuard {
    #[allow(clippy::too_many_arguments)]
    fn from_locked_row(
        transaction_id: String,
        conversation_id: Uuid,
        prior_coordinate: Option<PublicGroupSnapshotCoordinate>,
        next_entry_seq: u64,
        locked_at: DateTime<Utc>,
        durable_row_digest: [u8; 32],
    ) -> Option<Self> {
        if !canonical_transaction_id(&transaction_id)
            || !uuid_is_canonical_v4(conversation_id)
            || next_entry_seq == 0
            || next_entry_seq > MAX_PROTOCOL_INTEGER
            || durable_row_digest == [0; 32]
            || prior_coordinate.as_ref().is_some_and(|coordinate| {
                coordinate.conversation_id() != conversation_id.as_bytes()
            })
            || (prior_coordinate.is_none() && next_entry_seq != 1)
        {
            return None;
        }
        Some(Self {
            transaction_id,
            conversation_id,
            prior_coordinate,
            next_entry_seq,
            locked_at,
            durable_row_digest,
        })
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(crate) fn conversation_id(&self) -> Uuid {
        self.conversation_id
    }

    pub(crate) fn prior_coordinate(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.prior_coordinate.as_ref()
    }

    pub(crate) fn next_entry_seq(&self) -> u64 {
        self.next_entry_seq
    }

    pub(crate) fn locked_at(&self) -> DateTime<Utc> {
        self.locked_at
    }

    pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
        &self.durable_row_digest
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        transaction_id: String,
        conversation_id: Uuid,
        prior_coordinate: Option<PublicGroupSnapshotCoordinate>,
        next_entry_seq: u64,
        locked_at: DateTime<Utc>,
        durable_row_digest: [u8; 32],
    ) -> Self {
        Self::from_locked_row(
            transaction_id,
            conversation_id,
            prior_coordinate,
            next_entry_seq,
            locked_at,
            durable_row_digest,
        )
        .expect("valid test conversation-head guard")
    }
}

/// Conversation graph hydrated from the same deterministic `FOR UPDATE`
/// read-set as its head. Production planners accept this aggregate witness,
/// never a raw cached `ConversationState` paired later with a fresh head.
#[derive(Debug)]
pub(crate) struct LockedConversationStateGuard {
    state: ConversationState,
    head: LockedConversationHeadGuard,
    locked_graph_digest: [u8; 32],
    locked_snapshot_digest: Option<[u8; 32]>,
}

/// Repository-internal handoff used only after one deterministic locked
/// hydration query has produced both values. Handlers cannot call this seam.
pub(super) fn seal_locked_conversation(
    state: ConversationState,
    head: LockedConversationHeadGuard,
    locked_graph_digest: [u8; 32],
    locked_snapshot_digest: Option<[u8; 32]>,
) -> Option<LockedConversationStateGuard> {
    LockedConversationStateGuard::from_locked_hydration(
        state,
        head,
        locked_graph_digest,
        locked_snapshot_digest,
    )
}

/// Exact locked generation-row + blob witness consumed by public-state
/// hydration. The binding and both blobs leave the repository only as one
/// non-cloneable value, so callers cannot pair a valid snapshot with a digest
/// or tree summary selected from another generation.
#[derive(Debug)]
pub(crate) struct LockedPublicStateHydrationGuard {
    transaction_id: String,
    conversation_id: Uuid,
    coordinate: PublicGroupSnapshotCoordinate,
    snapshot: Vec<u8>,
    binding: PublicGroupSnapshotBinding,
    encoded_tree_summary: Vec<u8>,
    expected_tree_summary_sha256: [u8; 32],
    locked_at: DateTime<Utc>,
    locked_generation_row_digest: [u8; 32],
}

/// Repository-only seal after the generation row and both blob columns were
/// selected in the same `FOR UPDATE` read-set.
#[allow(clippy::too_many_arguments)]
pub(super) fn seal_locked_public_state_hydration(
    transaction_id: String,
    conversation_id: Uuid,
    coordinate: PublicGroupSnapshotCoordinate,
    snapshot: Vec<u8>,
    binding: PublicGroupSnapshotBinding,
    encoded_tree_summary: Vec<u8>,
    expected_tree_summary_sha256: [u8; 32],
    locked_at: DateTime<Utc>,
    locked_generation_row_digest: [u8; 32],
) -> Option<LockedPublicStateHydrationGuard> {
    let actual_snapshot_sha256: [u8; 32] = Sha256::digest(&snapshot).into();
    let actual_summary_sha256: [u8; 32] = Sha256::digest(&encoded_tree_summary).into();
    if !canonical_transaction_id(&transaction_id)
        || coordinate.conversation_id() != conversation_id.as_bytes()
        || binding.coordinate() != &coordinate
        || snapshot.is_empty()
        || binding.snapshot_sha256() != &actual_snapshot_sha256
        || encoded_tree_summary.is_empty()
        || expected_tree_summary_sha256 != actual_summary_sha256
        || locked_at.timestamp_millis() < 0
        || locked_at.timestamp_subsec_nanos() % 1_000_000 != 0
        || locked_generation_row_digest == [0; 32]
    {
        return None;
    }
    Some(LockedPublicStateHydrationGuard {
        transaction_id,
        conversation_id,
        coordinate,
        snapshot,
        binding,
        encoded_tree_summary,
        expected_tree_summary_sha256,
        locked_at,
        locked_generation_row_digest,
    })
}

impl LockedPublicStateHydrationGuard {
    pub(crate) fn into_parts(
        self,
    ) -> (
        String,
        Uuid,
        PublicGroupSnapshotCoordinate,
        Vec<u8>,
        PublicGroupSnapshotBinding,
        Vec<u8>,
        [u8; 32],
        DateTime<Utc>,
        [u8; 32],
    ) {
        (
            self.transaction_id,
            self.conversation_id,
            self.coordinate,
            self.snapshot,
            self.binding,
            self.encoded_tree_summary,
            self.expected_tree_summary_sha256,
            self.locked_at,
            self.locked_generation_row_digest,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LockedDirectLookupOutcome {
    Absent,
    Existing {
        conversation_id: Uuid,
        coordinate: PublicGroupSnapshotCoordinate,
        locked_head_digest: [u8; 32],
    },
}

/// Exact result of the transaction-scoped canonical direct-pair uniqueness
/// lookup. It is consumed by creation, so a caller cannot turn a stale cached
/// conversation into an ExistingDirect result or skip the pair lock on insert.
#[derive(Debug)]
pub(crate) struct LockedDirectConversationLookupGuard {
    transaction_id: String,
    did_low: String,
    did_high: String,
    locked_at: DateTime<Utc>,
    outcome: LockedDirectLookupOutcome,
    durable_row_digest: [u8; 32],
}

impl LockedDirectConversationLookupGuard {
    fn from_locked_lookup(
        transaction_id: String,
        did_low: String,
        did_high: String,
        locked_at: DateTime<Utc>,
        outcome: LockedDirectLookupOutcome,
        durable_row_digest: [u8; 32],
    ) -> Option<Self> {
        if !canonical_transaction_id(&transaction_id)
            || BareDid::parse(&did_low).is_err()
            || BareDid::parse(&did_high).is_err()
            || did_low >= did_high
            || locked_at.timestamp_millis() < 0
            || locked_at.timestamp_subsec_nanos() % 1_000_000 != 0
            || matches!(
                &outcome,
                LockedDirectLookupOutcome::Existing {
                    conversation_id,
                    coordinate,
                    locked_head_digest,
                } if !uuid_is_canonical_v4(*conversation_id)
                    || coordinate.conversation_id() != conversation_id.as_bytes()
                    || *locked_head_digest == [0; 32]
            )
            || durable_row_digest
                != direct_lookup_guard_digest(
                    &transaction_id,
                    &did_low,
                    &did_high,
                    locked_at,
                    &outcome,
                )
        {
            return None;
        }
        Some(Self {
            transaction_id,
            did_low,
            did_high,
            locked_at,
            outcome,
            durable_row_digest,
        })
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn did_low(&self) -> &str {
        &self.did_low
    }
    pub(crate) fn did_high(&self) -> &str {
        &self.did_high
    }
    pub(crate) fn locked_at(&self) -> DateTime<Utc> {
        self.locked_at
    }
    pub(crate) fn outcome(&self) -> &LockedDirectLookupOutcome {
        &self.outcome
    }
    pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
        &self.durable_row_digest
    }
}

fn direct_lookup_guard_digest(
    transaction_id: &str,
    did_low: &str,
    did_high: &str,
    locked_at: DateTime<Utc>,
    outcome: &LockedDirectLookupOutcome,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-DIRECT-LOOKUP\0");
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update((did_low.len() as u64).to_be_bytes());
    digest.update(did_low.as_bytes());
    digest.update((did_high.len() as u64).to_be_bytes());
    digest.update(did_high.as_bytes());
    digest.update(locked_at.timestamp_millis().to_be_bytes());
    match outcome {
        LockedDirectLookupOutcome::Absent => digest.update([0]),
        LockedDirectLookupOutcome::Existing {
            conversation_id,
            coordinate,
            locked_head_digest,
        } => {
            digest.update([1]);
            digest.update(conversation_id.as_bytes());
            digest.update(coordinate.generation().to_be_bytes());
            digest.update(coordinate.state_version().to_be_bytes());
            digest.update(coordinate.group_id());
            digest.update(coordinate.epoch().to_be_bytes());
            digest.update(coordinate.group_context_hash());
            digest.update(coordinate.confirmation_tag());
            digest.update([match coordinate.lifecycle() {
                super::super::snapshot::PublicGroupSnapshotLifecycle::Active => 1,
                super::super::snapshot::PublicGroupSnapshotLifecycle::Superseded => 2,
            }]);
            digest.update(locked_head_digest);
        }
    }
    digest.finalize().into()
}

impl LockedConversationStateGuard {
    fn from_locked_hydration(
        state: ConversationState,
        head: LockedConversationHeadGuard,
        locked_graph_digest: [u8; 32],
        locked_snapshot_digest: Option<[u8; 32]>,
    ) -> Option<Self> {
        if state.coordinate().conversation_id() != head.conversation_id().as_bytes()
            || head.prior_coordinate() != Some(state.coordinate())
            || locked_graph_digest == [0; 32]
            || match (state.active_public_state(), locked_snapshot_digest.as_ref()) {
                (Some(public_state), Some(expected)) => {
                    let actual: [u8; 32] = Sha256::digest(public_state.snapshot()).into();
                    expected != public_state.snapshot_sha256() || expected != &actual
                }
                (None, None) => false,
                _ => true,
            }
        {
            return None;
        }
        Some(Self {
            state,
            head,
            locked_graph_digest,
            locked_snapshot_digest,
        })
    }

    pub(crate) fn state(&self) -> &ConversationState {
        &self.state
    }
    pub(crate) fn head(&self) -> &LockedConversationHeadGuard {
        &self.head
    }

    pub(crate) fn locked_graph_digest(&self) -> &[u8; 32] {
        &self.locked_graph_digest
    }

    pub(crate) fn locked_snapshot_digest(&self) -> Option<&[u8; 32]> {
        self.locked_snapshot_digest.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        state: ConversationState,
        head: LockedConversationHeadGuard,
        locked_graph_digest: [u8; 32],
        locked_snapshot_digest: Option<[u8; 32]>,
    ) -> Self {
        Self::from_locked_hydration(state, head, locked_graph_digest, locked_snapshot_digest)
            .expect("matching locked conversation hydration")
    }
}

/// Exact available KeyPackage row and proposed recovery-reservation identity,
/// both locked by the same transaction as the conversation head and device
/// authority. No handler or sibling planner can construct this witness.
#[derive(Debug)]
pub(crate) struct LockedRecoveryPackageGuard {
    transaction_id: String,
    conversation_id: Uuid,
    request_id: Uuid,
    target_did: String,
    target_device_id: Uuid,
    target_key_id: String,
    target_auth_generation: i64,
    bound_coordinate: PublicGroupSnapshotCoordinate,
    key_package_ref: [u8; 32],
    wrapper_bytes: Vec<u8>,
    wrapper_sha256: [u8; 32],
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    claimed_at: DateTime<Utc>,
    status: LockedRecoveryPackageStatus,
    use_kind: LockedRecoveryPackageUse,
    reservation_created_at: Option<DateTime<Utc>>,
    reservation_expires_at: Option<DateTime<Utc>>,
    request_provenance_digest: Option<[u8; 32]>,
    durable_row_digest: [u8; 32],
}

impl LockedRecoveryPackageGuard {
    #[allow(clippy::too_many_arguments)]
    fn from_locked_row(
        transaction_id: String,
        conversation_id: Uuid,
        request_id: Uuid,
        target_did: String,
        target_device_id: Uuid,
        target_key_id: String,
        target_auth_generation: i64,
        bound_coordinate: PublicGroupSnapshotCoordinate,
        key_package_ref: [u8; 32],
        wrapper_bytes: Vec<u8>,
        wrapper_sha256: [u8; 32],
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
        claimed_at: DateTime<Utc>,
        status: LockedRecoveryPackageStatus,
        use_kind: LockedRecoveryPackageUse,
        reservation_created_at: Option<DateTime<Utc>>,
        reservation_expires_at: Option<DateTime<Utc>>,
        request_provenance_digest: Option<[u8; 32]>,
        durable_row_digest: [u8; 32],
    ) -> Option<Self> {
        if !canonical_transaction_id(&transaction_id)
            || !uuid_is_canonical_v4(conversation_id)
            || !uuid_is_canonical_v4(request_id)
            || !uuid_is_canonical_v4(target_device_id)
            || BareDid::parse(&target_did).is_err()
            || KeyThumbprint::parse(&target_key_id).is_err()
            || target_auth_generation <= 0
            || u64::try_from(target_auth_generation)
                .map_or(true, |value| value > MAX_PROTOCOL_INTEGER)
            || bound_coordinate.conversation_id() != conversation_id.as_bytes()
            || key_package_ref == [0; 32]
            || wrapper_bytes.is_empty()
            || wrapper_sha256 == [0; 32]
            || <[u8; 32]>::from(Sha256::digest(&wrapper_bytes)) != wrapper_sha256
            || not_before >= claimed_at
            || claimed_at >= not_after
            || not_after - claimed_at < chrono::TimeDelta::seconds(600)
            || not_after - not_before > chrono::TimeDelta::seconds(2_595_600)
            || !matches!(
                (
                    use_kind,
                    status,
                    reservation_created_at,
                    reservation_expires_at,
                    request_provenance_digest
                ),
                (
                    LockedRecoveryPackageUse::AvailableSelection,
                    LockedRecoveryPackageStatus::Available,
                    None,
                    None,
                    None
                ) | (
                    LockedRecoveryPackageUse::ReservedFulfillment,
                    LockedRecoveryPackageStatus::Reserved,
                    Some(_),
                    Some(_),
                    Some(_)
                )
            )
            || (use_kind == LockedRecoveryPackageUse::ReservedFulfillment
                && (reservation_created_at.is_none_or(|created| created > claimed_at)
                    || reservation_expires_at
                        .is_none_or(|expires| claimed_at >= expires || expires > not_after)
                    || request_provenance_digest == Some([0; 32])))
            || durable_row_digest == [0; 32]
        {
            return None;
        }
        Some(Self {
            transaction_id,
            conversation_id,
            request_id,
            target_did,
            target_device_id,
            target_key_id,
            target_auth_generation,
            bound_coordinate,
            key_package_ref,
            wrapper_bytes,
            wrapper_sha256,
            not_before,
            not_after,
            claimed_at,
            status,
            use_kind,
            reservation_created_at,
            reservation_expires_at,
            request_provenance_digest,
            durable_row_digest,
        })
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(crate) fn conversation_id(&self) -> Uuid {
        self.conversation_id
    }

    pub(crate) fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub(crate) fn target_did(&self) -> &str {
        &self.target_did
    }

    pub(crate) fn target_device_id(&self) -> Uuid {
        self.target_device_id
    }

    pub(crate) fn target_key_id(&self) -> &str {
        &self.target_key_id
    }

    pub(crate) fn target_auth_generation(&self) -> i64 {
        self.target_auth_generation
    }

    pub(crate) fn bound_coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.bound_coordinate
    }

    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }

    pub(crate) fn wrapper_bytes(&self) -> &[u8] {
        &self.wrapper_bytes
    }

    pub(crate) fn wrapper_sha256(&self) -> &[u8; 32] {
        &self.wrapper_sha256
    }

    pub(crate) fn not_before(&self) -> DateTime<Utc> {
        self.not_before
    }

    pub(crate) fn not_after(&self) -> DateTime<Utc> {
        self.not_after
    }

    pub(crate) fn claimed_at(&self) -> DateTime<Utc> {
        self.claimed_at
    }

    pub(crate) fn status(&self) -> LockedRecoveryPackageStatus {
        self.status
    }

    pub(crate) fn use_kind(&self) -> LockedRecoveryPackageUse {
        self.use_kind
    }

    pub(crate) fn reservation_created_at(&self) -> Option<DateTime<Utc>> {
        self.reservation_created_at
    }

    pub(crate) fn reservation_expires_at(&self) -> Option<DateTime<Utc>> {
        self.reservation_expires_at
    }

    pub(crate) fn request_provenance_digest(&self) -> Option<&[u8; 32]> {
        self.request_provenance_digest.as_ref()
    }

    pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
        &self.durable_row_digest
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test(
        transaction_id: String,
        conversation_id: Uuid,
        request_id: Uuid,
        target_did: String,
        target_device_id: Uuid,
        target_key_id: String,
        target_auth_generation: i64,
        bound_coordinate: PublicGroupSnapshotCoordinate,
        key_package_ref: [u8; 32],
        wrapper_bytes: Vec<u8>,
        wrapper_sha256: [u8; 32],
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
        claimed_at: DateTime<Utc>,
        status: LockedRecoveryPackageStatus,
        use_kind: LockedRecoveryPackageUse,
        reservation_created_at: Option<DateTime<Utc>>,
        reservation_expires_at: Option<DateTime<Utc>>,
        request_provenance_digest: Option<[u8; 32]>,
        durable_row_digest: [u8; 32],
    ) -> Self {
        Self::from_locked_row(
            transaction_id,
            conversation_id,
            request_id,
            target_did,
            target_device_id,
            target_key_id,
            target_auth_generation,
            bound_coordinate,
            key_package_ref,
            wrapper_bytes,
            wrapper_sha256,
            not_before,
            not_after,
            claimed_at,
            status,
            use_kind,
            reservation_created_at,
            reservation_expires_at,
            request_provenance_digest,
            durable_row_digest,
        )
        .expect("valid test recovery-package guard")
    }
}

fn canonical_transaction_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.as_bytes()[0] != b'0'
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|value| value > 0)
}

fn uuid_is_canonical_v4(value: Uuid) -> bool {
    value.get_variant() == uuid::Variant::RFC4122 && value.get_version_num() == 4
}

// ===========================================================================
// T4-H2-pre G5 — production recovery-package lock hydration.
//
// The available and reserved shapes are intentionally separate entry points:
// an available package is claimed at the request's trusted/head instant, while
// a reserved package remains bound to the original recovery request instant.
// Both acquire the package row under `FOR UPDATE`; the reserved arm also locks
// its exact reservation row. Constructors remain private and no caller-supplied
// digest is accepted.
// ===========================================================================

#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum RecoveryPackageHydrationError {
    #[error("clean-chat recovery package is absent")]
    PackageMissing,
    #[error("clean-chat recovery package column is out of domain")]
    OutOfDomain,
    #[error("clean-chat recovery package does not match its locked recovery work")]
    ReadSetMismatch,
    #[error("clean-chat recovery package guard invariant was violated")]
    GuardInvariant,
    #[error("clean-chat recovery package provenance failed re-verification: {0}")]
    Recovery(#[from] RecoveryHydrationError),
    #[error("clean-chat recovery package database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct LockedAvailableRecoveryPackageRow {
    key_package_ref: Vec<u8>,
    wrapper_bytes: Vec<u8>,
    wrapper_sha256: Vec<u8>,
    owner_did: String,
    owner_device_id: Uuid,
    owner_key_id: String,
    owner_auth_generation: i64,
    owner_signing_public_key: Vec<u8>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    created_at: DateTime<Utc>,
    status: String,
}

#[derive(sqlx::FromRow)]
struct LockedReservedRecoveryPackageRow {
    conversation_id: Uuid,
    recovery_request_id: Uuid,
    generation: i64,
    bound_state_version: i64,
    bound_group_id: Vec<u8>,
    bound_epoch: i64,
    bound_group_context_hash: Vec<u8>,
    bound_confirmation_tag: Vec<u8>,
    requester_did: String,
    requester_device_id: Uuid,
    requester_key_id: String,
    requester_auth_generation: i64,
    recipient_did: String,
    recipient_device_id: Uuid,
    key_package_ref: Vec<u8>,
    reservation_created_at: DateTime<Utc>,
    reservation_expires_at: DateTime<Utc>,
    reservation_status: String,
    package_owner_did: String,
    package_owner_device_id: Uuid,
    package_owner_key_id: String,
    package_owner_auth_generation: i64,
    package_owner_signing_public_key: Vec<u8>,
    wrapper_bytes: Vec<u8>,
    wrapper_sha256: Vec<u8>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    package_created_at: DateTime<Utc>,
    package_status: String,
}

fn whole_millis_nonnegative(value: DateTime<Utc>) -> bool {
    value.timestamp_millis() >= 0 && value.timestamp_subsec_nanos().is_multiple_of(1_000_000)
}

fn recovery_package_bytes32(value: Vec<u8>) -> Result<[u8; 32], RecoveryPackageHydrationError> {
    value
        .try_into()
        .map_err(|_| RecoveryPackageHydrationError::OutOfDomain)
}

fn recovery_package_safe_u64(value: i64) -> Result<u64, RecoveryPackageHydrationError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(RecoveryPackageHydrationError::OutOfDomain)
}

#[allow(clippy::too_many_arguments)]
fn recovery_package_guard_digest(
    transaction_id: &str,
    conversation_id: Uuid,
    request_id: Uuid,
    target_did: &str,
    target_device_id: Uuid,
    target_key_id: &str,
    target_auth_generation: i64,
    bound_coordinate: &PublicGroupSnapshotCoordinate,
    key_package_ref: &[u8; 32],
    wrapper_bytes: &[u8],
    wrapper_sha256: &[u8; 32],
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    claimed_at: DateTime<Utc>,
    status: LockedRecoveryPackageStatus,
    use_kind: LockedRecoveryPackageUse,
    reservation_created_at: Option<DateTime<Utc>>,
    reservation_expires_at: Option<DateTime<Utc>>,
    request_provenance_digest: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-RECOVERY-PACKAGE\0");
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update(conversation_id.as_bytes());
    digest.update(request_id.as_bytes());
    digest.update((target_did.len() as u64).to_be_bytes());
    digest.update(target_did.as_bytes());
    digest.update(target_device_id.as_bytes());
    digest.update((target_key_id.len() as u64).to_be_bytes());
    digest.update(target_key_id.as_bytes());
    digest.update(target_auth_generation.to_be_bytes());
    graph_digest_coordinate(&mut digest, bound_coordinate);
    digest.update(key_package_ref);
    digest.update((wrapper_bytes.len() as u64).to_be_bytes());
    digest.update(wrapper_bytes);
    digest.update(wrapper_sha256);
    digest.update(not_before.timestamp_millis().to_be_bytes());
    digest.update(not_after.timestamp_millis().to_be_bytes());
    digest.update(claimed_at.timestamp_millis().to_be_bytes());
    digest.update([match status {
        LockedRecoveryPackageStatus::Available => 1,
        LockedRecoveryPackageStatus::Reserved => 2,
        LockedRecoveryPackageStatus::Consumed => 3,
        LockedRecoveryPackageStatus::Expired => 4,
        LockedRecoveryPackageStatus::Revoked => 5,
    }]);
    digest.update([match use_kind {
        LockedRecoveryPackageUse::AvailableSelection => 1,
        LockedRecoveryPackageUse::ReservedFulfillment => 2,
    }]);
    for timestamp in [reservation_created_at, reservation_expires_at] {
        match timestamp {
            None => digest.update([0]),
            Some(value) => {
                digest.update([1]);
                digest.update(value.timestamp_millis().to_be_bytes());
            }
        }
    }
    match request_provenance_digest {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            digest.update(value);
        }
    }
    digest.finalize().into()
}

fn recovery_origin_binding(
    origin: &RecoveryOriginHydrationRow,
) -> Result<([u8; 32], u64, [u8; 32]), RecoveryPackageHydrationError> {
    match origin {
        RecoveryOriginHydrationRow::Acceptance(evidence) => {
            let authority = evidence
                .signed_authority()
                .ok_or(RecoveryPackageHydrationError::ReadSetMismatch)?;
            Ok((
                *authority.key_id(),
                authority.auth_generation(),
                *evidence.outer_entry_fingerprint(),
            ))
        }
        RecoveryOriginHydrationRow::Request(evidence) => {
            let authority = evidence
                .signed_authority()
                .ok_or(RecoveryPackageHydrationError::ReadSetMismatch)?;
            Ok((
                *authority.key_id(),
                authority.auth_generation(),
                *evidence.durable_row_digest(),
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_locked_recovery_package_artifact(
    wrapper_bytes: &[u8],
    expected_key_package_ref: &[u8; 32],
    target_did: &str,
    target_device_id: Uuid,
    target_signing_public_key: &[u8],
    claimed_at: DateTime<Utc>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
) -> Result<(), RecoveryPackageHydrationError> {
    let now_unix_seconds = u64::try_from(claimed_at.timestamp())
        .map_err(|_| RecoveryPackageHydrationError::OutOfDomain)?;
    let validated = validate_key_package(
        wrapper_bytes,
        KeyPackageValidationPolicy {
            expected_basic_credential: format!("{target_did}#{target_device_id}").as_bytes(),
            expected_signature_key: target_signing_public_key,
            now_unix_seconds,
            max_bytes: MAX_KEY_PACKAGE_WIRE_BYTES,
        },
    )
    .map_err(|_| RecoveryPackageHydrationError::ReadSetMismatch)?;
    let validated_not_before = i64::try_from(validated.not_before())
        .ok()
        .and_then(|value| value.checked_mul(1_000));
    let validated_not_after = i64::try_from(validated.not_after())
        .ok()
        .and_then(|value| value.checked_mul(1_000));
    if validated.key_package_ref() != expected_key_package_ref
        || validated_not_before != Some(not_before.timestamp_millis())
        || validated_not_after != Some(not_after.timestamp_millis())
    {
        return Err(RecoveryPackageHydrationError::ReadSetMismatch);
    }
    Ok(())
}

/// Lock the deterministic first available KeyPackage for an exact active
/// device/key generation. The existing conversation head is the serialization
/// root and supplies the one trusted instant shared by sibling guards.
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) async fn hydrate_locked_available_recovery_package(
    transaction: &mut Transaction<'_, Postgres>,
    head: &LockedConversationHeadGuard,
    request_id: Uuid,
    target_did: &str,
    target_device_id: Uuid,
    target_key_id: &str,
    target_auth_generation: i64,
    bound_coordinate: PublicGroupSnapshotCoordinate,
) -> Result<LockedRecoveryPackageGuard, RecoveryPackageHydrationError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if transaction_id != head.transaction_id()
        || head.prior_coordinate() != Some(&bound_coordinate)
        || !whole_millis_nonnegative(head.locked_at())
        || !uuid_is_canonical_v4(request_id)
        || !uuid_is_canonical_v4(target_device_id)
        || BareDid::parse(target_did).is_err()
        || KeyThumbprint::parse(target_key_id).is_err()
        || !(1..=i64::try_from(MAX_PROTOCOL_INTEGER).unwrap()).contains(&target_auth_generation)
    {
        return Err(RecoveryPackageHydrationError::ReadSetMismatch);
    }
    let claimed_at = head.locked_at();
    let row: Option<LockedAvailableRecoveryPackageRow> = sqlx::query_as(
        r#"
        SELECT
            kp.key_package_ref,
            kp.wrapper_bytes,
            kp.wrapper_sha256,
            kp.owner_did,
            kp.owner_device_id,
            kp.owner_key_id,
            kp.owner_auth_generation,
            dk.signing_public_key AS owner_signing_public_key,
            kp.not_before,
            kp.not_after,
            kp.created_at,
            kp.status
        FROM chat.key_packages kp
        JOIN chat.device_keys dk
          ON dk.user_did = kp.owner_did
         AND dk.device_id = kp.owner_device_id
         AND dk.key_id = kp.owner_key_id
        WHERE kp.owner_did = $1
          AND kp.owner_device_id = $2
          AND kp.owner_key_id = $3
          AND kp.owner_auth_generation = $4
          AND kp.status = 'available'
          AND kp.not_before < $5
          AND kp.created_at <= $5
          AND $5 < kp.not_after
        ORDER BY kp.created_at, kp.key_package_ref
        LIMIT 1
        FOR UPDATE OF kp
        "#,
    )
    .bind(target_did)
    .bind(target_device_id)
    .bind(target_key_id)
    .bind(target_auth_generation)
    .bind(claimed_at)
    .fetch_optional(&mut **transaction)
    .await?;
    let row = row.ok_or(RecoveryPackageHydrationError::PackageMissing)?;
    if row.status != "available"
        || row.owner_did != target_did
        || row.owner_device_id != target_device_id
        || row.owner_key_id != target_key_id
        || row.owner_auth_generation != target_auth_generation
        || !whole_millis_nonnegative(row.not_before)
        || !whole_millis_nonnegative(row.not_after)
        || !whole_millis_nonnegative(row.created_at)
        || row.created_at > claimed_at
    {
        return Err(RecoveryPackageHydrationError::ReadSetMismatch);
    }
    let key_package_ref = recovery_package_bytes32(row.key_package_ref)?;
    let wrapper_sha256 = recovery_package_bytes32(row.wrapper_sha256)?;
    validate_locked_recovery_package_artifact(
        &row.wrapper_bytes,
        &key_package_ref,
        target_did,
        target_device_id,
        &row.owner_signing_public_key,
        claimed_at,
        row.not_before,
        row.not_after,
    )?;
    let durable_row_digest = recovery_package_guard_digest(
        &transaction_id,
        head.conversation_id(),
        request_id,
        target_did,
        target_device_id,
        target_key_id,
        target_auth_generation,
        &bound_coordinate,
        &key_package_ref,
        &row.wrapper_bytes,
        &wrapper_sha256,
        row.not_before,
        row.not_after,
        claimed_at,
        LockedRecoveryPackageStatus::Available,
        LockedRecoveryPackageUse::AvailableSelection,
        None,
        None,
        None,
    );
    LockedRecoveryPackageGuard::from_locked_row(
        transaction_id,
        head.conversation_id(),
        request_id,
        target_did.to_owned(),
        target_device_id,
        target_key_id.to_owned(),
        target_auth_generation,
        bound_coordinate,
        key_package_ref,
        row.wrapper_bytes,
        wrapper_sha256,
        row.not_before,
        row.not_after,
        claimed_at,
        LockedRecoveryPackageStatus::Available,
        LockedRecoveryPackageUse::AvailableSelection,
        None,
        None,
        None,
        durable_row_digest,
    )
    .ok_or(RecoveryPackageHydrationError::GuardInvariant)
}

/// Lock one exact active reservation and its reserved KeyPackage, then match
/// every durable binding against independently re-verified recovery hydration
/// under the same conversation-head lock.
#[allow(dead_code)]
pub(crate) async fn hydrate_locked_reserved_recovery_package(
    transaction: &mut Transaction<'_, Postgres>,
    head: &LockedConversationHeadGuard,
    request_id: Uuid,
) -> Result<LockedRecoveryPackageGuard, RecoveryPackageHydrationError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if transaction_id != head.transaction_id() || !uuid_is_canonical_v4(request_id) {
        return Err(RecoveryPackageHydrationError::ReadSetMismatch);
    }
    let row: Option<LockedReservedRecoveryPackageRow> = sqlx::query_as(
        r#"
        SELECT
            r.conversation_id,
            r.recovery_request_id,
            r.generation,
            r.bound_state_version,
            r.bound_group_id,
            r.bound_epoch,
            r.bound_group_context_hash,
            r.bound_confirmation_tag,
            r.requester_did,
            r.requester_device_id,
            r.requester_key_id,
            r.requester_auth_generation,
            r.recipient_did,
            r.recipient_device_id,
            r.key_package_ref,
            r.created_at AS reservation_created_at,
            r.expires_at AS reservation_expires_at,
            r.status AS reservation_status,
            kp.owner_did AS package_owner_did,
            kp.owner_device_id AS package_owner_device_id,
            kp.owner_key_id AS package_owner_key_id,
            kp.owner_auth_generation AS package_owner_auth_generation,
            dk.signing_public_key AS package_owner_signing_public_key,
            kp.wrapper_bytes,
            kp.wrapper_sha256,
            kp.not_before,
            kp.not_after,
            kp.created_at AS package_created_at,
            kp.status AS package_status
        FROM chat.key_package_reservations r
        JOIN chat.key_packages kp
          ON kp.key_package_ref = r.key_package_ref
         AND kp.owner_did = r.recipient_did
         AND kp.owner_device_id = r.recipient_device_id
        JOIN chat.device_keys dk
          ON dk.user_did = kp.owner_did
         AND dk.device_id = kp.owner_device_id
         AND dk.key_id = kp.owner_key_id
        WHERE r.conversation_id = $1
          AND r.recovery_request_id = $2
        FOR UPDATE OF r, kp
        "#,
    )
    .bind(head.conversation_id())
    .bind(request_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let row = row.ok_or(RecoveryPackageHydrationError::PackageMissing)?;

    let generation = recovery_package_safe_u64(row.generation)?;
    let state_version = recovery_package_safe_u64(row.bound_state_version)?;
    let epoch = recovery_package_safe_u64(row.bound_epoch)?;
    let bound_coordinate = PublicGroupSnapshotCoordinate::new(
        *row.conversation_id.as_bytes(),
        generation,
        state_version,
        recovery_package_bytes32(row.bound_group_id)?,
        epoch,
        recovery_package_bytes32(row.bound_group_context_hash)?,
        recovery_package_bytes32(row.bound_confirmation_tag)?,
        super::super::snapshot::PublicGroupSnapshotLifecycle::Active,
    );
    let key_package_ref = recovery_package_bytes32(row.key_package_ref)?;
    let wrapper_sha256 = recovery_package_bytes32(row.wrapper_sha256)?;
    let claimed_at = row.reservation_created_at;
    validate_locked_recovery_package_artifact(
        &row.wrapper_bytes,
        &key_package_ref,
        &row.requester_did,
        row.requester_device_id,
        &row.package_owner_signing_public_key,
        claimed_at,
        row.not_before,
        row.not_after,
    )?;
    let target_key_id = KeyThumbprint::parse(&row.requester_key_id)
        .map_err(|_| RecoveryPackageHydrationError::OutOfDomain)?;
    let decoded_target_key_id: [u8; 32] = URL_SAFE_NO_PAD
        .decode(target_key_id.as_str())
        .map_err(|_| RecoveryPackageHydrationError::OutOfDomain)?
        .try_into()
        .map_err(|_| RecoveryPackageHydrationError::OutOfDomain)?;
    let target_auth_generation = recovery_package_safe_u64(row.requester_auth_generation)?;

    let historical = historical_authority_for_locked_head(head)
        .map_err(|_| RecoveryPackageHydrationError::ReadSetMismatch)?;
    let (requests, reservations) =
        load_recovery_work_hydration_rows(transaction, &historical, head.conversation_id()).await?;
    let request = requests
        .iter()
        .find(|value| value.request_id == *request_id.as_bytes())
        .ok_or(RecoveryPackageHydrationError::ReadSetMismatch)?;
    let reservation = reservations
        .iter()
        .find(|value| value.request_id == *request_id.as_bytes())
        .ok_or(RecoveryPackageHydrationError::ReadSetMismatch)?;
    let (origin_key_id, origin_auth_generation, request_provenance_digest) =
        recovery_origin_binding(&request.origin)?;
    let claimed_server = recovery_timestamp(claimed_at)?;
    let expires_server = recovery_timestamp(row.reservation_expires_at)?;
    let not_after_server = recovery_timestamp(row.not_after)?;

    if row.conversation_id != head.conversation_id()
        || row.recovery_request_id != request_id
        || head.prior_coordinate() != Some(&bound_coordinate)
        || row.requester_did != row.recipient_did
        || row.requester_device_id != row.recipient_device_id
        || row.requester_did != row.package_owner_did
        || row.requester_device_id != row.package_owner_device_id
        || row.requester_key_id != row.package_owner_key_id
        || row.requester_auth_generation != row.package_owner_auth_generation
        || row.reservation_status != "active"
        || row.package_status != "reserved"
        || BareDid::parse(&row.requester_did).is_err()
        || !uuid_is_canonical_v4(row.requester_device_id)
        || target_auth_generation == 0
        || origin_key_id != decoded_target_key_id
        || origin_auth_generation != target_auth_generation
        || !whole_millis_nonnegative(row.not_before)
        || !whole_millis_nonnegative(row.not_after)
        || !whole_millis_nonnegative(row.package_created_at)
        || !whole_millis_nonnegative(claimed_at)
        || !whole_millis_nonnegative(row.reservation_expires_at)
        || row.package_created_at > claimed_at
        || request.target.principal().as_bytes() != row.requester_did.as_bytes()
        || request.target.device_id() != row.requester_device_id.as_bytes()
        || request.bound_coordinate != bound_coordinate
        || request.key_package_ref != key_package_ref
        || request.received_at != claimed_server
        || request.expires_at != expires_server
        || request.status != RecoveryRequestStatus::Open
        || reservation.target != request.target
        || reservation.bound_coordinate != bound_coordinate
        || reservation.key_package_ref != key_package_ref
        || reservation.received_at != claimed_server
        || reservation.expires_at != expires_server
        || reservation.package_not_after != not_after_server
        || reservation.status != ReservationStatus::Active
    {
        return Err(RecoveryPackageHydrationError::ReadSetMismatch);
    }

    let durable_row_digest = recovery_package_guard_digest(
        &transaction_id,
        row.conversation_id,
        request_id,
        &row.requester_did,
        row.requester_device_id,
        &row.requester_key_id,
        row.requester_auth_generation,
        &bound_coordinate,
        &key_package_ref,
        &row.wrapper_bytes,
        &wrapper_sha256,
        row.not_before,
        row.not_after,
        claimed_at,
        LockedRecoveryPackageStatus::Reserved,
        LockedRecoveryPackageUse::ReservedFulfillment,
        Some(claimed_at),
        Some(row.reservation_expires_at),
        Some(&request_provenance_digest),
    );
    LockedRecoveryPackageGuard::from_locked_row(
        transaction_id,
        row.conversation_id,
        request_id,
        row.requester_did,
        row.requester_device_id,
        row.requester_key_id,
        row.requester_auth_generation,
        bound_coordinate,
        key_package_ref,
        row.wrapper_bytes,
        wrapper_sha256,
        row.not_before,
        row.not_after,
        claimed_at,
        LockedRecoveryPackageStatus::Reserved,
        LockedRecoveryPackageUse::ReservedFulfillment,
        Some(claimed_at),
        Some(row.reservation_expires_at),
        Some(request_provenance_digest),
        durable_row_digest,
    )
    .ok_or(RecoveryPackageHydrationError::GuardInvariant)
}

// ===========================================================================
// T4-H2-pre G2 — production hydrator for the EXISTING-conversation head lock.
//
// ADDITION under the coordinator grant "T4-H2-pre G2 FORK RULING" (Option 2):
// it locks and hydrates a `LockedConversationHeadGuard` for an EXISTING
// conversation (`prior_coordinate == Some(current coordinate)`) from ONE
// deterministic locked read. This is the reusable head-lock primitive that G1's
// aggregate (`seal_locked_conversation`) embeds and that the existing-conversation
// planners consume. The bare guard's constructor `from_locked_row` is
// module-private, so the hydrator must live in this module. The CREATION/absence
// head (`prior_coordinate == None`) is a separate variant landing with G3.
// ===========================================================================

/// Failure modes of [`hydrate_locked_conversation_head`].
// `#[allow(dead_code)]` on the G2 additions until the H2 conversation handlers
// call the hydrator in (the "unused until wired" convention the H1 repository
// modules use); the live-DB suite already exercises every arm.
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum ConversationHeadHydrationError {
    /// No live `chat.conversations` row (with its current `chat.generation_states`
    /// row) exists for the requested id under the transaction. Fail-closed: an
    /// absent conversation can never yield an existing-head witness.
    #[error("clean-chat conversation head is absent")]
    ConversationMissing,
    /// A stored column fell outside the protocol integer/byte-length domain the
    /// guard requires (safe-integer range or 32-byte crypto column).
    #[error("clean-chat conversation head column is out of domain")]
    OutOfDomain,
    /// The current generation-state lifecycle string was neither `active` nor
    /// `superseded`. Never defaulted — an unknown value fails closed.
    #[error("clean-chat conversation head lifecycle is not canonical")]
    NonCanonicalLifecycle,
    /// The locked row-set did not satisfy the guard invariant (e.g. a
    /// caller-supplied `locked_at` that is not a whole millisecond, or a
    /// non-canonical conversation id).
    #[error("clean-chat conversation head guard invariant was violated")]
    GuardInvariant,
    #[error("clean-chat conversation head database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Transaction-local identity digest over exactly the guard-exposed columns of a
/// locked conversation head, in this module's domain-separated, length-prefixed
/// `*_digest` style.
///
/// This is NOT a durable cross-transaction commitment: it exists only so a head
/// re-derived from the SAME locked read compares equal under the
/// `HydrationAuthority` head-equality checks. `LockedConversationHeadGuard::from_locked_row`
/// accepts any non-zero digest (it does not recompute one), so this function is
/// the sole definition of the head witness's identity within a transaction.
#[allow(dead_code)]
fn conversation_head_guard_digest(
    transaction_id: &str,
    conversation_id: Uuid,
    prior_coordinate: Option<&PublicGroupSnapshotCoordinate>,
    next_entry_seq: u64,
    locked_at: DateTime<Utc>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-CONVERSATION-HEAD\0");
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update(conversation_id.as_bytes());
    match prior_coordinate {
        None => digest.update([0]),
        Some(coordinate) => {
            digest.update([1]);
            digest.update(coordinate.generation().to_be_bytes());
            digest.update(coordinate.state_version().to_be_bytes());
            digest.update(coordinate.group_id());
            digest.update(coordinate.epoch().to_be_bytes());
            digest.update(coordinate.group_context_hash());
            digest.update(coordinate.confirmation_tag());
            digest.update([match coordinate.lifecycle() {
                super::super::snapshot::PublicGroupSnapshotLifecycle::Active => 1,
                super::super::snapshot::PublicGroupSnapshotLifecycle::Superseded => 2,
            }]);
        }
    }
    digest.update(next_entry_seq.to_be_bytes());
    digest.update(locked_at.timestamp_millis().to_be_bytes());
    digest.finalize().into()
}

/// Lock and hydrate the head of an EXISTING conversation.
///
/// Serialization + freshness (coordinator ruling "T4-H2-pre G2 FORK RULING"):
///   * `FOR UPDATE OF c` on `chat.conversations` is the head lock — the SAME
///     single-row serialization point the append-log allocator takes
///     (`repository::delivery::append_entry`, delivery.rs). Every head-advancing
///     transition UPDATEs `chat.conversations` (`repository::transition` head
///     CAS, transition.rs), so a concurrent advancer blocks on this row lock and
///     the lock pins WHICH `chat.generation_states` row is current for the life
///     of the transaction.
///   * `chat.generation_states` is read as a plain (unlocked) row because it is
///     INSERT-ONLY: the `generation_states_immutable` trigger (BEFORE UPDATE OR
///     DELETE, migration `20260722000001_chat_protocol_core.sql`) forbids
///     mutation, and lifecycle supersession is written to
///     `chat.generations`/`chat.conversations`, never to `generation_states`. So
///     the row selected by the `c`-pinned `current_generation` /
///     `current_state_version` has immutable content under the `c` lock.
///
/// `locked_at` is the caller's single canonical trusted request instant (a whole
/// millisecond), shared with the entry `received_at` and every sibling guard so
/// the planner's head/entry/authority equality checks hold; a sub-millisecond or
/// otherwise non-canonical value fails guard construction with `GuardInvariant`.
#[allow(dead_code)]
pub(crate) async fn hydrate_locked_conversation_head(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    locked_at: DateTime<Utc>,
) -> Result<LockedConversationHeadGuard, ConversationHeadHydrationError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;

    #[allow(clippy::type_complexity)]
    let row: Option<(i64, i64, i64, Vec<u8>, i64, Vec<u8>, Vec<u8>, String)> = sqlx::query_as(
        r#"
        SELECT
            c.current_generation,
            c.current_state_version,
            c.next_entry_seq,
            gs.group_id,
            gs.epoch,
            gs.group_context_hash,
            gs.confirmation_tag,
            gs.lifecycle
        FROM chat.conversations c
        JOIN chat.generation_states gs
          ON gs.conversation_id = c.conversation_id
         AND gs.generation = c.current_generation
         AND gs.state_version = c.current_state_version
        WHERE c.conversation_id = $1
        FOR UPDATE OF c
        "#,
    )
    .bind(conversation_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let (
        current_generation,
        current_state_version,
        stored_next_entry_seq,
        group_id,
        epoch,
        group_context_hash,
        confirmation_tag,
        lifecycle,
    ) = row.ok_or(ConversationHeadHydrationError::ConversationMissing)?;

    let generation = safe_protocol_u64(current_generation)?;
    let state_version = safe_protocol_u64(current_state_version)?;
    let epoch = safe_protocol_u64(epoch)?;
    let next_entry_seq = u64::try_from(stored_next_entry_seq)
        .ok()
        .filter(|value| (1..=MAX_PROTOCOL_INTEGER).contains(value))
        .ok_or(ConversationHeadHydrationError::OutOfDomain)?;
    let group_id: [u8; 32] = group_id
        .try_into()
        .map_err(|_| ConversationHeadHydrationError::OutOfDomain)?;
    let group_context_hash: [u8; 32] = group_context_hash
        .try_into()
        .map_err(|_| ConversationHeadHydrationError::OutOfDomain)?;
    let confirmation_tag: [u8; 32] = confirmation_tag
        .try_into()
        .map_err(|_| ConversationHeadHydrationError::OutOfDomain)?;
    let lifecycle = match lifecycle.as_str() {
        "active" => super::super::snapshot::PublicGroupSnapshotLifecycle::Active,
        "superseded" => super::super::snapshot::PublicGroupSnapshotLifecycle::Superseded,
        _ => return Err(ConversationHeadHydrationError::NonCanonicalLifecycle),
    };

    let prior_coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        generation,
        state_version,
        group_id,
        epoch,
        group_context_hash,
        confirmation_tag,
        lifecycle,
    );

    let durable_row_digest = conversation_head_guard_digest(
        &transaction_id,
        conversation_id,
        Some(&prior_coordinate),
        next_entry_seq,
        locked_at,
    );

    LockedConversationHeadGuard::from_locked_row(
        transaction_id,
        conversation_id,
        Some(prior_coordinate),
        next_entry_seq,
        locked_at,
        durable_row_digest,
    )
    .ok_or(ConversationHeadHydrationError::GuardInvariant)
}

#[allow(dead_code)]
fn safe_protocol_u64(value: i64) -> Result<u64, ConversationHeadHydrationError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(ConversationHeadHydrationError::OutOfDomain)
}

// ===========================================================================
// T4-H2-pre G3 — direct-pair absence-CAS lookup + the creation/absence head
// variant (coordinator grant "T4-H2-pre G2 FORK RULING": the creation head +
// its conflict-based exclusion test land with G3).
//
// ADDITIONS ONLY. `from_locked_lookup` / `from_locked_row` / `direct_lookup_guard_digest`
// are module-private, so both hydrators live here.
// ===========================================================================

/// Failure modes of [`hydrate_locked_direct_conversation_lookup`].
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum DirectConversationLookupError {
    /// The two DIDs are not a canonical `did_low < did_high` bare-DID pair.
    #[error("clean-chat direct-pair dids are not a canonical low<high pair")]
    NonCanonicalPair,
    /// A stored column of an existing direct conversation fell outside the
    /// protocol integer/byte-length domain.
    #[error("clean-chat direct conversation column is out of domain")]
    OutOfDomain,
    /// The existing direct conversation's current lifecycle string was neither
    /// `active` nor `superseded`. Never defaulted — fail closed.
    #[error("clean-chat direct conversation lifecycle is not canonical")]
    NonCanonicalLifecycle,
    /// The locked lookup did not satisfy the guard invariant.
    #[error("clean-chat direct lookup guard invariant was violated")]
    GuardInvariant,
    #[error("clean-chat direct lookup database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Lock the canonical `(did_low, did_high)` principal pair and, under those
/// locks, determine whether an ACTIVE direct conversation already exists for the
/// pair (the absence-CAS witness feeding createConversation's direct arm).
///
/// Serialization (coordinator ruling "T4-H2-pre G2 FORK RULING" / G3 confirm):
/// the absence-CAS point is `chat.principals FOR UPDATE` on the two DIDs in
/// canonical order — the same parent-lock pattern `chat.enforce_invitation_quota`
/// documents (migration `20260722000001_chat_protocol_core.sql`,
/// `PERFORM 1 FROM chat.principals WHERE user_did IN (...) ORDER BY user_did FOR
/// UPDATE`). Two concurrent creators of the same pair contend on those rows, so
/// the "absent" observation and the subsequent create are race-free; the partial
/// unique index `conversations_active_direct_pair_uq` (one active direct row per
/// `(direct_did_low, direct_did_high)`) is the ultimate arbiter.
///
/// `locked_at` is the caller's single canonical whole-ms trusted request instant
/// (shared with the sibling guards and cross-checked in `plan_creation`).
#[allow(dead_code)]
pub(crate) async fn hydrate_locked_direct_conversation_lookup(
    transaction: &mut Transaction<'_, Postgres>,
    did_low: &str,
    did_high: &str,
    locked_at: DateTime<Utc>,
) -> Result<LockedDirectConversationLookupGuard, DirectConversationLookupError> {
    if BareDid::parse(did_low).is_err() || BareDid::parse(did_high).is_err() || did_low >= did_high
    {
        return Err(DirectConversationLookupError::NonCanonicalPair);
    }

    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;

    // Absence-CAS serialization: lock both principals in canonical DID order.
    sqlx::query(
        r#"
        SELECT user_did
          FROM chat.principals
         WHERE user_did IN ($1, $2)
         ORDER BY user_did
           FOR UPDATE
        "#,
    )
    .bind(did_low)
    .bind(did_high)
    .fetch_all(&mut **transaction)
    .await?;

    // Under those locks, read the (at most one) active direct conversation for
    // the pair together with its current coordinate columns.
    #[allow(clippy::type_complexity)]
    let existing: Option<(Uuid, i64, i64, i64, Vec<u8>, i64, Vec<u8>, Vec<u8>, String)> =
        sqlx::query_as(
            r#"
        SELECT
            c.conversation_id,
            c.current_generation,
            c.current_state_version,
            c.next_entry_seq,
            gs.group_id,
            gs.epoch,
            gs.group_context_hash,
            gs.confirmation_tag,
            gs.lifecycle
        FROM chat.conversations c
        JOIN chat.generation_states gs
          ON gs.conversation_id = c.conversation_id
         AND gs.generation = c.current_generation
         AND gs.state_version = c.current_state_version
        WHERE c.kind = 'direct'
          AND c.lifecycle = 'active'
          AND c.direct_did_low = $1
          AND c.direct_did_high = $2
        "#,
        )
        .bind(did_low)
        .bind(did_high)
        .fetch_optional(&mut **transaction)
        .await?;

    let outcome = match existing {
        None => LockedDirectLookupOutcome::Absent,
        Some((
            conversation_id,
            current_generation,
            current_state_version,
            stored_next_entry_seq,
            group_id,
            epoch,
            group_context_hash,
            confirmation_tag,
            lifecycle,
        )) => {
            let domain = |value: i64| -> Result<u64, DirectConversationLookupError> {
                u64::try_from(value)
                    .ok()
                    .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
                    .ok_or(DirectConversationLookupError::OutOfDomain)
            };
            let generation = domain(current_generation)?;
            let state_version = domain(current_state_version)?;
            let epoch = domain(epoch)?;
            let next_entry_seq = u64::try_from(stored_next_entry_seq)
                .ok()
                .filter(|value| (1..=MAX_PROTOCOL_INTEGER).contains(value))
                .ok_or(DirectConversationLookupError::OutOfDomain)?;
            let group_id: [u8; 32] = group_id
                .try_into()
                .map_err(|_| DirectConversationLookupError::OutOfDomain)?;
            let group_context_hash: [u8; 32] = group_context_hash
                .try_into()
                .map_err(|_| DirectConversationLookupError::OutOfDomain)?;
            let confirmation_tag: [u8; 32] = confirmation_tag
                .try_into()
                .map_err(|_| DirectConversationLookupError::OutOfDomain)?;
            let lifecycle = match lifecycle.as_str() {
                "active" => super::super::snapshot::PublicGroupSnapshotLifecycle::Active,
                "superseded" => super::super::snapshot::PublicGroupSnapshotLifecycle::Superseded,
                _ => return Err(DirectConversationLookupError::NonCanonicalLifecycle),
            };
            let coordinate = PublicGroupSnapshotCoordinate::new(
                *conversation_id.as_bytes(),
                generation,
                state_version,
                group_id,
                epoch,
                group_context_hash,
                confirmation_tag,
                lifecycle,
            );
            // Bind the existing head: the same transaction-local head identity a
            // G2 hydration of this conversation would mint.
            let locked_head_digest = conversation_head_guard_digest(
                &transaction_id,
                conversation_id,
                Some(&coordinate),
                next_entry_seq,
                locked_at,
            );
            LockedDirectLookupOutcome::Existing {
                conversation_id,
                coordinate,
                locked_head_digest,
            }
        }
    };

    let durable_row_digest =
        direct_lookup_guard_digest(&transaction_id, did_low, did_high, locked_at, &outcome);

    LockedDirectConversationLookupGuard::from_locked_lookup(
        transaction_id,
        did_low.to_owned(),
        did_high.to_owned(),
        locked_at,
        outcome,
        durable_row_digest,
    )
    .ok_or(DirectConversationLookupError::GuardInvariant)
}

/// Failure modes of [`hydrate_locked_creation_head`].
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum CreationHeadHydrationError {
    /// A `chat.conversations` row already exists for the proposed id — creation
    /// cannot proceed (fail-closed; the caller chose a colliding id or is racing).
    #[error("clean-chat conversation id already exists")]
    ConversationExists,
    /// The creation-head guard invariant was violated (e.g. a non-canonical
    /// conversation id or a non-whole-millisecond `locked_at`).
    #[error("clean-chat creation-head guard invariant was violated")]
    GuardInvariant,
    #[error("clean-chat creation-head database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Witness the ABSENCE of `conversation_id` under the transaction and mint the
/// CREATION head guard (`prior_coordinate == None`, `next_entry_seq == 1`) that
/// createConversation feeds to `from_locked_creation_head`.
///
/// Exclusion is CONFLICT-based, not a blocking row lock (fork ruling): a
/// `FOR UPDATE` of an absent row locks nothing, so this only witnesses absence.
/// The executor's INSERT is the arbiter — the `chat.conversations` primary key
/// for a group, and additionally the `conversations_active_direct_pair_uq`
/// partial unique index for a direct conversation. For a direct creation the
/// caller ALSO holds the G3 principals-pair lock from
/// [`hydrate_locked_direct_conversation_lookup`], which serializes the racing
/// creators before they reach the insert.
///
/// `locked_at` is the caller's single canonical whole-ms trusted request instant.
#[allow(dead_code)]
pub(crate) async fn hydrate_locked_creation_head(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    locked_at: DateTime<Utc>,
) -> Result<LockedConversationHeadGuard, CreationHeadHydrationError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;

    let existing: Option<Uuid> = sqlx::query_scalar(
        r#"
        SELECT conversation_id
          FROM chat.conversations
         WHERE conversation_id = $1
           FOR UPDATE
        "#,
    )
    .bind(conversation_id)
    .fetch_optional(&mut **transaction)
    .await?;
    if existing.is_some() {
        return Err(CreationHeadHydrationError::ConversationExists);
    }

    let durable_row_digest =
        conversation_head_guard_digest(&transaction_id, conversation_id, None, 1, locked_at);

    LockedConversationHeadGuard::from_locked_row(
        transaction_id,
        conversation_id,
        None,
        1,
        locked_at,
        durable_row_digest,
    )
    .ok_or(CreationHeadHydrationError::GuardInvariant)
}

// ===========================================================================
// T4-H2-pre G1 (snapshot leg) — production hydrator for the locked public-state
// witness of an EXISTING conversation's current generation.
//
// ADDITION under the H2-pre grant. It locks and hydrates a
// `LockedPublicStateHydrationGuard` from ONE deterministic locked read, sealing
// through the existing `seal_locked_public_state_hydration` seam (pub(super), so
// the hydrator must live in this module). This is the reusable snapshot leg the
// G1 aggregate (`hydrate_locked_conversation_state`) embeds to build its
// `active_public_state` + `locked_snapshot_digest`, and that the read-only
// getConversationState assembly (G7) reuses. `load_persisted_active_snapshot`
// (public_state.rs) then decodes the sealed guard into an `ActivePublicState`.
//
// Lock scope is IDENTICAL to G2's ratified head lock: `FOR UPDATE OF c` on
// `chat.conversations` is the single-row serialization point; the current
// `chat.generation_states` row is a plain read because that table is INSERT-ONLY
// (the `generation_states_immutable` trigger forbids UPDATE/DELETE; lifecycle
// supersession writes `chat.generations`/`chat.conversations`, never
// `generation_states`), so the `c`-pinned current gen-state row has immutable
// content under the lock. No new lock-scope ruling is required.
// ===========================================================================

/// Failure modes of [`hydrate_locked_public_state`].
// `#[allow(dead_code)]` until the H2 conversation handlers / the G1 aggregate
// call the hydrator (the "unused until wired" convention); the live-DB suite
// exercises every arm.
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum PublicStateHydrationError {
    /// No live `chat.conversations` row (with its current `chat.generation_states`
    /// row) exists for the requested id under the transaction. Fail-closed: an
    /// absent conversation can never yield a public-state witness.
    #[error("clean-chat conversation public state is absent")]
    ConversationMissing,
    /// A stored column fell outside the protocol integer/byte-length domain the
    /// guard requires (safe-integer range or 32-byte crypto column).
    #[error("clean-chat public state column is out of domain")]
    OutOfDomain,
    /// The current generation-state lifecycle string was neither `active` nor
    /// `superseded`. Never defaulted — an unknown value fails closed.
    #[error("clean-chat public state lifecycle is not canonical")]
    NonCanonicalLifecycle,
    /// The stored canonical tree-summary bytes were not the exact canonical
    /// encoding, or their digest did not match the stored tree-summary digest.
    #[error("clean-chat persisted tree summary is invalid")]
    InvalidTreeSummary,
    /// The supplied head was not minted by this database transaction or the
    /// immutable generation row no longer byte-equaled its pinned coordinate.
    #[error("clean-chat public state does not match the already-locked head")]
    LockedHeadMismatch,
    #[error("clean-chat conversation head hydration failed: {0}")]
    Head(ConversationHeadHydrationError),
    /// The locked row-set did not satisfy the guard invariant (e.g. a
    /// caller-supplied `locked_at` that is not a whole millisecond, or an empty
    /// snapshot column).
    #[error("clean-chat public state guard invariant was violated")]
    GuardInvariant,
    #[error("clean-chat public state database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Transaction-local identity digest over exactly the guard-exposed generation
/// columns, in this module's domain-separated, length-prefixed `*_digest` style.
///
/// This is NOT a durable cross-transaction commitment: it exists only as the
/// `locked_generation_row_digest` witness that the sealed guard was produced from
/// the SAME locked read. `seal_locked_public_state_hydration` accepts any
/// non-zero digest (it does not recompute one), so this function is the sole
/// definition of the public-state witness's identity within a transaction.
#[allow(dead_code)]
fn public_state_hydration_guard_digest(
    transaction_id: &str,
    coordinate: &PublicGroupSnapshotCoordinate,
    snapshot_sha256: &[u8; 32],
    tree_summary_sha256: &[u8; 32],
    locked_at: DateTime<Utc>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-PUBLIC-STATE\0");
    digest.update((transaction_id.len() as u64).to_be_bytes());
    digest.update(transaction_id.as_bytes());
    digest.update(coordinate.conversation_id());
    digest.update(coordinate.generation().to_be_bytes());
    digest.update(coordinate.state_version().to_be_bytes());
    digest.update(coordinate.group_id());
    digest.update(coordinate.epoch().to_be_bytes());
    digest.update(coordinate.group_context_hash());
    digest.update(coordinate.confirmation_tag());
    digest.update([match coordinate.lifecycle() {
        super::super::snapshot::PublicGroupSnapshotLifecycle::Active => 1,
        super::super::snapshot::PublicGroupSnapshotLifecycle::Superseded => 2,
    }]);
    digest.update(snapshot_sha256);
    digest.update(tree_summary_sha256);
    digest.update(locked_at.timestamp_millis().to_be_bytes());
    digest.finalize().into()
}

/// Lock and hydrate the public-state witness of an EXISTING conversation's
/// current generation.
///
/// Serialization + freshness are exactly the G2 head lock (see the module
/// section header): `FOR UPDATE OF c` on `chat.conversations` pins the current
/// `chat.generation_states` row, read plain because that table is INSERT-ONLY.
///
/// Snapshot-digest coherence is enforced BEFORE this hydrator by the
/// `generation_states_snapshot_hash_check` DDL constraint (the stored
/// `snapshot_sha256` must equal `sha256(public_snapshot_bytes)`, so a spliced
/// blob is unpersistable) and re-verified WITHIN
/// `seal_locked_public_state_hydration`, which recomputes `sha256(snapshot)` and
/// rejects any binding whose `snapshot_sha256` disagrees. The stored tree-summary
/// bytes are re-decoded canonically against their stored digest here
/// (`decode_public_tree_summary`, `InvalidTreeSummary`), so a non-canonical row
/// fails closed rather than entering a witness. `load_persisted_active_snapshot`
/// later decodes the sealed guard's snapshot blob into the verified
/// `ActivePublicState`.
///
/// `locked_at` is the caller's single canonical whole-ms trusted request instant,
/// shared with the sibling head/authority guards; a sub-millisecond value fails
/// guard construction with `GuardInvariant`.
#[allow(dead_code)]
pub(crate) async fn hydrate_locked_public_state(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    locked_at: DateTime<Utc>,
) -> Result<LockedPublicStateHydrationGuard, PublicStateHydrationError> {
    let head = hydrate_locked_conversation_head(transaction, conversation_id, locked_at)
        .await
        .map_err(|error| match error {
            ConversationHeadHydrationError::ConversationMissing => {
                PublicStateHydrationError::ConversationMissing
            }
            error => PublicStateHydrationError::Head(error),
        })?;
    hydrate_public_state_under_locked_head(transaction, &head).await
}

/// Hydrate the immutable generation row selected by an already-held head lock.
///
/// No second `FOR UPDATE` is issued here. The caller's conversation-head guard
/// is the sole serialization point; this query reads only its exact
/// generation/state-version and proves it is executing in the same transaction.
#[allow(dead_code)]
pub(crate) async fn hydrate_public_state_under_locked_head(
    transaction: &mut Transaction<'_, Postgres>,
    head: &LockedConversationHeadGuard,
) -> Result<LockedPublicStateHydrationGuard, PublicStateHydrationError> {
    let Some(head_coordinate) = head.prior_coordinate() else {
        return Err(PublicStateHydrationError::LockedHeadMismatch);
    };
    let conversation_id = head.conversation_id();
    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    )> = sqlx::query_as(
        r#"
        SELECT
            txid_current()::text,
            gs.group_id,
            gs.epoch,
            gs.group_context_hash,
            gs.confirmation_tag,
            gs.lifecycle,
            gs.public_snapshot_bytes,
            gs.snapshot_sha256,
            gs.tree_summary_bytes,
            gs.tree_summary_sha256
        FROM chat.generation_states gs
        WHERE gs.conversation_id = $1
          AND gs.generation = $2
          AND gs.state_version = $3
        "#,
    )
    .bind(conversation_id)
    .bind(
        i64::try_from(head_coordinate.generation())
            .map_err(|_| PublicStateHydrationError::LockedHeadMismatch)?,
    )
    .bind(
        i64::try_from(head_coordinate.state_version())
            .map_err(|_| PublicStateHydrationError::LockedHeadMismatch)?,
    )
    .fetch_optional(&mut **transaction)
    .await?;
    let (
        transaction_id,
        group_id,
        epoch,
        group_context_hash,
        confirmation_tag,
        lifecycle,
        public_snapshot_bytes,
        snapshot_sha256,
        tree_summary_bytes,
        tree_summary_sha256,
    ) = row.ok_or(PublicStateHydrationError::ConversationMissing)?;

    if transaction_id != head.transaction_id() {
        return Err(PublicStateHydrationError::LockedHeadMismatch);
    }
    let generation = head_coordinate.generation();
    let state_version = head_coordinate.state_version();
    let epoch = safe_public_state_u64(epoch)?;
    let group_id: [u8; 32] = group_id
        .try_into()
        .map_err(|_| PublicStateHydrationError::OutOfDomain)?;
    let group_context_hash: [u8; 32] = group_context_hash
        .try_into()
        .map_err(|_| PublicStateHydrationError::OutOfDomain)?;
    let confirmation_tag: [u8; 32] = confirmation_tag
        .try_into()
        .map_err(|_| PublicStateHydrationError::OutOfDomain)?;
    let snapshot_sha256: [u8; 32] = snapshot_sha256
        .try_into()
        .map_err(|_| PublicStateHydrationError::OutOfDomain)?;
    let tree_summary_sha256: [u8; 32] = tree_summary_sha256
        .try_into()
        .map_err(|_| PublicStateHydrationError::OutOfDomain)?;
    let lifecycle = match lifecycle.as_str() {
        "active" => super::super::snapshot::PublicGroupSnapshotLifecycle::Active,
        "superseded" => super::super::snapshot::PublicGroupSnapshotLifecycle::Superseded,
        _ => return Err(PublicStateHydrationError::NonCanonicalLifecycle),
    };

    // The stored canonical tree summary must re-decode against its stored digest;
    // this rejects a mismatched digest or any non-canonical encoding.
    let tree_summary = super::super::public_state::decode_public_tree_summary(
        &tree_summary_bytes,
        &tree_summary_sha256,
    )
    .map_err(|_| PublicStateHydrationError::InvalidTreeSummary)?;

    let coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        generation,
        state_version,
        group_id,
        epoch,
        group_context_hash,
        confirmation_tag,
        lifecycle,
    );
    if &coordinate != head_coordinate {
        return Err(PublicStateHydrationError::LockedHeadMismatch);
    }

    let binding = PublicGroupSnapshotBinding::new(
        *conversation_id.as_bytes(),
        generation,
        state_version,
        group_id,
        epoch,
        group_context_hash,
        confirmation_tag,
        lifecycle,
        snapshot_sha256,
        tree_summary,
    );

    let locked_generation_row_digest = public_state_hydration_guard_digest(
        &transaction_id,
        &coordinate,
        &snapshot_sha256,
        &tree_summary_sha256,
        head.locked_at(),
    );

    seal_locked_public_state_hydration(
        transaction_id,
        conversation_id,
        coordinate,
        public_snapshot_bytes,
        binding,
        tree_summary_bytes,
        tree_summary_sha256,
        head.locked_at(),
        locked_generation_row_digest,
    )
    .ok_or(PublicStateHydrationError::GuardInvariant)
}

#[allow(dead_code)]
fn safe_public_state_u64(value: i64) -> Result<u64, PublicStateHydrationError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(PublicStateHydrationError::OutOfDomain)
}

// ===========================================================================
// G1b-2 — historical control-entry evidence loader (per-transition read leg).
//
// Every producer / opening / origin / terminal transition id the existing-
// conversation-state aggregate references resolves to exactly one durable
// control entry. This loader reads that entry's bytes and re-verifies them
// through the read-time `HistoricalRehydrationAuthority`, yielding the same
// sealed evidence the append-time path would — but bound to each historical
// entry's own recorded seq/receivedAt/prior (per OQ-G1-3(a)) rather than the
// head append expectation. It is the DB read half of the loader atom; the crypto
// half is `HistoricalRehydrationAuthority::hydrate_historical_control_from_durable_bytes`.
// ===========================================================================

/// Failure modes of the durable historical control-entry evidence loader.
#[derive(Debug, Error)]
pub(crate) enum ControlEvidenceLoadError {
    /// No `chat.entries` row (with its `chat.device_keys` signing key) exists for
    /// the requested `(conversation_id, transition_id)` under the transaction.
    /// Fail-closed: a missing producing entry can never yield evidence.
    #[error("clean-chat control entry is absent for the transition")]
    EntryMissing,
    /// The durable row failed read-time re-verification through the historical
    /// rehydration authority (signature, conversation binding, frozen row digest,
    /// or the strict `seq < head` constraint). Never coerced into evidence.
    #[error("clean-chat control entry failed historical re-verification")]
    InvalidEvidence,
    #[error("clean-chat control evidence load database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Load and re-verify the HISTORICAL control-entry evidence produced by one past
/// transition of an existing conversation, for the G1b-2 state aggregate.
///
/// Reads the durable `chat.entries` row keyed by `(conversation_id,
/// transition_id)` — `accepted_payload_bytes` is the canonical public control-row
/// JSON, `signed_request_bytes` the exact signed wrapper — together with the
/// actor's historical signing key JOINed from `chat.device_keys` on
/// `(actor_did, actor_device_id, actor_key_id)`. The device-keys `key_id` binding
/// pins `key_id = ed25519_key_id(signing_public_key)`, so the JOIN yields exactly
/// the immutable key that signed the entry. The bytes are then re-verified through
/// `HistoricalRehydrationAuthority::hydrate_historical_control_from_durable_bytes`
/// (ed25519 + DAG-CBOR structure re-checked, conversation binding enforced, the
/// entry's own `seq` required strictly below the locked head), so nothing the
/// aggregate consumes is trusted from un-reverified DB state.
///
/// No `FOR UPDATE`: `chat.entries` is append-only and immutable (the
/// `entries_immutable` trigger), and the caller already holds the head lock
/// (`FOR UPDATE OF c` on `chat.conversations`) that pins the historical suffix, so
/// a plain read is consistent. `authority` MUST be the read-time authority minted
/// from that same locked head.
#[allow(dead_code)]
pub(crate) async fn load_historical_control_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
    transition_id: Uuid,
) -> Result<PersistedControlAuthority, ControlEvidenceLoadError> {
    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT
            e.accepted_payload_bytes,
            e.signed_request_bytes,
            dk.signing_public_key
        FROM chat.entries e
        JOIN chat.device_keys dk
          ON dk.user_did = e.actor_did
         AND dk.device_id = e.actor_device_id
         AND dk.key_id = e.actor_key_id
        WHERE e.conversation_id = $1
          AND e.transition_id = $2
        "#,
    )
    .bind(conversation_id)
    .bind(transition_id)
    .fetch_optional(&mut **transaction)
    .await?;

    let (public_row_json, raw_signed_wrapper, signing_public_key) =
        row.ok_or(ControlEvidenceLoadError::EntryMissing)?;

    authority
        .hydrate_historical_control_from_durable_bytes(
            public_row_json,
            raw_signed_wrapper,
            &signing_public_key,
        )
        .map_err(|_| ControlEvidenceLoadError::InvalidEvidence)
}

// ===========================================================================
// G1b-2 — leaf-membership hydration leg (chat.member_devices + tree summary).
//
// READ-SET-MAP CORRECTION (coordinator ruling "T4-H2-pre G1b-2 aggregate-leg
// RULINGS", FINDING-1; same class as G2's chat.conversation_heads ->
// chat.conversations): the read-set map lists `leaves[].encryption_key` as a
// `chat.member_devices` column, but NO encryption_key column exists in that
// table — or anywhere in `20260722000001_chat_protocol_core.sql`. The
// authoritative source for a leaf's crypto material (leaf_index /
// basic_credential / signature_key / ENCRYPTION_KEY) is the TREE SUMMARY of the
// current public snapshot, exactly as the append-time
// `state_machine::singleton_genesis_leaf` derives it and as
// `state_machine::validate_state` re-checks by positionally byte-comparing
// `state.leaves` against `public_state.binding().tree_summary().leaves()`.
// `chat.member_devices` supplies ONLY the durable device identity + the join
// KeyPackage ref + the active/leaf_index correspondence.
// ===========================================================================

/// Failure modes of [`load_leaf_hydration_rows`].
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum LeafHydrationError {
    /// A stored `chat.member_devices` column fell outside the protocol domain
    /// (leaf-index range, DID/UUID grammar, or a non-32-byte KeyPackage ref).
    #[error("clean-chat member device column is out of domain")]
    OutOfDomain,
    /// The active `chat.member_devices` set did not correspond one-for-one, in
    /// leaf-index order, with the current authenticated tree-summary leaves
    /// (count, index, basic credential, or signature key disagreed). Fail
    /// closed: the durable membership binding and the authenticated public tree
    /// MUST agree, and the tree is the crypto authority.
    #[error("clean-chat member devices do not match the public tree summary")]
    TreeMismatch,
    #[error("clean-chat leaf hydration database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Load the active leaf-membership rows of an existing conversation, binding
/// each durable `chat.member_devices` row to its authenticated public tree leaf.
///
/// Leaf crypto (leaf_index / basic_credential / signature_key / encryption_key)
/// is taken from `binding`'s tree summary — the authenticated source per the
/// FINDING-1 correction above and `validate_state`'s positional byte-equality
/// gate. `chat.member_devices` supplies the device identity `(user_did,
/// device_id)` and the optional join KeyPackage ref; the row's own leaf_index /
/// basic_credential / leaf_signature_key MUST equal the tree leaf's (in
/// leaf-index order), or the leg fails closed with `TreeMismatch`.
///
/// `binding` MUST be the snapshot leg of the SAME locked read — i.e. the
/// digest-verified `PublicGroupSnapshotBinding` sealed by
/// `hydrate_locked_public_state` (the aggregate passes its `ActivePublicState`'s
/// `binding()`). The tree summary it carries was decoded and digest-checked
/// against the stored generation row, so only its per-leaf crypto is needed here
/// (not the full snapshot-blob reload).
///
/// No `FOR UPDATE`: the caller already holds the head lock (`FOR UPDATE OF c` on
/// `chat.conversations`) that pins the current generation and its immutable
/// `chat.member_devices` suffix, and `binding` was hydrated under that same lock.
#[allow(dead_code)]
pub(crate) async fn load_leaf_hydration_rows(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    binding: &PublicGroupSnapshotBinding,
) -> Result<Vec<LeafHydrationRow>, LeafHydrationError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, Uuid, i64, Vec<u8>, Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
        r#"
        SELECT
            md.user_did,
            md.device_id,
            md.leaf_index,
            md.basic_credential,
            md.leaf_signature_key,
            md.join_key_package_ref
        FROM chat.member_devices md
        WHERE md.conversation_id = $1
          AND md.active
        ORDER BY md.leaf_index
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;

    let public_leaves = binding.tree_summary().leaves();
    if rows.len() != public_leaves.len() {
        return Err(LeafHydrationError::TreeMismatch);
    }

    let mut leaves = Vec::with_capacity(rows.len());
    for (
        (user_did, device_id, leaf_index, basic_credential, signature_key, join_key_package_ref),
        public_leaf,
    ) in rows.into_iter().zip(public_leaves)
    {
        let leaf_index = u32::try_from(leaf_index).map_err(|_| LeafHydrationError::OutOfDomain)?;
        let principal =
            PrincipalId::new(user_did.into_bytes()).map_err(|_| LeafHydrationError::OutOfDomain)?;
        let device = DeviceIdentity::new(principal, *device_id.as_bytes())
            .map_err(|_| LeafHydrationError::OutOfDomain)?;
        // The durable membership row and the authenticated tree leaf must agree
        // on this position's crypto identity; the tree is authoritative, so its
        // values (never the row's) are carried into the hydrated leaf.
        if leaf_index != public_leaf.leaf_index()
            || basic_credential != public_leaf.basic_credential()
            || signature_key != public_leaf.signature_key()
            || device.basic_credential() != public_leaf.basic_credential()
        {
            return Err(LeafHydrationError::TreeMismatch);
        }
        let key_package_ref = match join_key_package_ref {
            None => None,
            Some(bytes) => Some(
                <[u8; 32]>::try_from(bytes.as_slice())
                    .map_err(|_| LeafHydrationError::OutOfDomain)?,
            ),
        };
        leaves.push(LeafHydrationRow {
            device,
            leaf_index: public_leaf.leaf_index(),
            basic_credential: public_leaf.basic_credential().to_vec(),
            signature_key: public_leaf.signature_key().to_vec(),
            encryption_key: public_leaf.encryption_key().to_vec(),
            key_package_ref,
        });
    }
    Ok(leaves)
}

// ===========================================================================
// G1b-2 sub-seal 1b — participant-membership hydration leg (chat.participants +
// per-participant historical provenance evidence).
//
// Each current-membership `chat.participants` row carries the participant's
// principal / status / role plus the transition ids that produced its role,
// invitation, and acceptance. The durable columns alone are not sealed evidence,
// so this leg re-loads and re-verifies each referenced control entry through
// `load_historical_control_evidence` (ed25519 + DAG-CBOR re-checked, bound to the
// locked conversation and strictly below the head), then classifies the verified
// evidence into the hydrated provenance shape via the module-private
// `state_machine` classifiers (FINDING-2 ruling). `chat.member_devices` and the
// leaves leg are orthogonal — this leg touches only participant rows.
// ===========================================================================

/// Failure modes of [`load_participant_hydration_rows`].
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum ParticipantHydrationError {
    /// A stored `chat.participants` column fell outside the protocol domain (a
    /// DID or UUID grammar violation, or an unrecognized status/role token).
    #[error("clean-chat participant column is out of domain")]
    OutOfDomain,
    /// A participant's referenced provenance transition (role / invitation /
    /// acceptance) has no durable `chat.entries` row. Fail closed: absent
    /// provenance can never yield evidence.
    #[error("clean-chat participant provenance entry is absent")]
    ProvenanceMissing,
    /// A provenance transition failed read-time re-verification, or the verified
    /// evidence did not attest the participant's claimed role / invitation /
    /// acceptance. Never coerced into a provenance it does not attest.
    #[error("clean-chat participant provenance failed re-verification")]
    InvalidProvenance,
    #[error("clean-chat participant hydration database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl From<ControlEvidenceLoadError> for ParticipantHydrationError {
    fn from(error: ControlEvidenceLoadError) -> Self {
        match error {
            ControlEvidenceLoadError::EntryMissing => ParticipantHydrationError::ProvenanceMissing,
            ControlEvidenceLoadError::InvalidEvidence => {
                ParticipantHydrationError::InvalidProvenance
            }
            ControlEvidenceLoadError::Database(error) => ParticipantHydrationError::Database(error),
        }
    }
}

#[derive(sqlx::FromRow)]
struct DurableParticipantHydrationRow {
    user_did: String,
    status: String,
    role: String,
    role_transition_id: Uuid,
    invitation_transition_id: Option<Uuid>,
    created_by_did: String,
    created_by_device_id: Uuid,
    acceptance_transition_id: Option<Uuid>,
}

async fn hydrate_participant_row(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
    row: DurableParticipantHydrationRow,
) -> Result<ParticipantHydrationRow, ParticipantHydrationError> {
    let principal = PrincipalId::new(row.user_did.into_bytes())
        .map_err(|_| ParticipantHydrationError::OutOfDomain)?;
    let status = match row.status.as_str() {
        "pending" => ParticipantStatus::Pending,
        "active" => ParticipantStatus::Active,
        _ => return Err(ParticipantHydrationError::OutOfDomain),
    };
    let role = match row.role.as_str() {
        "member" => ParticipantRole::Member,
        "admin" => ParticipantRole::Admin,
        _ => return Err(ParticipantHydrationError::OutOfDomain),
    };

    let role_evidence = load_historical_control_evidence(
        transaction,
        authority,
        conversation_id,
        row.role_transition_id,
    )
    .await?
    .into_transition()
    .map_err(|_| ParticipantHydrationError::InvalidProvenance)?;
    let role_producer = classify_role_producer(role_evidence, &principal, role)
        .map_err(|_| ParticipantHydrationError::InvalidProvenance)?;

    let invitation = match row.invitation_transition_id {
        None => None,
        Some(invitation_transition_id) => {
            let inviter_principal = PrincipalId::new(row.created_by_did.into_bytes())
                .map_err(|_| ParticipantHydrationError::OutOfDomain)?;
            let inviter =
                DeviceIdentity::new(inviter_principal, *row.created_by_device_id.as_bytes())
                    .map_err(|_| ParticipantHydrationError::OutOfDomain)?;
            let evidence = load_historical_control_evidence(
                transaction,
                authority,
                conversation_id,
                invitation_transition_id,
            )
            .await?
            .into_transition()
            .map_err(|_| ParticipantHydrationError::InvalidProvenance)?;
            Some(
                classify_invitation(evidence, &principal, inviter)
                    .map_err(|_| ParticipantHydrationError::InvalidProvenance)?,
            )
        }
    };

    let acceptance = match row.acceptance_transition_id {
        None => None,
        Some(acceptance_transition_id) => {
            let evidence = load_historical_control_evidence(
                transaction,
                authority,
                conversation_id,
                acceptance_transition_id,
            )
            .await?
            .into_transition()
            .map_err(|_| ParticipantHydrationError::InvalidProvenance)?;
            Some(
                classify_acceptance(evidence, &principal)
                    .map_err(|_| ParticipantHydrationError::InvalidProvenance)?,
            )
        }
    };

    Ok(ParticipantHydrationRow {
        principal,
        status,
        role,
        role_producer,
        invitation,
        acceptance,
    })
}

/// Load the current-membership participant rows of an existing conversation,
/// binding each to its re-verified historical provenance evidence for the
/// G1b-2 state aggregate.
///
/// Reads `chat.participants WHERE current_membership` and, per row, re-loads the
/// referenced provenance transitions through
/// [`load_historical_control_evidence`] (so the aggregate never trusts un-
/// reverified DB state) and classifies the verified evidence:
/// - `role_producer`: [`classify_role_producer`] over the `role_transition_id`
///   entry — `Some` for a policy role change, `None` for a creation / policy-add
///   established role, fail-closed otherwise;
/// - `invitation`: for a non-NULL `invitation_transition_id`,
///   [`classify_invitation`] over that entry with the durable inviter identity
///   (`created_by_did` / `created_by_device_id`);
/// - `acceptance`: for a non-NULL `acceptance_transition_id`,
///   [`classify_acceptance`] over that entry.
///
/// The rows are returned sorted by principal (matching the state-machine roster
/// invariant that the aggregate's `hydrate_conversation_state` re-checks via
/// `binary_search`), independent of the database's `user_did` text collation.
///
/// `authority` MUST be the read-time authority minted from the SAME locked head
/// as the rest of the aggregate. No `FOR UPDATE`: the caller already holds the
/// head lock (`FOR UPDATE OF c` on `chat.conversations`) that pins the current
/// membership suffix, and `chat.entries` is append-only + immutable.
#[allow(dead_code)]
pub(crate) async fn load_participant_hydration_rows(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
) -> Result<Vec<ParticipantHydrationRow>, ParticipantHydrationError> {
    let rows: Vec<DurableParticipantHydrationRow> = sqlx::query_as(
        r#"
        SELECT
            p.user_did,
            p.status,
            p.role,
            p.role_transition_id,
            p.invitation_transition_id,
            p.created_by_did,
            p.created_by_device_id,
            p.acceptance_transition_id
        FROM chat.participants p
        WHERE p.conversation_id = $1
          AND p.current_membership
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;

    let mut participants = Vec::with_capacity(rows.len());
    for row in rows {
        participants
            .push(hydrate_participant_row(transaction, authority, conversation_id, row).await?);
    }
    participants.sort_by(|left, right| left.principal.cmp(&right.principal));
    Ok(participants)
}

// ===========================================================================
// G1b-2 sub-seal 2a — application-interval hydration leg (chat.application_intervals
// + per-boundary historical transition evidence).
//
// Each `chat.application_intervals` row records one recipient device's access
// interval: the opening transition (creation / leafRecoveryFulfillment /
// resetActivation) plus, once the interval closes, the closing transition and
// its close kind. The opening/closing coordinates are FK-bound to
// `chat.generation_states`, so the durable snapshot columns are authentic; the
// opening/closing evidence, however, is not sealed by the row alone, so this leg
// re-loads and re-verifies each referenced control entry through
// `load_historical_control_evidence` (ed25519 + DAG-CBOR re-checked, bound to the
// locked conversation and strictly below the head) and downcasts it to a
// transition (`into_transition`; an interval boundary is always a coordinate
// control transition, never a signed request). The reconstructed
// `opening_context` coordinate carries the Active lifecycle: an interval opens
// into an active generation state, and `validate_intervals` (the assembly-time
// drift fence) requires `opening_context.lifecycle() == Active`.
// ===========================================================================

/// Failure modes of [`load_interval_hydration_rows`].
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum IntervalHydrationError {
    /// A stored `chat.application_intervals` column fell outside the protocol
    /// domain (a DID/UUID grammar violation, a non-32-byte crypto column, an
    /// out-of-range generation/seq, or an unrecognized opening/closing kind).
    #[error("clean-chat application interval column is out of domain")]
    OutOfDomain,
    /// An interval boundary's referenced transition (opening or closing) has no
    /// durable `chat.entries` row. Fail closed: absent provenance can never
    /// yield evidence.
    #[error("clean-chat application interval provenance entry is absent")]
    ProvenanceMissing,
    /// A boundary transition failed read-time re-verification, or the verified
    /// evidence was a signed request rather than a coordinate control
    /// transition. Never coerced into interval provenance.
    #[error("clean-chat application interval provenance failed re-verification")]
    InvalidProvenance,
    #[error("clean-chat application interval hydration database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl From<ControlEvidenceLoadError> for IntervalHydrationError {
    fn from(error: ControlEvidenceLoadError) -> Self {
        match error {
            ControlEvidenceLoadError::EntryMissing => IntervalHydrationError::ProvenanceMissing,
            ControlEvidenceLoadError::InvalidEvidence => IntervalHydrationError::InvalidProvenance,
            ControlEvidenceLoadError::Database(error) => IntervalHydrationError::Database(error),
        }
    }
}

/// Load the access-interval rows of an existing conversation, binding each to its
/// re-verified historical boundary evidence for the G1b-2 state aggregate.
///
/// Reads `chat.application_intervals` and, per row, re-loads the opening (and, if
/// closed, the closing) transition through [`load_historical_control_evidence`]
/// (so the aggregate never trusts un-reverified DB state), downcasting each to a
/// [`TransitionEvidence`](super::super::state_machine::TransitionEvidence) via
/// `into_transition`. The `opening_context` coordinate is reconstructed from the
/// row's FK-bound `chat.generation_states` columns at the Active lifecycle.
///
/// The rows are returned sorted by `(recipient, opening seq)` — the exact key
/// `validate_intervals` requires strictly increasing — using the durable
/// `start_seq` (equal to the opening entry's seq by the row's opening-provenance
/// FK), independent of the database's `recipient_did` text collation.
///
/// `authority` MUST be the read-time authority minted from the SAME locked head
/// as the rest of the aggregate. No `FOR UPDATE`: the caller already holds the
/// head lock (`FOR UPDATE OF c` on `chat.conversations`) that pins the interval
/// suffix, and `chat.entries` is append-only + immutable.
#[allow(dead_code)]
pub(crate) async fn load_interval_hydration_rows(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
) -> Result<Vec<IntervalHydrationRow>, IntervalHydrationError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        Uuid,
        i64,
        i64,
        String,
        Uuid,
        i64,
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        Option<Uuid>,
        Option<String>,
    )> = sqlx::query_as(
        r#"
        SELECT
            ai.recipient_did,
            ai.recipient_device_id,
            ai.generation,
            ai.start_seq,
            ai.opening_kind,
            ai.opening_transition_id,
            ai.opening_state_version,
            ai.opening_group_id,
            ai.opening_epoch,
            ai.opening_group_context_hash,
            ai.opening_confirmation_tag,
            ai.closing_transition_id,
            ai.closing_kind
        FROM chat.application_intervals ai
        WHERE ai.conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;

    let mut intervals: Vec<(DeviceIdentity, i64, IntervalHydrationRow)> =
        Vec::with_capacity(rows.len());
    for (
        recipient_did,
        recipient_device_id,
        generation,
        start_seq,
        opening_kind,
        opening_transition_id,
        opening_state_version,
        opening_group_id,
        opening_epoch,
        opening_group_context_hash,
        opening_confirmation_tag,
        closing_transition_id,
        closing_kind,
    ) in rows
    {
        let principal = PrincipalId::new(recipient_did.into_bytes())
            .map_err(|_| IntervalHydrationError::OutOfDomain)?;
        let recipient = DeviceIdentity::new(principal, *recipient_device_id.as_bytes())
            .map_err(|_| IntervalHydrationError::OutOfDomain)?;
        let generation = interval_u64(generation)?;
        let opening_kind = match opening_kind.as_str() {
            "creation" => OpeningKind::Creation,
            "add" => OpeningKind::Add,
            "reset" => OpeningKind::Reset,
            _ => return Err(IntervalHydrationError::OutOfDomain),
        };
        let opening_context = PublicGroupSnapshotCoordinate::new(
            *conversation_id.as_bytes(),
            generation,
            interval_u64(opening_state_version)?,
            interval_bytes32(opening_group_id)?,
            interval_u64(opening_epoch)?,
            interval_bytes32(opening_group_context_hash)?,
            interval_bytes32(opening_confirmation_tag)?,
            PublicGroupSnapshotLifecycle::Active,
        );

        let opening = load_historical_control_evidence(
            transaction,
            authority,
            conversation_id,
            opening_transition_id,
        )
        .await?
        .into_transition()
        .map_err(|_| IntervalHydrationError::InvalidProvenance)?;

        // The DDL close-shape check guarantees closing_transition_id and
        // closing_kind are jointly NULL (open) or jointly present (closed).
        let end = match (closing_transition_id, closing_kind) {
            (None, None) => None,
            (Some(closing_transition_id), Some(closing_kind)) => {
                let kind = match closing_kind.as_str() {
                    "remove" => CloseKind::Remove,
                    "replace" => CloseKind::Replace,
                    "reset" => CloseKind::Reset,
                    "terminal" => CloseKind::Terminal,
                    _ => return Err(IntervalHydrationError::OutOfDomain),
                };
                let evidence = load_historical_control_evidence(
                    transaction,
                    authority,
                    conversation_id,
                    closing_transition_id,
                )
                .await?
                .into_transition()
                .map_err(|_| IntervalHydrationError::InvalidProvenance)?;
                Some(IntervalEndHydrationRow { evidence, kind })
            }
            _ => return Err(IntervalHydrationError::OutOfDomain),
        };

        intervals.push((
            recipient.clone(),
            start_seq,
            IntervalHydrationRow {
                recipient,
                generation,
                opening,
                opening_kind,
                opening_context,
                end,
            },
        ));
    }
    // `validate_intervals` requires strictly increasing `(recipient, opening seq)`.
    // Sort by the durable `start_seq` (equal to the opening evidence seq) so the
    // ordering is independent of the database's `recipient_did` collation.
    intervals.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(intervals.into_iter().map(|(_, _, row)| row).collect())
}

fn interval_u64(value: i64) -> Result<u64, IntervalHydrationError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(IntervalHydrationError::OutOfDomain)
}

fn interval_bytes32(value: Vec<u8>) -> Result<[u8; 32], IntervalHydrationError> {
    <[u8; 32]>::try_from(value.as_slice()).map_err(|_| IntervalHydrationError::OutOfDomain)
}

// ===========================================================================
// G1b-2 — current-state producer evidence leg
// (chat.generation_states.producing_transition_id).
//
// The aggregate's `producer` field is the `TransitionEvidence` that produced the
// conversation's CURRENT generation-state. `chat.generation_states` records that
// transition id per (generation, state_version) in `producing_transition_id`
// (NOT NULL; core.sql). This leg reads it for the current coordinate — pinned by
// the head lock the caller holds — and re-verifies the transition through the
// sealed loader atom, exactly as the participant/interval legs re-verify their
// own provenance transitions. `validate_state`'s `current_state_producer_matches`
// re-checks this field against the state's own producer at hydration, so any
// residual disagreement fails closed downstream (availability, not integrity).
// ===========================================================================

/// Failure modes of [`load_producer_transition_evidence`].
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum ProducerHydrationError {
    /// No conversation (or no current generation-state matching its
    /// `(current_generation, current_state_version)`) exists under the lock.
    /// Fail closed: a missing current generation-state can never yield a
    /// producer.
    #[error("clean-chat conversation is absent for producer hydration")]
    ConversationMissing,
    /// The producing transition's control entry was absent. Fail closed: a
    /// producing transition without a durable entry can never yield evidence.
    #[error("clean-chat producer provenance is absent")]
    ProvenanceMissing,
    /// The producing transition failed read-time re-verification, or the verified
    /// evidence was a control request rather than a coordinate transition. Never
    /// coerced into evidence it does not attest.
    #[error("clean-chat producer provenance failed re-verification")]
    InvalidProvenance,
    #[error("clean-chat producer hydration database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl From<ControlEvidenceLoadError> for ProducerHydrationError {
    fn from(error: ControlEvidenceLoadError) -> Self {
        match error {
            ControlEvidenceLoadError::EntryMissing => ProducerHydrationError::ProvenanceMissing,
            ControlEvidenceLoadError::InvalidEvidence => ProducerHydrationError::InvalidProvenance,
            ControlEvidenceLoadError::Database(error) => ProducerHydrationError::Database(error),
        }
    }
}

/// Load and re-verify the `TransitionEvidence` that produced the CURRENT
/// generation-state of an existing conversation — the G1b-2 aggregate's
/// `producer` field.
///
/// Reads `chat.generation_states.producing_transition_id` for the conversation's
/// current `(generation, state_version)` (joined from `chat.conversations`), then
/// re-loads + re-verifies that transition's durable control entry through
/// [`load_historical_control_evidence`] and narrows it to the transition arm via
/// [`PersistedControlAuthority::into_transition`]. The producer of a coordinate
/// generation-state is always a coordinate transition (creation / commit /
/// policy / acceptance / metadata / reset-activation / …), never a control
/// request, so the request arm fails closed.
///
/// `authority` MUST be the read-time authority minted from the SAME locked head
/// as the rest of the aggregate. No `FOR UPDATE`: the caller already holds the
/// head lock (`FOR UPDATE OF c` on `chat.conversations`) that pins the current
/// generation-state row and the immutable `chat.entries` suffix.
#[allow(dead_code)]
pub(crate) async fn load_producer_transition_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
) -> Result<TransitionEvidence, ProducerHydrationError> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT gs.producing_transition_id
        FROM chat.conversations c
        JOIN chat.generation_states gs
          ON gs.conversation_id = c.conversation_id
         AND gs.generation = c.current_generation
         AND gs.state_version = c.current_state_version
        WHERE c.conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_optional(&mut **transaction)
    .await?;

    let (producing_transition_id,) = row.ok_or(ProducerHydrationError::ConversationMissing)?;

    load_historical_control_evidence(
        transaction,
        authority,
        conversation_id,
        producing_transition_id,
    )
    .await?
    .into_transition()
    .map_err(|_| ProducerHydrationError::InvalidProvenance)
}

// ===========================================================================
// G1b-2 sub-seal — retained-metadata provenance leg (metadata + metadata_producer).
//
// The G1b-2 aggregate carries two COUPLED optional fields: `metadata`
// (`Option<MetadataSnapshotBinding>`) and `metadata_producer`
// (`Option<TransitionEvidence>`). `validate_state`'s `metadata_provenance_matches`
// (state_machine.rs) admits only `(None, None)` or `(Some(metadata),
// Some(producer))` where `transition_metadata(producer) == metadata`,
// `producer.seq <= state.producer.seq`, and `producer.received_at <=
// state.producer.received_at` (plus the coordinate authority arm) — so the pair
// must be hydrated together.
//
// FAITHFULNESS (read-set-map correction, same class as the leaf leg's FINDING-1):
// production NEVER field-reconstructs `state.metadata` from the durable
// `chat.metadata_snapshots` columns. Every coordinate-advancing arm sets
// `state.metadata = transition_metadata(&command.transition).cloned()` and
// `state.metadata_producer = state.metadata.as_ref().map(|_| command.transition)`
// (state_machine.rs:8813, :9876, and the policy/reset/recovery/leave arms) — the
// binding is provenance-DERIVED from the producing transition's verified body.
// The durable row's `canonical_snapshot`/`digest` are not persisted at all, and
// `MetadataSnapshotBinding`'s fields (and the only literal ctor, the
// `#[cfg(test)]` `for_test_creation`) are unavailable to `repository::core`. So
// this leg selects the greatest same-generation snapshot producer whose immutable
// entry sequence does not exceed the current producer's sequence, re-verifies
// that transition through the sealed loader atom, and derives the metadata
// binding from its body via `metadata_binding_of_transition`. Sequence is the
// canonical order; mutable wall-clock fields never select a predecessor.
//
// The current-transition catalog is deliberately closed. Snapshot-producing
// transitions must select themselves. Policy, acceptance, leave-policy, and
// close retain a strictly earlier snapshot producer. Reset activation's mandatory
// successor-generation snapshot prevents fallback across the reset boundary.
//
// `(None, None)` is valid only when the conversation lookup itself is absent.
// Once a conversation row exists, a missing same-generation candidate is
// `ProvenanceMissing`; malformed head/catalog/lifecycle shapes are
// `OutOfDomain`.
// ===========================================================================

/// Failure modes of [`load_metadata_provenance`].
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum MetadataHydrationError {
    /// The current head, transition kind, lifecycle, or selected predecessor is
    /// outside the closed retained-metadata catalog shape.
    #[error("clean-chat metadata provenance is outside the protocol domain")]
    OutOfDomain,
    /// The metadata snapshot's producing transition had no durable control entry.
    /// Fail closed: a producing transition without an entry can never yield
    /// evidence.
    #[error("clean-chat metadata producer provenance is absent")]
    ProvenanceMissing,
    /// The producing transition failed read-time re-verification, was a control
    /// request rather than a coordinate transition, or its verified body carried
    /// NO metadata snapshot despite a durable metadata row naming it as producer
    /// (linkage inconsistency). Never coerced into evidence it does not attest.
    #[error("clean-chat metadata producer provenance failed re-verification")]
    InvalidProvenance,
    #[error("clean-chat metadata hydration database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl From<ControlEvidenceLoadError> for MetadataHydrationError {
    fn from(error: ControlEvidenceLoadError) -> Self {
        match error {
            ControlEvidenceLoadError::EntryMissing => MetadataHydrationError::ProvenanceMissing,
            ControlEvidenceLoadError::InvalidEvidence => MetadataHydrationError::InvalidProvenance,
            ControlEvidenceLoadError::Database(error) => MetadataHydrationError::Database(error),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RetainedMetadataCatalogHead<'a> {
    pub(crate) conversation_lifecycle: &'a str,
    pub(crate) generation_state_lifecycle: &'a str,
    pub(crate) current_generation: u64,
    pub(crate) current_transition_id: Uuid,
    pub(crate) close_transition_id: Option<Uuid>,
    pub(crate) close_seq: Option<u64>,
    pub(crate) closed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy)]
pub(crate) struct RetainedMetadataHead<'a> {
    pub(crate) conversation_lifecycle: &'a str,
    pub(crate) generation_state_lifecycle: &'a str,
    pub(crate) current_generation: u64,
    pub(crate) current_kind: &'a str,
    pub(crate) current_transition_id: Uuid,
    pub(crate) current_seq: u64,
    pub(crate) current_received_at: ServerTimestamp,
    pub(crate) close_transition_id: Option<Uuid>,
    pub(crate) close_seq: Option<u64>,
    pub(crate) closed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy)]
pub(crate) struct RetainedMetadataCandidate {
    pub(crate) transition_id: Uuid,
    pub(crate) generation: u64,
    pub(crate) seq: u64,
    #[allow(dead_code)] // carried only to prove that selection never orders by time
    pub(crate) accepted_at: DateTime<Utc>,
}

/// Mint the selector anchor exclusively from the reverified immutable current
/// control entry. The locked catalog supplies only lifecycle/close facts and the
/// exact transition ID that the entry must attest.
pub(crate) fn retained_metadata_head_from_current_evidence<'a>(
    catalog: RetainedMetadataCatalogHead<'a>,
    current: PersistedControlAuthority,
) -> Result<(RetainedMetadataHead<'a>, TransitionEvidence), MetadataHydrationError> {
    let current = current
        .into_transition()
        .map_err(|_| MetadataHydrationError::InvalidProvenance)?;
    if Uuid::from_bytes(*current.transition_id()) != catalog.current_transition_id {
        return Err(MetadataHydrationError::InvalidProvenance);
    }
    let signed_kind = current
        .signed_authority()
        .ok_or(MetadataHydrationError::InvalidProvenance)?
        .kind();
    let kind = match signed_kind {
        SignedMutationKind::Creation => "creation",
        SignedMutationKind::CommitTransition => "commit",
        SignedMutationKind::PolicyTransition => "policy",
        SignedMutationKind::ParticipantAcceptance => "acceptConversation",
        SignedMutationKind::MetadataTransition => "metadata",
        SignedMutationKind::ResetActivation => "resetActivation",
        SignedMutationKind::LeafRecoveryFulfillment => "leafRecovery",
        SignedMutationKind::ConversationClose => "closeConversation",
        SignedMutationKind::ZeroLeafLeave => "leavePolicy",
        SignedMutationKind::LeaveCommitFulfillment => "leaveCommit",
        _ => return Err(MetadataHydrationError::OutOfDomain),
    };
    if matches!(
        signed_kind,
        SignedMutationKind::Creation
            | SignedMutationKind::CommitTransition
            | SignedMutationKind::MetadataTransition
            | SignedMutationKind::ResetActivation
            | SignedMutationKind::LeafRecoveryFulfillment
            | SignedMutationKind::LeaveCommitFulfillment
    ) && metadata_binding_of_transition(&current).is_none()
    {
        return Err(MetadataHydrationError::InvalidProvenance);
    }
    let current_seq = current.seq();
    if current_seq == 0 || current_seq > MAX_PROTOCOL_INTEGER {
        return Err(MetadataHydrationError::OutOfDomain);
    }
    let head = RetainedMetadataHead {
        conversation_lifecycle: catalog.conversation_lifecycle,
        generation_state_lifecycle: catalog.generation_state_lifecycle,
        current_generation: catalog.current_generation,
        current_kind: kind,
        current_transition_id: catalog.current_transition_id,
        current_seq,
        current_received_at: current.received_at(),
        close_transition_id: catalog.close_transition_id,
        close_seq: catalog.close_seq,
        closed_at: catalog.closed_at,
    };
    Ok((head, current))
}

/// Apply the closed retained-metadata catalog ruling to the current head and
/// the greatest same-generation snapshot producer at or before it.
pub(crate) fn select_retained_metadata_producer(
    head: RetainedMetadataHead<'_>,
    candidates: Vec<RetainedMetadataCandidate>,
) -> Result<Uuid, MetadataHydrationError> {
    if head.current_seq == 0 || head.current_seq > MAX_PROTOCOL_INTEGER {
        return Err(MetadataHydrationError::OutOfDomain);
    }
    if candidates.is_empty() {
        return Err(MetadataHydrationError::ProvenanceMissing);
    }
    if candidates.iter().any(|candidate| {
        candidate.generation != head.current_generation
            || candidate.seq == 0
            || candidate.seq > head.current_seq
            || candidate.seq > MAX_PROTOCOL_INTEGER
    }) {
        return Err(MetadataHydrationError::OutOfDomain);
    }
    let greatest_seq = candidates
        .iter()
        .map(|candidate| candidate.seq)
        .max()
        .ok_or(MetadataHydrationError::ProvenanceMissing)?;
    if candidates
        .iter()
        .filter(|candidate| candidate.seq == greatest_seq)
        .count()
        != 1
    {
        return Err(MetadataHydrationError::OutOfDomain);
    }
    let candidate = candidates
        .into_iter()
        .find(|candidate| candidate.seq == greatest_seq)
        .ok_or(MetadataHydrationError::ProvenanceMissing)?;

    match (head.conversation_lifecycle, head.generation_state_lifecycle) {
        ("active", "active") => {
            if head.current_kind == "closeConversation"
                || head.close_transition_id.is_some()
                || head.close_seq.is_some()
                || head.closed_at.is_some()
            {
                return Err(MetadataHydrationError::OutOfDomain);
            }
        }
        ("superseded", "superseded") => {
            let current_received_at =
                DateTime::<Utc>::from_timestamp_millis(head.current_received_at.unix_millis())
                    .ok_or(MetadataHydrationError::OutOfDomain)?;
            if head.current_kind != "closeConversation"
                || head.close_transition_id != Some(head.current_transition_id)
                || head.close_seq != Some(head.current_seq)
                || head.closed_at != Some(current_received_at)
                || candidate.seq >= head.current_seq
            {
                return Err(MetadataHydrationError::OutOfDomain);
            }
        }
        _ => return Err(MetadataHydrationError::OutOfDomain),
    }

    match head.current_kind {
        "creation" | "commit" | "metadata" | "leafRecovery" | "leaveCommit" | "resetActivation" => {
            if candidate.transition_id != head.current_transition_id
                || candidate.seq != head.current_seq
            {
                return Err(MetadataHydrationError::OutOfDomain);
            }
        }
        "policy" | "acceptConversation" | "leavePolicy" | "closeConversation" => {
            if candidate.transition_id == head.current_transition_id
                || candidate.seq >= head.current_seq
            {
                return Err(MetadataHydrationError::OutOfDomain);
            }
        }
        _ => return Err(MetadataHydrationError::OutOfDomain),
    }

    Ok(candidate.transition_id)
}

/// Narrow a reverified catalog row to a metadata-producing transition and
/// derive the binding solely from its signed body.
pub(crate) fn derive_retained_metadata_provenance(
    producer: PersistedControlAuthority,
) -> Result<(MetadataSnapshotBinding, TransitionEvidence), MetadataHydrationError> {
    let producer = producer
        .into_transition()
        .map_err(|_| MetadataHydrationError::InvalidProvenance)?;
    let metadata = metadata_binding_of_transition(&producer)
        .ok_or(MetadataHydrationError::InvalidProvenance)?;
    Ok((metadata, producer))
}

#[derive(sqlx::FromRow)]
struct RetainedMetadataHeadRow {
    conversation_lifecycle: String,
    current_generation: i64,
    close_transition_id: Option<Uuid>,
    close_seq: Option<i64>,
    closed_at: Option<DateTime<Utc>>,
    generation_state_lifecycle: Option<String>,
    current_transition_id: Option<Uuid>,
}

/// Load and re-verify the metadata provenance retained at the current head.
///
/// The selected producer is the greatest transition sequence at or before the
/// current producer among metadata snapshots in the pinned current generation.
/// Timestamps never order candidates. Snapshot-producing current transitions
/// select themselves; the closed snapshotless family selects a strictly earlier
/// producer. The selected immutable transition is then reverified and its
/// metadata binding is derived exclusively from its verified body.
///
/// `authority` MUST be the read-time authority minted from the SAME locked head
/// as the rest of the aggregate. No `FOR UPDATE`: the caller already holds the
/// head lock (`FOR UPDATE OF c` on `chat.conversations`) that pins the current
/// generation-state and the immutable `chat.entries`/`chat.metadata_snapshots`
/// suffix.
#[allow(dead_code)]
pub(crate) async fn load_metadata_provenance(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
) -> Result<(Option<MetadataSnapshotBinding>, Option<TransitionEvidence>), MetadataHydrationError> {
    let row: Option<RetainedMetadataHeadRow> = sqlx::query_as(
        r#"
        SELECT
            c.lifecycle AS conversation_lifecycle,
            c.current_generation,
            c.close_transition_id,
            c.close_seq,
            c.closed_at,
            gs.lifecycle AS generation_state_lifecycle,
            gs.producing_transition_id AS current_transition_id
        FROM chat.conversations c
        LEFT JOIN chat.generation_states gs
          ON gs.conversation_id = c.conversation_id
         AND gs.generation = c.current_generation
         AND gs.state_version = c.current_state_version
        WHERE c.conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_optional(&mut **transaction)
    .await?;

    let Some(row) = row else {
        // `(None, None)` is valid only for an absent conversation lookup.
        return Ok((None, None));
    };

    let (Some(generation_state_lifecycle), Some(current_transition_id)) =
        (row.generation_state_lifecycle, row.current_transition_id)
    else {
        return Err(MetadataHydrationError::ProvenanceMissing);
    };
    let current_generation = metadata_u64(row.current_generation)?;
    let close_seq = row.close_seq.map(metadata_positive_u64).transpose()?;
    let current = load_historical_control_evidence(
        transaction,
        authority,
        conversation_id,
        current_transition_id,
    )
    .await?;
    let (head, _current_producer) = retained_metadata_head_from_current_evidence(
        RetainedMetadataCatalogHead {
            conversation_lifecycle: &row.conversation_lifecycle,
            generation_state_lifecycle: &generation_state_lifecycle,
            current_generation,
            current_transition_id,
            close_transition_id: row.close_transition_id,
            close_seq,
            closed_at: row.closed_at,
        },
        current,
    )?;

    let candidates: Vec<(Uuid, i64, i64, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT
            metadata.producing_transition_id,
            producer.next_generation AS producer_generation,
            producer.entry_seq,
            producer.accepted_at
        FROM chat.metadata_snapshots metadata
        JOIN chat.transitions producer
          ON producer.conversation_id = metadata.conversation_id
         AND producer.transition_id = metadata.producing_transition_id
        WHERE metadata.conversation_id = $1
          AND metadata.generation = $2
          AND producer.entry_seq <= $3
        "#,
    )
    .bind(conversation_id)
    .bind(row.current_generation)
    .bind(i64::try_from(head.current_seq).map_err(|_| MetadataHydrationError::OutOfDomain)?)
    .fetch_all(&mut **transaction)
    .await?;
    let candidates = candidates
        .into_iter()
        .map(|(transition_id, generation, seq, accepted_at)| {
            Ok::<_, MetadataHydrationError>(RetainedMetadataCandidate {
                transition_id,
                generation: metadata_u64(generation)?,
                seq: metadata_positive_u64(seq)?,
                accepted_at,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let producing_transition_id = select_retained_metadata_producer(head, candidates)?;

    let producer = load_historical_control_evidence(
        transaction,
        authority,
        conversation_id,
        producing_transition_id,
    )
    .await?;
    // A request arm or transition body carrying no metadata is a fail-closed
    // linkage inconsistency, never a silent `None`.
    let (metadata, producer) = derive_retained_metadata_provenance(producer)?;

    Ok((Some(metadata), Some(producer)))
}

fn metadata_u64(value: i64) -> Result<u64, MetadataHydrationError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(MetadataHydrationError::OutOfDomain)
}

fn metadata_positive_u64(value: i64) -> Result<u64, MetadataHydrationError> {
    u64::try_from(value)
        .ok()
        .filter(|value| (1..=MAX_PROTOCOL_INTEGER).contains(value))
        .ok_or(MetadataHydrationError::OutOfDomain)
}

// ===========================================================================
// G1b-2 sub-seal — leaf-recovery work hydration leg (the recovery PAIR).
//
// `chat.leaf_recovery_requests` and `chat.key_package_reservations` are a
// mutually-1:1 set (each request row's `reservation_request_id` equals its own
// `recovery_request_id`, and the two tables carry reciprocal FKs), and
// `validate_recovery_work` (state_machine.rs) pairs them 1:1 by `request_id`,
// cross-checking coordinate / target / key_package_ref / received_at /
// expires_at / terminal. The request row alone cannot produce a
// `RecoveryRequestHydrationRow` — its `key_package_ref` lives ONLY on the paired
// reservation — so this leg loads BOTH tables together and pairs them by
// `recovery_request_id`, failing closed (`PairMismatch`) on any break in the
// correspondence.
//
// The request ORIGIN is historical signed evidence. `requestLeafRecovery`
// re-mints a `RequestEvidence` from the row's OWN `signed_request_bytes` +
// `requested_at` under the requester's historical signing key. For
// `acceptConversation`, the request has no direct origin-transition FK, so its
// exact immutable participant-period acceptance provenance is joined to the
// transition and control entry by conversation/requester/key/time/successor/
// signed bytes; the full candidate set must contain exactly one row, and that
// entry is re-verified through `load_historical_control_evidence`.
//
// SCOPE (NEXT-STEP follow-ups, fail-closed until reconstructed + tested): the
// remaining TERMINAL families (`cancelled` / `expired` / `superseded`
// requests and `expired` / `released` reservations) each need their own later
// real-signed / expiry / device-revocation coherent seed. This leg reconstructs
// both `open` / `active` (terminal `None`) and `fulfilled` / `consumed` (one
// exact re-verified leafRecovery transition) and fails CLOSED
// (`UnsupportedTerminal`) on the named remainder — never
// fabricating a terminal or an origin it cannot re-verify.
//
// `validate_recovery_work` at assembly is the drift fence: it re-derives the 1:1
// pairing, the expiry, and every cross-field equality against the hydrated rows,
// so any residual disagreement fails closed downstream (availability, not
// integrity).
// ===========================================================================

/// Failure modes of [`load_recovery_work_hydration_rows`].
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum RecoveryHydrationError {
    /// A stored recovery/reservation column fell outside the protocol domain (a
    /// DID/UUID grammar violation, a non-32-byte crypto field, an out-of-range
    /// integer, or an unrecognized kind token).
    #[error("clean-chat recovery column is out of domain")]
    OutOfDomain,
    /// A request's origin signed request failed read-time re-verification. Never
    /// coerced into evidence it does not attest.
    #[error("clean-chat recovery origin failed re-verification")]
    InvalidProvenance,
    /// The request and reservation collections did not correspond 1:1 by
    /// `recovery_request_id` (a request without its reservation, a reservation
    /// without its request, unequal counts, or a duplicate). Fail closed.
    #[error("clean-chat recovery request/reservation pairing is not 1:1")]
    PairMismatch,
    /// The request/reservation carries a terminal status outside this sub-seal's
    /// fulfilled/consumed arm. Cancellation is owned by the signed cancellation
    /// fixture, expiry by the expiry fixture, and supersession/release by the
    /// transition/device-revocation fixtures. Fail closed until each is built.
    #[error("clean-chat recovery terminal status is not yet reconstructed")]
    UnsupportedTerminal,
    /// A status selected an incomplete, unrelated, or request/reservation-
    /// disagreeing terminal column arm.
    #[error("clean-chat recovery terminal columns do not match the selected status")]
    TerminalMismatch,
    /// The selected fulfillment transition was absent, foreign, wrong-kind, or
    /// did not bind the exact request, target, coordinate, package, and time.
    #[error("clean-chat recovery fulfillment terminal failed re-verification")]
    InvalidTerminal,
    #[error("clean-chat recovery hydration database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone, Copy)]
pub(crate) struct FulfilledRecoveryTerminalColumns<'a> {
    pub(crate) request_fulfilling_transition_id: Option<Uuid>,
    pub(crate) request_has_unrelated_terminal: bool,
    pub(crate) request_terminal_at: Option<DateTime<Utc>>,
    pub(crate) request_reservation_binding_matches: bool,
    pub(crate) reservation_status: &'a str,
    pub(crate) reservation_consumed_transition_id: Option<Uuid>,
    pub(crate) reservation_has_unrelated_terminal: bool,
    pub(crate) reservation_terminal_at: Option<DateTime<Utc>>,
    pub(crate) package_status: &'a str,
    pub(crate) package_terminal_transition_id: Option<Uuid>,
    pub(crate) package_terminal_revocation_id: Option<Uuid>,
    pub(crate) package_terminal_at: Option<DateTime<Utc>>,
    pub(crate) durable_transition_kind: Option<&'a str>,
    pub(crate) durable_transition_accepted_at: Option<DateTime<Utc>>,
}

/// Select the sole legal fulfilled/consumed recovery terminal arm. The schema
/// makes most malformed combinations uncommittable; keeping this selection
/// pure gives the read side an explicit drift fence instead of relying on
/// optional-column coincidence.
pub(crate) fn select_fulfilled_recovery_terminal(
    columns: FulfilledRecoveryTerminalColumns<'_>,
) -> Result<(Uuid, DateTime<Utc>), RecoveryHydrationError> {
    let (Some(transition_id), Some(terminal_at)) = (
        columns.request_fulfilling_transition_id,
        columns.request_terminal_at,
    ) else {
        return Err(RecoveryHydrationError::TerminalMismatch);
    };
    if columns.request_has_unrelated_terminal
        || !columns.request_reservation_binding_matches
        || columns.reservation_status != "consumed"
        || columns.reservation_consumed_transition_id != Some(transition_id)
        || columns.reservation_has_unrelated_terminal
        || columns.reservation_terminal_at != Some(terminal_at)
        || columns.package_status != "consumed"
        || columns.package_terminal_transition_id != Some(transition_id)
        || columns.package_terminal_revocation_id.is_some()
        || columns.package_terminal_at != Some(terminal_at)
        || columns.durable_transition_kind != Some("leafRecovery")
        || columns.durable_transition_accepted_at != Some(terminal_at)
    {
        return Err(RecoveryHydrationError::TerminalMismatch);
    }
    Ok((transition_id, terminal_at))
}

#[derive(Clone)]
enum RecoveryReservationTerminal {
    None,
    Transition {
        transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
}

/// A reservation paired to its request during recovery-work hydration; carries
/// the `key_package_ref` the request row lacks.
struct PairedReservation {
    key_package_ref: [u8; 32],
    package_wrapper: Vec<u8>,
    package_wrapper_sha256: Vec<u8>,
    package_status: String,
    package_terminal_transition_id: Option<Uuid>,
    package_terminal_revocation_id: Option<Uuid>,
    package_terminal_at: Option<DateTime<Utc>>,
    terminal: RecoveryReservationTerminal,
    row: RecoveryReservationHydrationRow,
}

#[derive(sqlx::FromRow)]
struct DurableRecoveryReservationRow {
    recovery_request_id: Uuid,
    recipient_did: String,
    recipient_device_id: Uuid,
    generation: i64,
    bound_state_version: i64,
    bound_group_id: Vec<u8>,
    bound_epoch: i64,
    bound_group_context_hash: Vec<u8>,
    bound_confirmation_tag: Vec<u8>,
    key_package_ref: Vec<u8>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    status: String,
    consumed_transition_id: Option<Uuid>,
    terminal_transition_id: Option<Uuid>,
    terminal_revocation_id: Option<Uuid>,
    terminal_request_digest: Option<Vec<u8>>,
    terminal_at: Option<DateTime<Utc>>,
    package_status: String,
    package_terminal_transition_id: Option<Uuid>,
    package_terminal_revocation_id: Option<Uuid>,
    package_terminal_at: Option<DateTime<Utc>>,
    not_after: DateTime<Utc>,
    package_wrapper: Vec<u8>,
    package_wrapper_sha256: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct DurableRecoveryRequestRow {
    recovery_request_id: Uuid,
    requester_did: String,
    requester_device_id: Uuid,
    requester_key_id: String,
    requester_auth_generation: i64,
    recovery_kind: String,
    source: String,
    generation: i64,
    bound_state_version: i64,
    bound_group_id: Vec<u8>,
    bound_epoch: i64,
    bound_group_context_hash: Vec<u8>,
    bound_confirmation_tag: Vec<u8>,
    status: String,
    signed_request_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    requested_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    fulfilling_transition_id: Option<Uuid>,
    terminal_transition_id: Option<Uuid>,
    terminal_revocation_id: Option<Uuid>,
    terminal_signed_request_bytes: Option<Vec<u8>>,
    terminal_signing_transcript_bytes: Option<Vec<u8>>,
    terminal_request_digest: Option<Vec<u8>>,
    terminal_signature: Option<Vec<u8>>,
    terminal_at: Option<DateTime<Utc>>,
    fulfilling_transition_kind: Option<String>,
    fulfilling_transition_accepted_at: Option<DateTime<Utc>>,
    signing_public_key: Vec<u8>,
}

/// An acceptance-origin request has no direct origin-transition FK. The SQL
/// locator therefore returns the complete immutable candidate set and this
/// selector refuses both absence and ambiguity.
pub(crate) fn select_single_acceptance_origin(
    candidates: Vec<Uuid>,
) -> Result<Uuid, RecoveryHydrationError> {
    let [candidate] = candidates.as_slice() else {
        return Err(RecoveryHydrationError::InvalidProvenance);
    };
    Ok(*candidate)
}

pub(crate) fn map_recovery_control_evidence_error(
    error: ControlEvidenceLoadError,
) -> RecoveryHydrationError {
    match error {
        ControlEvidenceLoadError::Database(error) => RecoveryHydrationError::Database(error),
        ControlEvidenceLoadError::EntryMissing | ControlEvidenceLoadError::InvalidEvidence => {
            RecoveryHydrationError::InvalidProvenance
        }
    }
}

pub(crate) fn recovery_acceptance_authority_matches_durable(
    evidence: &TransitionEvidence,
    transition_id: &[u8; 16],
    received_at: ServerTimestamp,
    conversation_id: &[u8; 16],
    target: &DeviceIdentity,
    requester_key_id: &[u8; 32],
    requester_auth_generation: u64,
    signed_request_bytes: &[u8],
    signing_transcript_bytes: &[u8],
    request_digest: &[u8],
    signature: &[u8],
) -> bool {
    evidence.signed_authority().is_some_and(|authority| {
        evidence.transition_id() == transition_id
            && evidence.received_at() == received_at
            && authority.kind() == SignedMutationKind::ParticipantAcceptance
            && authority.control_conversation_id() == Some(conversation_id)
            && authority.actor() == target
            && authority.key_id() == requester_key_id
            && authority.auth_generation() == requester_auth_generation
            && authority.signed_request_bytes() == signed_request_bytes
            && authority.transcript_bytes() == signing_transcript_bytes
            && authority.request_digest() == request_digest
            && authority.signature() == signature
    })
}

/// Load the leaf-recovery work of an existing conversation as a validated 1:1
/// `(requests, reservations)` pair. See the module header for the origin /
/// terminal reconstruction scope.
///
/// `authority` MUST be the read-time authority minted from the SAME locked head
/// as the rest of the aggregate. No `FOR UPDATE`: the caller already holds the
/// head lock (`FOR UPDATE OF c` on `chat.conversations`) that pins the current
/// generation and the immutable `chat.entries` / projection suffix.
#[allow(dead_code)]
pub(crate) async fn load_recovery_work_hydration_rows(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
) -> Result<
    (
        Vec<RecoveryRequestHydrationRow>,
        Vec<RecoveryReservationHydrationRow>,
    ),
    RecoveryHydrationError,
> {
    let conversation_bytes = *conversation_id.as_bytes();

    // Reservations, with the bound key package's `not_after` (the reservation row
    // carries no origin evidence; `package_not_after` is the KP lifetime).
    let reservation_rows: Vec<DurableRecoveryReservationRow> = sqlx::query_as(
        r#"
        SELECT
            r.recovery_request_id,
            r.recipient_did,
            r.recipient_device_id,
            r.generation,
            r.bound_state_version,
            r.bound_group_id,
            r.bound_epoch,
            r.bound_group_context_hash,
            r.bound_confirmation_tag,
            r.key_package_ref,
            r.created_at,
            r.expires_at,
            r.status,
            r.consumed_transition_id,
            r.terminal_transition_id,
            r.terminal_revocation_id,
            r.terminal_request_digest,
            r.terminal_at,
            kp.status AS package_status,
            kp.terminal_transition_id AS package_terminal_transition_id,
            kp.terminal_revocation_id AS package_terminal_revocation_id,
            kp.terminal_at AS package_terminal_at,
            kp.not_after,
            kp.wrapper_bytes AS package_wrapper,
            kp.wrapper_sha256 AS package_wrapper_sha256
        FROM chat.key_package_reservations r
        JOIN chat.key_packages kp
          ON kp.key_package_ref = r.key_package_ref
         AND kp.owner_did = r.recipient_did
         AND kp.owner_device_id = r.recipient_device_id
        WHERE r.conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;

    let mut reservations_by_id: BTreeMap<[u8; 16], PairedReservation> = BTreeMap::new();
    for DurableRecoveryReservationRow {
        recovery_request_id,
        recipient_did,
        recipient_device_id,
        generation,
        bound_state_version,
        bound_group_id,
        bound_epoch,
        bound_group_context_hash,
        bound_confirmation_tag,
        key_package_ref,
        created_at,
        expires_at,
        status,
        consumed_transition_id,
        terminal_transition_id,
        terminal_revocation_id,
        terminal_request_digest,
        terminal_at,
        package_status,
        package_terminal_transition_id,
        package_terminal_revocation_id,
        package_terminal_at,
        not_after,
        package_wrapper,
        package_wrapper_sha256,
    } in reservation_rows
    {
        let request_id = *recovery_request_id.as_bytes();
        let target = recovery_device(recipient_did, recipient_device_id)?;
        let bound_coordinate = recovery_coordinate(
            conversation_bytes,
            generation,
            bound_state_version,
            bound_group_id,
            bound_epoch,
            bound_group_context_hash,
            bound_confirmation_tag,
        )?;
        let key_package_ref = recovery_bytes32(key_package_ref)?;
        let (status, terminal) = match status.as_str() {
            "active"
                if consumed_transition_id.is_none()
                    && terminal_transition_id.is_none()
                    && terminal_revocation_id.is_none()
                    && terminal_request_digest.is_none()
                    && terminal_at.is_none() =>
            {
                (ReservationStatus::Active, RecoveryReservationTerminal::None)
            }
            "consumed"
                if consumed_transition_id.is_some()
                    && terminal_transition_id.is_none()
                    && terminal_revocation_id.is_none()
                    && terminal_request_digest.is_none()
                    && terminal_at.is_some() =>
            {
                (
                    ReservationStatus::Consumed,
                    RecoveryReservationTerminal::Transition {
                        transition_id: consumed_transition_id.unwrap(),
                        terminal_at: terminal_at.unwrap(),
                    },
                )
            }
            "active" | "consumed" => return Err(RecoveryHydrationError::TerminalMismatch),
            "expired" | "released" => return Err(RecoveryHydrationError::UnsupportedTerminal),
            _ => return Err(RecoveryHydrationError::OutOfDomain),
        };
        let row = RecoveryReservationHydrationRow {
            request_id,
            target,
            bound_coordinate,
            key_package_ref,
            received_at: recovery_timestamp(created_at)?,
            expires_at: recovery_timestamp(expires_at)?,
            package_not_after: recovery_timestamp(not_after)?,
            status,
            terminal: None,
        };
        if reservations_by_id
            .insert(
                request_id,
                PairedReservation {
                    key_package_ref,
                    package_wrapper,
                    package_wrapper_sha256,
                    package_status,
                    package_terminal_transition_id,
                    package_terminal_revocation_id,
                    package_terminal_at,
                    terminal,
                    row,
                },
            )
            .is_some()
        {
            return Err(RecoveryHydrationError::PairMismatch);
        }
    }

    // Requests, with the requester's historical signing key for the origin re-mint.
    let request_rows: Vec<DurableRecoveryRequestRow> = sqlx::query_as(
        r#"
        SELECT
            lr.recovery_request_id,
            lr.requester_did,
            lr.requester_device_id,
            lr.requester_key_id,
            lr.requester_auth_generation,
            lr.recovery_kind,
            lr.source,
            lr.generation,
            lr.bound_state_version,
            lr.bound_group_id,
            lr.bound_epoch,
            lr.bound_group_context_hash,
            lr.bound_confirmation_tag,
            lr.status,
            lr.signed_request_bytes,
            lr.signing_transcript_bytes,
            lr.request_digest,
            lr.signature,
            lr.requested_at,
            lr.expires_at,
            lr.fulfilling_transition_id,
            lr.terminal_transition_id,
            lr.terminal_revocation_id,
            lr.terminal_signed_request_bytes,
            lr.terminal_signing_transcript_bytes,
            lr.terminal_request_digest,
            lr.terminal_signature,
            lr.terminal_at,
            ft.kind AS fulfilling_transition_kind,
            ft.accepted_at AS fulfilling_transition_accepted_at,
            dk.signing_public_key
        FROM chat.leaf_recovery_requests lr
        JOIN chat.device_keys dk
          ON dk.user_did = lr.requester_did
         AND dk.device_id = lr.requester_device_id
         AND dk.key_id = lr.requester_key_id
        LEFT JOIN chat.transitions ft
          ON ft.transition_id = lr.fulfilling_transition_id
        WHERE lr.conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;

    let mut requests: Vec<RecoveryRequestHydrationRow> = Vec::with_capacity(request_rows.len());
    let mut paired: usize = 0;
    for DurableRecoveryRequestRow {
        recovery_request_id,
        requester_did,
        requester_device_id,
        requester_key_id,
        requester_auth_generation,
        recovery_kind,
        source,
        generation,
        bound_state_version,
        bound_group_id,
        bound_epoch,
        bound_group_context_hash,
        bound_confirmation_tag,
        status,
        signed_request_bytes,
        signing_transcript_bytes,
        request_digest,
        signature,
        requested_at,
        expires_at,
        fulfilling_transition_id,
        terminal_transition_id,
        terminal_revocation_id,
        terminal_signed_request_bytes,
        terminal_signing_transcript_bytes,
        terminal_request_digest,
        terminal_signature,
        terminal_at,
        fulfilling_transition_kind,
        fulfilling_transition_accepted_at,
        signing_public_key,
    } in request_rows
    {
        let request_id = *recovery_request_id.as_bytes();
        let requester_did_locator = requester_did.clone();
        let target = recovery_device(requester_did, requester_device_id)?;
        let kind = match recovery_kind.as_str() {
            "add" => LeafRecoveryKind::Add,
            "replace" => LeafRecoveryKind::Replace,
            _ => return Err(RecoveryHydrationError::OutOfDomain),
        };
        let source = match source.as_str() {
            "requestLeafRecovery" => RecoverySource::Request,
            "acceptConversation" => RecoverySource::Acceptance,
            _ => return Err(RecoveryHydrationError::OutOfDomain),
        };
        let bound_coordinate = recovery_coordinate(
            conversation_bytes,
            generation,
            bound_state_version,
            bound_group_id,
            bound_epoch,
            bound_group_context_hash,
            bound_confirmation_tag,
        )?;
        let reservation = reservations_by_id
            .get(&request_id)
            .ok_or(RecoveryHydrationError::PairMismatch)?;
        let request_reservation_binding_matches = reservation.row.target == target
            && reservation.row.bound_coordinate == bound_coordinate
            && reservation.row.received_at == recovery_timestamp(requested_at)?
            && reservation.row.expires_at == recovery_timestamp(expires_at)?;
        let reservation_status = reservation.row.status;
        let reservation_terminal = reservation.terminal.clone();
        let reservation_key_package_ref = reservation.key_package_ref;
        let package_wrapper = reservation.package_wrapper.clone();
        let package_wrapper_sha256 = reservation.package_wrapper_sha256.clone();
        let package_status = reservation.package_status.clone();
        let package_terminal_transition_id = reservation.package_terminal_transition_id;
        let package_terminal_revocation_id = reservation.package_terminal_revocation_id;
        let package_terminal_at = reservation.package_terminal_at;
        paired += 1;

        let request_has_signed_terminal = terminal_signed_request_bytes.is_some()
            || terminal_signing_transcript_bytes.is_some()
            || terminal_request_digest.is_some()
            || terminal_signature.is_some();
        let (status, terminal) = match status.as_str() {
            "open"
                if fulfilling_transition_id.is_none()
                    && terminal_transition_id.is_none()
                    && terminal_revocation_id.is_none()
                    && !request_has_signed_terminal
                    && terminal_at.is_none()
                    && matches!(&reservation_terminal, RecoveryReservationTerminal::None)
                    && reservation_status == ReservationStatus::Active
                    && request_reservation_binding_matches
                    && package_status == "reserved"
                    && package_terminal_transition_id.is_none()
                    && package_terminal_revocation_id.is_none()
                    && package_terminal_at.is_none() =>
            {
                (RecoveryRequestStatus::Open, None)
            }
            "fulfilled" => {
                let (reservation_consumed_transition_id, reservation_terminal_at) =
                    match &reservation_terminal {
                        RecoveryReservationTerminal::Transition {
                            transition_id: reservation_transition_id,
                            terminal_at: reservation_terminal_at,
                        } => (
                            Some(*reservation_transition_id),
                            Some(*reservation_terminal_at),
                        ),
                        RecoveryReservationTerminal::None => (None, None),
                    };
                let (transition_id, terminal_at) =
                    select_fulfilled_recovery_terminal(FulfilledRecoveryTerminalColumns {
                        request_fulfilling_transition_id: fulfilling_transition_id,
                        request_has_unrelated_terminal: terminal_transition_id.is_some()
                            || terminal_revocation_id.is_some()
                            || request_has_signed_terminal,
                        request_terminal_at: terminal_at,
                        request_reservation_binding_matches,
                        reservation_status: match reservation_status {
                            ReservationStatus::Active => "active",
                            ReservationStatus::Consumed => "consumed",
                            ReservationStatus::Expired => "expired",
                            ReservationStatus::Released => "released",
                        },
                        reservation_consumed_transition_id,
                        reservation_has_unrelated_terminal: false,
                        reservation_terminal_at,
                        package_status: &package_status,
                        package_terminal_transition_id,
                        package_terminal_revocation_id,
                        package_terminal_at,
                        durable_transition_kind: fulfilling_transition_kind.as_deref(),
                        durable_transition_accepted_at: fulfilling_transition_accepted_at,
                    })?;
                let terminal = load_work_terminal_hydration_row(
                    transaction,
                    authority,
                    conversation_id,
                    WorkTerminalLocator::Transition { transition_id },
                )
                .await
                .map_err(|_| RecoveryHydrationError::InvalidTerminal)?;
                let WorkTerminalHydrationRow::Transition(ref evidence) = terminal else {
                    return Err(RecoveryHydrationError::InvalidTerminal);
                };
                if evidence.transition_id() != transition_id.as_bytes()
                    || !recovery_fulfillment_terminal_matches(
                        evidence,
                        &request_id,
                        &target,
                        kind,
                        &bound_coordinate,
                        &reservation_key_package_ref,
                        recovery_timestamp(terminal_at)?,
                    )
                {
                    return Err(RecoveryHydrationError::InvalidTerminal);
                }
                (RecoveryRequestStatus::Fulfilled, Some(terminal))
            }
            "open" => return Err(RecoveryHydrationError::TerminalMismatch),
            "cancelled" | "expired" | "superseded" => {
                return Err(RecoveryHydrationError::UnsupportedTerminal)
            }
            _ => return Err(RecoveryHydrationError::OutOfDomain),
        };

        let received_at = recovery_timestamp(requested_at)?;
        let origin = match source {
            RecoverySource::Request => {
                let received_at_canonical = canonical_millis(requested_at);
                let origin = authority
                    .hydrate_historical_signed_request_from_durable_bytes(
                        conversation_bytes,
                        &received_at_canonical,
                        &signed_request_bytes,
                        &signing_public_key,
                    )
                    .map_err(|_| RecoveryHydrationError::InvalidProvenance)?;
                RecoveryOriginHydrationRow::Request(origin)
            }
            RecoverySource::Acceptance => {
                let candidates: Vec<(Uuid,)> = sqlx::query_as(
                    r#"
                    SELECT p.acceptance_transition_id
                    FROM chat.participants p
                    JOIN chat.transitions t
                      ON t.conversation_id = p.conversation_id
                     AND t.transition_id = p.acceptance_transition_id
                     AND t.accepted_at = p.accepted_at
                    JOIN chat.entries e
                      ON e.conversation_id = t.conversation_id
                     AND e.entry_id = p.acceptance_entry_id
                     AND e.transition_id = t.transition_id
                     AND e.seq = t.entry_seq
                    WHERE p.conversation_id = $1
                      AND p.user_did = $2
                      AND p.acceptance_transition_id IS NOT NULL
                      AND p.accepted_at = $3
                      AND t.kind = 'acceptConversation'
                      AND t.actor_did = $2
                      AND t.actor_device_id = $4
                      AND t.actor_key_id = $5
                      AND t.actor_auth_generation = $6
                      AND t.accepted_at = $3
                      AND t.next_generation = $7
                      AND t.next_state_version = $8
                      AND t.signed_request_bytes = $9
                      AND e.entry_kind =
                          'blue.catbird.chat.defs#participantAcceptanceEntry'
                      AND e.actor_did = $2
                      AND e.actor_device_id = $4
                      AND e.actor_key_id = $5
                      AND e.actor_auth_generation = $6
                      AND e.received_at = $3
                      AND e.signed_request_bytes = $9
                    "#,
                )
                .bind(conversation_id)
                .bind(&requester_did_locator)
                .bind(requested_at)
                .bind(requester_device_id)
                .bind(&requester_key_id)
                .bind(requester_auth_generation)
                .bind(generation)
                .bind(bound_state_version)
                .bind(&signed_request_bytes)
                .fetch_all(&mut **transaction)
                .await?;
                let transition_id = select_single_acceptance_origin(
                    candidates
                        .into_iter()
                        .map(|(transition_id,)| transition_id)
                        .collect(),
                )?;
                let evidence = load_historical_control_evidence(
                    transaction,
                    authority,
                    conversation_id,
                    transition_id,
                )
                .await
                .map_err(map_recovery_control_evidence_error)?
                .into_transition()
                .map_err(|_| RecoveryHydrationError::InvalidProvenance)?;
                let requester_key_bytes = URL_SAFE_NO_PAD
                    .decode(&requester_key_id)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .ok_or(RecoveryHydrationError::OutOfDomain)?;
                let requester_auth_generation = recovery_u64(requester_auth_generation)?;
                if !recovery_acceptance_authority_matches_durable(
                    &evidence,
                    transition_id.as_bytes(),
                    received_at,
                    &conversation_bytes,
                    &target,
                    &requester_key_bytes,
                    requester_auth_generation,
                    &signed_request_bytes,
                    &signing_transcript_bytes,
                    &request_digest,
                    &signature,
                ) || !acceptance_recovery_package_artifact_matches(
                    &evidence,
                    &package_wrapper,
                    &package_wrapper_sha256,
                ) {
                    return Err(RecoveryHydrationError::InvalidProvenance);
                }
                let evidence = classify_acceptance(evidence, target.principal())
                    .map_err(|_| RecoveryHydrationError::InvalidProvenance)?;
                RecoveryOriginHydrationRow::Acceptance(evidence)
            }
        };

        requests.push(RecoveryRequestHydrationRow {
            request_id,
            target,
            kind,
            source,
            bound_coordinate,
            key_package_ref: reservation_key_package_ref,
            received_at,
            expires_at: recovery_timestamp(expires_at)?,
            status,
            origin,
            terminal: terminal.clone(),
        });
        reservations_by_id
            .get_mut(&request_id)
            .ok_or(RecoveryHydrationError::PairMismatch)?
            .row
            .terminal = terminal;
    }

    // 1:1 correspondence: every reservation was paired to exactly one request.
    if paired != reservations_by_id.len() {
        return Err(RecoveryHydrationError::PairMismatch);
    }

    let mut reservations: Vec<RecoveryReservationHydrationRow> = reservations_by_id
        .into_values()
        .map(|reservation| reservation.row)
        .collect();

    // `validate_recovery_work` requires both collections strictly increasing by
    // `(target, request_id)`. Sort in Rust so the ordering is independent of the
    // database's `recipient_did` collation.
    requests.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.request_id.cmp(&right.request_id))
    });
    reservations.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.request_id.cmp(&right.request_id))
    });

    Ok((requests, reservations))
}

fn recovery_device(did: String, device_id: Uuid) -> Result<DeviceIdentity, RecoveryHydrationError> {
    let principal =
        PrincipalId::new(did.into_bytes()).map_err(|_| RecoveryHydrationError::OutOfDomain)?;
    DeviceIdentity::new(principal, *device_id.as_bytes())
        .map_err(|_| RecoveryHydrationError::OutOfDomain)
}

#[allow(clippy::too_many_arguments)]
fn recovery_coordinate(
    conversation_id: [u8; 16],
    generation: i64,
    state_version: i64,
    group_id: Vec<u8>,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
) -> Result<PublicGroupSnapshotCoordinate, RecoveryHydrationError> {
    Ok(PublicGroupSnapshotCoordinate::new(
        conversation_id,
        recovery_u64(generation)?,
        recovery_u64(state_version)?,
        recovery_bytes32(group_id)?,
        recovery_u64(epoch)?,
        recovery_bytes32(group_context_hash)?,
        recovery_bytes32(confirmation_tag)?,
        PublicGroupSnapshotLifecycle::Active,
    ))
}

fn recovery_u64(value: i64) -> Result<u64, RecoveryHydrationError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(RecoveryHydrationError::OutOfDomain)
}

fn recovery_bytes32(value: Vec<u8>) -> Result<[u8; 32], RecoveryHydrationError> {
    <[u8; 32]>::try_from(value.as_slice()).map_err(|_| RecoveryHydrationError::OutOfDomain)
}

fn recovery_timestamp(value: DateTime<Utc>) -> Result<ServerTimestamp, RecoveryHydrationError> {
    ServerTimestamp::from_canonical_stored(&canonical_millis(value))
        .map_err(|_| RecoveryHydrationError::OutOfDomain)
}

/// Canonical millisecond RFC3339 form (`YYYY-MM-DDThh:mm:ss.sssZ`) that the state
/// machine's `CanonicalTimestamp` grammar requires. Postgres stores microsecond
/// precision; the read-time origin re-mint is self-consistent because BOTH the
/// durable-row digest derivation and this hydration read the same truncated
/// instant through this one formatter.
fn canonical_millis(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

// ===========================================================================
// T4-H2-pre terminal-family sub-seal C — Welcome hydration.
//
// A Welcome is the exact join of one immutable bundle and one delivery. The
// bundle supplies its creation transition sequence, successor coordinate, and
// opaque artifact; the delivery supplies the recipient, recovery/package
// binding, expiry, and status. Terminal dispositions are direct causes only:
// no timestamp or coordinate candidate search is permitted.
// ===========================================================================

#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum WelcomeHydrationError {
    #[error("clean-chat Welcome durable column is out of domain")]
    OutOfDomain,
    #[error("clean-chat Welcome terminal columns do not match the selected status")]
    TerminalMismatch,
    #[error("clean-chat Welcome terminal evidence failed re-verification")]
    InvalidTerminal,
    #[error("clean-chat Welcome hydration database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone, Copy)]
pub(crate) struct WelcomeTerminalColumns<'a> {
    pub(crate) status: &'a str,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) delivery_terminal_at: Option<DateTime<Utc>>,
    pub(crate) disposition_present: bool,
    pub(crate) disposition_matches_welcome: bool,
    pub(crate) winner_kind: Option<&'a str>,
    pub(crate) signed_request_bytes: Option<&'a [u8]>,
    pub(crate) signing_transcript_bytes: Option<&'a [u8]>,
    pub(crate) request_digest: Option<&'a [u8]>,
    pub(crate) signature: Option<&'a [u8]>,
    pub(crate) rejection_reason: Option<&'a str>,
    pub(crate) disposition_terminal_at: Option<DateTime<Utc>>,
    pub(crate) event_position: Option<i64>,
    pub(crate) terminal_transition_id: Option<Uuid>,
    pub(crate) terminal_revocation_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WelcomeTerminalSelection {
    Pending,
    Acknowledged {
        terminal_at: DateTime<Utc>,
    },
    Rejected {
        terminal_at: DateTime<Utc>,
    },
    Expired {
        terminal_at: DateTime<Utc>,
    },
    Transition {
        transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    DeviceRevocation {
        revocation_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
}

/// Select the only legal disposition/cause shape for each durable Welcome
/// status. Evidence is reconstructed only after this pure ruling succeeds.
pub(crate) fn select_welcome_terminal(
    columns: WelcomeTerminalColumns<'_>,
) -> Result<WelcomeTerminalSelection, WelcomeHydrationError> {
    let no_signed_fields = columns.signed_request_bytes.is_none()
        && columns.signing_transcript_bytes.is_none()
        && columns.request_digest.is_none()
        && columns.signature.is_none();
    let exact_signed_fields = columns
        .signed_request_bytes
        .is_some_and(|value| !value.is_empty())
        && columns
            .signing_transcript_bytes
            .is_some_and(|value| !value.is_empty())
        && columns
            .request_digest
            .is_some_and(|value| value.len() == 32)
        && columns.signature.is_some_and(|value| value.len() == 64);
    let no_disposition = !columns.disposition_present
        && !columns.disposition_matches_welcome
        && columns.winner_kind.is_none()
        && no_signed_fields
        && columns.rejection_reason.is_none()
        && columns.disposition_terminal_at.is_none()
        && columns.event_position.is_none()
        && columns.terminal_transition_id.is_none()
        && columns.terminal_revocation_id.is_none();
    let shared_terminal = columns.disposition_present
        && columns.disposition_matches_welcome
        && columns
            .event_position
            .and_then(|value| u64::try_from(value).ok())
            .is_some_and(|value| (1..=MAX_PROTOCOL_INTEGER).contains(&value))
        && columns.delivery_terminal_at.is_some()
        && columns.delivery_terminal_at == columns.disposition_terminal_at;

    match columns.status {
        "pending" if columns.delivery_terminal_at.is_none() && no_disposition => {
            Ok(WelcomeTerminalSelection::Pending)
        }
        "acknowledged"
            if shared_terminal
                && columns.winner_kind == Some("acknowledged")
                && exact_signed_fields
                && columns.rejection_reason.is_none()
                && columns.terminal_transition_id.is_none()
                && columns.terminal_revocation_id.is_none()
                && columns
                    .delivery_terminal_at
                    .is_some_and(|value| value < columns.expires_at) =>
        {
            Ok(WelcomeTerminalSelection::Acknowledged {
                terminal_at: columns.delivery_terminal_at.unwrap(),
            })
        }
        "rejected"
            if shared_terminal
                && columns.winner_kind == Some("rejected")
                && exact_signed_fields
                && matches!(
                    columns.rejection_reason,
                    Some(
                        "noMatchingKeyPackage"
                            | "invalidWelcome"
                            | "unsupportedCipherSuite"
                            | "coordinateMismatch"
                            | "localStateConflict"
                    )
                )
                && columns.terminal_transition_id.is_none()
                && columns.terminal_revocation_id.is_none()
                && columns
                    .delivery_terminal_at
                    .is_some_and(|value| value < columns.expires_at) =>
        {
            Ok(WelcomeTerminalSelection::Rejected {
                terminal_at: columns.delivery_terminal_at.unwrap(),
            })
        }
        "expired"
            if shared_terminal
                && columns.winner_kind == Some("expired")
                && no_signed_fields
                && columns.rejection_reason.is_none()
                && columns.terminal_transition_id.is_none()
                && columns.terminal_revocation_id.is_none()
                && columns.delivery_terminal_at == Some(columns.expires_at) =>
        {
            Ok(WelcomeTerminalSelection::Expired {
                terminal_at: columns.expires_at,
            })
        }
        "superseded"
            if shared_terminal
                && columns.winner_kind == Some("superseded")
                && no_signed_fields
                && columns.rejection_reason.is_none()
                && columns
                    .delivery_terminal_at
                    .is_some_and(|value| value < columns.expires_at)
                && columns.terminal_transition_id.is_some()
                && columns.terminal_revocation_id.is_none() =>
        {
            Ok(WelcomeTerminalSelection::Transition {
                transition_id: columns.terminal_transition_id.unwrap(),
                terminal_at: columns.delivery_terminal_at.unwrap(),
            })
        }
        "superseded"
            if shared_terminal
                && columns.winner_kind == Some("superseded")
                && no_signed_fields
                && columns.rejection_reason.is_none()
                && columns
                    .delivery_terminal_at
                    .is_some_and(|value| value < columns.expires_at)
                && columns.terminal_transition_id.is_none()
                && columns.terminal_revocation_id.is_some() =>
        {
            Ok(WelcomeTerminalSelection::DeviceRevocation {
                revocation_id: columns.terminal_revocation_id.unwrap(),
                terminal_at: columns.delivery_terminal_at.unwrap(),
            })
        }
        "pending" | "acknowledged" | "rejected" | "expired" | "superseded" => {
            Err(WelcomeHydrationError::TerminalMismatch)
        }
        _ => Err(WelcomeHydrationError::OutOfDomain),
    }
}

#[derive(sqlx::FromRow)]
struct DurableWelcomeHydrationRow {
    welcome_id: Uuid,
    conversation_id: Uuid,
    entry_seq: i64,
    generation: i64,
    state_version: i64,
    group_id: Vec<u8>,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    wrapper_bytes: Vec<u8>,
    wrapper_sha256: Vec<u8>,
    recipient_did: String,
    recipient_device_id: Uuid,
    recovery_request_id: Uuid,
    key_package_ref: Vec<u8>,
    expires_at: DateTime<Utc>,
    status: String,
    delivery_terminal_at: Option<DateTime<Utc>>,
    disposition_welcome_id: Option<Uuid>,
    winner_kind: Option<String>,
    signed_request_bytes: Option<Vec<u8>>,
    signing_transcript_bytes: Option<Vec<u8>>,
    request_digest: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
    rejection_reason: Option<String>,
    disposition_terminal_at: Option<DateTime<Utc>>,
    event_position: Option<i64>,
    terminal_transition_id: Option<Uuid>,
    terminal_revocation_id: Option<Uuid>,
}

/// Load every Welcome for one conversation from its exact bundle/delivery row
/// pair. Terminal dispositions are selected by their direct durable cause
/// columns; pending rows require the complete disposition shape to be absent.
#[allow(dead_code)]
pub(crate) async fn load_welcome_hydration_rows(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
) -> Result<Vec<WelcomeHydrationRow>, WelcomeHydrationError> {
    let rows: Vec<DurableWelcomeHydrationRow> = sqlx::query_as(
        r#"
        SELECT
            bundle.welcome_id,
            bundle.conversation_id,
            bundle.entry_seq,
            bundle.generation,
            bundle.state_version,
            bundle.group_id,
            bundle.epoch,
            bundle.group_context_hash,
            bundle.confirmation_tag,
            bundle.wrapper_bytes,
            bundle.wrapper_sha256,
            delivery.recipient_did,
            delivery.recipient_device_id,
            delivery.recovery_request_id,
            delivery.key_package_ref,
            delivery.expires_at,
            delivery.status,
            delivery.terminal_at AS delivery_terminal_at,
            disposition.welcome_id AS disposition_welcome_id,
            disposition.winner_kind,
            disposition.signed_request_bytes,
            disposition.signing_transcript_bytes,
            disposition.request_digest,
            disposition.signature,
            disposition.rejection_reason,
            disposition.terminal_at AS disposition_terminal_at,
            disposition.event_position,
            disposition.terminal_transition_id,
            disposition.terminal_revocation_id
        FROM chat.welcome_bundles bundle
        JOIN chat.welcome_deliveries delivery
          ON delivery.welcome_id = bundle.welcome_id
        LEFT JOIN chat.welcome_dispositions disposition
          ON disposition.welcome_id = delivery.welcome_id
        WHERE bundle.conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;

    let mut welcomes = Vec::with_capacity(rows.len());
    for row in rows {
        if row.conversation_id != conversation_id
            || !uuid_is_canonical_v4(row.welcome_id)
            || !uuid_is_canonical_v4(row.recovery_request_id)
            || row.wrapper_bytes.is_empty()
        {
            return Err(WelcomeHydrationError::OutOfDomain);
        }
        let transition_seq = welcome_positive_u64(row.entry_seq)?;
        let coordinate = welcome_coordinate(
            *row.conversation_id.as_bytes(),
            row.generation,
            row.state_version,
            row.group_id,
            row.epoch,
            row.group_context_hash,
            row.confirmation_tag,
        )?;
        let sha256 = welcome_bytes32(row.wrapper_sha256)?;
        if <[u8; 32]>::from(Sha256::digest(&row.wrapper_bytes)) != sha256 {
            return Err(WelcomeHydrationError::OutOfDomain);
        }
        let recipient = welcome_device(row.recipient_did, row.recipient_device_id)?;
        let recovery_request_id = *row.recovery_request_id.as_bytes();
        let key_package_ref = welcome_bytes32(row.key_package_ref)?;
        let expires_at = welcome_timestamp(row.expires_at)?;

        let selection = select_welcome_terminal(WelcomeTerminalColumns {
            status: &row.status,
            expires_at: row.expires_at,
            delivery_terminal_at: row.delivery_terminal_at,
            disposition_present: row.disposition_welcome_id.is_some(),
            disposition_matches_welcome: row.disposition_welcome_id == Some(row.welcome_id),
            winner_kind: row.winner_kind.as_deref(),
            signed_request_bytes: row.signed_request_bytes.as_deref(),
            signing_transcript_bytes: row.signing_transcript_bytes.as_deref(),
            request_digest: row.request_digest.as_deref(),
            signature: row.signature.as_deref(),
            rejection_reason: row.rejection_reason.as_deref(),
            disposition_terminal_at: row.disposition_terminal_at,
            event_position: row.event_position,
            terminal_transition_id: row.terminal_transition_id,
            terminal_revocation_id: row.terminal_revocation_id,
        })?;
        let (status, terminal) = match selection {
            WelcomeTerminalSelection::Pending => (WelcomeStatus::Pending, None),
            WelcomeTerminalSelection::Acknowledged { terminal_at }
            | WelcomeTerminalSelection::Rejected { terminal_at } => {
                let expected_kind =
                    if matches!(selection, WelcomeTerminalSelection::Acknowledged { .. }) {
                        RequestEntryKind::WelcomeAcknowledgement
                    } else {
                        RequestEntryKind::WelcomeRejection
                    };
                let raw = row
                    .signed_request_bytes
                    .as_deref()
                    .ok_or(WelcomeHydrationError::TerminalMismatch)?;
                let transcript = row
                    .signing_transcript_bytes
                    .as_deref()
                    .ok_or(WelcomeHydrationError::TerminalMismatch)?;
                let request_digest: [u8; 32] = row
                    .request_digest
                    .as_deref()
                    .and_then(|value| value.try_into().ok())
                    .ok_or(WelcomeHydrationError::TerminalMismatch)?;
                let signature: [u8; 64] = row
                    .signature
                    .as_deref()
                    .and_then(|value| value.try_into().ok())
                    .ok_or(WelcomeHydrationError::TerminalMismatch)?;
                let canonical = decode_canonical_signed_mutation(raw)
                    .map_err(|_| WelcomeHydrationError::InvalidTerminal)?;
                let recipient_did = std::str::from_utf8(recipient.principal().as_bytes())
                    .map_err(|_| WelcomeHydrationError::OutOfDomain)?;
                let signing_public_key: Vec<u8> = sqlx::query_scalar(
                    r#"SELECT signing_public_key
                       FROM chat.device_keys
                       WHERE user_did=$1 AND device_id=$2 AND key_id=$3"#,
                )
                .bind(recipient_did)
                .bind(Uuid::from_bytes(*recipient.device_id()))
                .bind(canonical.key_id().as_str())
                .fetch_optional(&mut **transaction)
                .await?
                .ok_or(WelcomeHydrationError::InvalidTerminal)?;
                if <[u8; 32]>::from(Sha256::digest(transcript)) != request_digest {
                    return Err(WelcomeHydrationError::InvalidTerminal);
                }
                let terminal = load_work_terminal_hydration_row(
                    transaction,
                    authority,
                    conversation_id,
                    WorkTerminalLocator::Request {
                        kind: expected_kind,
                        source: WorkTerminalRequestSource::Signed {
                            received_at: terminal_at,
                            signed_request_bytes: raw,
                            signing_transcript_bytes: transcript,
                            request_digest,
                            signature,
                            signing_public_key: &signing_public_key,
                        },
                    },
                )
                .await
                .map_err(|_| WelcomeHydrationError::InvalidTerminal)?;
                let WorkTerminalHydrationRow::Request(ref evidence) = terminal else {
                    return Err(WelcomeHydrationError::InvalidTerminal);
                };
                let terminal_timestamp = welcome_timestamp(terminal_at)?;
                if evidence.kind() != expected_kind
                    || evidence.conversation_id() != conversation_id.as_bytes()
                    || evidence.request_id() != row.welcome_id.as_bytes()
                    || evidence.actor() != &recipient
                    || evidence.received_at() != terminal_timestamp
                    || !welcome_response_body_matches(
                        raw,
                        &signing_public_key,
                        expected_kind,
                        *row.welcome_id.as_bytes(),
                        &coordinate,
                        transition_seq,
                        row.rejection_reason.as_deref(),
                    )
                {
                    return Err(WelcomeHydrationError::InvalidTerminal);
                }
                let status = if expected_kind == RequestEntryKind::WelcomeAcknowledgement {
                    WelcomeStatus::Acknowledged
                } else {
                    WelcomeStatus::Rejected
                };
                (status, Some(terminal))
            }
            WelcomeTerminalSelection::Expired { terminal_at } => {
                let terminal = load_work_terminal_hydration_row(
                    transaction,
                    authority,
                    conversation_id,
                    WorkTerminalLocator::Expiry { terminal_at },
                )
                .await
                .map_err(|_| WelcomeHydrationError::InvalidTerminal)?;
                (WelcomeStatus::Expired, Some(terminal))
            }
            WelcomeTerminalSelection::Transition {
                transition_id,
                terminal_at,
            } => {
                let terminal = load_work_terminal_hydration_row(
                    transaction,
                    authority,
                    conversation_id,
                    WorkTerminalLocator::Transition { transition_id },
                )
                .await
                .map_err(|_| WelcomeHydrationError::InvalidTerminal)?;
                let WorkTerminalHydrationRow::Transition(ref evidence) = terminal else {
                    return Err(WelcomeHydrationError::InvalidTerminal);
                };
                if evidence.transition_id() != transition_id.as_bytes()
                    || evidence.seq() <= transition_seq
                    || evidence.received_at() != welcome_timestamp(terminal_at)?
                {
                    return Err(WelcomeHydrationError::InvalidTerminal);
                }
                (WelcomeStatus::Superseded, Some(terminal))
            }
            WelcomeTerminalSelection::DeviceRevocation {
                revocation_id,
                terminal_at,
            } => {
                let terminal = load_work_terminal_hydration_row(
                    transaction,
                    authority,
                    conversation_id,
                    WorkTerminalLocator::DeviceRevocation { revocation_id },
                )
                .await
                .map_err(|_| WelcomeHydrationError::InvalidTerminal)?;
                let WorkTerminalHydrationRow::DeviceRevocation(ref evidence) = terminal else {
                    return Err(WelcomeHydrationError::InvalidTerminal);
                };
                if evidence.revocation_id() != revocation_id.as_bytes()
                    || evidence.target() != &recipient
                    || evidence.accepted_at() != welcome_timestamp(terminal_at)?
                {
                    return Err(WelcomeHydrationError::InvalidTerminal);
                }
                (WelcomeStatus::Superseded, Some(terminal))
            }
        };

        welcomes.push(WelcomeHydrationRow {
            welcome_id: *row.welcome_id.as_bytes(),
            recipient,
            transition_seq,
            coordinate,
            recovery_request_id,
            key_package_ref,
            opaque_welcome: row.wrapper_bytes,
            sha256,
            expires_at,
            status,
            terminal,
        });
    }
    welcomes.sort_by_key(|welcome| welcome.welcome_id);
    Ok(welcomes)
}

fn welcome_device(did: String, device_id: Uuid) -> Result<DeviceIdentity, WelcomeHydrationError> {
    if !uuid_is_canonical_v4(device_id) {
        return Err(WelcomeHydrationError::OutOfDomain);
    }
    DeviceIdentity::new(
        PrincipalId::new(did.into_bytes()).map_err(|_| WelcomeHydrationError::OutOfDomain)?,
        *device_id.as_bytes(),
    )
    .map_err(|_| WelcomeHydrationError::OutOfDomain)
}

#[allow(clippy::too_many_arguments)]
fn welcome_coordinate(
    conversation_id: [u8; 16],
    generation: i64,
    state_version: i64,
    group_id: Vec<u8>,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
) -> Result<PublicGroupSnapshotCoordinate, WelcomeHydrationError> {
    Ok(PublicGroupSnapshotCoordinate::new(
        conversation_id,
        welcome_u64(generation)?,
        welcome_u64(state_version)?,
        welcome_bytes32(group_id)?,
        welcome_u64(epoch)?,
        welcome_bytes32(group_context_hash)?,
        welcome_bytes32(confirmation_tag)?,
        PublicGroupSnapshotLifecycle::Active,
    ))
}

fn welcome_u64(value: i64) -> Result<u64, WelcomeHydrationError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(WelcomeHydrationError::OutOfDomain)
}

fn welcome_positive_u64(value: i64) -> Result<u64, WelcomeHydrationError> {
    u64::try_from(value)
        .ok()
        .filter(|value| (1..=MAX_PROTOCOL_INTEGER).contains(value))
        .ok_or(WelcomeHydrationError::OutOfDomain)
}

fn welcome_bytes32(value: Vec<u8>) -> Result<[u8; 32], WelcomeHydrationError> {
    value
        .try_into()
        .map_err(|_| WelcomeHydrationError::OutOfDomain)
}

fn welcome_timestamp(value: DateTime<Utc>) -> Result<ServerTimestamp, WelcomeHydrationError> {
    ServerTimestamp::from_canonical_stored(&canonical_millis(value))
        .map_err(|_| WelcomeHydrationError::OutOfDomain)
}

fn welcome_response_body_matches(
    raw: &[u8],
    signing_public_key: &[u8],
    expected_kind: RequestEntryKind,
    welcome_id: [u8; 16],
    coordinate: &PublicGroupSnapshotCoordinate,
    transition_seq: u64,
    durable_rejection_reason: Option<&str>,
) -> bool {
    let Ok(mutation) = decode_and_verify_signed_mutation(raw, signing_public_key) else {
        return false;
    };
    let body = match (expected_kind, mutation.projection()) {
        (
            RequestEntryKind::WelcomeAcknowledgement,
            VerifiedMutationProjection::WelcomeAcknowledgement(body),
        ) => body.body(),
        (
            RequestEntryKind::WelcomeRejection,
            VerifiedMutationProjection::WelcomeRejection(body),
        ) => body.body(),
        _ => return false,
    };
    let Some(CanonicalValueRef::Uuid(signed_welcome_id)) = body.get("welcomeId") else {
        return false;
    };
    let Some(CanonicalValueRef::Integer(signed_transition_seq)) = body.get("transitionSeq") else {
        return false;
    };
    let Some(CanonicalValueRef::Object(signed_coordinate)) = body.get("coordinates") else {
        return false;
    };
    let reason_matches = match expected_kind {
        RequestEntryKind::WelcomeAcknowledgement => {
            durable_rejection_reason.is_none() && body.get("reason").is_none()
        }
        RequestEntryKind::WelcomeRejection => matches!(
            body.get("reason"),
            Some(CanonicalValueRef::Text(signed_reason))
                if Some(signed_reason) == durable_rejection_reason
        ),
        _ => false,
    };
    signed_welcome_id.as_bytes() == &welcome_id
        && signed_transition_seq == transition_seq
        && canonical_welcome_coordinate_matches(signed_coordinate, coordinate)
        && reason_matches
}

fn canonical_welcome_coordinate_matches(
    value: super::super::transcript::ClosedObjectRef<'_>,
    expected: &PublicGroupSnapshotCoordinate,
) -> bool {
    matches!(
        (
            value.get("conversationId"),
            value.get("generation"),
            value.get("stateVersion"),
            value.get("groupId"),
            value.get("epoch"),
            value.get("groupContextHash"),
            value.get("confirmationTag"),
            value.get("lifecycle"),
        ),
        (
            Some(CanonicalValueRef::Uuid(conversation_id)),
            Some(CanonicalValueRef::Integer(generation)),
            Some(CanonicalValueRef::Integer(state_version)),
            Some(CanonicalValueRef::Bytes(group_id)),
            Some(CanonicalValueRef::Integer(epoch)),
            Some(CanonicalValueRef::Bytes(group_context_hash)),
            Some(CanonicalValueRef::Bytes(confirmation_tag)),
            Some(CanonicalValueRef::Text("active")),
        ) if conversation_id.as_bytes() == expected.conversation_id()
            && generation == expected.generation()
            && state_version == expected.state_version()
            && group_id == expected.group_id()
            && epoch == expected.epoch()
            && group_context_hash == expected.group_context_hash()
            && confirmation_tag == expected.confirmation_tag()
            && expected.lifecycle() == PublicGroupSnapshotLifecycle::Active
    )
}

// ===========================================================================
// T4-H2-pre terminal-family sub-seal A — shared WorkTerminalHydrationRow atom.
//
// DeviceRevocation is global and entry-less. The immutable durable row is
// located by its UUID under an EXACTLY-ONE guard, JOINed to the actor's
// historical signing key, and then re-entered through the state machine's
// certified signed-mutation verifier. Every row field is compared exactly with
// the re-minted evidence; no digest-only trust or placeholder evidence exists.
// ===========================================================================

#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum WorkTerminalHydrationError {
    #[error("clean-chat terminal evidence is absent")]
    EvidenceMissing,
    #[error("clean-chat terminal evidence is ambiguous")]
    EvidenceAmbiguous,
    #[error("clean-chat terminal evidence failed full re-verification")]
    InvalidEvidence,
    #[error("clean-chat terminal durable column is out of domain")]
    OutOfDomain,
    #[error("clean-chat terminal request kind does not use the supplied verifier path")]
    RequestPathMismatch,
    #[error("clean-chat terminal hydration database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[allow(dead_code)]
pub(crate) enum WorkTerminalRequestSource<'a> {
    Control {
        request_digest: &'a [u8],
        signed_request_bytes: &'a [u8],
    },
    Signed {
        received_at: DateTime<Utc>,
        signed_request_bytes: &'a [u8],
        signing_transcript_bytes: &'a [u8],
        request_digest: [u8; 32],
        signature: [u8; 64],
        signing_public_key: &'a [u8],
    },
}

#[allow(dead_code)]
pub(crate) enum WorkTerminalLocator<'a> {
    Transition {
        transition_id: Uuid,
    },
    Request {
        kind: RequestEntryKind,
        source: WorkTerminalRequestSource<'a>,
    },
    DeviceRevocation {
        revocation_id: Uuid,
    },
    Expiry {
        terminal_at: DateTime<Utc>,
    },
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
    signing_public_key: Vec<u8>,
}

/// Resolve an immutable terminal-evidence lookup under the binding ruling:
/// exactly one row or fail closed. This decision is shared by locators whose DB
/// constraints make duplicate rows structurally impossible, so the read side
/// still never silently selects if that invariant drifts.
pub(crate) fn resolve_single_terminal_candidate<T>(
    rows: Vec<T>,
) -> Result<T, WorkTerminalHydrationError> {
    let mut rows = rows.into_iter();
    match (rows.next(), rows.next()) {
        (Some(row), None) => Ok(row),
        (None, _) => Err(WorkTerminalHydrationError::EvidenceMissing),
        (Some(_), Some(_)) => Err(WorkTerminalHydrationError::EvidenceAmbiguous),
    }
}

/// Reconstruct one terminal-family evidence arm from its verified source.
/// Evidence-bearing arms re-read or re-verify their exact durable provenance.
/// For Expiry, the owning B-E loader remains responsible for selecting the
/// persisted timestamp; this dispatcher validates and preserves that timestamp
/// as the typed terminal arm. Callers never construct evidence directly.
#[allow(dead_code)]
pub(crate) async fn load_work_terminal_hydration_row(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
    locator: WorkTerminalLocator<'_>,
) -> Result<WorkTerminalHydrationRow, WorkTerminalHydrationError> {
    match locator {
        WorkTerminalLocator::Transition { transition_id } => {
            let evidence = load_historical_control_evidence(
                transaction,
                authority,
                conversation_id,
                transition_id,
            )
            .await
            .map_err(|error| match error {
                ControlEvidenceLoadError::EntryMissing => {
                    WorkTerminalHydrationError::EvidenceMissing
                }
                ControlEvidenceLoadError::InvalidEvidence => {
                    WorkTerminalHydrationError::InvalidEvidence
                }
                ControlEvidenceLoadError::Database(error) => {
                    WorkTerminalHydrationError::Database(error)
                }
            })?
            .into_transition()
            .map_err(|_| WorkTerminalHydrationError::InvalidEvidence)?;
            if evidence.transition_id() != transition_id.as_bytes() {
                return Err(WorkTerminalHydrationError::InvalidEvidence);
            }
            Ok(WorkTerminalHydrationRow::Transition(evidence))
        }
        WorkTerminalLocator::Request { kind, source } => match source {
            WorkTerminalRequestSource::Control {
                request_digest,
                signed_request_bytes,
            } => {
                let entry_kind = match kind {
                    RequestEntryKind::ResetRequest => RESET_REQUEST_ENTRY_KIND,
                    RequestEntryKind::LeaveRequest => LEAVE_REQUEST_ENTRY_KIND,
                    RequestEntryKind::LeaveCancellation => {
                        "blue.catbird.chat.defs#leaveCancellationEntry"
                    }
                    RequestEntryKind::LeafRecoveryRequest
                    | RequestEntryKind::LeafRecoveryCancellation
                    | RequestEntryKind::WelcomeAcknowledgement
                    | RequestEntryKind::WelcomeRejection => {
                        return Err(WorkTerminalHydrationError::RequestPathMismatch);
                    }
                };
                let evidence = load_control_request_origin(
                    transaction,
                    authority,
                    conversation_id,
                    entry_kind,
                    request_digest,
                    signed_request_bytes,
                )
                .await
                .map_err(work_terminal_from_reset_leave_error)?;
                if evidence.kind() != kind {
                    return Err(WorkTerminalHydrationError::InvalidEvidence);
                }
                Ok(WorkTerminalHydrationRow::Request(evidence))
            }
            WorkTerminalRequestSource::Signed {
                received_at,
                signed_request_bytes,
                signing_transcript_bytes,
                request_digest,
                signature,
                signing_public_key,
            } => {
                if matches!(
                    kind,
                    RequestEntryKind::ResetRequest
                        | RequestEntryKind::LeaveRequest
                        | RequestEntryKind::LeaveCancellation
                ) {
                    return Err(WorkTerminalHydrationError::RequestPathMismatch);
                }
                let evidence = authority
                    .hydrate_historical_signed_request_from_exact_durable_fields(
                        *conversation_id.as_bytes(),
                        &canonical_millis(received_at),
                        signed_request_bytes,
                        signing_transcript_bytes,
                        request_digest,
                        signature,
                        signing_public_key,
                    )
                    .map_err(|_| WorkTerminalHydrationError::InvalidEvidence)?;
                if evidence.kind() != kind {
                    return Err(WorkTerminalHydrationError::InvalidEvidence);
                }
                Ok(WorkTerminalHydrationRow::Request(evidence))
            }
        },
        WorkTerminalLocator::DeviceRevocation { revocation_id } => {
            load_device_revocation_terminal(transaction, revocation_id).await
        }
        WorkTerminalLocator::Expiry { terminal_at } => {
            let timestamp = ServerTimestamp::from_canonical_stored(&canonical_millis(terminal_at))
                .map_err(|_| WorkTerminalHydrationError::OutOfDomain)?;
            Ok(WorkTerminalHydrationRow::Expiry(timestamp))
        }
    }
}

fn work_terminal_from_reset_leave_error(
    error: ResetLeaveHydrationError,
) -> WorkTerminalHydrationError {
    match error {
        ResetLeaveHydrationError::OriginMissing => WorkTerminalHydrationError::EvidenceMissing,
        ResetLeaveHydrationError::OriginAmbiguous => WorkTerminalHydrationError::EvidenceAmbiguous,
        ResetLeaveHydrationError::OutOfDomain => WorkTerminalHydrationError::OutOfDomain,
        ResetLeaveHydrationError::Database(error) => WorkTerminalHydrationError::Database(error),
        ResetLeaveHydrationError::BindingMismatch
        | ResetLeaveHydrationError::InvalidOrigin
        | ResetLeaveHydrationError::TerminalMismatch
        | ResetLeaveHydrationError::InvalidTerminal
        | ResetLeaveHydrationError::UnsupportedTerminal => {
            WorkTerminalHydrationError::InvalidEvidence
        }
    }
}

async fn load_device_revocation_terminal(
    transaction: &mut Transaction<'_, Postgres>,
    revocation_id: Uuid,
) -> Result<WorkTerminalHydrationRow, WorkTerminalHydrationError> {
    let rows: Vec<DurableDeviceRevocationRow> = sqlx::query_as(
        r#"
        SELECT
            rev.revocation_id,
            rev.actor_did,
            rev.actor_device_id,
            rev.actor_key_id,
            rev.actor_auth_generation,
            rev.target_did,
            rev.target_device_id,
            rev.target_auth_generation,
            rev.accepted_request_bytes,
            rev.signing_transcript_bytes,
            rev.request_digest,
            rev.signature,
            rev.signed_at,
            rev.accepted_at,
            actor_key.signing_public_key
        FROM chat.device_revocations rev
        JOIN chat.device_keys actor_key
          ON actor_key.user_did = rev.actor_did
         AND actor_key.device_id = rev.actor_device_id
         AND actor_key.key_id = rev.actor_key_id
        WHERE rev.revocation_id = $1
        "#,
    )
    .bind(revocation_id)
    .fetch_all(&mut **transaction)
    .await?;

    let row = resolve_single_terminal_candidate(rows)?;
    if row.revocation_id != revocation_id
        || !uuid_is_canonical_v4(row.revocation_id)
        || KeyThumbprint::parse(&row.actor_key_id).is_err()
    {
        return Err(WorkTerminalHydrationError::OutOfDomain);
    }

    let actor = terminal_device(row.actor_did, row.actor_device_id)?;
    let target = terminal_device(row.target_did, row.target_device_id)?;
    let actor_key_id: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&row.actor_key_id)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(WorkTerminalHydrationError::OutOfDomain)?;
    let actor_auth_generation = terminal_u64(row.actor_auth_generation)?;
    let target_auth_generation = terminal_u64(row.target_auth_generation)?;
    let request_digest = terminal_bytes32(row.request_digest)?;
    let signature = terminal_bytes64(row.signature)?;
    let signed_at = canonical_millis(row.signed_at);
    let accepted_at = canonical_millis(row.accepted_at);

    HydrationAuthority::hydrate_persisted_device_revocation_from_durable_fields(
        *row.revocation_id.as_bytes(),
        actor,
        target,
        actor_key_id,
        actor_auth_generation,
        target_auth_generation,
        &row.accepted_request_bytes,
        &row.signing_transcript_bytes,
        request_digest,
        signature,
        &signed_at,
        &accepted_at,
        &row.signing_public_key,
    )
    .map(WorkTerminalHydrationRow::DeviceRevocation)
    .map_err(|_| WorkTerminalHydrationError::InvalidEvidence)
}

fn terminal_device(
    did: String,
    device_id: Uuid,
) -> Result<DeviceIdentity, WorkTerminalHydrationError> {
    if !uuid_is_canonical_v4(device_id) {
        return Err(WorkTerminalHydrationError::OutOfDomain);
    }
    DeviceIdentity::new(
        PrincipalId::new(did.into_bytes()).map_err(|_| WorkTerminalHydrationError::OutOfDomain)?,
        *device_id.as_bytes(),
    )
    .map_err(|_| WorkTerminalHydrationError::OutOfDomain)
}

fn terminal_u64(value: i64) -> Result<u64, WorkTerminalHydrationError> {
    u64::try_from(value)
        .ok()
        .filter(|value| (1..=MAX_PROTOCOL_INTEGER).contains(value))
        .ok_or(WorkTerminalHydrationError::OutOfDomain)
}

fn terminal_bytes32(value: Vec<u8>) -> Result<[u8; 32], WorkTerminalHydrationError> {
    value
        .try_into()
        .map_err(|_| WorkTerminalHydrationError::OutOfDomain)
}

fn terminal_bytes64(value: Vec<u8>) -> Result<[u8; 64], WorkTerminalHydrationError> {
    value
        .try_into()
        .map_err(|_| WorkTerminalHydrationError::OutOfDomain)
}

// ===========================================================================
// G1b-2 sub-seal — reset/leave request hydration leg (chat.reset_requests +
// chat.leave_requests).
//
// ORIGIN IS A CONTROL REQUEST, NOT A SIGNED REQUEST (corrected 2b-map,
// coordinator ruling "T4-H2-pre G1b-2 reset/leave origin RULING"). Unlike the
// leaf-recovery origin (a standalone signed request via the signed-path seam),
// a reset/leave request's origin is a `resetRequestEntry` / `leaveRequestEntry`
// CONTROL entry: `state_machine::historical_control_request_evidence` handles
// only Reset/Leave/LeaveCancellation, and `validate_request_evidence` classifies
// those three as `is_control = true`, REQUIRING `control_entry_id` / `control_seq`
// = `Some`. So the origin `RequestEvidence` is re-minted through the CONTROL
// pipeline (`hydrate_historical_control_from_durable_bytes` ->
// `PersistedControlAuthority::into_request`), not the signed-request seam.
//
// JOIN RULING (coordinator, self-verifying, uniqueness-assumption-free). No
// column links a `chat.entries` row to its `chat.reset_requests` /
// `chat.leave_requests` projection: request entries carry `transition_id = NULL`
// and their `entry_id` derives from the ExecutionContext, so the existing
// `(conversation_id, transition_id)` loader atom cannot reach them. The two rows
// share only `request_digest` + `signed_request_bytes`, and there is NO unique
// constraint on `request_digest`. So the origin entry is located by
// `(conversation_id, entry_kind, request_digest)` under THREE mandatory guards:
//   (a) EXACTLY ONE match — 0 => fail-closed missing, >1 => fail-closed ambiguous
//       (NEVER pick one);
//   (b) the located entry's `signed_request_bytes` MUST byte-equal the projection
//       row's `signed_request_bytes` — this pins the binding INDEPENDENTLY of
//       digest uniqueness (a `request_digest` value is not unique on its own);
//   (c) full control-pipeline re-verification (ed25519 + DAG-CBOR re-checked,
//       conversation binding enforced, entry seq strictly below the locked head)
//       through the shared historical-rehydration seam — nothing is trusted from
//       un-reverified DB state.
//
// DEFENSE-IN-DEPTH / STRUCTURAL-GUARD DISCLOSURE (for the reviewer): the (a)/(b)
// fail-closed arms — 0-match `OriginMissing`, >1-match `OriginAmbiguous`, and
// byte-mismatch `BindingMismatch` — are NOT constructible on a coherent gate DB.
// The reciprocal deferred mapping triggers force an EXACTLY-1:1 entry<->row
// correspondence at commit:
//   - `chat.assert_reset_request_mapping` / `chat.assert_leave_request_mapping`
//     (delivery.sql:273 / :335) require EXACTLY ONE `resetRequestEntry` /
//     `leaveRequestEntry` matching the row on `signed_request_bytes` +
//     `request_digest` + `signature` + actor identity + `received_at`
//     (`request_entry_count <> 1` raises 23514);
//   - `chat.assert_control_request_entry` (delivery.sql:408) requires the reverse
//     (each request entry maps to EXACTLY ONE projection row on the same columns).
// Therefore a projection row with 0 entries (=> `OriginMissing`) and a row with 2
// matching entries (=> `OriginAmbiguous`) both fail the deferred trigger at
// commit, and an entry whose `signed_request_bytes` differ but whose
// `request_digest` collides (=> `BindingMismatch`) needs a SHA-256 preimage
// collision (`request_digest = digest(signing_transcript_bytes, 'sha256')`,
// reset_requests.sql:1380). The loader's EXACTLY-ONE + byte-binding checks are the
// application-level backstop for those DB invariants and are unit-tested as a
// PURE decision (`resolve_single_control_request_origin`) over synthetic row sets
// — the only faithful way to exercise arms the coherent seed cannot reach (same
// class + resolution as the participant leg's structurally-guarded absence arm).
//
// TERMINAL SCOPE: stale/expired reset and stale/cancelled/expired/fulfilled leave
// terminals are reconstructed from their exact durable transition, request, or
// expiry authority. Reset `consumed` remains fail-closed behind
// `UnsupportedTerminal` until its activation-specific proof lands. A fulfilled
// leave additionally requires exactly one historical active participant period
// removed by that same terminal; the state validator then proves complete
// pre-terminal requester-leaf removal. `validate_reset_work` /
// `validate_leave_work` at assembly remain the final drift fences.
//
// No `FOR UPDATE`: the caller already holds the head lock (`FOR UPDATE OF c` on
// `chat.conversations`) that pins the historical suffix, and `chat.entries` /
// `chat.reset_requests` / `chat.leave_requests` are immutable-suffix under it.
// ===========================================================================

const RESET_REQUEST_ENTRY_KIND: &str = "blue.catbird.chat.defs#resetRequestEntry";
const LEAVE_REQUEST_ENTRY_KIND: &str = "blue.catbird.chat.defs#leaveRequestEntry";

/// Failure modes of [`load_reset_request_hydration_rows`] /
/// [`load_leave_request_hydration_rows`].
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum ResetLeaveHydrationError {
    /// A stored reset/leave column fell outside the protocol domain (a DID/UUID
    /// grammar violation, a non-32-byte crypto field, an out-of-range integer, or
    /// an unrecognized status token).
    #[error("clean-chat reset/leave column is out of domain")]
    OutOfDomain,
    /// No `chat.entries` control request row matched the projection row's
    /// `(conversation_id, entry_kind, request_digest)`. Fail closed: a request
    /// without its origin entry can never yield evidence. Structurally guarded by
    /// the reciprocal entry<->row mapping triggers (see module header).
    #[error("clean-chat reset/leave origin control entry is absent")]
    OriginMissing,
    /// More than one `chat.entries` control request row matched the projection
    /// row's `(conversation_id, entry_kind, request_digest)`. Fail closed — NEVER
    /// pick one. Structurally guarded (see module header).
    #[error("clean-chat reset/leave origin control entry is ambiguous")]
    OriginAmbiguous,
    /// The located origin entry's `signed_request_bytes` did not byte-equal the
    /// projection row's `signed_request_bytes`. Fail closed: the binding is pinned
    /// by exact bytes, not by the (non-unique) `request_digest`. Structurally
    /// guarded (see module header).
    #[error("clean-chat reset/leave origin signed bytes do not match the projection")]
    BindingMismatch,
    /// The located origin entry failed read-time control re-verification, or was a
    /// coordinate transition rather than a control request. Never coerced into
    /// evidence it does not attest.
    #[error("clean-chat reset/leave origin failed re-verification")]
    InvalidOrigin,
    /// A recognized terminal status carried a different optional-column shape
    /// than its closed durable arm permits.
    #[error("clean-chat reset/leave terminal columns do not match the status")]
    TerminalMismatch,
    /// The exact durable terminal evidence could not be re-verified or did not
    /// match the terminal columns that selected it.
    #[error("clean-chat reset/leave terminal evidence is invalid")]
    InvalidTerminal,
    /// The request carries a terminal status (non-`pending`) whose
    /// `WorkTerminalHydrationRow` reconstruction is the NEXT-STEP follow-up. Fail
    /// closed until that arm is reconstructed + tested.
    #[error("clean-chat reset/leave terminal status is not yet reconstructed")]
    UnsupportedTerminal,
    #[error("clean-chat reset/leave hydration database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone, Copy)]
pub(crate) struct ResetTerminalColumns {
    pub(crate) status: &'static str,
    pub(crate) terminal_transition_id: Option<Uuid>,
    pub(crate) terminal_at: Option<DateTime<Utc>>,
    pub(crate) expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResetTerminalSelection {
    Pending,
    StaleTransition {
        transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    ConsumedTransition {
        transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    Expiry {
        terminal_at: DateTime<Utc>,
    },
}

pub(crate) fn select_reset_terminal(
    columns: ResetTerminalColumns,
) -> Result<ResetTerminalSelection, ResetLeaveHydrationError> {
    match columns.status {
        "pending" if columns.terminal_transition_id.is_none() && columns.terminal_at.is_none() => {
            Ok(ResetTerminalSelection::Pending)
        }
        "expired"
            if columns.terminal_transition_id.is_none()
                && columns.terminal_at == Some(columns.expires_at) =>
        {
            Ok(ResetTerminalSelection::Expiry {
                terminal_at: columns.expires_at,
            })
        }
        "stale" if columns.terminal_transition_id.is_some() && columns.terminal_at.is_some() => {
            Ok(ResetTerminalSelection::StaleTransition {
                transition_id: columns.terminal_transition_id.expect("shape checked"),
                terminal_at: columns.terminal_at.expect("shape checked"),
            })
        }
        "consumed" if columns.terminal_transition_id.is_some() && columns.terminal_at.is_some() => {
            Ok(ResetTerminalSelection::ConsumedTransition {
                transition_id: columns.terminal_transition_id.expect("shape checked"),
                terminal_at: columns.terminal_at.expect("shape checked"),
            })
        }
        "pending" | "stale" | "consumed" | "expired" => {
            Err(ResetLeaveHydrationError::TerminalMismatch)
        }
        _ => Err(ResetLeaveHydrationError::OutOfDomain),
    }
}

#[derive(Clone, Copy)]
pub(crate) struct LeaveTerminalColumns<'a> {
    pub(crate) status: &'static str,
    pub(crate) terminal_request_digest: Option<&'a [u8]>,
    pub(crate) terminal_transition_id: Option<Uuid>,
    pub(crate) terminal_at: Option<DateTime<Utc>>,
    pub(crate) expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaveTerminalSelection {
    Pending,
    Transition {
        terminal_request_digest: [u8; 32],
        transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    Cancellation {
        terminal_request_digest: [u8; 32],
        terminal_at: DateTime<Utc>,
    },
    Expiry {
        terminal_at: DateTime<Utc>,
    },
}

pub(crate) fn select_leave_terminal(
    columns: LeaveTerminalColumns<'_>,
) -> Result<LeaveTerminalSelection, ResetLeaveHydrationError> {
    match columns.status {
        "pending"
            if columns.terminal_request_digest.is_none()
                && columns.terminal_transition_id.is_none()
                && columns.terminal_at.is_none() =>
        {
            Ok(LeaveTerminalSelection::Pending)
        }
        "expired"
            if columns.terminal_request_digest.is_none()
                && columns.terminal_transition_id.is_none()
                && columns.terminal_at == Some(columns.expires_at) =>
        {
            Ok(LeaveTerminalSelection::Expiry {
                terminal_at: columns.expires_at,
            })
        }
        "stale" | "fulfilled"
            if columns.terminal_transition_id.is_some()
                && columns.terminal_at.is_some()
                && columns
                    .terminal_request_digest
                    .is_some_and(|digest| digest.len() == 32) =>
        {
            Ok(LeaveTerminalSelection::Transition {
                terminal_request_digest: columns
                    .terminal_request_digest
                    .expect("shape checked")
                    .try_into()
                    .expect("length checked"),
                transition_id: columns.terminal_transition_id.expect("shape checked"),
                terminal_at: columns.terminal_at.expect("shape checked"),
            })
        }
        "cancelled"
            if columns.terminal_transition_id.is_none()
                && columns.terminal_at.is_some()
                && columns
                    .terminal_request_digest
                    .is_some_and(|digest| digest.len() == 32) =>
        {
            Ok(LeaveTerminalSelection::Cancellation {
                terminal_request_digest: columns
                    .terminal_request_digest
                    .expect("shape checked")
                    .try_into()
                    .expect("length checked"),
                terminal_at: columns.terminal_at.expect("shape checked"),
            })
        }
        "pending" | "fulfilled" | "cancelled" | "expired" | "stale" => {
            Err(ResetLeaveHydrationError::TerminalMismatch)
        }
        _ => Err(ResetLeaveHydrationError::OutOfDomain),
    }
}

#[derive(sqlx::FromRow)]
struct DurableLeaveRequestHydrationRow {
    leave_request_id: Uuid,
    requester_did: String,
    requester_device_id: Uuid,
    prior_generation: i64,
    prior_state_version: i64,
    prior_group_id: Vec<u8>,
    prior_epoch: i64,
    prior_group_context_hash: Vec<u8>,
    prior_confirmation_tag: Vec<u8>,
    status: String,
    request_digest: Vec<u8>,
    signed_request_bytes: Vec<u8>,
    received_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    terminal_request_digest: Option<Vec<u8>>,
    terminal_transition_id: Option<Uuid>,
    terminal_at: Option<DateTime<Utc>>,
}

/// Require one exact historical participant-period candidate for a fulfilled
/// leave. The SQL predicate binds conversation, requester, active historical
/// status, and terminal transition ID/sequence/time; this final cardinality
/// fence never chooses among duplicate durable claims.
pub(crate) fn resolve_single_fulfilled_participant<T>(
    rows: Vec<T>,
) -> Result<T, ResetLeaveHydrationError> {
    let mut rows = rows.into_iter();
    match (rows.next(), rows.next()) {
        (Some(row), None) => Ok(row),
        _ => Err(ResetLeaveHydrationError::InvalidTerminal),
    }
}

/// The `(accepted_payload_bytes, signed_request_bytes, signing_public_key)` of a
/// single located origin control entry.
type LocatedOriginEntry = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Apply JOIN-ruling guards (a) EXACTLY-ONE and (b) byte-binding to the set of
/// `chat.entries` rows located by `(conversation_id, entry_kind, request_digest)`.
///
/// Pure decision extracted from [`load_control_request_origin`] so the fail-closed
/// arms — which the reciprocal DB mapping triggers make un-constructible on a
/// coherent gate DB (module header) — are still faithfully exercised. Never picks
/// among multiple matches; never trusts a digest match without exact bytes.
pub(crate) fn resolve_single_control_request_origin(
    rows: Vec<LocatedOriginEntry>,
    expected_signed_request_bytes: &[u8],
) -> Result<LocatedOriginEntry, ResetLeaveHydrationError> {
    let mut located = rows.into_iter();
    let entry = match (located.next(), located.next()) {
        (Some(entry), None) => entry,
        (None, _) => return Err(ResetLeaveHydrationError::OriginMissing),
        (Some(_), Some(_)) => return Err(ResetLeaveHydrationError::OriginAmbiguous),
    };
    if entry.1.as_slice() != expected_signed_request_bytes {
        return Err(ResetLeaveHydrationError::BindingMismatch);
    }
    Ok(entry)
}

/// Locate + re-verify a reset/leave request's ORIGIN control entry per the
/// JOIN ruling, returning its re-minted `RequestEvidence`.
///
/// The origin is found by `(conversation_id, entry_kind, request_digest)` with the
/// entries-lookup variant this leg introduces (keyed off `request_digest` /
/// `entry_kind`, since request entries carry `transition_id = NULL` and the
/// `(conversation_id, transition_id)` atom cannot reach them), gated by the three
/// JOIN-ruling guards, then re-minted through the shared control-rehydration seam
/// and narrowed to the request arm via
/// [`PersistedControlAuthority::into_request`].
async fn load_control_request_origin(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
    entry_kind: &str,
    request_digest: &[u8],
    projection_signed_request_bytes: &[u8],
) -> Result<RequestEvidence, ResetLeaveHydrationError> {
    let rows: Vec<LocatedOriginEntry> = sqlx::query_as(
        r#"
        SELECT
            e.accepted_payload_bytes,
            e.signed_request_bytes,
            dk.signing_public_key
        FROM chat.entries e
        JOIN chat.device_keys dk
          ON dk.user_did = e.actor_did
         AND dk.device_id = e.actor_device_id
         AND dk.key_id = e.actor_key_id
        WHERE e.conversation_id = $1
          AND e.entry_kind = $2
          AND e.request_digest = $3
        "#,
    )
    .bind(conversation_id)
    .bind(entry_kind)
    .bind(request_digest)
    .fetch_all(&mut **transaction)
    .await?;

    let (public_row_json, raw_signed_wrapper, signing_public_key) =
        resolve_single_control_request_origin(rows, projection_signed_request_bytes)?;

    authority
        .hydrate_historical_control_from_durable_bytes(
            public_row_json,
            raw_signed_wrapper,
            &signing_public_key,
        )
        .and_then(PersistedControlAuthority::into_request)
        .map_err(|_| ResetLeaveHydrationError::InvalidOrigin)
}

/// Load a control terminal identified only by its durable request digest.
/// Unlike origin rows, the owning leave projection has no duplicate copy of the
/// signed bytes. Fetch every matching immutable entry and require exactly one
/// before full control-entry re-verification; never select a candidate.
async fn load_control_request_terminal_by_digest(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
    entry_kind: &str,
    request_digest: &[u8],
    expected_kind: RequestEntryKind,
) -> Result<RequestEvidence, ResetLeaveHydrationError> {
    let rows: Vec<LocatedOriginEntry> = sqlx::query_as(
        r#"
        SELECT
            e.accepted_payload_bytes,
            e.signed_request_bytes,
            dk.signing_public_key
        FROM chat.entries e
        JOIN chat.device_keys dk
          ON dk.user_did = e.actor_did
         AND dk.device_id = e.actor_device_id
         AND dk.key_id = e.actor_key_id
        WHERE e.conversation_id = $1
          AND e.entry_kind = $2
          AND e.request_digest = $3
        "#,
    )
    .bind(conversation_id)
    .bind(entry_kind)
    .bind(request_digest)
    .fetch_all(&mut **transaction)
    .await?;

    let (public_row_json, raw_signed_wrapper, signing_public_key) =
        resolve_single_terminal_candidate(rows).map_err(|error| match error {
            WorkTerminalHydrationError::Database(error) => {
                ResetLeaveHydrationError::Database(error)
            }
            _ => ResetLeaveHydrationError::InvalidTerminal,
        })?;
    let evidence = authority
        .hydrate_historical_control_from_durable_bytes(
            public_row_json,
            raw_signed_wrapper,
            &signing_public_key,
        )
        .and_then(PersistedControlAuthority::into_request)
        .map_err(|_| ResetLeaveHydrationError::InvalidTerminal)?;
    if evidence.kind() != expected_kind {
        return Err(ResetLeaveHydrationError::InvalidTerminal);
    }
    Ok(evidence)
}

/// Load the PENDING reset requests of an existing conversation, each bound to its
/// re-verified control-request origin. See the module header for the JOIN ruling
/// and the terminal-arm scope.
///
/// `authority` MUST be the read-time authority minted from the SAME locked head as
/// the rest of the aggregate.
#[allow(dead_code)]
pub(crate) async fn load_reset_request_hydration_rows(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
) -> Result<Vec<ResetRequestHydrationRow>, ResetLeaveHydrationError> {
    let conversation_bytes = *conversation_id.as_bytes();

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        String,
        Uuid,
        i64,
        i64,
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        String,
        Vec<u8>,
        Vec<u8>,
        DateTime<Utc>,
        DateTime<Utc>,
        Option<Uuid>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        r#"
        SELECT
            reset_request_id,
            requester_did,
            requester_device_id,
            prior_generation,
            prior_state_version,
            prior_group_id,
            prior_epoch,
            prior_group_context_hash,
            prior_confirmation_tag,
            status,
            request_digest,
            signed_request_bytes,
            received_at,
            expires_at,
            terminal_transition_id,
            terminal_at
        FROM chat.reset_requests
        WHERE conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;

    let mut requests: Vec<ResetRequestHydrationRow> = Vec::with_capacity(rows.len());
    for (
        reset_request_id,
        requester_did,
        requester_device_id,
        prior_generation,
        prior_state_version,
        prior_group_id,
        prior_epoch,
        prior_group_context_hash,
        prior_confirmation_tag,
        status,
        request_digest,
        signed_request_bytes,
        received_at,
        expires_at,
        terminal_transition_id,
        terminal_at,
    ) in rows
    {
        let request_id = *reset_request_id.as_bytes();
        let requester = reset_leave_device(requester_did, requester_device_id)?;
        let bound_coordinate = reset_leave_coordinate(
            conversation_bytes,
            prior_generation,
            prior_state_version,
            prior_group_id,
            prior_epoch,
            prior_group_context_hash,
            prior_confirmation_tag,
        )?;
        let selection = select_reset_terminal(ResetTerminalColumns {
            status: match status.as_str() {
                "pending" => "pending",
                "stale" => "stale",
                "consumed" => "consumed",
                "expired" => "expired",
                _ => return Err(ResetLeaveHydrationError::OutOfDomain),
            },
            terminal_transition_id,
            terminal_at,
            expires_at,
        })?;
        let status = match selection {
            ResetTerminalSelection::Pending => ResetRequestStatus::Pending,
            ResetTerminalSelection::StaleTransition { .. } => ResetRequestStatus::Stale,
            ResetTerminalSelection::ConsumedTransition { .. } => ResetRequestStatus::Consumed,
            ResetTerminalSelection::Expiry { .. } => ResetRequestStatus::Expired,
        };
        let origin = load_control_request_origin(
            transaction,
            authority,
            conversation_id,
            RESET_REQUEST_ENTRY_KIND,
            &request_digest,
            &signed_request_bytes,
        )
        .await?;

        let terminal = match selection {
            ResetTerminalSelection::Pending => None,
            ResetTerminalSelection::StaleTransition {
                transition_id,
                terminal_at,
            }
            | ResetTerminalSelection::ConsumedTransition {
                transition_id,
                terminal_at,
            } => {
                let terminal = load_work_terminal_hydration_row(
                    transaction,
                    authority,
                    conversation_id,
                    WorkTerminalLocator::Transition { transition_id },
                )
                .await
                .map_err(|error| match error {
                    WorkTerminalHydrationError::Database(error) => {
                        ResetLeaveHydrationError::Database(error)
                    }
                    _ => ResetLeaveHydrationError::InvalidTerminal,
                })?;
                let WorkTerminalHydrationRow::Transition(evidence) = &terminal else {
                    return Err(ResetLeaveHydrationError::InvalidTerminal);
                };
                require_terminal_timestamp(evidence.received_at(), terminal_at)?;
                Some(terminal)
            }
            ResetTerminalSelection::Expiry { terminal_at } => Some(
                load_work_terminal_hydration_row(
                    transaction,
                    authority,
                    conversation_id,
                    WorkTerminalLocator::Expiry { terminal_at },
                )
                .await
                .map_err(|error| match error {
                    WorkTerminalHydrationError::Database(error) => {
                        ResetLeaveHydrationError::Database(error)
                    }
                    _ => ResetLeaveHydrationError::InvalidTerminal,
                })?,
            ),
        };

        requests.push(ResetRequestHydrationRow {
            request_id,
            requester,
            bound_coordinate,
            received_at: reset_leave_timestamp(received_at)?,
            expires_at: reset_leave_timestamp(expires_at)?,
            status,
            origin,
            terminal,
        });
    }

    // `validate_reset_work` requires the collection strictly increasing by
    // `request_id`. Sort in Rust so the ordering is independent of the database's
    // `reset_request_id` collation.
    requests.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    Ok(requests)
}

/// Load the leave requests of an existing conversation, each bound to its
/// re-verified control-request origin and, when fulfilled, the exact removed
/// historical participant period. See the module header for the JOIN ruling and
/// terminal scope.
///
/// `authority` MUST be the read-time authority minted from the SAME locked head as
/// the rest of the aggregate.
#[allow(dead_code)]
pub(crate) async fn load_leave_request_hydration_rows(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
) -> Result<Vec<LeaveRequestHydrationRow>, ResetLeaveHydrationError> {
    let conversation_bytes = *conversation_id.as_bytes();

    let rows: Vec<DurableLeaveRequestHydrationRow> = sqlx::query_as(
        r#"
        SELECT
            leave_request_id,
            requester_did,
            requester_device_id,
            prior_generation,
            prior_state_version,
            prior_group_id,
            prior_epoch,
            prior_group_context_hash,
            prior_confirmation_tag,
            status,
            request_digest,
            signed_request_bytes,
            received_at,
            expires_at,
            terminal_request_digest,
            terminal_transition_id,
            terminal_at
        FROM chat.leave_requests
        WHERE conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;

    let mut requests: Vec<LeaveRequestHydrationRow> = Vec::with_capacity(rows.len());
    for DurableLeaveRequestHydrationRow {
        leave_request_id,
        requester_did,
        requester_device_id,
        prior_generation,
        prior_state_version,
        prior_group_id,
        prior_epoch,
        prior_group_context_hash,
        prior_confirmation_tag,
        status,
        request_digest,
        signed_request_bytes,
        received_at,
        expires_at,
        terminal_request_digest,
        terminal_transition_id,
        terminal_at,
    } in rows
    {
        let request_id = *leave_request_id.as_bytes();
        let requester_did_for_proof = requester_did.clone();
        let requester = reset_leave_device(requester_did, requester_device_id)?;
        let bound_coordinate = reset_leave_coordinate(
            conversation_bytes,
            prior_generation,
            prior_state_version,
            prior_group_id,
            prior_epoch,
            prior_group_context_hash,
            prior_confirmation_tag,
        )?;
        let selection = select_leave_terminal(LeaveTerminalColumns {
            status: match status.as_str() {
                "pending" => "pending",
                "fulfilled" => "fulfilled",
                "cancelled" => "cancelled",
                "expired" => "expired",
                "stale" => "stale",
                _ => return Err(ResetLeaveHydrationError::OutOfDomain),
            },
            terminal_request_digest: terminal_request_digest.as_deref(),
            terminal_transition_id,
            terminal_at,
            expires_at,
        })?;
        let fulfilled = status == "fulfilled";
        let status = match selection {
            LeaveTerminalSelection::Pending => LeaveRequestStatus::Pending,
            LeaveTerminalSelection::Transition { .. } if fulfilled => LeaveRequestStatus::Fulfilled,
            LeaveTerminalSelection::Transition { .. } => LeaveRequestStatus::Stale,
            LeaveTerminalSelection::Cancellation { .. } => LeaveRequestStatus::Cancelled,
            LeaveTerminalSelection::Expiry { .. } => LeaveRequestStatus::Expired,
        };
        let origin = load_control_request_origin(
            transaction,
            authority,
            conversation_id,
            LEAVE_REQUEST_ENTRY_KIND,
            &request_digest,
            &signed_request_bytes,
        )
        .await?;

        let (terminal, fulfilled_participant) = match selection {
            LeaveTerminalSelection::Pending => (None, None),
            LeaveTerminalSelection::Transition {
                terminal_request_digest,
                transition_id,
                terminal_at,
            } => {
                let terminal = load_work_terminal_hydration_row(
                    transaction,
                    authority,
                    conversation_id,
                    WorkTerminalLocator::Transition { transition_id },
                )
                .await
                .map_err(|error| match error {
                    WorkTerminalHydrationError::Database(error) => {
                        ResetLeaveHydrationError::Database(error)
                    }
                    _ => ResetLeaveHydrationError::InvalidTerminal,
                })?;
                let WorkTerminalHydrationRow::Transition(evidence) = &terminal else {
                    return Err(ResetLeaveHydrationError::InvalidTerminal);
                };
                require_terminal_timestamp(evidence.received_at(), terminal_at)?;
                if evidence
                    .signed_authority()
                    .is_none_or(|signed| signed.request_digest() != &terminal_request_digest)
                {
                    return Err(ResetLeaveHydrationError::InvalidTerminal);
                }
                let fulfilled_participant = if fulfilled {
                    let participant_rows: Vec<DurableParticipantHydrationRow> = sqlx::query_as(
                        r#"
                        SELECT
                            p.user_did,
                            p.status,
                            p.role,
                            p.role_transition_id,
                            p.invitation_transition_id,
                            p.created_by_did,
                            p.created_by_device_id,
                            p.acceptance_transition_id
                        FROM chat.participants p
                        WHERE p.conversation_id = $1
                          AND p.user_did = $2
                          AND NOT p.current_membership
                          AND p.status = 'active'
                          AND p.removing_transition_id = $3
                          AND p.removing_seq = $4
                          AND p.removed_at = $5
                        "#,
                    )
                    .bind(conversation_id)
                    .bind(&requester_did_for_proof)
                    .bind(transition_id)
                    .bind(
                        i64::try_from(evidence.seq())
                            .map_err(|_| ResetLeaveHydrationError::OutOfDomain)?,
                    )
                    .bind(terminal_at)
                    .fetch_all(&mut **transaction)
                    .await?;
                    let participant_row = resolve_single_fulfilled_participant(participant_rows)?;
                    let participant = hydrate_participant_row(
                        transaction,
                        authority,
                        conversation_id,
                        participant_row,
                    )
                    .await
                    .map_err(|error| match error {
                        ParticipantHydrationError::Database(error) => {
                            ResetLeaveHydrationError::Database(error)
                        }
                        ParticipantHydrationError::OutOfDomain => {
                            ResetLeaveHydrationError::OutOfDomain
                        }
                        ParticipantHydrationError::ProvenanceMissing
                        | ParticipantHydrationError::InvalidProvenance => {
                            ResetLeaveHydrationError::InvalidTerminal
                        }
                    })?;
                    Some(ParticipantRemovalEvidence::from_hydration(
                        participant,
                        evidence.clone(),
                    ))
                } else {
                    None
                };
                (Some(terminal), fulfilled_participant)
            }
            LeaveTerminalSelection::Cancellation {
                terminal_request_digest,
                terminal_at,
            } => {
                let evidence = load_control_request_terminal_by_digest(
                    transaction,
                    authority,
                    conversation_id,
                    "blue.catbird.chat.defs#leaveCancellationEntry",
                    &terminal_request_digest,
                    RequestEntryKind::LeaveCancellation,
                )
                .await?;
                let terminal_at = reset_leave_timestamp(terminal_at)?;
                if evidence.received_at() != terminal_at
                    || evidence
                        .signed_authority()
                        .is_none_or(|signed| signed.request_digest() != &terminal_request_digest)
                {
                    return Err(ResetLeaveHydrationError::InvalidTerminal);
                }
                (Some(WorkTerminalHydrationRow::Request(evidence)), None)
            }
            LeaveTerminalSelection::Expiry { terminal_at } => (
                Some(
                    load_work_terminal_hydration_row(
                        transaction,
                        authority,
                        conversation_id,
                        WorkTerminalLocator::Expiry { terminal_at },
                    )
                    .await
                    .map_err(|error| match error {
                        WorkTerminalHydrationError::Database(error) => {
                            ResetLeaveHydrationError::Database(error)
                        }
                        _ => ResetLeaveHydrationError::InvalidTerminal,
                    })?,
                ),
                None,
            ),
        };

        requests.push(LeaveRequestHydrationRow {
            request_id,
            requester,
            bound_coordinate,
            received_at: reset_leave_timestamp(received_at)?,
            expires_at: reset_leave_timestamp(expires_at)?,
            status,
            origin,
            terminal,
            fulfilled_participant,
        });
    }

    // `validate_leave_work` requires the collection strictly increasing by
    // `(requester, request_id)`. Sort in Rust so the ordering is independent of the
    // database's `requester_did` collation.
    requests.sort_by(|left, right| {
        left.requester
            .cmp(&right.requester)
            .then_with(|| left.request_id.cmp(&right.request_id))
    });
    Ok(requests)
}

fn reset_leave_device(
    did: String,
    device_id: Uuid,
) -> Result<DeviceIdentity, ResetLeaveHydrationError> {
    let principal =
        PrincipalId::new(did.into_bytes()).map_err(|_| ResetLeaveHydrationError::OutOfDomain)?;
    DeviceIdentity::new(principal, *device_id.as_bytes())
        .map_err(|_| ResetLeaveHydrationError::OutOfDomain)
}

/// Reconstruct a pending request's `bound_coordinate` from its `prior_*` columns.
/// A pending reset/leave request binds the CURRENT active head (validated by
/// `validate_reset_work` / `validate_leave_work` as `bound_coordinate ==
/// state.coordinate`), so the reconstructed lifecycle is `Active`.
#[allow(clippy::too_many_arguments)]
fn reset_leave_coordinate(
    conversation_id: [u8; 16],
    generation: i64,
    state_version: i64,
    group_id: Vec<u8>,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
) -> Result<PublicGroupSnapshotCoordinate, ResetLeaveHydrationError> {
    Ok(PublicGroupSnapshotCoordinate::new(
        conversation_id,
        reset_leave_u64(generation)?,
        reset_leave_u64(state_version)?,
        reset_leave_bytes32(group_id)?,
        reset_leave_u64(epoch)?,
        reset_leave_bytes32(group_context_hash)?,
        reset_leave_bytes32(confirmation_tag)?,
        PublicGroupSnapshotLifecycle::Active,
    ))
}

fn reset_leave_u64(value: i64) -> Result<u64, ResetLeaveHydrationError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(ResetLeaveHydrationError::OutOfDomain)
}

fn reset_leave_bytes32(value: Vec<u8>) -> Result<[u8; 32], ResetLeaveHydrationError> {
    <[u8; 32]>::try_from(value.as_slice()).map_err(|_| ResetLeaveHydrationError::OutOfDomain)
}

fn reset_leave_timestamp(
    value: DateTime<Utc>,
) -> Result<ServerTimestamp, ResetLeaveHydrationError> {
    ServerTimestamp::from_canonical_stored(&canonical_millis(value))
        .map_err(|_| ResetLeaveHydrationError::OutOfDomain)
}

pub(crate) fn require_terminal_timestamp(
    evidence_received_at: ServerTimestamp,
    terminal_at: DateTime<Utc>,
) -> Result<(), ResetLeaveHydrationError> {
    if evidence_received_at == reset_leave_timestamp(terminal_at)? {
        Ok(())
    } else {
        Err(ResetLeaveHydrationError::InvalidTerminal)
    }
}

// ===========================================================================
// T4-H2-pre terminal-family sub-seal E — immutable scheduleTerminal proofs.
//
// A proof row is only a locator. Its authority comes from reloading the exact
// referenced historical control entry through the sealed verifier and then
// matching every duplicated durable field byte-for-byte. No current-head or
// timestamp search may substitute another close transition.
// ===========================================================================

#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum TerminalProofHydrationError {
    #[error("clean-chat schedule terminal proof column is out of domain")]
    OutOfDomain,
    #[error("clean-chat schedule terminal proof transition is absent")]
    EvidenceMissing,
    #[error("clean-chat schedule terminal proof transition failed re-verification")]
    InvalidEvidence,
    #[error("clean-chat schedule terminal proof does not match its verified transition")]
    BindingMismatch,
    #[error("clean-chat schedule terminal proof hydration database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl From<ControlEvidenceLoadError> for TerminalProofHydrationError {
    fn from(error: ControlEvidenceLoadError) -> Self {
        match error {
            ControlEvidenceLoadError::EntryMissing => TerminalProofHydrationError::EvidenceMissing,
            ControlEvidenceLoadError::InvalidEvidence => {
                TerminalProofHydrationError::InvalidEvidence
            }
            ControlEvidenceLoadError::Database(error) => {
                TerminalProofHydrationError::Database(error)
            }
        }
    }
}

#[derive(sqlx::FromRow)]
struct DurableTerminalProofHydrationRow {
    conversation_id: Uuid,
    recipient_did: String,
    recipient_device_id: Uuid,
    terminal_seq: i64,
    transition_id: Uuid,
    outer_entry_fingerprint: Vec<u8>,
    received_at: DateTime<Utc>,
}

pub(crate) fn terminal_proof_timestamp(
    value: DateTime<Utc>,
) -> Result<ServerTimestamp, TerminalProofHydrationError> {
    if value.timestamp_millis() < 0 || !value.timestamp_subsec_nanos().is_multiple_of(1_000_000) {
        return Err(TerminalProofHydrationError::OutOfDomain);
    }
    ServerTimestamp::from_canonical_stored(&canonical_millis(value))
        .map_err(|_| TerminalProofHydrationError::OutOfDomain)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn match_terminal_proof_evidence(
    expected_conversation_id: [u8; 16],
    proof_conversation_id: [u8; 16],
    terminal_seq: u64,
    transition_id: [u8; 16],
    outer_entry_fingerprint: [u8; 32],
    received_at: ServerTimestamp,
    authority: PersistedControlAuthority,
) -> Result<TransitionEvidence, TerminalProofHydrationError> {
    if !uuid_is_canonical_v4(Uuid::from_bytes(expected_conversation_id))
        || !uuid_is_canonical_v4(Uuid::from_bytes(proof_conversation_id))
        || !uuid_is_canonical_v4(Uuid::from_bytes(transition_id))
        || terminal_seq == 0
        || terminal_seq > MAX_PROTOCOL_INTEGER
        || outer_entry_fingerprint == [0; 32]
    {
        return Err(TerminalProofHydrationError::OutOfDomain);
    }
    let evidence = authority
        .into_transition()
        .map_err(|_| TerminalProofHydrationError::InvalidEvidence)?;
    let signed = evidence
        .signed_authority()
        .ok_or(TerminalProofHydrationError::InvalidEvidence)?;
    if signed.kind() != SignedMutationKind::ConversationClose
        || signed.control_conversation_id() != Some(&expected_conversation_id)
    {
        return Err(TerminalProofHydrationError::InvalidEvidence);
    }
    if proof_conversation_id != expected_conversation_id
        || evidence.seq() != terminal_seq
        || evidence.transition_id() != &transition_id
        || evidence.outer_entry_fingerprint() != &outer_entry_fingerprint
        || evidence.received_at() != received_at
    {
        return Err(TerminalProofHydrationError::BindingMismatch);
    }
    Ok(evidence)
}

async fn hydrate_terminal_proof_row(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    expected_conversation_id: Uuid,
    row: DurableTerminalProofHydrationRow,
) -> Result<TerminalProofHydrationRow, TerminalProofHydrationError> {
    if row.conversation_id != expected_conversation_id
        || !uuid_is_canonical_v4(row.conversation_id)
        || !uuid_is_canonical_v4(row.transition_id)
    {
        return Err(TerminalProofHydrationError::OutOfDomain);
    }
    let terminal_seq = u64::try_from(row.terminal_seq)
        .ok()
        .filter(|value| (1..=MAX_PROTOCOL_INTEGER).contains(value))
        .ok_or(TerminalProofHydrationError::OutOfDomain)?;
    let outer_entry_fingerprint: [u8; 32] = row
        .outer_entry_fingerprint
        .as_slice()
        .try_into()
        .map_err(|_| TerminalProofHydrationError::OutOfDomain)?;
    let received_at = terminal_proof_timestamp(row.received_at)?;
    let recipient = DeviceIdentity::new(
        PrincipalId::new(row.recipient_did.into_bytes())
            .map_err(|_| TerminalProofHydrationError::OutOfDomain)?,
        *row.recipient_device_id.as_bytes(),
    )
    .map_err(|_| TerminalProofHydrationError::OutOfDomain)?;

    let authority = load_historical_control_evidence(
        transaction,
        authority,
        expected_conversation_id,
        row.transition_id,
    )
    .await?;
    let evidence = match_terminal_proof_evidence(
        *expected_conversation_id.as_bytes(),
        *row.conversation_id.as_bytes(),
        terminal_seq,
        *row.transition_id.as_bytes(),
        outer_entry_fingerprint,
        received_at,
        authority,
    )?;

    Ok(TerminalProofHydrationRow {
        recipient,
        conversation_id: *expected_conversation_id.as_bytes(),
        evidence,
    })
}

/// Rehydrate all immutable scheduleTerminal rows for a locked conversation.
///
/// Every row reloads only its directly referenced transition. The returned
/// collection is sorted by protocol `DeviceIdentity` bytes, not PostgreSQL text
/// collation, and duplicate device identities fail closed.
pub(crate) fn canonicalize_terminal_proof_hydration_rows(
    mut rows: Vec<TerminalProofHydrationRow>,
) -> Result<Vec<TerminalProofHydrationRow>, TerminalProofHydrationError> {
    rows.sort_by(|left, right| left.recipient.cmp(&right.recipient));
    if rows
        .windows(2)
        .any(|pair| pair[0].recipient == pair[1].recipient)
    {
        return Err(TerminalProofHydrationError::BindingMismatch);
    }
    Ok(rows)
}

#[allow(dead_code)]
pub(crate) async fn load_terminal_proof_hydration_rows(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &HistoricalRehydrationAuthority,
    conversation_id: Uuid,
) -> Result<Vec<TerminalProofHydrationRow>, TerminalProofHydrationError> {
    let durable_rows: Vec<DurableTerminalProofHydrationRow> = sqlx::query_as(
        r#"
        SELECT conversation_id, recipient_did, recipient_device_id, terminal_seq,
               transition_id, outer_entry_fingerprint, received_at
          FROM chat.application_schedule_terminal_proofs
         WHERE conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;

    let mut rows = Vec::with_capacity(durable_rows.len());
    for row in durable_rows {
        rows.push(hydrate_terminal_proof_row(transaction, authority, conversation_id, row).await?);
    }
    canonicalize_terminal_proof_hydration_rows(rows)
}

// ===========================================================================
// T4-H2-pre G1 — locked active or terminal conversation aggregate.
//
// Every leg below is read while the caller owns the conversation-row lock
// acquired by `hydrate_locked_conversation_head`. Historical evidence is
// reverified from durable entry bytes; no cached state or test authority enters
// the production path. Closed/superseded state is deliberately unsupported
// Terminal heads deliberately skip active public-state material and instead
// require the exact immutable scheduleTerminal proof set below.
// ===========================================================================

#[derive(Debug, Error)]
pub(crate) enum ConversationStateHydrationError {
    #[error("clean-chat aggregate head hydration failed: {0}")]
    Head(ConversationHeadHydrationError),
    #[error("clean-chat aggregate public-state hydration failed: {0}")]
    PublicState(PublicStateHydrationError),
    #[error("clean-chat aggregate producer hydration failed: {0}")]
    Producer(ProducerHydrationError),
    #[error("clean-chat aggregate metadata hydration failed: {0}")]
    Metadata(MetadataHydrationError),
    #[error("clean-chat aggregate participant hydration failed: {0}")]
    Participants(ParticipantHydrationError),
    #[error("clean-chat aggregate leaf hydration failed: {0}")]
    Leaves(LeafHydrationError),
    #[error("clean-chat aggregate interval hydration failed: {0}")]
    Intervals(IntervalHydrationError),
    #[error("clean-chat aggregate recovery-work hydration failed: {0}")]
    RecoveryWork(RecoveryHydrationError),
    #[error("clean-chat aggregate reset-work hydration failed: {0}")]
    ResetWork(ResetLeaveHydrationError),
    #[error("clean-chat aggregate leave-work hydration failed: {0}")]
    LeaveWork(ResetLeaveHydrationError),
    #[error("clean-chat aggregate Welcome hydration failed: {0}")]
    Welcomes(WelcomeHydrationError),
    #[error("clean-chat aggregate terminal-proof hydration failed: {0}")]
    TerminalProofs(TerminalProofHydrationError),
    #[error("clean-chat aggregate authority construction failed: {0}")]
    Authority(StateMachineError),
    #[error("clean-chat aggregate state validation failed: {0}")]
    State(StateMachineError),
    #[error("clean-chat aggregate snapshot decode failed: {0}")]
    Snapshot(super::super::public_state::PublicStateError),
    #[error("clean-chat aggregate read-set does not match the locked head")]
    ReadSetMismatch,
    #[error("clean-chat catalog and head lifecycle disagree")]
    TerminalLifecycleUnsupported,
    #[error("clean-chat conversation kind or lifecycle is out of domain")]
    ConversationDomain,
    #[error("clean-chat active aggregate unexpectedly contains schedule terminal proofs")]
    UnexpectedTerminalProof,
    #[error("clean-chat terminal aggregate retains an active leaf")]
    TerminalLeafPresent,
    #[error("clean-chat aggregate graph digest is invalid")]
    GraphDigest,
    #[error("clean-chat aggregate could not be sealed")]
    Seal,
    #[error("clean-chat aggregate database error: {0}")]
    Database(#[from] sqlx::Error),
}

fn historical_authority_for_locked_head(
    head: &LockedConversationHeadGuard,
) -> Result<HistoricalRehydrationAuthority, StateMachineError> {
    HistoricalRehydrationAuthority::from_locked_head(head)
}

fn hydration_authority_for_locked_head(
    head: &LockedConversationHeadGuard,
) -> Result<HydrationAuthority, StateMachineError> {
    HydrationAuthority::from_locked_existing_head(head)
}

fn graph_digest_frame(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn graph_digest_option<T: ?Sized>(
    digest: &mut Sha256,
    value: Option<&T>,
    encode: impl FnOnce(&mut Sha256, &T),
) {
    match value {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            encode(digest, value);
        }
    }
}

fn graph_digest_coordinate(digest: &mut Sha256, value: &PublicGroupSnapshotCoordinate) {
    digest.update(value.conversation_id());
    digest.update(value.generation().to_be_bytes());
    digest.update(value.state_version().to_be_bytes());
    digest.update(value.group_id());
    digest.update(value.epoch().to_be_bytes());
    digest.update(value.group_context_hash());
    digest.update(value.confirmation_tag());
    digest.update([match value.lifecycle() {
        PublicGroupSnapshotLifecycle::Active => 1,
        PublicGroupSnapshotLifecycle::Superseded => 2,
    }]);
}

fn graph_digest_device(digest: &mut Sha256, value: &DeviceIdentity) {
    graph_digest_frame(digest, value.principal().as_bytes());
    digest.update(value.device_id());
}

fn graph_digest_transition(digest: &mut Sha256, value: &TransitionEvidence) {
    digest.update(value.seq().to_be_bytes());
    digest.update(value.transition_id());
    digest.update(value.outer_entry_fingerprint());
    graph_digest_frame(digest, value.outer_control_projection());
    graph_digest_frame(digest, value.server_fields_dag_cbor());
    digest.update(value.durable_row_digest());
    digest.update(value.received_at().unix_millis().to_be_bytes());
}

fn graph_digest_request(digest: &mut Sha256, value: &RequestEvidence) {
    digest.update([match value.kind() {
        RequestEntryKind::LeafRecoveryRequest => 1,
        RequestEntryKind::LeafRecoveryCancellation => 2,
        RequestEntryKind::ResetRequest => 3,
        RequestEntryKind::LeaveRequest => 4,
        RequestEntryKind::LeaveCancellation => 5,
        RequestEntryKind::WelcomeAcknowledgement => 6,
        RequestEntryKind::WelcomeRejection => 7,
    }]);
    graph_digest_option(digest, value.control_entry_id(), |digest, id| {
        digest.update(id);
    });
    digest.update(value.conversation_id());
    graph_digest_option(digest, value.control_seq().as_ref(), |digest, seq| {
        digest.update(seq.to_be_bytes());
    });
    graph_digest_option(
        digest,
        value.control_outer_entry_fingerprint(),
        |digest, fingerprint| digest.update(fingerprint),
    );
    graph_digest_option(digest, value.control_outer_projection(), graph_digest_frame);
    graph_digest_option(
        digest,
        value.control_server_fields_dag_cbor(),
        graph_digest_frame,
    );
    digest.update(value.request_id());
    graph_digest_device(digest, value.actor());
    digest.update(value.received_at().unix_millis().to_be_bytes());
    digest.update(value.durable_row_digest());
}

fn graph_digest_device_revocation(
    digest: &mut Sha256,
    value: &super::super::state_machine::DeviceRevocationEvidence,
) {
    digest.update(value.revocation_id());
    graph_digest_device(digest, value.actor());
    graph_digest_device(digest, value.target());
    digest.update(value.actor_key_id());
    digest.update(value.actor_auth_generation().to_be_bytes());
    digest.update(value.expected_target_auth_generation().to_be_bytes());
    digest.update(value.signed_at().unix_millis().to_be_bytes());
    digest.update(value.accepted_at().unix_millis().to_be_bytes());
    digest.update(value.request_digest());
    graph_digest_frame(digest, value.signature());
    graph_digest_frame(digest, value.signed_request_bytes());
    graph_digest_frame(digest, value.signing_transcript_bytes());
    digest.update(value.durable_row_digest());
}

fn graph_digest_terminal(digest: &mut Sha256, value: &WorkTerminalHydrationRow) {
    match value {
        WorkTerminalHydrationRow::Transition(value) => {
            digest.update([1]);
            graph_digest_transition(digest, value);
        }
        WorkTerminalHydrationRow::Request(value) => {
            digest.update([2]);
            graph_digest_request(digest, value);
        }
        WorkTerminalHydrationRow::DeviceRevocation(value) => {
            digest.update([3]);
            graph_digest_device_revocation(digest, value);
        }
        WorkTerminalHydrationRow::Expiry(value) => {
            digest.update([4]);
            digest.update(value.unix_millis().to_be_bytes());
        }
    }
}

fn graph_digest_metadata(digest: &mut Sha256, value: &MetadataSnapshotBinding) {
    digest.update(value.coordinate_conversation_id());
    digest.update(value.coordinate_generation().to_be_bytes());
    digest.update(value.coordinate_epoch().to_be_bytes());
    digest.update(value.coordinate_group_context_hash());
    digest.update(value.origin_transition_id());
    digest.update(value.metadata_version().to_be_bytes());
    digest.update(value.nonce());
    graph_digest_frame(digest, value.ciphertext());
    digest.update(value.ciphertext_sha256());
    graph_digest_option(digest, value.avatar_binding_digest(), |digest, value| {
        digest.update(value)
    });
    graph_digest_device(digest, value.author());
    digest.update(value.author_key_id());
    digest.update(value.signature_public_key());
    digest.update(value.author_auth_generation_at_origin().to_be_bytes());
    digest.update(value.author_origin_transition_id());
    digest.update(value.author_origin_seq().to_be_bytes());
    graph_digest_frame(digest, value.canonical_snapshot());
    digest.update(value.digest());
}

fn graph_digest_public_state(
    digest: &mut Sha256,
    value: &super::super::public_state::ActivePublicState,
) {
    graph_digest_coordinate(digest, value.coordinate());
    graph_digest_frame(digest, value.snapshot());
    digest.update(value.snapshot_sha256());
    let tree = value.binding().tree_summary();
    digest.update(tree.tree_hash());
    digest.update((tree.leaves().len() as u64).to_be_bytes());
    for leaf in tree.leaves() {
        digest.update(leaf.leaf_index().to_be_bytes());
        graph_digest_frame(digest, leaf.basic_credential());
        graph_digest_frame(digest, leaf.signature_key());
        graph_digest_frame(digest, leaf.encryption_key());
    }
}

fn graph_digest_participant(digest: &mut Sha256, value: &ParticipantHydrationRow) {
    graph_digest_frame(digest, value.principal.as_bytes());
    digest.update([match value.status {
        ParticipantStatus::Pending => 1,
        ParticipantStatus::Active => 2,
    }]);
    digest.update([match value.role {
        ParticipantRole::Member => 1,
        ParticipantRole::Admin => 2,
    }]);
    graph_digest_option(
        digest,
        value.role_producer.as_ref(),
        graph_digest_transition,
    );
    graph_digest_option(digest, value.invitation.as_ref(), |digest, invitation| {
        graph_digest_transition(digest, &invitation.transition);
        graph_digest_device(digest, &invitation.inviter);
    });
    graph_digest_option(digest, value.acceptance.as_ref(), graph_digest_transition);
}

fn graph_digest_participant_removal(
    digest: &mut Sha256,
    value: &super::super::state_machine::ParticipantRemovalEvidence,
) {
    graph_digest_participant(digest, &value.participant_hydration());
    graph_digest_transition(digest, value.terminal());
}

#[cfg(test)]
pub(crate) fn participant_removal_graph_digest_for_test(
    value: &super::super::state_machine::ParticipantRemovalEvidence,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-PARTICIPANT-REMOVAL-EVIDENCE\0");
    graph_digest_participant_removal(&mut digest, value);
    digest.finalize().into()
}

fn graph_digest_leaf(digest: &mut Sha256, value: &LeafHydrationRow) {
    graph_digest_device(digest, &value.device);
    digest.update(value.leaf_index.to_be_bytes());
    graph_digest_frame(digest, &value.basic_credential);
    graph_digest_frame(digest, &value.signature_key);
    graph_digest_frame(digest, &value.encryption_key);
    graph_digest_option(digest, value.key_package_ref.as_ref(), |digest, value| {
        digest.update(value);
    });
}

fn graph_digest_interval(digest: &mut Sha256, value: &IntervalHydrationRow) {
    graph_digest_device(digest, &value.recipient);
    digest.update(value.generation.to_be_bytes());
    graph_digest_transition(digest, &value.opening);
    digest.update([match value.opening_kind {
        OpeningKind::Creation => 1,
        OpeningKind::Add => 2,
        OpeningKind::Reset => 3,
    }]);
    graph_digest_coordinate(digest, &value.opening_context);
    graph_digest_option(digest, value.end.as_ref(), |digest, end| {
        graph_digest_transition(digest, &end.evidence);
        digest.update([match end.kind {
            CloseKind::Remove => 1,
            CloseKind::Replace => 2,
            CloseKind::Reset => 3,
            CloseKind::Terminal => 4,
        }]);
    });
}

fn graph_digest_recovery_request(digest: &mut Sha256, value: &RecoveryRequestHydrationRow) {
    digest.update(value.request_id);
    graph_digest_device(digest, &value.target);
    digest.update([match value.kind {
        LeafRecoveryKind::Add => 1,
        LeafRecoveryKind::Replace => 2,
    }]);
    digest.update([match value.source {
        RecoverySource::Request => 1,
        RecoverySource::Acceptance => 2,
    }]);
    graph_digest_coordinate(digest, &value.bound_coordinate);
    digest.update(value.key_package_ref);
    digest.update(value.received_at.unix_millis().to_be_bytes());
    digest.update(value.expires_at.unix_millis().to_be_bytes());
    digest.update([match value.status {
        RecoveryRequestStatus::Open => 1,
        RecoveryRequestStatus::Fulfilled => 2,
        RecoveryRequestStatus::Cancelled => 3,
        RecoveryRequestStatus::Expired => 4,
        RecoveryRequestStatus::Superseded => 5,
    }]);
    match &value.origin {
        RecoveryOriginHydrationRow::Acceptance(value) => {
            digest.update([1]);
            graph_digest_transition(digest, value);
        }
        RecoveryOriginHydrationRow::Request(value) => {
            digest.update([2]);
            graph_digest_request(digest, value);
        }
    }
    graph_digest_option(digest, value.terminal.as_ref(), graph_digest_terminal);
}

fn graph_digest_recovery_reservation(digest: &mut Sha256, value: &RecoveryReservationHydrationRow) {
    digest.update(value.request_id);
    graph_digest_device(digest, &value.target);
    graph_digest_coordinate(digest, &value.bound_coordinate);
    digest.update(value.key_package_ref);
    digest.update(value.received_at.unix_millis().to_be_bytes());
    digest.update(value.expires_at.unix_millis().to_be_bytes());
    digest.update(value.package_not_after.unix_millis().to_be_bytes());
    digest.update([match value.status {
        ReservationStatus::Active => 1,
        ReservationStatus::Consumed => 2,
        ReservationStatus::Expired => 3,
        ReservationStatus::Released => 4,
    }]);
    graph_digest_option(digest, value.terminal.as_ref(), graph_digest_terminal);
}

fn graph_digest_reset(digest: &mut Sha256, value: &ResetRequestHydrationRow) {
    digest.update(value.request_id);
    graph_digest_device(digest, &value.requester);
    graph_digest_coordinate(digest, &value.bound_coordinate);
    digest.update(value.received_at.unix_millis().to_be_bytes());
    digest.update(value.expires_at.unix_millis().to_be_bytes());
    digest.update([match value.status {
        ResetRequestStatus::Pending => 1,
        ResetRequestStatus::Stale => 2,
        ResetRequestStatus::Consumed => 3,
        ResetRequestStatus::Expired => 4,
    }]);
    graph_digest_request(digest, &value.origin);
    graph_digest_option(digest, value.terminal.as_ref(), graph_digest_terminal);
}

fn graph_digest_leave(digest: &mut Sha256, value: &LeaveRequestHydrationRow) {
    digest.update(value.request_id);
    graph_digest_device(digest, &value.requester);
    graph_digest_coordinate(digest, &value.bound_coordinate);
    digest.update(value.received_at.unix_millis().to_be_bytes());
    digest.update(value.expires_at.unix_millis().to_be_bytes());
    digest.update([match value.status {
        LeaveRequestStatus::Pending => 1,
        LeaveRequestStatus::Fulfilled => 2,
        LeaveRequestStatus::Cancelled => 3,
        LeaveRequestStatus::Expired => 4,
        LeaveRequestStatus::Stale => 5,
    }]);
    graph_digest_request(digest, &value.origin);
    graph_digest_option(digest, value.terminal.as_ref(), graph_digest_terminal);
    graph_digest_option(
        digest,
        value.fulfilled_participant.as_ref(),
        graph_digest_participant_removal,
    );
}

fn graph_digest_welcome(digest: &mut Sha256, value: &WelcomeHydrationRow) {
    digest.update(value.welcome_id);
    graph_digest_device(digest, &value.recipient);
    digest.update(value.transition_seq.to_be_bytes());
    graph_digest_coordinate(digest, &value.coordinate);
    digest.update(value.recovery_request_id);
    digest.update(value.key_package_ref);
    graph_digest_frame(digest, &value.opaque_welcome);
    digest.update(value.sha256);
    digest.update(value.expires_at.unix_millis().to_be_bytes());
    digest.update([match value.status {
        WelcomeStatus::Pending => 1,
        WelcomeStatus::Acknowledged => 2,
        WelcomeStatus::Rejected => 3,
        WelcomeStatus::Expired => 4,
        WelcomeStatus::Superseded => 5,
    }]);
    graph_digest_option(digest, value.terminal.as_ref(), graph_digest_terminal);
}

fn graph_digest_terminal_proof(digest: &mut Sha256, value: &TerminalProofHydrationRow) {
    graph_digest_device(digest, &value.recipient);
    digest.update(value.conversation_id);
    graph_digest_transition(digest, &value.evidence);
}

fn conversation_graph_digest(
    head: &LockedConversationHeadGuard,
    snapshot_digest: Option<&[u8; 32]>,
    rows: &ConversationStateHydration,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(match snapshot_digest {
        Some(_) => b"CATBIRD-CHAT-ACTIVE-CONVERSATION-GRAPH\0".as_slice(),
        None => b"CATBIRD-CHAT-TERMINAL-CONVERSATION-GRAPH\0".as_slice(),
    });
    digest.update(head.conversation_id().as_bytes());
    graph_digest_option(
        &mut digest,
        head.prior_coordinate(),
        graph_digest_coordinate,
    );
    digest.update(head.next_entry_seq().to_be_bytes());
    graph_digest_option(&mut digest, snapshot_digest, |digest, value| {
        digest.update(value)
    });
    digest.update([match rows.kind {
        ConversationKind::Direct => 1,
        ConversationKind::Group => 2,
    }]);
    graph_digest_coordinate(&mut digest, &rows.coordinate);
    graph_digest_transition(&mut digest, &rows.producer);
    graph_digest_option(
        &mut digest,
        rows.public_state.as_ref(),
        graph_digest_public_state,
    );
    graph_digest_option(&mut digest, rows.metadata.as_ref(), graph_digest_metadata);
    graph_digest_option(
        &mut digest,
        rows.metadata_producer.as_ref(),
        graph_digest_transition,
    );

    digest.update((rows.participants.len() as u64).to_be_bytes());
    for value in &rows.participants {
        graph_digest_participant(&mut digest, value);
    }
    digest.update((rows.leaves.len() as u64).to_be_bytes());
    for value in &rows.leaves {
        graph_digest_leaf(&mut digest, value);
    }
    digest.update((rows.intervals.len() as u64).to_be_bytes());
    for value in &rows.intervals {
        graph_digest_interval(&mut digest, value);
    }
    digest.update((rows.terminal_proofs.len() as u64).to_be_bytes());
    for value in &rows.terminal_proofs {
        graph_digest_terminal_proof(&mut digest, value);
    }
    digest.update((rows.recovery_requests.len() as u64).to_be_bytes());
    for value in &rows.recovery_requests {
        graph_digest_recovery_request(&mut digest, value);
    }
    digest.update((rows.recovery_reservations.len() as u64).to_be_bytes());
    for value in &rows.recovery_reservations {
        graph_digest_recovery_reservation(&mut digest, value);
    }
    digest.update((rows.reset_requests.len() as u64).to_be_bytes());
    for value in &rows.reset_requests {
        graph_digest_reset(&mut digest, value);
    }
    digest.update((rows.leave_requests.len() as u64).to_be_bytes());
    for value in &rows.leave_requests {
        graph_digest_leave(&mut digest, value);
    }
    digest.update((rows.welcomes.len() as u64).to_be_bytes());
    for value in &rows.welcomes {
        graph_digest_welcome(&mut digest, value);
    }
    digest.finalize().into()
}

#[cfg(test)]
pub(crate) fn active_conversation_graph_digest_for_test(
    head: &LockedConversationHeadGuard,
    snapshot_digest: &[u8; 32],
    rows: &ConversationStateHydration,
) -> [u8; 32] {
    conversation_graph_digest(head, Some(snapshot_digest), rows)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConversationHydrationLifecycle {
    Active,
    Terminal,
}

pub(crate) fn resolve_conversation_hydration_kind(
    head_lifecycle: PublicGroupSnapshotLifecycle,
    stored_kind: &str,
    stored_lifecycle: &str,
) -> Result<(ConversationKind, ConversationHydrationLifecycle), ConversationStateHydrationError> {
    let lifecycle = match (head_lifecycle, stored_lifecycle) {
        (PublicGroupSnapshotLifecycle::Active, "active") => ConversationHydrationLifecycle::Active,
        (PublicGroupSnapshotLifecycle::Superseded, "superseded") => {
            ConversationHydrationLifecycle::Terminal
        }
        _ => return Err(ConversationStateHydrationError::TerminalLifecycleUnsupported),
    };
    let kind = match stored_kind {
        "direct" => ConversationKind::Direct,
        "group" => ConversationKind::Group,
        _ => return Err(ConversationStateHydrationError::ConversationDomain),
    };
    Ok((kind, lifecycle))
}

pub(crate) fn certify_no_terminal_proofs(
    terminal_proof_count: i64,
) -> Result<
    Vec<super::super::state_machine::TerminalProofHydrationRow>,
    ConversationStateHydrationError,
> {
    if terminal_proof_count != 0 {
        return Err(ConversationStateHydrationError::UnexpectedTerminalProof);
    }
    Ok(Vec::new())
}

/// Hydrate, validate, and seal one active or terminal conversation graph under
/// the caller's transaction-local conversation-row lock.
///
/// The returned guard remains valid only while `transaction` remains open. This
/// function never begins, commits, or rolls back a transaction.
#[allow(dead_code)]
pub(crate) async fn hydrate_locked_conversation_state(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    locked_at: DateTime<Utc>,
) -> Result<LockedConversationStateGuard, ConversationStateHydrationError> {
    let head = hydrate_locked_conversation_head(transaction, conversation_id, locked_at)
        .await
        .map_err(ConversationStateHydrationError::Head)?;
    let Some(head_coordinate) = head.prior_coordinate() else {
        return Err(ConversationStateHydrationError::ReadSetMismatch);
    };

    let kind_and_lifecycle: Option<(String, String)> =
        sqlx::query_as("SELECT kind,lifecycle FROM chat.conversations WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_optional(&mut **transaction)
            .await?;
    let (kind, lifecycle) =
        kind_and_lifecycle.ok_or(ConversationStateHydrationError::ReadSetMismatch)?;
    let (kind, aggregate_lifecycle) =
        resolve_conversation_hydration_kind(head_coordinate.lifecycle(), &kind, &lifecycle)?;

    let (public_state, snapshot_digest) = match aggregate_lifecycle {
        ConversationHydrationLifecycle::Active => {
            let public_guard = hydrate_public_state_under_locked_head(transaction, &head)
                .await
                .map_err(ConversationStateHydrationError::PublicState)?;
            let (
                public_transaction_id,
                public_conversation_id,
                coordinate,
                snapshot,
                binding,
                encoded_tree_summary,
                expected_tree_summary_sha256,
                public_locked_at,
                generation_row_digest,
            ) = public_guard.into_parts();
            if public_transaction_id != head.transaction_id()
                || public_conversation_id != head.conversation_id()
                || &coordinate != head_coordinate
                || public_locked_at != head.locked_at()
            {
                return Err(ConversationStateHydrationError::ReadSetMismatch);
            }
            let snapshot_digest = *binding.snapshot_sha256();
            let public_guard = seal_locked_public_state_hydration(
                public_transaction_id,
                public_conversation_id,
                coordinate,
                snapshot,
                binding,
                encoded_tree_summary,
                expected_tree_summary_sha256,
                public_locked_at,
                generation_row_digest,
            )
            .ok_or(ConversationStateHydrationError::ReadSetMismatch)?;
            let public_state =
                super::super::public_state::load_persisted_active_snapshot(public_guard)
                    .map_err(ConversationStateHydrationError::Snapshot)?;
            (Some(public_state), Some(snapshot_digest))
        }
        ConversationHydrationLifecycle::Terminal => (None, None),
    };

    let historical = historical_authority_for_locked_head(&head)
        .map_err(ConversationStateHydrationError::Authority)?;
    let hydration = hydration_authority_for_locked_head(&head)
        .map_err(ConversationStateHydrationError::Authority)?;
    let producer = load_producer_transition_evidence(transaction, &historical, conversation_id)
        .await
        .map_err(ConversationStateHydrationError::Producer)?;
    let (metadata, metadata_producer) =
        load_metadata_provenance(transaction, &historical, conversation_id)
            .await
            .map_err(ConversationStateHydrationError::Metadata)?;
    let participants = load_participant_hydration_rows(transaction, &historical, conversation_id)
        .await
        .map_err(ConversationStateHydrationError::Participants)?;
    let leaves = match public_state.as_ref() {
        Some(public_state) => {
            load_leaf_hydration_rows(transaction, conversation_id, public_state.binding())
                .await
                .map_err(ConversationStateHydrationError::Leaves)?
        }
        None => {
            let active_leaf_count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.member_devices \
                 WHERE conversation_id=$1 AND active",
            )
            .bind(conversation_id)
            .fetch_one(&mut **transaction)
            .await?;
            if active_leaf_count != 0 {
                return Err(ConversationStateHydrationError::TerminalLeafPresent);
            }
            Vec::new()
        }
    };
    let intervals = load_interval_hydration_rows(transaction, &historical, conversation_id)
        .await
        .map_err(ConversationStateHydrationError::Intervals)?;
    let (recovery_requests, recovery_reservations) =
        load_recovery_work_hydration_rows(transaction, &historical, conversation_id)
            .await
            .map_err(ConversationStateHydrationError::RecoveryWork)?;
    let reset_requests =
        load_reset_request_hydration_rows(transaction, &historical, conversation_id)
            .await
            .map_err(ConversationStateHydrationError::ResetWork)?;
    let leave_requests =
        load_leave_request_hydration_rows(transaction, &historical, conversation_id)
            .await
            .map_err(ConversationStateHydrationError::LeaveWork)?;
    let welcomes = load_welcome_hydration_rows(transaction, &historical, conversation_id)
        .await
        .map_err(ConversationStateHydrationError::Welcomes)?;

    let terminal_proofs = match aggregate_lifecycle {
        ConversationHydrationLifecycle::Active => {
            let terminal_proof_count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.application_schedule_terminal_proofs \
                 WHERE conversation_id=$1",
            )
            .bind(conversation_id)
            .fetch_one(&mut **transaction)
            .await?;
            certify_no_terminal_proofs(terminal_proof_count)?
        }
        ConversationHydrationLifecycle::Terminal => {
            load_terminal_proof_hydration_rows(transaction, &historical, conversation_id)
                .await
                .map_err(ConversationStateHydrationError::TerminalProofs)?
        }
    };

    let rows = ConversationStateHydration {
        kind,
        coordinate: *head_coordinate,
        producer,
        public_state,
        metadata,
        metadata_producer,
        participants,
        leaves,
        intervals,
        terminal_proofs,
        recovery_requests,
        recovery_reservations,
        reset_requests,
        leave_requests,
        welcomes,
    };
    let graph_digest = conversation_graph_digest(&head, snapshot_digest.as_ref(), &rows);
    if graph_digest == [0; 32] {
        return Err(ConversationStateHydrationError::GraphDigest);
    }
    let state = hydrate_conversation_state(&hydration, rows)
        .map_err(ConversationStateHydrationError::State)?;
    seal_locked_conversation(state, head, graph_digest, snapshot_digest)
        .ok_or(ConversationStateHydrationError::Seal)
}
