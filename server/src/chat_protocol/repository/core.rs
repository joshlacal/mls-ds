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

use super::super::{
    snapshot::{
        PublicGroupSnapshotBinding, PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle,
    },
    state_machine::{
        classify_acceptance, classify_invitation, classify_role_producer,
        metadata_binding_of_transition, CloseKind, ConversationState, DeviceIdentity,
        HistoricalRehydrationAuthority, HydrationAuthority, IntervalEndHydrationRow,
        IntervalHydrationRow, LeafHydrationRow, LeafRecoveryKind, LeaveRequestHydrationRow,
        LeaveRequestStatus, MetadataSnapshotBinding, OpeningKind, ParticipantHydrationRow,
        ParticipantRole, ParticipantStatus, PersistedControlAuthority, PrincipalId,
        RecoveryOriginHydrationRow, RecoveryRequestHydrationRow, RecoveryRequestStatus,
        RecoveryReservationHydrationRow, RecoverySource, RequestEntryKind, RequestEvidence,
        ReservationStatus, ResetRequestHydrationRow, ResetRequestStatus, ServerTimestamp,
        TransitionEvidence, WorkTerminalHydrationRow,
    },
    validation::{BareDid, KeyThumbprint},
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
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;

    #[allow(clippy::type_complexity)]
    let row: Option<(
        i64,
        i64,
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
            c.current_generation,
            c.current_state_version,
            gs.group_id,
            gs.epoch,
            gs.group_context_hash,
            gs.confirmation_tag,
            gs.lifecycle,
            gs.public_snapshot_bytes,
            gs.snapshot_sha256,
            gs.tree_summary_bytes,
            gs.tree_summary_sha256
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

    let generation = safe_public_state_u64(current_generation)?;
    let state_version = safe_public_state_u64(current_state_version)?;
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
        locked_at,
    );

    seal_locked_public_state_hydration(
        transaction_id,
        conversation_id,
        coordinate,
        public_snapshot_bytes,
        binding,
        tree_summary_bytes,
        tree_summary_sha256,
        locked_at,
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
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        Uuid,
        Option<Uuid>,
        String,
        Uuid,
        Option<Uuid>,
    )> = sqlx::query_as(
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
    for (
        user_did,
        status,
        role,
        role_transition_id,
        invitation_transition_id,
        created_by_did,
        created_by_device_id,
        acceptance_transition_id,
    ) in rows
    {
        let principal = PrincipalId::new(user_did.into_bytes())
            .map_err(|_| ParticipantHydrationError::OutOfDomain)?;
        let status = match status.as_str() {
            "pending" => ParticipantStatus::Pending,
            "active" => ParticipantStatus::Active,
            _ => return Err(ParticipantHydrationError::OutOfDomain),
        };
        let role = match role.as_str() {
            "member" => ParticipantRole::Member,
            "admin" => ParticipantRole::Admin,
            _ => return Err(ParticipantHydrationError::OutOfDomain),
        };

        let role_evidence = load_historical_control_evidence(
            transaction,
            authority,
            conversation_id,
            role_transition_id,
        )
        .await?
        .into_transition()
        .map_err(|_| ParticipantHydrationError::InvalidProvenance)?;
        let role_producer = classify_role_producer(role_evidence, &principal, role)
            .map_err(|_| ParticipantHydrationError::InvalidProvenance)?;

        let invitation = match invitation_transition_id {
            None => None,
            Some(invitation_transition_id) => {
                let inviter_principal = PrincipalId::new(created_by_did.into_bytes())
                    .map_err(|_| ParticipantHydrationError::OutOfDomain)?;
                let inviter =
                    DeviceIdentity::new(inviter_principal, *created_by_device_id.as_bytes())
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

        let acceptance = match acceptance_transition_id {
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

        participants.push(ParticipantHydrationRow {
            principal,
            status,
            role,
            role_producer,
            invitation,
            acceptance,
        });
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
// G1b-2 sub-seal — current-metadata provenance leg (metadata + metadata_producer).
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
// this leg reads `chat.metadata_snapshots.producing_transition_id` (pinned to the
// current generation-state's producer — see below), re-verifies that transition
// through the sealed loader atom, and derives the metadata binding from its body
// via `metadata_binding_of_transition`, exactly reproducing the append-time
// derivation. `metadata_provenance_matches` is the assembly-time drift fence.
//
// PRODUCER PIN: the metadata row is joined to the CURRENT generation-state's
// `producing_transition_id`. A generation-state is produced by exactly one
// transition, and the executor writes that state and its metadata snapshot (when
// metadata is present) in one persistence with a shared `producing_transition_id`
// (`metadata_snapshots_transition_uq` makes it globally unique), so
// `chat.metadata_snapshots.producing_transition_id` for the current `(generation,
// state_version)` always equals `chat.generation_states.producing_transition_id`.
// Pinning the join on that equality is deterministic (there is no bare
// `(conversation_id, generation, state_version)` unique index on
// `chat.metadata_snapshots`) and fails toward `(None, None)` — never a
// non-deterministic pick — should the invariant ever be violated.
//
// (None, None) vs fail-closed: a coherent conversation ALWAYS carries metadata —
// `createConversation` mints a `metadata_version == 1` snapshot, every advance
// carries one forward, and `chat.transitions.metadata_snapshot_id` FK-references
// the row (so it cannot be orphaned/deleted). So on any conversation the caller
// has head-locked, the current metadata row is present and this leg returns
// `(Some, Some)`. The `(None, None)` arm is the faithful DB mirror for the
// no-current-metadata-row case (structurally unreachable for an existing
// conversation); it is NOT fabricated evidence, and `validate_state` is the
// arbiter of whether a metadata-less state is legal for the coordinate. The
// handoff's "missing metadata row" fail-closed maps to `ProvenanceMissing` (the
// producing transition's ENTRY is absent), not the absent-snapshot-row case.
// ===========================================================================

/// Failure modes of [`load_metadata_provenance`].
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(crate) enum MetadataHydrationError {
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

/// Load and re-verify the CURRENT metadata provenance of an existing
/// conversation — the G1b-2 aggregate's coupled `metadata` + `metadata_producer`
/// fields.
///
/// Reads `chat.metadata_snapshots.producing_transition_id` for the conversation's
/// current `(generation, state_version)` — pinned to the current
/// generation-state's producer (see the module comment) — then re-loads +
/// re-verifies that transition's durable control entry through
/// [`load_historical_control_evidence`], narrows it to the transition arm via
/// [`PersistedControlAuthority::into_transition`] (a coordinate metadata producer
/// is always a transition, never a control request), and derives the metadata
/// binding from its verified body via
/// [`metadata_binding_of_transition`] — exactly as the append-time path derives
/// `state.metadata`. Returns `(None, None)` when no current metadata snapshot
/// exists (the legal validator arm, structurally unreachable for a coherent
/// conversation).
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
    let row: Option<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT ms.producing_transition_id
        FROM chat.conversations c
        JOIN chat.generation_states gs
          ON gs.conversation_id = c.conversation_id
         AND gs.generation = c.current_generation
         AND gs.state_version = c.current_state_version
        JOIN chat.metadata_snapshots ms
          ON ms.conversation_id = c.conversation_id
         AND ms.generation = c.current_generation
         AND ms.state_version = c.current_state_version
         AND ms.producing_transition_id = gs.producing_transition_id
        WHERE c.conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_optional(&mut **transaction)
    .await?;

    let Some((producing_transition_id,)) = row else {
        // No current metadata snapshot: the legal `(None, None)` validator arm.
        return Ok((None, None));
    };

    let producer = load_historical_control_evidence(
        transaction,
        authority,
        conversation_id,
        producing_transition_id,
    )
    .await?
    .into_transition()
    .map_err(|_| MetadataHydrationError::InvalidProvenance)?;

    // Derive the metadata binding from the re-verified producer body, mirroring
    // the append-time `state.metadata = transition_metadata(&producer).cloned()`.
    // A metadata snapshot row whose producing transition body carries NO metadata
    // is a fail-closed linkage inconsistency, never a silent `None`.
    let metadata = metadata_binding_of_transition(&producer)
        .ok_or(MetadataHydrationError::InvalidProvenance)?;

    Ok((Some(metadata), Some(producer)))
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
// The request ORIGIN is a HISTORICAL signed request: for `source =
// 'requestLeafRecovery'` it is a `RequestEvidence` re-minted from the row's OWN
// `signed_request_bytes` + `requested_at` under the requester's historical
// signing key (JOINed from `chat.device_keys`), through the certified
// `HistoricalRehydrationAuthority::hydrate_historical_signed_request_from_durable_bytes`
// seam (ed25519 re-verified, conversation binding enforced).
//
// SCOPE (NEXT-STEP follow-ups, fail-closed until reconstructed + tested): the
// `acceptConversation` source (an `Acceptance` `TransitionEvidence` origin) and
// the TERMINAL reconstruction of non-`open` requests / non-`active` reservations
// (`WorkTerminalHydrationRow`: fulfilling / cancellation / expiry /
// device-revocation evidence) each need their own bespoke real-signed /
// real-close / device-revocation coherent seed to exercise the populated arm, so
// shipping them untested would be REJECT-class. This leg reconstructs the
// `open` / `active` (terminal `None`) arm fully and fails CLOSED
// (`UnsupportedSource` / `UnsupportedTerminal`) on the others — never fabricating
// a terminal or an origin it cannot re-verify.
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
    /// The request's `source` is `acceptConversation`, whose `Acceptance`
    /// transition origin is the NEXT-STEP follow-up of this leg. Fail closed until
    /// that arm is reconstructed + tested.
    #[error("clean-chat recovery acceptConversation source is not yet reconstructed")]
    UnsupportedSource,
    /// The request/reservation carries a terminal status (non-`open` request or
    /// non-`active` reservation) whose `WorkTerminalHydrationRow` reconstruction
    /// is the NEXT-STEP follow-up. Fail closed until that arm is reconstructed +
    /// tested.
    #[error("clean-chat recovery terminal status is not yet reconstructed")]
    UnsupportedTerminal,
    #[error("clean-chat recovery hydration database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// A reservation paired to its request during recovery-work hydration; carries
/// the `key_package_ref` the request row lacks.
struct PairedReservation {
    key_package_ref: [u8; 32],
    row: RecoveryReservationHydrationRow,
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
    #[allow(clippy::type_complexity)]
    let reservation_rows: Vec<(
        Uuid,
        String,
        Uuid,
        i64,
        i64,
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        DateTime<Utc>,
        DateTime<Utc>,
        String,
        DateTime<Utc>,
    )> = sqlx::query_as(
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
            kp.not_after
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
    for (
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
        not_after,
    ) in reservation_rows
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
        let status = match status.as_str() {
            "active" => ReservationStatus::Active,
            "consumed" | "expired" | "released" => {
                return Err(RecoveryHydrationError::UnsupportedTerminal)
            }
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
                    row,
                },
            )
            .is_some()
        {
            return Err(RecoveryHydrationError::PairMismatch);
        }
    }

    // Requests, with the requester's historical signing key for the origin re-mint.
    #[allow(clippy::type_complexity)]
    let request_rows: Vec<(
        Uuid,
        String,
        Uuid,
        String,
        String,
        i64,
        i64,
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        String,
        Vec<u8>,
        DateTime<Utc>,
        DateTime<Utc>,
        Vec<u8>,
    )> = sqlx::query_as(
        r#"
        SELECT
            lr.recovery_request_id,
            lr.requester_did,
            lr.requester_device_id,
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
            lr.requested_at,
            lr.expires_at,
            dk.signing_public_key
        FROM chat.leaf_recovery_requests lr
        JOIN chat.device_keys dk
          ON dk.user_did = lr.requester_did
         AND dk.device_id = lr.requester_device_id
         AND dk.key_id = lr.requester_key_id
        WHERE lr.conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;

    let mut requests: Vec<RecoveryRequestHydrationRow> = Vec::with_capacity(request_rows.len());
    let mut paired: usize = 0;
    for (
        recovery_request_id,
        requester_did,
        requester_device_id,
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
        requested_at,
        expires_at,
        signing_public_key,
    ) in request_rows
    {
        let request_id = *recovery_request_id.as_bytes();
        let target = recovery_device(requester_did, requester_device_id)?;
        let kind = match recovery_kind.as_str() {
            "add" => LeafRecoveryKind::Add,
            "replace" => LeafRecoveryKind::Replace,
            _ => return Err(RecoveryHydrationError::OutOfDomain),
        };
        let source = match source.as_str() {
            "requestLeafRecovery" => RecoverySource::Request,
            "acceptConversation" => return Err(RecoveryHydrationError::UnsupportedSource),
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
        let status = match status.as_str() {
            "open" => RecoveryRequestStatus::Open,
            "fulfilled" | "cancelled" | "expired" | "superseded" => {
                return Err(RecoveryHydrationError::UnsupportedTerminal)
            }
            _ => return Err(RecoveryHydrationError::OutOfDomain),
        };
        let reservation = reservations_by_id
            .get(&request_id)
            .ok_or(RecoveryHydrationError::PairMismatch)?;
        paired += 1;

        let received_at_canonical = canonical_millis(requested_at);
        let origin = authority
            .hydrate_historical_signed_request_from_durable_bytes(
                conversation_bytes,
                &received_at_canonical,
                &signed_request_bytes,
                &signing_public_key,
            )
            .map_err(|_| RecoveryHydrationError::InvalidProvenance)?;

        requests.push(RecoveryRequestHydrationRow {
            request_id,
            target,
            kind,
            source,
            bound_coordinate,
            key_package_ref: reservation.key_package_ref,
            received_at: recovery_timestamp(requested_at)?,
            expires_at: recovery_timestamp(expires_at)?,
            status,
            origin: RecoveryOriginHydrationRow::Request(origin),
            terminal: None,
        });
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

/// Reconstruct one terminal-family evidence arm from its exact durable
/// provenance. Further terminal arms extend this dispatcher; callers never
/// construct `WorkTerminalHydrationRow` evidence directly.
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
// chat.leave_requests, pending arm).
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
// SCOPE (pending arm only; the terminal arms are the terminal-family follow-up,
// REJECT-class if shipped untested): a non-`pending` reset (`stale` / `consumed`
// / `expired`) or leave (`fulfilled` / `cancelled` / `expired` / `stale`) carries
// a terminal whose `WorkTerminalHydrationRow` reconstruction (a resetActivation /
// leaveCommit transition, a leaveCancellation control request, or an expiry
// instant) needs its own bespoke coherent terminal seed; the leg fails CLOSED
// (`UnsupportedTerminal`) on those rather than fabricate a terminal. The pending
// arm (terminal `None`) is reconstructed fully. `validate_reset_work` /
// `validate_leave_work` at assembly are the drift fences (they re-run
// `validate_request_evidence` + `require_request_prior` + the coordinate/expiry
// checks over every hydrated row).
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
    /// The request carries a terminal status (non-`pending`) whose
    /// `WorkTerminalHydrationRow` reconstruction is the NEXT-STEP follow-up. Fail
    /// closed until that arm is reconstructed + tested.
    #[error("clean-chat reset/leave terminal status is not yet reconstructed")]
    UnsupportedTerminal,
    #[error("clean-chat reset/leave hydration database error: {0}")]
    Database(#[from] sqlx::Error),
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

/// Locate + re-verify a pending reset/leave request's ORIGIN control entry per the
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
            expires_at
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
        let status = match status.as_str() {
            "pending" => ResetRequestStatus::Pending,
            "stale" | "consumed" | "expired" => {
                return Err(ResetLeaveHydrationError::UnsupportedTerminal)
            }
            _ => return Err(ResetLeaveHydrationError::OutOfDomain),
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

        requests.push(ResetRequestHydrationRow {
            request_id,
            requester,
            bound_coordinate,
            received_at: reset_leave_timestamp(received_at)?,
            expires_at: reset_leave_timestamp(expires_at)?,
            status,
            origin,
            terminal: None,
        });
    }

    // `validate_reset_work` requires the collection strictly increasing by
    // `request_id`. Sort in Rust so the ordering is independent of the database's
    // `reset_request_id` collation.
    requests.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    Ok(requests)
}

/// Load the PENDING leave requests of an existing conversation, each bound to its
/// re-verified control-request origin. See the module header for the JOIN ruling
/// and the terminal-arm scope.
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
    )> = sqlx::query_as(
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
            expires_at
        FROM chat.leave_requests
        WHERE conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;

    let mut requests: Vec<LeaveRequestHydrationRow> = Vec::with_capacity(rows.len());
    for (
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
    ) in rows
    {
        let request_id = *leave_request_id.as_bytes();
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
        let status = match status.as_str() {
            "pending" => LeaveRequestStatus::Pending,
            "fulfilled" | "cancelled" | "expired" | "stale" => {
                return Err(ResetLeaveHydrationError::UnsupportedTerminal)
            }
            _ => return Err(ResetLeaveHydrationError::OutOfDomain),
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

        requests.push(LeaveRequestHydrationRow {
            request_id,
            requester,
            bound_coordinate,
            received_at: reset_leave_timestamp(received_at)?,
            expires_at: reset_leave_timestamp(expires_at)?,
            status,
            origin,
            terminal: None,
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
