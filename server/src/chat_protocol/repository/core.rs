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

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use super::super::{
    snapshot::{PublicGroupSnapshotBinding, PublicGroupSnapshotCoordinate},
    state_machine::{ConversationState, HistoricalRehydrationAuthority, PersistedControlAuthority},
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
