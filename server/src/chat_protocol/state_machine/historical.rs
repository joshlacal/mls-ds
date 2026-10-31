#![allow(unused_imports)]
use super::*;


/// Exact KeyPackage row authority retained for adapter-side compare-and-set.
/// Unlike `PackageTransition`, this is not a semantic summary: it binds the
/// transaction, owner generation, immutable wrapper, lifetime, coordinate,
/// and locked durable-row digest that authorized the status edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryPackageCasBinding {
    pub(in crate::chat_protocol::state_machine) transaction_id: String,
    pub(in crate::chat_protocol::state_machine) conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) target: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) target_key_id: [u8; 32],
    pub(in crate::chat_protocol::state_machine) target_auth_generation: u64,
    pub(in crate::chat_protocol::state_machine) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) key_package_ref: [u8; 32],
    pub(in crate::chat_protocol::state_machine) key_package_wrapper_sha256: [u8; 32],
    pub(in crate::chat_protocol::state_machine) package_not_after: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) claimed_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) expected_status: PackageStatus,
    pub(in crate::chat_protocol::state_machine) successor_status: PackageStatus,
    pub(in crate::chat_protocol::state_machine) locked_row_digest: [u8; 32],
    /// Domain-separated seal over every retained locked-row/CAS authority
    /// column. This makes drift in any non-semantic guard field detectable
    /// before the conversation-head CAS.
    pub(in crate::chat_protocol::state_machine) authority_digest: [u8; 32],
}

pub(in crate::chat_protocol::state_machine) fn recovery_package_cas_authority_digest(binding: &RecoveryPackageCasBinding) -> [u8; 32] {
    fn status_byte(status: PackageStatus) -> u8 {
        match status {
            PackageStatus::Available => 1,
            PackageStatus::Reserved => 2,
            PackageStatus::Consumed => 3,
            PackageStatus::Expired => 4,
            PackageStatus::Revoked => 5,
        }
    }

    let coordinate = &binding.bound_coordinate;
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-RECOVERY-PACKAGE-CAS-AUTHORITY\0");
    digest.update((binding.transaction_id.len() as u64).to_be_bytes());
    digest.update(binding.transaction_id.as_bytes());
    digest.update(binding.conversation_id);
    digest.update(binding.request_id);
    digest.update((binding.target.principal().as_bytes().len() as u64).to_be_bytes());
    digest.update(binding.target.principal().as_bytes());
    digest.update(binding.target.device_id());
    digest.update(binding.target_key_id);
    digest.update(binding.target_auth_generation.to_be_bytes());
    digest.update(coordinate.conversation_id());
    digest.update(coordinate.generation().to_be_bytes());
    digest.update(coordinate.state_version().to_be_bytes());
    digest.update(coordinate.group_id());
    digest.update(coordinate.epoch().to_be_bytes());
    digest.update(coordinate.group_context_hash());
    digest.update(coordinate.confirmation_tag());
    digest.update([match coordinate.lifecycle() {
        PublicGroupSnapshotLifecycle::Active => 1,
        PublicGroupSnapshotLifecycle::Superseded => 2,
    }]);
    digest.update(binding.key_package_ref);
    digest.update(binding.key_package_wrapper_sha256);
    digest.update(binding.package_not_after.unix_millis().to_be_bytes());
    digest.update(binding.claimed_at.unix_millis().to_be_bytes());
    digest.update([status_byte(binding.expected_status)]);
    digest.update([status_byte(binding.successor_status)]);
    digest.update(binding.locked_row_digest);
    digest.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RevocationTargetCasBinding {
    pub(in crate::chat_protocol::state_machine) transaction_id: String,
    pub(in crate::chat_protocol::state_machine) target: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) expected_auth_generation: u64,
    pub(in crate::chat_protocol::state_machine) expected_status: PersistedRegistrationStatus,
    pub(in crate::chat_protocol::state_machine) successor_status: PersistedRegistrationStatus,
    pub(in crate::chat_protocol::state_machine) locked_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) locked_row_digest: [u8; 32],
}

/// Exact live KeyPackage -> Revoked CAS with immutable signed revocation
/// provenance. Available packages have no reservation IDs; Reserved packages
/// bind the exact conversation/request edge they terminate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RevocationPackageCasBinding {
    pub(in crate::chat_protocol::state_machine) transaction_id: String,
    pub(in crate::chat_protocol::state_machine) target: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) target_key_id: [u8; 32],
    pub(in crate::chat_protocol::state_machine) target_auth_generation: u64,
    pub(in crate::chat_protocol::state_machine) key_package_ref: [u8; 32],
    pub(in crate::chat_protocol::state_machine) wrapper_sha256: [u8; 32],
    pub(in crate::chat_protocol::state_machine) package_not_after: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) expected_status: PackageStatus,
    pub(in crate::chat_protocol::state_machine) successor_status: PackageStatus,
    pub(in crate::chat_protocol::state_machine) conversation_id: Option<[u8; 16]>,
    pub(in crate::chat_protocol::state_machine) request_id: Option<[u8; 16]>,
    pub(in crate::chat_protocol::state_machine) revocation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) revoked_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) revocation_request_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) revocation_row_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) locked_row_digest: [u8; 32],
}

impl RevocationPackageCasBinding {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn target(&self) -> &DeviceIdentity {
        &self.target
    }
    pub(crate) fn target_key_id(&self) -> &[u8; 32] {
        &self.target_key_id
    }
    pub(crate) fn target_auth_generation(&self) -> u64 {
        self.target_auth_generation
    }
    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }
    pub(crate) fn expected_status(&self) -> PackageStatus {
        self.expected_status
    }
    pub(crate) fn successor_status(&self) -> PackageStatus {
        self.successor_status
    }
    pub(crate) fn conversation_id(&self) -> Option<&[u8; 16]> {
        self.conversation_id.as_ref()
    }
    pub(crate) fn request_id(&self) -> Option<&[u8; 16]> {
        self.request_id.as_ref()
    }
    pub(crate) fn revocation_id(&self) -> &[u8; 16] {
        &self.revocation_id
    }
    pub(crate) fn revoked_at(&self) -> ServerTimestamp {
        self.revoked_at
    }
    pub(crate) fn revocation_request_digest(&self) -> &[u8; 32] {
        &self.revocation_request_digest
    }
    pub(crate) fn revocation_row_digest(&self) -> &[u8; 32] {
        &self.revocation_row_digest
    }
    pub(crate) fn locked_row_digest(&self) -> &[u8; 32] {
        &self.locked_row_digest
    }

    /// A batch-plan binding for an AVAILABLE (conversation_id == None) target
    /// package the device revocation revokes directly via
    /// `apply_device_revocation_batch_prefix`. That arm reads only
    /// `conversation_id()` (to skip the Reserved ones the per-conversation arm
    /// owns) and `key_package_ref()`; the `Revoke` CAS takes `revocation_id` +
    /// `revoked_at` from the batch authority, not the binding — so the remaining
    /// provenance fields are stable placeholders here. Mirrors the shape the
    /// production `plan_device_revocation_batch` builds for a live available
    /// package.
    #[cfg(test)]
    pub(crate) fn for_test_available(
        target: DeviceIdentity,
        key_package_ref: [u8; 32],
        revocation_id: [u8; 16],
        revoked_at: ServerTimestamp,
    ) -> Self {
        Self::for_test_available_with_transaction_id(
            String::new(),
            target,
            key_package_ref,
            revocation_id,
            revoked_at,
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test_available_with_transaction_id(
        transaction_id: String,
        target: DeviceIdentity,
        key_package_ref: [u8; 32],
        revocation_id: [u8; 16],
        revoked_at: ServerTimestamp,
    ) -> Self {
        Self {
            transaction_id,
            target,
            target_key_id: [0u8; 32],
            target_auth_generation: 1,
            key_package_ref,
            wrapper_sha256: [0xC1u8; 32],
            package_not_after: revoked_at,
            expected_status: PackageStatus::Available,
            successor_status: PackageStatus::Revoked,
            conversation_id: None,
            request_id: None,
            revocation_id,
            revoked_at,
            revocation_request_digest: [0u8; 32],
            revocation_row_digest: [0u8; 32],
            locked_row_digest: [0u8; 32],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvitationQuotaRecipientCasFact {
    pub(in crate::chat_protocol::state_machine) recipient: PrincipalId,
    pub(in crate::chat_protocol::state_machine) expected_pair_live: u64,
    pub(in crate::chat_protocol::state_machine) successor_pair_live: u64,
    pub(in crate::chat_protocol::state_machine) pair_limit: u64,
    pub(in crate::chat_protocol::state_machine) expected_recipient_live: u64,
    pub(in crate::chat_protocol::state_machine) successor_recipient_live: u64,
    pub(in crate::chat_protocol::state_machine) recipient_limit: u64,
}

impl InvitationQuotaRecipientCasFact {
    pub(crate) fn recipient(&self) -> &PrincipalId {
        &self.recipient
    }
    pub(crate) fn expected_pair_live(&self) -> u64 {
        self.expected_pair_live
    }
    pub(crate) fn successor_pair_live(&self) -> u64 {
        self.successor_pair_live
    }
    pub(crate) fn pair_limit(&self) -> u64 {
        self.pair_limit
    }
    pub(crate) fn expected_recipient_live(&self) -> u64 {
        self.expected_recipient_live
    }
    pub(crate) fn successor_recipient_live(&self) -> u64 {
        self.successor_recipient_live
    }
    pub(crate) fn recipient_limit(&self) -> u64 {
        self.recipient_limit
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvitationQuotaCasBinding {
    pub(in crate::chat_protocol::state_machine) transaction_id: String,
    pub(in crate::chat_protocol::state_machine) inviter: PrincipalId,
    pub(in crate::chat_protocol::state_machine) new_recipients: Vec<PrincipalId>,
    pub(in crate::chat_protocol::state_machine) expected_inviter_recent_24h: u64,
    pub(in crate::chat_protocol::state_machine) successor_inviter_recent_24h: u64,
    pub(in crate::chat_protocol::state_machine) inviter_limit: u64,
    pub(in crate::chat_protocol::state_machine) recipient_facts: Vec<InvitationQuotaRecipientCasFact>,
    pub(in crate::chat_protocol::state_machine) locked_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) locked_row_digest: [u8; 32],
}

impl InvitationQuotaCasBinding {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn inviter(&self) -> &PrincipalId {
        &self.inviter
    }
    pub(crate) fn new_recipients(&self) -> &[PrincipalId] {
        &self.new_recipients
    }
    pub(crate) fn expected_inviter_recent_24h(&self) -> u64 {
        self.expected_inviter_recent_24h
    }
    pub(crate) fn successor_inviter_recent_24h(&self) -> u64 {
        self.successor_inviter_recent_24h
    }
    pub(crate) fn inviter_limit(&self) -> u64 {
        self.inviter_limit
    }
    pub(crate) fn recipient_facts(&self) -> &[InvitationQuotaRecipientCasFact] {
        &self.recipient_facts
    }
    pub(crate) fn locked_at(&self) -> ServerTimestamp {
        self.locked_at
    }
    pub(crate) fn locked_row_digest(&self) -> &[u8; 32] {
        &self.locked_row_digest
    }
}

/// Exact Pending -> terminal Welcome row compare-and-set retained for the
/// persistence adapter. The immutable delivery bytes and all request-binding
/// coordinates come from the consumed repository lock witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WelcomeCasBinding {
    pub(in crate::chat_protocol::state_machine) transaction_id: String,
    pub(in crate::chat_protocol::state_machine) conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) welcome_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) recipient: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) transition_seq: u64,
    pub(in crate::chat_protocol::state_machine) coordinate: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) recovery_request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) key_package_ref: [u8; 32],
    pub(in crate::chat_protocol::state_machine) opaque_welcome_sha256: [u8; 32],
    pub(in crate::chat_protocol::state_machine) expires_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) expected_status: WelcomeStatus,
    pub(in crate::chat_protocol::state_machine) successor_status: WelcomeStatus,
    pub(in crate::chat_protocol::state_machine) locked_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) locked_row_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) seal: [u8; 32],
}

impl WelcomeCasBinding {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn conversation_id(&self) -> &[u8; 16] {
        &self.conversation_id
    }
    pub(crate) fn welcome_id(&self) -> &[u8; 16] {
        &self.welcome_id
    }
    pub(crate) fn recipient(&self) -> &DeviceIdentity {
        &self.recipient
    }
    pub(crate) fn transition_seq(&self) -> u64 {
        self.transition_seq
    }
    pub(crate) fn coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.coordinate
    }
    pub(crate) fn recovery_request_id(&self) -> &[u8; 16] {
        &self.recovery_request_id
    }
    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }
    pub(crate) fn opaque_welcome_sha256(&self) -> &[u8; 32] {
        &self.opaque_welcome_sha256
    }
    pub(crate) fn expires_at(&self) -> ServerTimestamp {
        self.expires_at
    }
    pub(crate) fn expected_status(&self) -> WelcomeStatus {
        self.expected_status
    }
    pub(crate) fn successor_status(&self) -> WelcomeStatus {
        self.successor_status
    }
    pub(crate) fn locked_at(&self) -> ServerTimestamp {
        self.locked_at
    }
    pub(crate) fn locked_row_digest(&self) -> &[u8; 32] {
        &self.locked_row_digest
    }

    pub(crate) fn verify_seal(&self) -> bool {
        self.seal == welcome_cas_seal(self)
    }
}

pub(in crate::chat_protocol::state_machine) fn welcome_cas_seal(binding: &WelcomeCasBinding) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-WELCOME-CAS-BINDING\0");
    digest.update((binding.transaction_id.len() as u64).to_be_bytes());
    digest.update(binding.transaction_id.as_bytes());
    digest.update(binding.conversation_id);
    digest.update(binding.welcome_id);
    digest.update((binding.recipient.principal().as_bytes().len() as u64).to_be_bytes());
    digest.update(binding.recipient.principal().as_bytes());
    digest.update(binding.recipient.device_id());
    digest.update(binding.transition_seq.to_be_bytes());
    digest.update(binding.coordinate.conversation_id());
    digest.update(binding.coordinate.generation().to_be_bytes());
    digest.update(binding.coordinate.state_version().to_be_bytes());
    digest.update(binding.coordinate.group_id());
    digest.update(binding.coordinate.epoch().to_be_bytes());
    digest.update(binding.coordinate.group_context_hash());
    digest.update(binding.coordinate.confirmation_tag());
    digest.update([match binding.coordinate.lifecycle() {
        PublicGroupSnapshotLifecycle::Active => 1,
        PublicGroupSnapshotLifecycle::Superseded => 2,
    }]);
    digest.update(binding.recovery_request_id);
    digest.update(binding.key_package_ref);
    digest.update(binding.opaque_welcome_sha256);
    digest.update(binding.expires_at.unix_millis().to_be_bytes());
    digest.update([welcome_status_code(binding.expected_status)]);
    digest.update([welcome_status_code(binding.successor_status)]);
    digest.update(binding.locked_at.unix_millis().to_be_bytes());
    digest.update(binding.locked_row_digest);
    digest.finalize().into()
}

pub(in crate::chat_protocol::state_machine) fn welcome_status_code(status: WelcomeStatus) -> u8 {
    match status {
        WelcomeStatus::Pending => 1,
        WelcomeStatus::Acknowledged => 2,
        WelcomeStatus::Rejected => 3,
        WelcomeStatus::Expired => 4,
        WelcomeStatus::Superseded => 5,
    }
}

/// Repository-issued authority for a due Recovery expiry. The terminal instant
/// is fixed by the open request; `observed_at` proves the transaction observed
/// it no earlier than that instant, and the read-set digest binds the locked
/// request/reservation/package triple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryExpiryPlanAuthority {
    pub(in crate::chat_protocol::state_machine) request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) requester: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) terminal_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) observed_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) locked_read_set_digest: [u8; 32],
}

impl RecoveryExpiryPlanAuthority {
    #[cfg(test)]
    pub(crate) fn for_test(
        request_id: [u8; 16],
        requester: DeviceIdentity,
        terminal_at: ServerTimestamp,
        observed_at: ServerTimestamp,
        locked_read_set_digest: [u8; 32],
    ) -> Self {
        Self {
            request_id,
            requester,
            terminal_at,
            observed_at,
            locked_read_set_digest,
        }
    }

    pub(crate) fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }
    pub(crate) fn requester(&self) -> &DeviceIdentity {
        &self.requester
    }
    pub(crate) fn terminal_at(&self) -> ServerTimestamp {
        self.terminal_at
    }
    pub(crate) fn observed_at(&self) -> ServerTimestamp {
        self.observed_at
    }
    pub(crate) fn locked_read_set_digest(&self) -> &[u8; 32] {
        &self.locked_read_set_digest
    }
}

/// Repository-issued authority for an unsigned expiry worker decision. The
/// work row itself fixes the terminal instant; `observed_at` only proves the
/// worker ran no earlier than that instant under the conversation lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WelcomeExpiryAuthority {
    pub(in crate::chat_protocol::state_machine) welcome_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) recipient: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) coordinate: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) transition_seq: u64,
    pub(in crate::chat_protocol::state_machine) terminal_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) observed_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) locked_row_digest: [u8; 32],
}

impl WelcomeExpiryAuthority {
    pub(crate) fn welcome_id(&self) -> &[u8; 16] {
        &self.welcome_id
    }
    pub(crate) fn recipient(&self) -> &DeviceIdentity {
        &self.recipient
    }
    pub(crate) fn coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.coordinate
    }
    pub(crate) fn transition_seq(&self) -> u64 {
        self.transition_seq
    }
    pub(crate) fn terminal_at(&self) -> ServerTimestamp {
        self.terminal_at
    }
    pub(crate) fn observed_at(&self) -> ServerTimestamp {
        self.observed_at
    }
    pub(crate) fn locked_row_digest(&self) -> &[u8; 32] {
        &self.locked_row_digest
    }
}

#[cfg(test)]
impl WelcomeExpiryAuthority {
    pub(crate) fn for_test(
        welcome_id: [u8; 16],
        recipient: DeviceIdentity,
        coordinate: PublicGroupSnapshotCoordinate,
        transition_seq: u64,
        terminal_at: ServerTimestamp,
        observed_at: ServerTimestamp,
    ) -> Self {
        assert!(observed_at >= terminal_at);
        Self {
            welcome_id,
            recipient,
            coordinate,
            transition_seq,
            terminal_at,
            observed_at,
            locked_row_digest: [1; 32],
        }
    }
}

impl RevocationTargetCasBinding {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn target(&self) -> &DeviceIdentity {
        &self.target
    }
    pub(crate) fn expected_auth_generation(&self) -> u64 {
        self.expected_auth_generation
    }
    pub(crate) fn expected_status(&self) -> PersistedRegistrationStatus {
        self.expected_status
    }
    pub(crate) fn successor_status(&self) -> PersistedRegistrationStatus {
        self.successor_status
    }
    pub(crate) fn locked_at(&self) -> ServerTimestamp {
        self.locked_at
    }
    pub(crate) fn locked_row_digest(&self) -> &[u8; 32] {
        &self.locked_row_digest
    }
}

#[cfg(test)]
impl RevocationTargetCasBinding {
    /// The batch-level `active -> revoked` registration CAS a test drives once,
    /// mirroring the binding `plan_device_revocation_batch` produces.
    pub(crate) fn for_test(
        target: DeviceIdentity,
        expected_auth_generation: u64,
        locked_at: ServerTimestamp,
    ) -> Self {
        Self::for_test_with_transaction_id(
            "e2b7-revocation-test".to_owned(),
            target,
            expected_auth_generation,
            locked_at,
        )
    }

    pub(crate) fn for_test_with_transaction_id(
        transaction_id: String,
        target: DeviceIdentity,
        expected_auth_generation: u64,
        locked_at: ServerTimestamp,
    ) -> Self {
        Self {
            transaction_id,
            target,
            expected_auth_generation,
            expected_status: PersistedRegistrationStatus::Active,
            successor_status: PersistedRegistrationStatus::Revoked,
            locked_at,
            locked_row_digest: [1u8; 32],
        }
    }
}

impl RecoveryPackageCasBinding {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn conversation_id(&self) -> &[u8; 16] {
        &self.conversation_id
    }
    pub(crate) fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }
    pub(crate) fn target(&self) -> &DeviceIdentity {
        &self.target
    }
    pub(crate) fn target_key_id(&self) -> &[u8; 32] {
        &self.target_key_id
    }
    pub(crate) fn target_auth_generation(&self) -> u64 {
        self.target_auth_generation
    }
    pub(crate) fn bound_coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.bound_coordinate
    }
    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }
    pub(crate) fn key_package_wrapper_sha256(&self) -> &[u8; 32] {
        &self.key_package_wrapper_sha256
    }
    pub(crate) fn package_not_after(&self) -> ServerTimestamp {
        self.package_not_after
    }
    pub(crate) fn claimed_at(&self) -> ServerTimestamp {
        self.claimed_at
    }
    pub(crate) fn expected_status(&self) -> PackageStatus {
        self.expected_status
    }
    pub(crate) fn successor_status(&self) -> PackageStatus {
        self.successor_status
    }
    pub(crate) fn locked_row_digest(&self) -> &[u8; 32] {
        &self.locked_row_digest
    }
    pub(crate) fn authority_digest(&self) -> &[u8; 32] {
        &self.authority_digest
    }
}

impl PackageTransition {
    pub(crate) fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }

    pub(crate) fn from(&self) -> PackageStatus {
        self.from
    }

    pub(crate) fn to(&self) -> PackageStatus {
        self.to
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StateChange<T> {
    pub(in crate::chat_protocol::state_machine) before: Option<T>,
    pub(in crate::chat_protocol::state_machine) after: Option<T>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PlanAuthority {
    Transition(TransitionEvidence),
    Request(RequestEvidence),
    DeviceRevocation(DeviceRevocationEvidence),
    RecoveryExpiry(RecoveryExpiryPlanAuthority),
    WelcomeExpiry(WelcomeExpiryAuthority),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConversationHeadCasBinding {
    pub(in crate::chat_protocol::state_machine) transaction_id: String,
    pub(in crate::chat_protocol::state_machine) conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) expected_prior: Option<PublicGroupSnapshotCoordinate>,
    pub(in crate::chat_protocol::state_machine) expected_next_entry_seq: u64,
    pub(in crate::chat_protocol::state_machine) allocated_entry_id: Option<[u8; 16]>,
    pub(in crate::chat_protocol::state_machine) allocated_seq: Option<u64>,
    pub(in crate::chat_protocol::state_machine) successor_next_entry_seq: u64,
    pub(in crate::chat_protocol::state_machine) locked_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) locked_head_digest: [u8; 32],
}

impl ConversationHeadCasBinding {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(crate) fn conversation_id(&self) -> &[u8; 16] {
        &self.conversation_id
    }

    pub(crate) fn expected_prior(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.expected_prior.as_ref()
    }

    pub(crate) fn expected_next_entry_seq(&self) -> u64 {
        self.expected_next_entry_seq
    }

    pub(crate) fn allocated_entry_id(&self) -> Option<&[u8; 16]> {
        self.allocated_entry_id.as_ref()
    }

    pub(crate) fn allocated_seq(&self) -> Option<u64> {
        self.allocated_seq
    }

    pub(crate) fn successor_next_entry_seq(&self) -> u64 {
        self.successor_next_entry_seq
    }

    pub(crate) fn locked_at(&self) -> ServerTimestamp {
        self.locked_at
    }

    pub(crate) fn locked_head_digest(&self) -> &[u8; 32] {
        &self.locked_head_digest
    }
}

impl<T> StateChange<T> {
    pub(crate) fn before(&self) -> Option<&T> {
        self.before.as_ref()
    }

    pub(crate) fn after(&self) -> Option<&T> {
        self.after.as_ref()
    }

    pub(crate) fn into_parts(self) -> (Option<T>, Option<T>) {
        (self.before, self.after)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct StateCounts {
    pub(in crate::chat_protocol::state_machine) participants: usize,
    pub(in crate::chat_protocol::state_machine) pending_participants: usize,
    pub(in crate::chat_protocol::state_machine) active_participants: usize,
    pub(in crate::chat_protocol::state_machine) active_admins: usize,
    pub(in crate::chat_protocol::state_machine) leaves: usize,
    pub(in crate::chat_protocol::state_machine) intervals: usize,
    pub(in crate::chat_protocol::state_machine) open_intervals: usize,
    pub(in crate::chat_protocol::state_machine) terminal_proofs: usize,
    pub(in crate::chat_protocol::state_machine) open_recovery_requests: usize,
    pub(in crate::chat_protocol::state_machine) active_reservations: usize,
    pub(in crate::chat_protocol::state_machine) pending_reset_requests: usize,
    pub(in crate::chat_protocol::state_machine) pending_leave_requests: usize,
    pub(in crate::chat_protocol::state_machine) pending_welcomes: usize,
}

impl StateCounts {
    pub(crate) fn participants(&self) -> usize {
        self.participants
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransitionEffects {
    pub(in crate::chat_protocol::state_machine) kind: PlanKind,
    pub(in crate::chat_protocol::state_machine) opened_intervals: Vec<DeviceIdentity>,
    pub(in crate::chat_protocol::state_machine) closed_intervals: Vec<DeviceIdentity>,
    pub(in crate::chat_protocol::state_machine) superseded_recovery_requests: Vec<[u8; 16]>,
    pub(in crate::chat_protocol::state_machine) terminal_proof_recipients: Vec<DeviceIdentity>,
    pub(in crate::chat_protocol::state_machine) complete: bool,
    pub(in crate::chat_protocol::state_machine) before_counts: StateCounts,
    pub(in crate::chat_protocol::state_machine) after_counts: StateCounts,
    pub(in crate::chat_protocol::state_machine) metadata_change: Option<StateChange<MetadataSnapshotBinding>>,
    pub(in crate::chat_protocol::state_machine) policy_evidence_digest: Option<[u8; 32]>,
    pub(in crate::chat_protocol::state_machine) participant_changes: Vec<StateChange<ParticipantRecord>>,
    pub(in crate::chat_protocol::state_machine) leaf_changes: Vec<StateChange<LeafRecord>>,
    pub(in crate::chat_protocol::state_machine) interval_changes: Vec<StateChange<AccessInterval>>,
    pub(in crate::chat_protocol::state_machine) terminal_proof_changes: Vec<StateChange<ScheduleTerminalProof>>,
    pub(in crate::chat_protocol::state_machine) recovery_request_changes: Vec<StateChange<RecoveryRequest>>,
    pub(in crate::chat_protocol::state_machine) reservation_changes: Vec<StateChange<RecoveryReservation>>,
    pub(in crate::chat_protocol::state_machine) reset_request_changes: Vec<StateChange<ResetRequest>>,
    pub(in crate::chat_protocol::state_machine) leave_request_changes: Vec<StateChange<LeaveRequest>>,
    pub(in crate::chat_protocol::state_machine) welcome_changes: Vec<StateChange<WelcomeWork>>,
    pub(in crate::chat_protocol::state_machine) package_transitions: Vec<PackageTransition>,
    pub(in crate::chat_protocol::state_machine) recovery_package_cas: Vec<RecoveryPackageCasBinding>,
    pub(in crate::chat_protocol::state_machine) revocation_package_cas: Vec<RevocationPackageCasBinding>,
    pub(in crate::chat_protocol::state_machine) revocation_target_cas: Option<RevocationTargetCasBinding>,
    pub(in crate::chat_protocol::state_machine) welcome_cas: Option<WelcomeCasBinding>,
    pub(in crate::chat_protocol::state_machine) invitation_quota_cas: Option<InvitationQuotaCasBinding>,
    pub(in crate::chat_protocol::state_machine) authority: Option<PlanAuthority>,
    pub(in crate::chat_protocol::state_machine) head_cas: Option<ConversationHeadCasBinding>,
}
