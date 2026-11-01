#![allow(unused_imports)]
use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FederatedOperationAdmission {
    pub(in crate::chat_protocol::state_machine) actor_did: BareDid,
    pub(in crate::chat_protocol::state_machine) actor_device_id: CanonicalUuidV4,
    pub(in crate::chat_protocol::state_machine) actor_key_id: KeyThumbprint,
    pub(in crate::chat_protocol::state_machine) registered_mls_signature_key: [u8; 32],
    pub(in crate::chat_protocol::state_machine) auth_generation: u64,
    pub(in crate::chat_protocol::state_machine) trusted_read_at: DateTime<Utc>,
    pub(in crate::chat_protocol::state_machine) transaction_id: String,
    pub(in crate::chat_protocol::state_machine) requester_ds: String,
    pub(in crate::chat_protocol::state_machine) conversation_id: Uuid,
    pub(in crate::chat_protocol::state_machine) delivery_id: Uuid,
    pub(in crate::chat_protocol::state_machine) envelope_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) operation_id: Uuid,
    pub(in crate::chat_protocol::state_machine) endpoint_nsid: String,
    pub(in crate::chat_protocol::state_machine) mutation_request_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) mutation_signature: [u8; 64],
    pub(in crate::chat_protocol::state_machine) durable_row_digest: [u8; 32],
}

impl FederatedOperationAdmission {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal(
        actor_did: BareDid,
        actor_device_id: CanonicalUuidV4,
        actor_key_id: KeyThumbprint,
        registered_mls_signature_key: [u8; 32],
        auth_generation: u64,
        trusted_read_at: DateTime<Utc>,
        transaction_id: String,
        requester_ds: String,
        conversation_id: Uuid,
        delivery_id: Uuid,
        envelope_digest: [u8; 32],
        operation_id: Uuid,
        endpoint_nsid: String,
        mutation_request_digest: [u8; 32],
        mutation_signature: [u8; 64],
    ) -> Result<Self, StateMachineError> {
        if requester_ds.is_empty() || transaction_id.is_empty() || endpoint_nsid.is_empty() {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let key_id: [u8; 32] = URL_SAFE_NO_PAD
            .decode(actor_key_id.as_str())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let trusted_timestamp =
            ServerTimestamp::from_unix_millis(trusted_read_at.timestamp_millis())?;
        let mut digest = Sha256::new();
        digest.update(b"CATBIRD-CHAT-REPOSITORY-AUTHORITY-GUARD\0");
        digest.update(*conversation_id.as_bytes());
        digest.update((actor_did.as_str().as_bytes().len() as u64).to_be_bytes());
        digest.update(actor_did.as_str().as_bytes());
        digest.update(*actor_device_id.as_bytes());
        digest.update(key_id);
        digest.update(registered_mls_signature_key);
        digest.update(auth_generation.to_be_bytes());
        digest.update(trusted_timestamp.unix_millis().to_be_bytes());
        digest.update((transaction_id.len() as u64).to_be_bytes());
        digest.update(transaction_id.as_bytes());
        digest.update((requester_ds.len() as u64).to_be_bytes());
        digest.update(requester_ds.as_bytes());
        digest.update(delivery_id.as_bytes());
        digest.update(envelope_digest);
        digest.update(operation_id.as_bytes());
        digest.update((endpoint_nsid.len() as u64).to_be_bytes());
        digest.update(endpoint_nsid.as_bytes());
        digest.update(mutation_request_digest);
        digest.update(mutation_signature);
        Ok(Self {
            actor_did,
            actor_device_id,
            actor_key_id,
            registered_mls_signature_key,
            auth_generation,
            trusted_read_at,
            transaction_id,
            requester_ds,
            conversation_id,
            delivery_id,
            envelope_digest,
            operation_id,
            endpoint_nsid,
            mutation_request_digest,
            mutation_signature,
            durable_row_digest: digest.finalize().into(),
        })
    }

    pub(crate) fn delivery_id(&self) -> Uuid {
        self.delivery_id
    }

    pub(crate) fn envelope_digest(&self) -> &[u8; 32] {
        &self.envelope_digest
    }

    pub(crate) fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub(crate) fn endpoint_nsid(&self) -> &str {
        &self.endpoint_nsid
    }

    pub(crate) fn mutation_request_digest(&self) -> &[u8; 32] {
        &self.mutation_request_digest
    }

    pub(crate) fn mutation_signature(&self) -> &[u8; 64] {
        &self.mutation_signature
    }

    pub(crate) fn requester_ds(&self) -> &str {
        &self.requester_ds
    }

    pub(crate) fn actor_did(&self) -> &str {
        self.actor_did.as_str()
    }

    pub(crate) fn actor_device_id(&self) -> &CanonicalUuidV4 {
        &self.actor_device_id
    }

    pub(crate) fn actor_key_id(&self) -> &KeyThumbprint {
        &self.actor_key_id
    }

    pub(crate) fn actor_auth_generation(&self) -> u64 {
        self.auth_generation
    }

    pub(crate) fn trusted_read_at(&self) -> DateTime<Utc> {
        self.trusted_read_at
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
}

/// Exact available KeyPackage selection read under the same transaction that
/// will reserve it. The row is untrusted until `HydrationAuthority` validates
/// its digest, current registration binding, MLS wire, lifetime, and captured
/// server instant.
#[cfg(test)]
pub(crate) struct PersistedRecoveryReservationSelectionRow {
    pub(in crate::chat_protocol::state_machine) conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) target: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) target_key_id: [u8; 32],
    pub(in crate::chat_protocol::state_machine) target_auth_generation: u64,
    pub(in crate::chat_protocol::state_machine) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) key_package_ref: [u8; 32],
    pub(in crate::chat_protocol::state_machine) key_package_wrapper: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) key_package_wrapper_sha256: [u8; 32],
    pub(in crate::chat_protocol::state_machine) package_not_before: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) package_not_after: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) claimed_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) package_status: PackageStatus,
    pub(in crate::chat_protocol::state_machine) durable_row_digest: [u8; 32],
}

#[cfg(test)]
impl PersistedRecoveryReservationSelectionRow {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        conversation_id: [u8; 16],
        request_id: [u8; 16],
        target: DeviceIdentity,
        target_key_id: [u8; 32],
        target_auth_generation: u64,
        bound_coordinate: PublicGroupSnapshotCoordinate,
        key_package_ref: [u8; 32],
        key_package_wrapper: Vec<u8>,
        key_package_wrapper_sha256: [u8; 32],
        package_not_before: ServerTimestamp,
        package_not_after: ServerTimestamp,
        claimed_at: ServerTimestamp,
        package_status: PackageStatus,
        durable_row_digest: [u8; 32],
    ) -> Result<Self, StateMachineError> {
        if !is_uuid_v4(&conversation_id)
            || !is_uuid_v4(&request_id)
            || target_key_id == [0; 32]
            || target_auth_generation == 0
            || target_auth_generation > MAX_PROTOCOL_INTEGER
            || key_package_ref == [0; 32]
            || key_package_wrapper.is_empty()
            || key_package_wrapper_sha256 == [0; 32]
            || durable_row_digest == [0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            conversation_id,
            request_id,
            target,
            target_key_id,
            target_auth_generation,
            bound_coordinate,
            key_package_ref,
            key_package_wrapper,
            key_package_wrapper_sha256,
            package_not_before,
            package_not_after,
            claimed_at,
            package_status,
            durable_row_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn expected_digest(
        conversation_id: [u8; 16],
        request_id: [u8; 16],
        target: &DeviceIdentity,
        target_key_id: [u8; 32],
        target_auth_generation: u64,
        bound_coordinate: &PublicGroupSnapshotCoordinate,
        key_package_ref: [u8; 32],
        key_package_wrapper: &[u8],
        key_package_wrapper_sha256: [u8; 32],
        package_not_before: ServerTimestamp,
        package_not_after: ServerTimestamp,
        claimed_at: ServerTimestamp,
        package_status: PackageStatus,
    ) -> [u8; 32] {
        recovery_reservation_selection_digest_fields(
            &conversation_id,
            &request_id,
            target,
            &target_key_id,
            target_auth_generation,
            bound_coordinate,
            &key_package_ref,
            key_package_wrapper,
            &key_package_wrapper_sha256,
            package_not_before,
            package_not_after,
            claimed_at,
            package_status,
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LockedRecoveryReservationProjection {
    pub(in crate::chat_protocol::state_machine) conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) target: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) target_key_id: [u8; 32],
    pub(in crate::chat_protocol::state_machine) target_auth_generation: u64,
    pub(in crate::chat_protocol::state_machine) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) key_package_ref: [u8; 32],
    pub(in crate::chat_protocol::state_machine) key_package_wrapper: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) key_package_wrapper_sha256: [u8; 32],
    pub(in crate::chat_protocol::state_machine) package_not_after: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) claimed_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) durable_row_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) transaction_id: String,
}

impl LockedRecoveryReservationProjection {
    pub(in crate::chat_protocol::state_machine) fn authorizes_acceptance(
        &self,
        transition: &TransitionEvidence,
    ) -> bool {
        let Some(TransitionBodyBinding::Acceptance { recovery, .. }) =
            transition.body_binding.as_ref()
        else {
            return false;
        };
        transition.received_at == self.claimed_at
            && recovery.request_id == self.request_id
            && recovery.conversation_id == self.conversation_id
            && recovery.target == self.target
            && recovery.kind == LeafRecoveryKind::Add
            && recovery.bound_coordinate == self.bound_coordinate
            && recovery.requester_key_id == self.target_key_id
            && recovery.requester_auth_generation == self.target_auth_generation
            && recovery.key_package_ref == self.key_package_ref
            && recovery.key_package_wrapper == self.key_package_wrapper
            && recovery.key_package_wrapper_sha256 == self.key_package_wrapper_sha256
            && recovery.requested_at == self.claimed_at
            && recovery.expires_at
                == recovery_expiry(self.claimed_at, self.package_not_after)
                    .ok()
                    .unwrap_or(
                        // impossible sentinel: valid timestamps can never be negative
                        ServerTimestamp(-1),
                    )
            && self.durable_row_digest != [0; 32]
    }

    pub(in crate::chat_protocol::state_machine) fn authorizes_request(
        &self,
        evidence: &RequestEvidence,
        kind: LeafRecoveryKind,
    ) -> bool {
        evidence.kind == RequestEntryKind::LeafRecoveryRequest
            && evidence.conversation_id == self.conversation_id
            && evidence.request_id == self.request_id
            && evidence.actor == self.target
            && evidence.key_id == self.target_key_id
            && evidence.auth_generation == self.target_auth_generation
            && evidence.received_at == self.claimed_at
            && matches!(
                evidence.body_binding.as_ref(),
                Some(RequestBodyBinding::LeafRecoveryRequest { prior, kind: signed_kind })
                    if prior == &self.bound_coordinate && signed_kind == &kind
            )
            && self.durable_row_digest != [0; 32]
    }

    pub(crate) fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Exact request-bound target identity and package projection retained for
    /// acceptance control-entry server fields. These accessors expose only
    /// validated, transaction-bound values selected by the locked row.
    pub(crate) fn conversation_id(&self) -> &[u8; 16] {
        &self.conversation_id
    }

    pub(crate) fn target_key_id(&self) -> &[u8; 32] {
        &self.target_key_id
    }

    pub(crate) fn target_auth_generation(&self) -> u64 {
        self.target_auth_generation
    }

    pub(crate) fn key_package_wrapper(&self) -> &[u8] {
        &self.key_package_wrapper
    }

    pub(crate) fn key_package_wrapper_sha256(&self) -> &[u8; 32] {
        &self.key_package_wrapper_sha256
    }

    pub(crate) fn claimed_at(&self) -> ServerTimestamp {
        self.claimed_at
    }

    pub(crate) fn target(&self) -> &DeviceIdentity {
        &self.target
    }

    pub(crate) fn bound_coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.bound_coordinate
    }

    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }

    pub(crate) fn package_not_after(&self) -> ServerTimestamp {
        self.package_not_after
    }

    pub(in crate::chat_protocol::state_machine) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(in crate::chat_protocol::state_machine) fn available_package_cas(
        &self,
    ) -> RecoveryPackageCasBinding {
        let mut binding = RecoveryPackageCasBinding {
            transaction_id: self.transaction_id.clone(),
            conversation_id: self.conversation_id,
            request_id: self.request_id,
            target: self.target.clone(),
            target_key_id: self.target_key_id,
            target_auth_generation: self.target_auth_generation,
            bound_coordinate: self.bound_coordinate,
            key_package_ref: self.key_package_ref,
            key_package_wrapper_sha256: self.key_package_wrapper_sha256,
            package_not_after: self.package_not_after,
            claimed_at: self.claimed_at,
            expected_status: PackageStatus::Available,
            successor_status: PackageStatus::Reserved,
            locked_row_digest: self.durable_row_digest,
            authority_digest: [0; 32],
        };
        binding.authority_digest = recovery_package_cas_authority_digest(&binding);
        binding
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        evidence: &RequestEvidence,
        bound_coordinate: PublicGroupSnapshotCoordinate,
        key_package_ref: [u8; 32],
        package_not_after: ServerTimestamp,
    ) -> Self {
        Self {
            conversation_id: evidence.conversation_id,
            request_id: evidence.request_id,
            target: evidence.actor.clone(),
            target_key_id: evidence.key_id,
            target_auth_generation: evidence.auth_generation,
            bound_coordinate,
            key_package_ref,
            key_package_wrapper: vec![0x42],
            key_package_wrapper_sha256: Sha256::digest([0x42]).into(),
            package_not_after,
            claimed_at: evidence.received_at,
            durable_row_digest: [0x8d; 32],
            // Pure state-machine tests never cross the locked repository
            // facade; an empty transaction identity therefore remains
            // deliberately unusable by every production package-CAS binder.
            transaction_id: String::new(),
        }
    }
}

pub(crate) fn historical_available_package_cas(
    guard: LockedRecoveryPackageGuard,
    transition: &TransitionEvidence,
    transaction_id: &str,
) -> Result<RecoveryPackageCasBinding, StateMachineError> {
    let Some(TransitionBodyBinding::Acceptance { recovery, .. }) = transition.body_binding.as_ref()
    else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    let target_key_id: [u8; 32] = URL_SAFE_NO_PAD
        .decode(
            KeyThumbprint::parse(guard.target_key_id())
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
                .as_str(),
        )
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
        .try_into()
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
    let target_auth_generation = u64::try_from(guard.target_auth_generation())
        .ok()
        .filter(|value| (1..=MAX_PROTOCOL_INTEGER).contains(value))
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
    let claimed_at = ServerTimestamp::from_unix_millis(guard.claimed_at().timestamp_millis())?;
    let package_not_after =
        ServerTimestamp::from_unix_millis(guard.not_after().timestamp_millis())?;
    let expected_expiry = recovery_expiry(claimed_at, package_not_after)?;

    if guard.transaction_id() != transaction_id
        || guard.status() != LockedRecoveryPackageStatus::Available
        || guard.use_kind() != LockedRecoveryPackageUse::AvailableSelection
        || guard.durable_row_digest() == &[0; 32]
        || transition.received_at != claimed_at
        || recovery.request_id != *guard.request_id().as_bytes()
        || recovery.conversation_id != *guard.conversation_id().as_bytes()
        || recovery.target.principal().as_bytes() != guard.target_did().as_bytes()
        || recovery.target.device_id() != guard.target_device_id().as_bytes()
        || recovery.kind != LeafRecoveryKind::Add
        || recovery.bound_coordinate != *guard.bound_coordinate()
        || recovery.requester_key_id != target_key_id
        || recovery.requester_auth_generation != target_auth_generation
        || recovery.key_package_ref != *guard.key_package_ref()
        || recovery.key_package_wrapper != guard.wrapper_bytes()
        || recovery.key_package_wrapper_sha256 != *guard.wrapper_sha256()
        || recovery.requested_at != claimed_at
        || recovery.expires_at != expected_expiry
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }

    let mut binding = RecoveryPackageCasBinding {
        transaction_id: transaction_id.to_owned(),
        conversation_id: *guard.conversation_id().as_bytes(),
        request_id: *guard.request_id().as_bytes(),
        target: recovery.target.clone(),
        target_key_id,
        target_auth_generation,
        bound_coordinate: recovery.bound_coordinate,
        key_package_ref: *guard.key_package_ref(),
        key_package_wrapper_sha256: *guard.wrapper_sha256(),
        package_not_after,
        claimed_at: recovery.requested_at,
        expected_status: PackageStatus::Available,
        successor_status: PackageStatus::Reserved,
        locked_row_digest: *guard.durable_row_digest(),
        authority_digest: [0; 32],
    };
    binding.authority_digest = recovery_package_cas_authority_digest(&binding);
    Ok(binding)
}

pub(crate) fn reserved_package_cas_for_request(
    guard: LockedRecoveryPackageGuard,
    request: &RecoveryRequest,
    reservation: &RecoveryReservation,
    transaction_id: &str,
    successor_status: PackageStatus,
) -> Result<RecoveryPackageCasBinding, StateMachineError> {
    let target_key_id: [u8; 32] = URL_SAFE_NO_PAD
        .decode(
            KeyThumbprint::parse(guard.target_key_id())
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
                .as_str(),
        )
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
        .try_into()
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
    let target_auth_generation = u64::try_from(guard.target_auth_generation())
        .ok()
        .filter(|value| (1..=MAX_PROTOCOL_INTEGER).contains(value))
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
    let (origin_key_id, origin_auth_generation, origin_digest) = match &request.origin {
        RecoveryOriginEvidence::Acceptance(value) => {
            let authority = value
                .authority
                .as_ref()
                .ok_or(StateMachineError::InvalidHydrationAuthority)?;
            (
                authority.key_id,
                authority.auth_generation,
                value.outer_entry_fingerprint,
            )
        }
        RecoveryOriginEvidence::Request(value) => (
            value.key_id,
            value.auth_generation,
            value.durable_row_digest,
        ),
    };
    let claimed_at = ServerTimestamp::from_unix_millis(guard.claimed_at().timestamp_millis())?;
    let not_after = ServerTimestamp::from_unix_millis(guard.not_after().timestamp_millis())?;
    let reservation_created_at = guard
        .reservation_created_at()
        .ok_or(StateMachineError::InvalidHydrationAuthority)
        .and_then(|value| ServerTimestamp::from_unix_millis(value.timestamp_millis()))?;
    let reservation_expires_at = guard
        .reservation_expires_at()
        .ok_or(StateMachineError::InvalidHydrationAuthority)
        .and_then(|value| ServerTimestamp::from_unix_millis(value.timestamp_millis()))?;
    if guard.transaction_id() != transaction_id
        || guard.status() != LockedRecoveryPackageStatus::Reserved
        || guard.use_kind() != LockedRecoveryPackageUse::ReservedFulfillment
        || guard.conversation_id().as_bytes() != request.bound_coordinate.conversation_id()
        || guard.request_id().as_bytes() != &request.request_id
        || guard.target_did().as_bytes() != request.target.principal().as_bytes()
        || guard.target_device_id().as_bytes() != request.target.device_id()
        || target_key_id != origin_key_id
        || target_auth_generation != origin_auth_generation
        || guard.bound_coordinate() != &request.bound_coordinate
        || guard.key_package_ref() != &request.key_package_ref
        || claimed_at != request.received_at
        || not_after != reservation.package_not_after
        || reservation_created_at != reservation.received_at
        || reservation_expires_at != reservation.expires_at
        || guard.request_provenance_digest() != Some(&origin_digest)
        || reservation.request_id != request.request_id
        || reservation.target != request.target
        || reservation.bound_coordinate != request.bound_coordinate
        || reservation.key_package_ref != request.key_package_ref
        || reservation.status != ReservationStatus::Active
        || guard.durable_row_digest() == &[0; 32]
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let mut binding = RecoveryPackageCasBinding {
        transaction_id: transaction_id.to_owned(),
        conversation_id: *request.bound_coordinate.conversation_id(),
        request_id: request.request_id,
        target: request.target.clone(),
        target_key_id,
        target_auth_generation,
        bound_coordinate: request.bound_coordinate,
        key_package_ref: request.key_package_ref,
        key_package_wrapper_sha256: *guard.wrapper_sha256(),
        package_not_after: not_after,
        claimed_at,
        expected_status: PackageStatus::Reserved,
        successor_status,
        locked_row_digest: *guard.durable_row_digest(),
        authority_digest: [0; 32],
    };
    binding.authority_digest = recovery_package_cas_authority_digest(&binding);
    Ok(binding)
}

#[cfg(test)]
pub(in crate::chat_protocol::state_machine) fn recovery_reservation_selection_digest(
    row: &PersistedRecoveryReservationSelectionRow,
) -> [u8; 32] {
    recovery_reservation_selection_digest_fields(
        &row.conversation_id,
        &row.request_id,
        &row.target,
        &row.target_key_id,
        row.target_auth_generation,
        &row.bound_coordinate,
        &row.key_package_ref,
        &row.key_package_wrapper,
        &row.key_package_wrapper_sha256,
        row.package_not_before,
        row.package_not_after,
        row.claimed_at,
        row.package_status,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(in crate::chat_protocol::state_machine) fn recovery_reservation_selection_digest_fields(
    conversation_id: &[u8; 16],
    request_id: &[u8; 16],
    target: &DeviceIdentity,
    target_key_id: &[u8; 32],
    target_auth_generation: u64,
    bound_coordinate: &PublicGroupSnapshotCoordinate,
    key_package_ref: &[u8; 32],
    key_package_wrapper: &[u8],
    key_package_wrapper_sha256: &[u8; 32],
    package_not_before: ServerTimestamp,
    package_not_after: ServerTimestamp,
    claimed_at: ServerTimestamp,
    package_status: PackageStatus,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-RECOVERY-PACKAGE\0");
    digest.update(conversation_id);
    digest.update(request_id);
    digest.update((target.principal().as_bytes().len() as u64).to_be_bytes());
    digest.update(target.principal().as_bytes());
    digest.update(target.device_id());
    digest.update(target_key_id);
    digest.update(target_auth_generation.to_be_bytes());
    digest.update(coordinate_digest(bound_coordinate));
    digest.update(key_package_ref);
    digest.update((key_package_wrapper.len() as u64).to_be_bytes());
    digest.update(key_package_wrapper);
    digest.update(key_package_wrapper_sha256);
    digest.update(package_not_before.unix_millis().to_be_bytes());
    digest.update(package_not_after.unix_millis().to_be_bytes());
    digest.update(claimed_at.unix_millis().to_be_bytes());
    digest.update([package_status as u8]);
    digest.finalize().into()
}

#[cfg(test)]
pub(in crate::chat_protocol::state_machine) fn coordinate_digest(
    coordinate: &PublicGroupSnapshotCoordinate,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-COORDINATE\0");
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
    digest.finalize().into()
}

#[cfg(test)]
pub(in crate::chat_protocol::state_machine) fn uuid_from_test_byte(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x40 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine) enum WorkTerminalEvidence {
    Transition(TransitionEvidence),
    Request(RequestEvidence),
    DeviceRevocation(DeviceRevocationEvidence),
    Expiry(ServerTimestamp),
}

pub(in crate::chat_protocol::state_machine) fn validate_request_evidence(
    evidence: &RequestEvidence,
    expected_kind: RequestEntryKind,
    expected_conversation_id: &[u8; 16],
    expected_request_id: &[u8; 16],
    expected_actor: &DeviceIdentity,
    expected_received_at: ServerTimestamp,
) -> Result<(), StateMachineError> {
    let is_control = matches!(
        evidence.kind,
        RequestEntryKind::ResetRequest
            | RequestEntryKind::LeaveRequest
            | RequestEntryKind::LeaveCancellation
    );
    let control_shape_is_valid = if is_control {
        evidence.control_entry_id.is_some_and(|id| is_uuid_v4(&id))
            && evidence
                .control_seq
                .is_some_and(|seq| seq > 0 && seq <= MAX_PROTOCOL_INTEGER)
            && (evidence.authority.is_none()
                || (evidence
                    .control_outer_entry_fingerprint
                    .is_some_and(|digest| digest != [0; 32])
                    && evidence
                        .control_outer_projection
                        .as_ref()
                        .is_some_and(|bytes| !bytes.is_empty())
                    && evidence
                        .control_server_fields_dag_cbor
                        .as_ref()
                        .is_some_and(|bytes| !bytes.is_empty())))
    } else {
        evidence.control_entry_id.is_none()
            && evidence.control_seq.is_none()
            && evidence.control_outer_entry_fingerprint.is_none()
            && evidence.control_outer_projection.is_none()
            && evidence.control_server_fields_dag_cbor.is_none()
    };
    if evidence.kind != expected_kind
        || &evidence.conversation_id != expected_conversation_id
        || &evidence.request_id != expected_request_id
        || &evidence.actor != expected_actor
        || evidence.received_at != expected_received_at
        || evidence.auth_generation == 0
        || evidence.auth_generation > MAX_PROTOCOL_INTEGER
        || evidence.key_id == [0; 32]
        || evidence.request_digest == [0; 32]
        || evidence.signature == [0; 64]
        || evidence.signed_request_bytes.is_empty()
        || evidence.durable_row_digest == [0; 32]
        || !control_shape_is_valid
        || evidence.body_binding.as_ref().is_some_and(|binding| {
            !matches!(
                (evidence.kind, binding),
                (
                    RequestEntryKind::LeafRecoveryRequest,
                    RequestBodyBinding::LeafRecoveryRequest { .. }
                ) | (
                    RequestEntryKind::LeafRecoveryCancellation,
                    RequestBodyBinding::LeafRecoveryCancellation
                ) | (
                    RequestEntryKind::ResetRequest,
                    RequestBodyBinding::ResetRequest { .. }
                ) | (
                    RequestEntryKind::LeaveRequest,
                    RequestBodyBinding::LeaveRequest { .. }
                ) | (
                    RequestEntryKind::LeaveCancellation,
                    RequestBodyBinding::LeaveCancellation { .. }
                ) | (
                    RequestEntryKind::WelcomeAcknowledgement | RequestEntryKind::WelcomeRejection,
                    RequestBodyBinding::WelcomeResponse { .. }
                )
            )
        })
        || evidence.authority.as_ref().is_some_and(|authority| {
            authority.kind != request_entry_signed_kind(evidence.kind)
                || authority.type_id != authority.kind.type_id()
                || authority.domain != authority.kind.domain()
                || authority.control_entry_id != evidence.control_entry_id
                || authority.control_conversation_id
                    != is_control.then_some(evidence.conversation_id)
                || authority.actor != evidence.actor
                || authority.key_id != evidence.key_id
                || authority.auth_generation != evidence.auth_generation
                || authority.request_digest != evidence.request_digest
                || authority.signature != evidence.signature
                || authority.signed_request_bytes != evidence.signed_request_bytes
                || authority.canonical_projection.is_empty()
                || authority.transcript_bytes.is_empty()
                || authority.signed_at > evidence.received_at
        })
        || (evidence.authority.is_some()
            && if is_control {
                durable_control_request_row_digest(evidence)
                    .map_or(true, |digest| evidence.durable_row_digest != digest)
            } else {
                evidence.durable_row_digest != durable_signed_request_evidence_digest(evidence)
            })
    {
        return Err(StateMachineError::InvalidTransition);
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn durable_signed_request_evidence_digest(
    evidence: &RequestEvidence,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-DURABLE-SIGNED-ROW\0");
    digest.update([evidence.kind as u8]);
    digest.update(evidence.conversation_id);
    digest.update(evidence.request_id);
    digest.update(evidence.received_at.unix_millis().to_be_bytes());
    digest.update(evidence.request_digest);
    digest.update(evidence.signature);
    digest.update((evidence.signed_request_bytes.len() as u64).to_be_bytes());
    digest.update(&evidence.signed_request_bytes);
    digest.finalize().into()
}

pub(in crate::chat_protocol::state_machine) fn durable_control_transition_row_digest(
    evidence: &TransitionEvidence,
) -> Result<[u8; 32], StateMachineError> {
    let authority = evidence
        .authority
        .as_ref()
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
    durable_control_row_digest(
        authority
            .control_entry_id
            .ok_or(StateMachineError::InvalidHydrationAuthority)?,
        authority
            .control_conversation_id
            .ok_or(StateMachineError::InvalidHydrationAuthority)?,
        evidence.seq,
        evidence.received_at,
        evidence.outer_entry_fingerprint,
        &evidence.outer_control_projection,
        &evidence.server_fields_dag_cbor,
        authority,
    )
}

pub(in crate::chat_protocol::state_machine) fn durable_control_request_row_digest(
    evidence: &RequestEvidence,
) -> Result<[u8; 32], StateMachineError> {
    let authority = evidence
        .authority
        .as_ref()
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
    durable_control_row_digest(
        evidence
            .control_entry_id
            .ok_or(StateMachineError::InvalidHydrationAuthority)?,
        evidence.conversation_id,
        evidence
            .control_seq
            .ok_or(StateMachineError::InvalidHydrationAuthority)?,
        evidence.received_at,
        evidence
            .control_outer_entry_fingerprint
            .ok_or(StateMachineError::InvalidHydrationAuthority)?,
        evidence
            .control_outer_projection
            .as_deref()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?,
        evidence
            .control_server_fields_dag_cbor
            .as_deref()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?,
        authority,
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine) fn durable_control_row_digest(
    entry_id: [u8; 16],
    conversation_id: [u8; 16],
    seq: u64,
    received_at: ServerTimestamp,
    outer_entry_fingerprint: [u8; 32],
    outer_control_projection: &[u8],
    server_fields_dag_cbor: &[u8],
    authority: &AuthenticatedEntryEvidence,
) -> Result<[u8; 32], StateMachineError> {
    if !is_uuid_v4(&entry_id)
        || !is_uuid_v4(&conversation_id)
        || !(1..=MAX_PROTOCOL_INTEGER).contains(&seq)
        || outer_entry_fingerprint == [0; 32]
        || outer_control_projection.is_empty()
        || server_fields_dag_cbor.is_empty()
        || authority.signed_request_bytes.is_empty()
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-DURABLE-CONTROL-ROW\0");
    digest.update(entry_id);
    digest.update(conversation_id);
    digest.update(seq.to_be_bytes());
    digest.update(received_at.unix_millis().to_be_bytes());
    digest.update(outer_entry_fingerprint);
    digest.update((outer_control_projection.len() as u64).to_be_bytes());
    digest.update(outer_control_projection);
    digest.update((server_fields_dag_cbor.len() as u64).to_be_bytes());
    digest.update(server_fields_dag_cbor);
    digest.update(authority.request_digest);
    digest.update(authority.signature);
    digest.update((authority.signed_request_bytes.len() as u64).to_be_bytes());
    digest.update(&authority.signed_request_bytes);
    Ok(digest.finalize().into())
}

pub(in crate::chat_protocol::state_machine) fn require_request_prior(
    evidence: &RequestEvidence,
    expected: &PublicGroupSnapshotCoordinate,
) -> Result<(), StateMachineError> {
    let bound_prior = match evidence.body_binding.as_ref() {
        Some(RequestBodyBinding::LeafRecoveryRequest { prior, .. })
        | Some(RequestBodyBinding::ResetRequest { prior })
        | Some(RequestBodyBinding::LeaveRequest { prior }) => Some(prior),
        Some(_) => return Err(StateMachineError::InvalidTransition),
        None => None,
    };
    if bound_prior.is_some_and(|prior| prior != expected) {
        return Err(StateMachineError::StaleCoordinates);
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn require_leaf_recovery_request_binding(
    evidence: &RequestEvidence,
    expected_prior: &PublicGroupSnapshotCoordinate,
    expected_kind: LeafRecoveryKind,
) -> Result<(), StateMachineError> {
    match evidence.body_binding.as_ref() {
        Some(RequestBodyBinding::LeafRecoveryRequest { prior, kind })
            if prior == expected_prior && *kind == expected_kind =>
        {
            Ok(())
        }
        Some(RequestBodyBinding::LeafRecoveryRequest { prior, .. }) if prior != expected_prior => {
            Err(StateMachineError::StaleCoordinates)
        }
        Some(_) => Err(StateMachineError::RecoveryKindMismatch),
        None => Ok(()),
    }
}
