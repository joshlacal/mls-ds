#![allow(unused_imports)]
use super::*;


impl HydrationAuthority {

    /// Re-enters a persisted public control row only after re-verifying its
    /// separately retained exact signed wrapper. Stored canonical projection,
    /// special server fields, fingerprint, and the digest of the complete
    /// durable row are all compared before sealed state evidence is returned.
    pub(crate) fn hydrate_persisted_control(
        &self,
        row: PersistedControlRow,
        historical_public_key: &[u8],
    ) -> Result<PersistedControlAuthority, StateMachineError> {
        let PersistedControlRow {
            public_row_json,
            raw_signed_wrapper,
            outer_control_projection,
            server_fields_dag_cbor,
            outer_entry_fingerprint,
            durable_row_digest,
        } = row;
        let decoded = decode_and_verify_control_entry(&public_row_json, historical_public_key)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        if decoded.conversation_id().as_bytes() != &self.expected_conversation_id
            || decoded.outer_control_projection() != outer_control_projection
            || decoded.outer_control_fingerprint() != &outer_entry_fingerprint
            || decoded
                .server_fields_dag_cbor()
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
                != server_fields_dag_cbor
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let entry =
            rebind_persisted_control_entry(decoded, &raw_signed_wrapper, historical_public_key)
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        match entry.mutation().projection() {
            VerifiedMutationProjection::ResetRequest(_)
            | VerifiedMutationProjection::LeaveRequest(_)
            | VerifiedMutationProjection::LeaveCancellation(_) => {
                let evidence = self.control_request(entry)?;
                if evidence.durable_row_digest != durable_row_digest {
                    return Err(StateMachineError::InvalidHydrationAuthority);
                }
                Ok(PersistedControlAuthority::Request(evidence))
            }
            _ => {
                let evidence = self.transition_from_control(&entry)?;
                if evidence.durable_row_digest != durable_row_digest {
                    return Err(StateMachineError::InvalidHydrationAuthority);
                }
                Ok(PersistedControlAuthority::Transition(evidence))
            }
        }
    }

    /// Re-enters a persisted non-control request by strictly decoding its raw
    /// signed wrapper, verifying it with the historical public key, and
    /// checking the frozen digest of the complete durable row. Stored
    /// `receivedAt` participates in that digest and therefore cannot be
    /// rewritten during restart.
    pub(crate) fn hydrate_persisted_signed_request(
        &self,
        row: PersistedSignedRequestRow,
        raw_signed_request: &[u8],
        historical_public_key: &[u8],
    ) -> Result<RequestEvidence, StateMachineError> {
        let PersistedSignedRequestRow {
            conversation_id,
            received_at,
            durable_row_digest,
        } = row;
        let envelope = DurableSignedRequestEnvelope {
            conversation_id,
            received_at: canonical_server_timestamp(&received_at)?,
        };
        let mutation = decode_and_verify_signed_mutation(raw_signed_request, historical_public_key)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let evidence = self.signed_request(envelope, mutation)?;
        if evidence.durable_row_digest != durable_row_digest {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(evidence)
    }

    /// Re-verifies a persisted global device-revocation wrapper using its
    /// historical key and the frozen server acceptance instant.
    pub(crate) fn hydrate_persisted_device_revocation(
        row: PersistedDeviceRevocationRow,
        raw_signed_request: &[u8],
        historical_public_key: &[u8],
    ) -> Result<DeviceRevocationEvidence, StateMachineError> {
        let mutation = decode_and_verify_signed_mutation(raw_signed_request, historical_public_key)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let evidence =
            Self::device_revocation_at(mutation, canonical_server_timestamp(&row.accepted_at)?)?;
        if evidence.durable_row_digest != row.durable_row_digest {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(evidence)
    }

    /// Re-verifies one exact durable `chat.device_revocations` row.
    ///
    /// Device revocations are global and entry-less, so there is no conversation
    /// head or control sequence to bind. Their authority is instead the strict
    /// signed `revokeDevice` wrapper under the actor's historical key plus exact
    /// equality against every immutable durable field. This seam deliberately
    /// accepts no precomputed evidence or caller-supplied row digest: it re-runs
    /// the certified signed-mutation decoder, mints through `device_revocation_at`,
    /// and then compares the resulting evidence field-for-field with the row.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn hydrate_persisted_device_revocation_from_durable_fields(
        revocation_id: [u8; 16],
        actor: DeviceIdentity,
        target: DeviceIdentity,
        actor_key_id: [u8; 32],
        actor_auth_generation: u64,
        expected_target_auth_generation: u64,
        raw_signed_request: &[u8],
        signing_transcript_bytes: &[u8],
        request_digest: [u8; 32],
        signature: [u8; 64],
        signed_at: &str,
        accepted_at: &str,
        historical_public_key: &[u8],
    ) -> Result<DeviceRevocationEvidence, StateMachineError> {
        let mutation = decode_and_verify_signed_mutation(raw_signed_request, historical_public_key)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let accepted_at = canonical_server_timestamp(
            &CanonicalTimestamp::parse(accepted_at)
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        )?;
        let signed_at = canonical_server_timestamp(
            &CanonicalTimestamp::parse(signed_at)
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        )?;
        let evidence = Self::device_revocation_at(mutation, accepted_at)?;
        if evidence.revocation_id != revocation_id
            || evidence.actor != actor
            || evidence.target != target
            || evidence.actor_key_id != actor_key_id
            || evidence.actor_auth_generation != actor_auth_generation
            || evidence.expected_target_auth_generation != expected_target_auth_generation
            || evidence.signed_at != signed_at
            || evidence.accepted_at != accepted_at
            || evidence.request_digest != request_digest
            || evidence.signature != signature
            || evidence.signed_request_bytes.as_slice() != raw_signed_request
            || evidence.signing_transcript_bytes.as_slice() != signing_transcript_bytes
            || !validate_device_revocation_evidence(&evidence)
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(evidence)
    }

    /// Seals one canonical persisted device/key row at a trusted read instant.
    /// Planners can consume only this projection, never caller-asserted
    /// registration booleans or loose key fields.
    #[cfg(test)]
    pub(crate) fn locked_registration(
        &self,
        row: PersistedRegistrationRow,
        trusted_read_at: &TrustedRequestInstant,
    ) -> Result<LockedRegistrationProjection, StateMachineError> {
        if row.conversation_id != self.expected_conversation_id
            || row.auth_generation == 0
            || row.auth_generation > MAX_PROTOCOL_INTEGER
            || row.key_id == [0; 32]
            || row.registered_mls_signature_key == [0; 32]
            || registration_row_digest(&row) != row.durable_row_digest
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(LockedRegistrationProjection {
            conversation_id: row.conversation_id,
            actor: row.actor,
            key_id: row.key_id,
            registered_mls_signature_key: row.registered_mls_signature_key,
            auth_generation: row.auth_generation,
            status: row.status,
            trusted_read_at: ServerTimestamp::from_trusted_request_instant(trusted_read_at)?,
            durable_row_digest: row.durable_row_digest,
            transaction_id: String::new(),
            authority_scope_digest: [0; 32],
        })
    }

    pub(crate) fn locked_registration_from_guard(
        &self,
        guard: BusinessAuthorityGuard,
    ) -> Result<LockedRegistrationProjection, StateMachineError> {
        if guard.class() != RepositoryAuthorityClass::ExistingDevice {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let did = BareDid::parse(guard.subject())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let actor = DeviceIdentity::new(
            PrincipalId::new(did.as_str().as_bytes().to_vec())?,
            *guard.device_id().as_bytes(),
        )?;
        let key = guard
            .stored_key_id()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let key =
            KeyThumbprint::parse(key).map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let key_id: [u8; 32] = URL_SAFE_NO_PAD
            .decode(key.as_str())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let registered_mls_signature_key: [u8; 32] = guard
            .stored_signing_public_key()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let auth_generation = u64::try_from(
            guard
                .stored_auth_generation()
                .ok_or(StateMachineError::InvalidHydrationAuthority)?,
        )
        .ok()
        .filter(|value| *value > 0 && *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let trusted_read_at =
            ServerTimestamp::from_unix_millis(guard.trusted_instant().timestamp_millis())?;
        let mut digest = Sha256::new();
        digest.update(b"CATBIRD-CHAT-REPOSITORY-AUTHORITY-GUARD\0");
        digest.update(self.expected_conversation_id);
        digest.update((actor.principal().as_bytes().len() as u64).to_be_bytes());
        digest.update(actor.principal().as_bytes());
        digest.update(actor.device_id());
        digest.update(key_id);
        digest.update(registered_mls_signature_key);
        digest.update(auth_generation.to_be_bytes());
        digest.update(trusted_read_at.unix_millis().to_be_bytes());
        Ok(LockedRegistrationProjection {
            conversation_id: self.expected_conversation_id,
            actor,
            key_id,
            registered_mls_signature_key,
            auth_generation,
            status: PersistedRegistrationStatus::Active,
            trusted_read_at,
            durable_row_digest: digest.finalize().into(),
            transaction_id: guard.transaction_id().to_owned(),
            authority_scope_digest: [0; 32],
        })
    }

    pub(crate) fn locked_registration_from_federated_admission(
        &self,
        admission: &FederatedOperationAdmission,
    ) -> Result<LockedRegistrationProjection, StateMachineError> {
        if admission.conversation_id != Uuid::from_bytes(self.expected_conversation_id) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let actor = DeviceIdentity::new(
            PrincipalId::new(admission.actor_did.as_str().as_bytes().to_vec())?,
            *admission.actor_device_id.as_bytes(),
        )?;
        let key_id: [u8; 32] = URL_SAFE_NO_PAD
            .decode(admission.actor_key_id.as_str())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let trusted_read_at =
            ServerTimestamp::from_unix_millis(admission.trusted_read_at.timestamp_millis())?;
        let transaction_id = self
            .locked
            .as_ref()
            .map(|l| l.transaction_id.clone())
            .unwrap_or_default();
        if !transaction_id.is_empty() && transaction_id != admission.transaction_id {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let mut digest = Sha256::new();
        digest.update(b"CATBIRD-CHAT-REPOSITORY-AUTHORITY-GUARD\0");
        digest.update(self.expected_conversation_id);
        digest.update((actor.principal().as_bytes().len() as u64).to_be_bytes());
        digest.update(actor.principal().as_bytes());
        digest.update(actor.device_id());
        digest.update(key_id);
        digest.update(admission.registered_mls_signature_key);
        digest.update(admission.auth_generation.to_be_bytes());
        digest.update(trusted_read_at.unix_millis().to_be_bytes());
        digest.update((admission.transaction_id.len() as u64).to_be_bytes());
        digest.update(admission.transaction_id.as_bytes());
        digest.update((admission.requester_ds.len() as u64).to_be_bytes());
        digest.update(admission.requester_ds.as_bytes());
        digest.update(admission.delivery_id.as_bytes());
        digest.update(admission.envelope_digest);
        digest.update(admission.operation_id.as_bytes());
        digest.update((admission.endpoint_nsid.len() as u64).to_be_bytes());
        digest.update(admission.endpoint_nsid.as_bytes());
        digest.update(admission.mutation_request_digest);
        digest.update(admission.mutation_signature);
        let computed_row_digest: [u8; 32] = digest.finalize().into();
        if computed_row_digest != admission.durable_row_digest {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(LockedRegistrationProjection {
            conversation_id: self.expected_conversation_id,
            actor,
            key_id,
            registered_mls_signature_key: admission.registered_mls_signature_key,
            auth_generation: admission.auth_generation,
            status: PersistedRegistrationStatus::Active,
            trusted_read_at,
            durable_row_digest: computed_row_digest,
            transaction_id: transaction_id.clone(),
            authority_scope_digest: [0; 32],
        })
    }

    /// Project the exact actor registration for a global device-revocation
    /// operation without inventing a conversation hydration authority.
    ///
    /// The zero conversation sentinel is deliberate: revocation authorization
    /// is the only consumer that does not compare `conversation_id`, while the
    /// ordinary request and transition authorization paths do. The distinct
    /// digest domain and non-zero scope binding therefore make this projection
    /// usable for G6 only, including the valid empty-fanout case.
    pub(crate) fn locked_global_registration_from_scope_authority(
        scope: &ScopeBoundBusinessAuthority,
    ) -> Result<LockedRegistrationProjection, StateMachineError> {
        const GLOBAL_CONVERSATION_SENTINEL: [u8; 16] = [0; 16];

        if scope.actor_class() != RepositoryAuthorityClass::ExistingDevice
            || scope.actor_device_id().get_version_num() != 4
            || scope.transaction_id().is_empty()
            || scope.scope_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let did = BareDid::parse(scope.actor_did())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let actor = DeviceIdentity::new(
            PrincipalId::new(did.as_str().as_bytes().to_vec())?,
            *scope.actor_device_id().as_bytes(),
        )?;
        let dpop_jkt = scope.actor_dpop_jkt();
        let actor_key_id = scope
            .actor_key_id()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let key = KeyThumbprint::parse(actor_key_id)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let key_id: [u8; 32] = URL_SAFE_NO_PAD
            .decode(key.as_str())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let actor_auth_generation = scope
            .actor_auth_generation()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let auth_generation = u64::try_from(actor_auth_generation)
            .ok()
            .filter(|value| *value > 0 && *value <= MAX_PROTOCOL_INTEGER)
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let actor_signing_public_key = scope
            .actor_signing_public_key()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let exact_signing_public_key = scope
            .actor_projected_signing_public_key()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if exact_signing_public_key != actor_signing_public_key {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let registered_mls_signature_key: [u8; 32] = exact_signing_public_key
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let trusted_read_at =
            ServerTimestamp::from_unix_millis(scope.trusted_instant().timestamp_millis())?;

        if scope
            .principals()
            .binary_search_by(|principal| principal.as_str().cmp(did.as_str()))
            .is_err()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let exact_device = scope
            .devices()
            .iter()
            .find(|device| {
                device.user_did() == did.as_str() && device.device_id() == scope.actor_device_id()
            })
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if exact_device.status() != "active"
            || exact_device.revoked_at().is_some()
            || exact_device.dpop_jkt() != dpop_jkt
            || exact_device.auth_generation() != actor_auth_generation
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let exact_key = scope
            .keys()
            .iter()
            .find(|locked_key| {
                locked_key.user_did() == did.as_str()
                    && locked_key.device_id() == scope.actor_device_id()
                    && locked_key.key_id() == actor_key_id
            })
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if exact_key.revoked_at().is_some()
            || exact_key.signing_public_key_sha256()
                != <[u8; 32]>::from(Sha256::digest(registered_mls_signature_key))
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }

        let mut digest = Sha256::new();
        digest.update(b"CATBIRD-CHAT-GLOBAL-REVOCATION-REGISTRATION\0");
        digest.update(GLOBAL_CONVERSATION_SENTINEL);
        digest.update((scope.transaction_id().len() as u64).to_be_bytes());
        digest.update(scope.transaction_id().as_bytes());
        digest.update((actor.principal().as_bytes().len() as u64).to_be_bytes());
        digest.update(actor.principal().as_bytes());
        digest.update(actor.device_id());
        let jkt_str = dpop_jkt.unwrap_or_default();
        digest.update((jkt_str.len() as u64).to_be_bytes());
        digest.update(jkt_str.as_bytes());
        digest.update(key_id);
        digest.update(registered_mls_signature_key);
        digest.update(auth_generation.to_be_bytes());
        digest.update(trusted_read_at.unix_millis().to_be_bytes());
        digest.update(scope.scope_digest());
        Ok(LockedRegistrationProjection {
            conversation_id: GLOBAL_CONVERSATION_SENTINEL,
            actor,
            key_id,
            registered_mls_signature_key,
            auth_generation,
            status: PersistedRegistrationStatus::Active,
            trusted_read_at,
            durable_row_digest: digest.finalize().into(),
            transaction_id: scope.transaction_id().to_owned(),
            authority_scope_digest: *scope.scope_digest(),
        })
    }

    /// Project an exact non-actor device registration solely from the locked
    /// business scope. Recovery fulfillment uses this for the original request
    /// target; no handler-selected key material crosses the planner boundary.
    pub(in crate::chat_protocol::state_machine) fn locked_registration_for_scoped_device(
        &self,
        scope: &ScopeBoundBusinessAuthority,
        did: &str,
        device_id: Uuid,
        key_id: &str,
        auth_generation: i64,
    ) -> Result<LockedRegistrationProjection, StateMachineError> {
        if scope.actor_class() != RepositoryAuthorityClass::ExistingDevice
            || device_id.get_version_num() != 4
            || auth_generation <= 0
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let did = BareDid::parse(did).map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        if scope
            .principals()
            .binary_search_by(|principal| principal.as_str().cmp(did.as_str()))
            .is_err()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let device = scope
            .devices()
            .iter()
            .find(|candidate| {
                candidate.user_did() == did.as_str() && candidate.device_id() == device_id
            })
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if device.status() != "active"
            || device.revoked_at().is_some()
            || device.auth_generation() != auth_generation
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let key = scope
            .keys()
            .iter()
            .find(|candidate| {
                candidate.user_did() == did.as_str()
                    && candidate.device_id() == device_id
                    && candidate.key_id() == key_id
                    && candidate.enrollment_auth_generation() == auth_generation
            })
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let signing_public_key = scope
            .signing_public_key_for(did.as_str(), device_id, key_id, auth_generation)
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if key.revoked_at().is_some()
            || signing_public_key.len() != 32
            || key.signing_public_key_sha256()
                != <[u8; 32]>::from(Sha256::digest(signing_public_key))
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let key = KeyThumbprint::parse(key_id)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let decoded_key_id: [u8; 32] = URL_SAFE_NO_PAD
            .decode(key.as_str())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let registered_mls_signature_key: [u8; 32] = signing_public_key
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let auth_generation = u64::try_from(auth_generation)
            .ok()
            .filter(|value| *value > 0 && *value <= MAX_PROTOCOL_INTEGER)
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let actor = DeviceIdentity::new(
            PrincipalId::new(did.as_str().as_bytes().to_vec())?,
            *device_id.as_bytes(),
        )?;
        let trusted_read_at =
            ServerTimestamp::from_unix_millis(scope.trusted_instant().timestamp_millis())?;
        let mut digest = Sha256::new();
        digest.update(b"CATBIRD-CHAT-REPOSITORY-AUTHORITY-GUARD\0");
        digest.update(self.expected_conversation_id);
        digest.update((actor.principal().as_bytes().len() as u64).to_be_bytes());
        digest.update(actor.principal().as_bytes());
        digest.update(actor.device_id());
        digest.update(decoded_key_id);
        digest.update(registered_mls_signature_key);
        digest.update(auth_generation.to_be_bytes());
        digest.update(trusted_read_at.unix_millis().to_be_bytes());
        Ok(LockedRegistrationProjection {
            conversation_id: self.expected_conversation_id,
            actor,
            key_id: decoded_key_id,
            registered_mls_signature_key,
            auth_generation,
            status: PersistedRegistrationStatus::Active,
            trusted_read_at,
            durable_row_digest: digest.finalize().into(),
            transaction_id: scope.transaction_id().to_owned(),
            authority_scope_digest: *scope.scope_digest(),
        })
    }
}

/// Untrusted durable-row DTO for a non-control signed request. Its timestamp is
/// parsed with the same reject-rather-than-normalize canonical grammar used by
/// the signed protocol, but authority is issued only after raw signature and
/// stored-row digest verification.
pub(crate) struct PersistedSignedRequestRow {
    pub(in crate::chat_protocol::state_machine) conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) received_at: CanonicalTimestamp,
    pub(in crate::chat_protocol::state_machine) durable_row_digest: [u8; 32],
}

/// Untrusted durable control-row material. Authority is issued only after the
/// public row and separately retained exact signed wrapper both verify under
/// the historical key, and every frozen outer-row byte/digest agrees.
pub(crate) struct PersistedControlRow {
    pub(in crate::chat_protocol::state_machine) public_row_json: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) raw_signed_wrapper: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) outer_control_projection: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) server_fields_dag_cbor: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) outer_entry_fingerprint: [u8; 32],
    pub(in crate::chat_protocol::state_machine) durable_row_digest: [u8; 32],
}

impl PersistedControlRow {
    pub(crate) fn new(
        public_row_json: Vec<u8>,
        raw_signed_wrapper: Vec<u8>,
        outer_control_projection: Vec<u8>,
        server_fields_dag_cbor: Vec<u8>,
        outer_entry_fingerprint: [u8; 32],
        durable_row_digest: [u8; 32],
    ) -> Result<Self, StateMachineError> {
        const MAX_PERSISTED_CONTROL_BYTES: usize = 1_048_576;
        if public_row_json.is_empty()
            || public_row_json.len() > MAX_PERSISTED_CONTROL_BYTES
            || raw_signed_wrapper.is_empty()
            || raw_signed_wrapper.len() > MAX_PERSISTED_CONTROL_BYTES
            || outer_control_projection.is_empty()
            || outer_control_projection.len() > MAX_PERSISTED_CONTROL_BYTES
            || server_fields_dag_cbor.is_empty()
            || server_fields_dag_cbor.len() > MAX_PERSISTED_CONTROL_BYTES
            || outer_entry_fingerprint == [0; 32]
            || durable_row_digest == [0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            public_row_json,
            raw_signed_wrapper,
            outer_control_projection,
            server_fields_dag_cbor,
            outer_entry_fingerprint,
            durable_row_digest,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PersistedControlAuthority {
    Transition(TransitionEvidence),
    Request(RequestEvidence),
}

impl PersistedControlAuthority {
    /// Downcast a re-hydrated durable control row to its transition arm for
    /// participant-provenance hydration (G1b-2). A participant's role,
    /// invitation, and acceptance provenance are ALWAYS coordinate control
    /// transitions (creation / policy / acceptance); a non-coordinate signed
    /// request can never be one, so the request arm fails closed. Called by the
    /// `repository::core` participant loader, which cannot inspect
    /// `TransitionEvidence` internals (they are module-private here).
    #[allow(dead_code)] // wired by the G1b-2 aggregate.
    pub(crate) fn into_transition(self) -> Result<TransitionEvidence, StateMachineError> {
        match self {
            PersistedControlAuthority::Transition(evidence) => Ok(evidence),
            PersistedControlAuthority::Request(_) => {
                Err(StateMachineError::InvalidHydrationAuthority)
            }
        }
    }

    /// Downcast a re-hydrated durable control row to its request arm for
    /// reset/leave request-origin hydration (G1b-2). A pending reset/leave
    /// request's origin is a CONTROL request (a `resetRequestEntry` /
    /// `leaveRequestEntry` — `validate_request_evidence` classifies these as
    /// `is_control`, requiring `control_entry_id`/`control_seq` = `Some`), never a
    /// coordinate transition, so the transition arm fails closed. Called by the
    /// `repository::core` reset/leave loader, which cannot inspect
    /// `RequestEvidence` internals (they are module-private here).
    #[allow(dead_code)] // wired by the G1b-2 aggregate.
    pub(crate) fn into_request(self) -> Result<RequestEvidence, StateMachineError> {
        match self {
            PersistedControlAuthority::Request(evidence) => Ok(evidence),
            PersistedControlAuthority::Transition(_) => {
                Err(StateMachineError::InvalidHydrationAuthority)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// G1b-2 participant-provenance classifiers (FINDING-2 ruling + SHAPE RULING A2,
// "T4-H2-pre G1b-2 aggregate-leg RULINGS"). `TransitionEvidence::body_binding`/
// `authority` are module-private, so the role/invitation/acceptance
// classification cannot run in `repository::core`; these additive free fns
// introspect the re-verified historical evidence and are consumed per
// participant by the core loader. Each resolves the hydrated provenance field or
// FAILS CLOSED — sealed evidence is never coerced into a provenance it does not
// attest.
//
// SHAPE RULING A2: these DUPLICATE the establishing/role-change decision
// additively rather than lifting a shared helper out of the validator; the
// UNCHANGED validator chain (`validate_state` -> `participant_provenance_matches`
// -> `participant_role_provenance_matches`/`invitation_matches_participant`/
// `acceptance_matches_participant`) is itself the DRIFT FENCE — it directly
// re-validates every hydrated `role_producer`/`invitation`/`acceptance` against
// the row + evidence at each hydration, so any classifier disagreement fails
// closed downstream (availability, not integrity — OQ-G1-3 philosophy). Each fn
// below names its certified original as that fence.
// ---------------------------------------------------------------------------

/// Classify a participant's `role_transition_id` evidence into its hydrated
/// `role_producer`:
/// - a `Policy` body carrying exactly one `ChangeRole(principal -> role)` for
///   this participant is a genuine role-change producer -> `Some(evidence)`;
/// - an establishing body — `Creation`, or a `Policy` that only `Add`s this
///   principal (the invitation-borne initial role) — carries no role producer
///   -> `None`;
/// - anything else (a policy that neither changes nor adds this principal's
///   role, or an unexpected transition kind) fails closed.
///
/// A `Creation` body is `None` regardless of the specific role: a
/// creation-established role is never a `ChangeRole` producer (the genesis
/// roster includes the creator at active/admin and each invitee at its initial
/// role — `RosterManifestBinding.participants`). An invited member's
/// `role_transition_id` stays equal to its invitation transition (creation or
/// policy-add) through acceptance, so it also classifies `None`. Certified
/// original / drift fence: `participant_role_provenance_matches` (this file) —
/// it re-derives the initial role from the invitation and re-checks `Some`
/// against a single `Policy` `ChangeRole(principal->role)`, failing closed on any
/// disagreement with this classifier's output.
#[allow(dead_code)] // wired by the G1b-2 aggregate.
pub(crate) fn classify_role_producer(
    evidence: TransitionEvidence,
    principal: &PrincipalId,
    role: ParticipantRole,
) -> Result<Option<TransitionEvidence>, StateMachineError> {
    match evidence.body_binding.as_ref() {
        Some(
            TransitionBodyBinding::Creation { .. }
            | TransitionBodyBinding::DirectRequestPublication { .. },
        ) => Ok(None),
        Some(TransitionBodyBinding::Policy {
            participant_changes,
            ..
        }) => {
            let role_changes = participant_changes
                .iter()
                .filter(|change| {
                    matches!(change, ManifestParticipantChange::ChangeRole(changed, changed_role)
                        if changed == principal && *changed_role == role)
                })
                .count();
            let adds = participant_changes
                .iter()
                .filter(|change| {
                    matches!(change, ManifestParticipantChange::Add(added) if added == principal)
                })
                .count();
            if role_changes == 1 {
                Ok(Some(evidence))
            } else if role_changes == 0 && adds == 1 {
                Ok(None)
            } else {
                Err(StateMachineError::InvalidHydrationAuthority)
            }
        }
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

/// Resolve a participant's invitation provenance from its
/// `invitation_transition_id` evidence and the durable inviter identity
/// (`created_by_did` / `created_by_device_id`). Requires the transition body to
/// actually record the invitation of this `principal`: a `Creation` roster entry
/// whose sealed invitation binding names this transition and inviter, or a
/// `Policy` that `Add`s this principal. Fails closed otherwise. Certified
/// original / drift fence: `invitation_matches_participant` (this file), which
/// re-checks the returned invitation against the row + evidence at hydration.
#[allow(dead_code)] // wired by the G1b-2 aggregate.
pub(crate) fn classify_invitation(
    evidence: TransitionEvidence,
    principal: &PrincipalId,
    inviter: DeviceIdentity,
) -> Result<InvitationHydrationRow, StateMachineError> {
    let records_invitation = match evidence.body_binding.as_ref() {
        Some(TransitionBodyBinding::DirectRequestPublication { prior: None, recipient, .. }) => recipient == principal && evidence.authority.as_ref().is_some_and(|a| a.actor == inviter),
        Some(TransitionBodyBinding::Creation { manifest, .. }) => {
            manifest.participants.iter().any(|participant| {
                &participant.principal == principal
                    && participant.status == ParticipantStatus::Pending
                    && participant.invitation.as_ref().is_some_and(|binding| {
                        binding.transition_id == *evidence.transition_id()
                            && binding.inviter == inviter
                    })
            })
        }
        Some(TransitionBodyBinding::Policy {
            participant_changes,
            ..
        }) => {
            participant_changes
                .iter()
                .filter(|change| {
                    matches!(change, ManifestParticipantChange::Add(added) if added == principal)
                })
                .count()
                == 1
        }
        _ => false,
    };
    if !records_invitation {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(InvitationHydrationRow {
        transition: evidence,
        inviter,
    })
}

/// Resolve a participant's acceptance evidence from its
/// `acceptance_transition_id`. Requires the transition to be a
/// `ParticipantAcceptance` whose authenticated actor principal is this
/// `principal`. Fails closed otherwise. Certified original / drift fence:
/// `acceptance_matches_participant` (this file), which re-checks the returned
/// acceptance against the row + evidence at hydration.
#[allow(dead_code)] // wired by the G1b-2 aggregate.
pub(crate) fn classify_acceptance(
    evidence: TransitionEvidence,
    principal: &PrincipalId,
) -> Result<TransitionEvidence, StateMachineError> {
    let records_acceptance = matches!(
        evidence.body_binding.as_ref(),
        Some(
            TransitionBodyBinding::Acceptance { .. }
                | TransitionBodyBinding::DirectRequestAcceptance { .. }
        )
    ) && evidence.authority.as_ref().is_some_and(|authority| {
        matches!(
            authority.kind,
            SignedMutationKind::ParticipantAcceptance | SignedMutationKind::DirectRequestAcceptance
        ) && authority.actor.principal() == principal
    });
    if !records_acceptance {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(evidence)
}

/// Compare the KeyPackage artifact retained by a durable reservation/package
/// row with the artifact signed into an already reverified participant
/// acceptance. This is a read-only drift fence; it neither constructs nor
/// relaxes transition evidence.
#[allow(dead_code)] // wired by recovery-work hydration.
pub(crate) fn acceptance_recovery_package_artifact_matches(
    evidence: &TransitionEvidence,
    durable_wrapper: &[u8],
    durable_wrapper_sha256: &[u8],
) -> bool {
    let Ok(durable_wrapper_sha256) = <[u8; 32]>::try_from(durable_wrapper_sha256) else {
        return false;
    };
    validate_transition_evidence(evidence)
        && matches!(
            evidence.body_binding.as_ref(),
            Some(TransitionBodyBinding::Acceptance { recovery, .. })
                if !durable_wrapper.is_empty()
                    && <[u8; 32]>::from(Sha256::digest(durable_wrapper))
                        == durable_wrapper_sha256
                    && recovery.key_package_wrapper == durable_wrapper
                    && recovery.key_package_wrapper_sha256 == durable_wrapper_sha256
                    && recovery.canonical_digest != [0; 32]
        )
}

/// Read-time authority that re-mints sealed evidence for HISTORICAL graph rows
/// during existing-conversation hydration (G1b). It is a DISTINCT, non-
/// substitutable counterpart of `HydrationAuthority` (OQ-G1-3 ruling (a)): the
/// append-time authority binds each entry to the locked head
/// (`seq == expected_next_entry_seq && received_at == locked_at &&
/// prior == expected_prior`), which by construction only the single head entry
/// can satisfy. Historical graph rows were produced by MANY past transitions at
/// earlier seqs, so they are re-verified here instead — through the SAME
/// `decode_and_verify_control_entry`/`decode_and_verify_signed_mutation`
/// pipelines (ed25519 + DAG-CBOR structure NEVER skipped) — but bound to each
/// entry's OWN signature-covered `seq`/`received_at`/prior plus the cheap
/// under-lock global constraint that a control entry's `seq` is strictly below
/// the locked head's `next_entry_seq` (a historical row cannot be at/after the
/// head). Digest-trust without re-verification (option (b)) was REJECTED.
pub(crate) struct HistoricalRehydrationAuthority {
    pub(in crate::chat_protocol::state_machine) expected_conversation_id: [u8; 16],
    /// Upper bound for the control-entry `seq < head` global constraint. Read
    /// only by the control-entry path (`hydrate_historical_control`); unused by
    /// the signed-request path (signed requests carry no entry seq).
    pub(in crate::chat_protocol::state_machine) head_next_entry_seq: u64,
}
