#![allow(unused_imports)]
use super::*;

impl DeviceRevocationEvidence {
    pub(crate) fn revocation_id(&self) -> &[u8; 16] {
        &self.revocation_id
    }

    pub(crate) fn actor(&self) -> &DeviceIdentity {
        &self.actor
    }

    pub(crate) fn target(&self) -> &DeviceIdentity {
        &self.target
    }

    pub(crate) fn accepted_at(&self) -> ServerTimestamp {
        self.accepted_at
    }

    pub(crate) fn actor_key_id(&self) -> &[u8; 32] {
        &self.actor_key_id
    }
    pub(crate) fn actor_auth_generation(&self) -> u64 {
        self.actor_auth_generation
    }
    pub(crate) fn expected_target_auth_generation(&self) -> u64 {
        self.expected_target_auth_generation
    }
    pub(crate) fn signed_at(&self) -> ServerTimestamp {
        self.signed_at
    }
    pub(crate) fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    pub(crate) fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    pub(crate) fn signed_request_bytes(&self) -> &[u8] {
        &self.signed_request_bytes
    }
    pub(crate) fn signing_transcript_bytes(&self) -> &[u8] {
        &self.signing_transcript_bytes
    }
    pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
        &self.durable_row_digest
    }
}

#[cfg(test)]
impl DeviceRevocationEvidence {
    /// Build a production-shape `DeviceRevocationEvidence` from its 12 signed
    /// fields; the `durable_row_digest` is computed (never supplied) exactly as
    /// `device_revocation_at` does, and the result must pass
    /// `validate_device_revocation_evidence` — a test seam for the entry-less
    /// executor revocation arm, mirroring the `for_test_*` family.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test(
        revocation_id: [u8; 16],
        actor: DeviceIdentity,
        target: DeviceIdentity,
        actor_key_id: [u8; 32],
        actor_auth_generation: u64,
        expected_target_auth_generation: u64,
        signed_at: ServerTimestamp,
        accepted_at: ServerTimestamp,
        request_digest: [u8; 32],
        signature: [u8; 64],
        signed_request_bytes: Vec<u8>,
        signing_transcript_bytes: Vec<u8>,
    ) -> Self {
        let mut evidence = Self {
            revocation_id,
            actor,
            target,
            actor_key_id,
            actor_auth_generation,
            expected_target_auth_generation,
            signed_at,
            accepted_at,
            request_digest,
            signature,
            signed_request_bytes,
            signing_transcript_bytes,
            durable_row_digest: [0; 32],
        };
        evidence.durable_row_digest = device_revocation_row_digest(&evidence);
        debug_assert!(
            validate_device_revocation_evidence(&evidence),
            "for_test device revocation evidence must be valid"
        );
        evidence
    }
}

impl RequestEvidence {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test(
        kind: RequestEntryKind,
        seq: u64,
        request_id: [u8; 16],
        actor: DeviceIdentity,
        conversation_id: [u8; 16],
        received_at: ServerTimestamp,
        byte: u8,
    ) -> Result<Self, StateMachineError> {
        let entry_id = uuid_from_test_byte(byte.wrapping_add(1));
        if seq == 0
            || seq > MAX_PROTOCOL_INTEGER
            || !is_uuid_v4(&request_id)
            || !is_uuid_v4(&conversation_id)
            || !is_uuid_v4(&entry_id)
        {
            return Err(StateMachineError::InvalidTransition);
        }
        Ok(Self {
            kind,
            control_entry_id: matches!(
                kind,
                RequestEntryKind::ResetRequest
                    | RequestEntryKind::LeaveRequest
                    | RequestEntryKind::LeaveCancellation
            )
            .then_some(entry_id),
            conversation_id,
            control_seq: matches!(
                kind,
                RequestEntryKind::ResetRequest
                    | RequestEntryKind::LeaveRequest
                    | RequestEntryKind::LeaveCancellation
            )
            .then_some(seq),
            control_outer_entry_fingerprint: None,
            control_outer_projection: None,
            control_server_fields_dag_cbor: None,
            request_id,
            actor,
            key_id: [byte; 32],
            auth_generation: 1,
            request_digest: [byte.wrapping_add(2); 32],
            signature: [byte.wrapping_add(3); 64],
            signed_request_bytes: vec![byte.wrapping_add(5)],
            durable_row_digest: [byte.wrapping_add(4); 32],
            received_at,
            authority: None,
            body_binding: None,
        })
    }

    /// `for_test`, but carrying a REAL registered key id. `for_test` synthesizes
    /// `key_id: [byte; 32]`, which can never equal the thumbprint of an actor actually
    /// registered in the database, and the durable CAS pins `owner_key_id`.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_with_key_id(
        kind: RequestEntryKind,
        seq: u64,
        request_id: [u8; 16],
        actor: DeviceIdentity,
        conversation_id: [u8; 16],
        received_at: ServerTimestamp,
        byte: u8,
        key_id: [u8; 32],
    ) -> Result<Self, StateMachineError> {
        let mut evidence = Self::for_test(
            kind,
            seq,
            request_id,
            actor,
            conversation_id,
            received_at,
            byte,
        )?;
        evidence.key_id = key_id;
        Ok(evidence)
    }

    /// A signed, NON-control welcome-response `RequestEvidence` (acknowledge /
    /// reject): entry-less (`control_entry_id`/`control_seq` = None) with the
    /// `WelcomeResponse` body binding `plan_welcome_response` requires to match the
    /// pending welcome's coordinate + `transition_seq`. `request_id` = the welcome
    /// id, actor = the recipient. `rejection_reason` must be `None` for an
    /// acknowledgement and one of the five protocol reasons for a rejection —
    /// the durable disposition row stores it verbatim, so the caller (not this
    /// constructor) owns which reason the client signed.
    ///
    /// The signed `authority` is populated because a welcome response is ALWAYS
    /// client-signed in production: `plan_welcome_response_entry` binds it through
    /// `bind_non_control_request_authority`, which rejects `authority.is_none()`,
    /// and the executor's `preflight_welcome_response_execution_context` re-reads
    /// that same authority to re-verify the accepted control-entry content. Without
    /// it this constructor yields a shape production can never emit. `type_id` /
    /// `domain` come from the signed kind itself and `durable_row_digest` is
    /// recomputed over the completed evidence, so the result satisfies every
    /// `validate_request_evidence` authority predicate exactly as a durable row does.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_welcome_response(
        kind: RequestEntryKind,
        welcome_id: [u8; 16],
        recipient: DeviceIdentity,
        conversation_id: [u8; 16],
        coordinates: PublicGroupSnapshotCoordinate,
        transition_seq: u64,
        received_at: ServerTimestamp,
        rejection_reason: Option<&str>,
        byte: u8,
    ) -> Result<Self, StateMachineError> {
        let mut evidence = Self::for_test(
            kind,
            1,
            welcome_id,
            recipient,
            conversation_id,
            received_at,
            byte,
        )?;
        evidence.control_entry_id = None;
        evidence.control_seq = None;
        evidence.body_binding = Some(RequestBodyBinding::WelcomeResponse {
            coordinates,
            transition_seq,
            rejection_reason: rejection_reason.map(str::to_owned),
        });
        let signed_kind = request_entry_signed_kind(kind);
        // The signing transcript is `domain || canonical_projection` and the request
        // digest is its SHA-256 — the exact shape `transcript_for` produces, which
        // `chat.welcome_dispositions_signature_shape_check`
        // (`request_digest = digest(signing_transcript_bytes,'sha256')`) enforces on
        // the durable disposition row.
        let canonical_projection = vec![byte.wrapping_add(6), byte.wrapping_add(7)];
        let mut transcript_bytes = signed_kind.domain().to_vec();
        transcript_bytes.extend_from_slice(&canonical_projection);
        evidence.request_digest = Sha256::digest(&transcript_bytes).into();
        evidence.authority = Some(AuthenticatedEntryEvidence {
            kind: signed_kind,
            type_id: signed_kind.type_id(),
            domain: signed_kind.domain().to_vec(),
            control_entry_id: None,
            control_conversation_id: None,
            actor: evidence.actor.clone(),
            key_id: evidence.key_id,
            auth_generation: evidence.auth_generation,
            signed_at: received_at,
            request_digest: evidence.request_digest,
            signature: evidence.signature,
            signed_request_bytes: evidence.signed_request_bytes.clone(),
            canonical_projection,
            transcript_bytes,
        });
        evidence.durable_row_digest = durable_signed_request_evidence_digest(&evidence);
        Ok(evidence)
    }

    pub(crate) fn actor(&self) -> &DeviceIdentity {
        &self.actor
    }

    pub(crate) fn kind(&self) -> RequestEntryKind {
        self.kind
    }

    pub(crate) fn conversation_id(&self) -> &[u8; 16] {
        &self.conversation_id
    }

    pub(crate) fn control_entry_id(&self) -> Option<&[u8; 16]> {
        self.control_entry_id.as_ref()
    }

    pub(crate) fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    pub(crate) fn control_seq(&self) -> Option<u64> {
        self.control_seq
    }

    pub(crate) fn control_outer_entry_fingerprint(&self) -> Option<&[u8; 32]> {
        self.control_outer_entry_fingerprint.as_ref()
    }

    pub(crate) fn control_outer_projection(&self) -> Option<&[u8]> {
        self.control_outer_projection.as_deref()
    }

    pub(crate) fn control_server_fields_dag_cbor(&self) -> Option<&[u8]> {
        self.control_server_fields_dag_cbor.as_deref()
    }

    pub(crate) fn received_at(&self) -> ServerTimestamp {
        self.received_at
    }

    pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
        &self.durable_row_digest
    }

    pub(crate) fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    pub(crate) fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    pub(crate) fn signed_request_bytes(&self) -> &[u8] {
        &self.signed_request_bytes
    }

    pub(crate) fn signed_authority(&self) -> Option<&AuthenticatedEntryEvidence> {
        self.authority.as_ref()
    }
}

/// Route-bound authority used by persistence adapters to project sealed auth
/// results into cloneable state evidence. It accepts no raw signatures, body
/// maps, caller-selected domains, or caller-selected type identifiers.
pub(crate) struct HydrationAuthority {
    pub(in crate::chat_protocol::state_machine) expected_conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) locked: Option<LockedHydrationBinding>,
}

/// Sealed witness proving that a historical plan is authorized for the exact source entry.
///
/// This witness is move-only and can only be minted by `HistoricalPrefixAuthority`
/// in `crate::chat_protocol::repository::remote_prefix`. It prevents unauthenticated callers
/// within the crate from bypassing live quota checks by calling `into_historical_persistence_plan`.
#[derive(Debug)]
pub(in crate::chat_protocol) struct HistoricalPlanWitness {
    pub(in crate::chat_protocol::state_machine) _witness:
        crate::chat_protocol::repository::remote_prefix::HistoricalWriteWitness,
    pub(in crate::chat_protocol::state_machine) source_entry_id: Uuid,
}

impl HistoricalPlanWitness {
    pub(in crate::chat_protocol) fn new(
        witness: crate::chat_protocol::repository::remote_prefix::HistoricalWriteWitness,
        source_entry_id: Uuid,
    ) -> Self {
        Self {
            _witness: witness,
            source_entry_id,
        }
    }
}

/// The device the transition's sealed authority names as actor.
pub(in crate::chat_protocol::state_machine) fn historical_actor(
    transition: &TransitionEvidence,
) -> Result<DeviceIdentity, StateMachineError> {
    transition
        .authority
        .as_ref()
        .map(|authority| authority.actor.clone())
        .ok_or(StateMachineError::InvalidHydrationAuthority)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::chat_protocol) enum RecoveryPlannedKind {
    Request {
        recovery_request_id: Uuid,
    },
    Cancellation {
        recovery_request_id: Uuid,
    },
    Fulfillment {
        recovery_request_id: Uuid,
        transition_id: Uuid,
    },
}

/// Sealed output of a planner that consumed exactly one opaque Recovery input.
/// The executor facade receives only the persistence plan and the canonical
/// control row minted here; the route never supplies event payload bytes.
pub(in crate::chat_protocol) struct PlannedRecoveryMutation {
    pub(in crate::chat_protocol::state_machine) transition: PlannedTransition,
    pub(in crate::chat_protocol::state_machine) scope_authority: ScopeBoundBusinessAuthority,
    pub(in crate::chat_protocol::state_machine) completion: OperationCompletionGuard,
    pub(in crate::chat_protocol::state_machine) prewrite: RecoveryPreludePrewriteWitness,
    pub(in crate::chat_protocol::state_machine) accepted_control_entry_bytes: Option<Vec<u8>>,
    pub(in crate::chat_protocol::state_machine) canonical_response_entry_bytes: Option<Vec<u8>>,
    pub(in crate::chat_protocol::state_machine) persistence_witness: RecoveryPersistenceWitness,
    pub(in crate::chat_protocol::state_machine) kind: RecoveryPlannedKind,
}

impl PlannedRecoveryMutation {
    pub(in crate::chat_protocol) fn into_parts(
        self,
    ) -> (
        PlannedTransition,
        ScopeBoundBusinessAuthority,
        OperationCompletionGuard,
        RecoveryPreludePrewriteWitness,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        RecoveryPersistenceWitness,
        RecoveryPlannedKind,
    ) {
        (
            self.transition,
            self.scope_authority,
            self.completion,
            self.prewrite,
            self.accepted_control_entry_bytes,
            self.canonical_response_entry_bytes,
            self.persistence_witness,
            self.kind,
        )
    }
}

pub(in crate::chat_protocol) struct PlannedClientRecoveryExpiry {
    pub(in crate::chat_protocol::state_machine) transition: PlannedTransition,
    pub(in crate::chat_protocol::state_machine) scope_authority: ScopeBoundBusinessAuthority,
    pub(in crate::chat_protocol::state_machine) completion: OperationCompletionGuard,
    pub(in crate::chat_protocol::state_machine) prewrite: RecoveryPreludePrewriteWitness,
    pub(in crate::chat_protocol::state_machine) recovery_request_id: Uuid,
    pub(in crate::chat_protocol::state_machine) terminal_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) persistence_witness: RecoveryPersistenceWitness,
    pub(in crate::chat_protocol::state_machine) post_apply_error: RecoveryClientTerminalError,
}

impl PlannedClientRecoveryExpiry {
    pub(in crate::chat_protocol) fn into_parts(
        self,
    ) -> (
        PlannedTransition,
        ScopeBoundBusinessAuthority,
        OperationCompletionGuard,
        RecoveryPreludePrewriteWitness,
        Uuid,
        ServerTimestamp,
        RecoveryPersistenceWitness,
        RecoveryClientTerminalError,
    ) {
        (
            self.transition,
            self.scope_authority,
            self.completion,
            self.prewrite,
            self.recovery_request_id,
            self.terminal_at,
            self.persistence_witness,
            self.post_apply_error,
        )
    }
}

pub(in crate::chat_protocol) struct PlannedSchedulerRecoveryExpiry {
    pub(in crate::chat_protocol::state_machine) transition: PlannedTransition,
    pub(in crate::chat_protocol::state_machine) recovery_request_id: Uuid,
    pub(in crate::chat_protocol::state_machine) terminal_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) persistence_witness: RecoveryPersistenceWitness,
}

impl PlannedSchedulerRecoveryExpiry {
    pub(in crate::chat_protocol) fn into_parts(
        self,
    ) -> (
        PlannedTransition,
        Uuid,
        ServerTimestamp,
        RecoveryPersistenceWitness,
    ) {
        (
            self.transition,
            self.recovery_request_id,
            self.terminal_at,
            self.persistence_witness,
        )
    }
}

pub(in crate::chat_protocol::state_machine) struct LockedHydrationBinding {
    pub(in crate::chat_protocol::state_machine) transaction_id: String,
    pub(in crate::chat_protocol::state_machine) expected_prior:
        Option<PublicGroupSnapshotCoordinate>,
    pub(in crate::chat_protocol::state_machine) expected_next_entry_seq: u64,
    pub(in crate::chat_protocol::state_machine) locked_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) locked_head_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) locked_graph_digest: Option<[u8; 32]>,
    pub(in crate::chat_protocol::state_machine) locked_snapshot_digest: Option<[u8; 32]>,
}
