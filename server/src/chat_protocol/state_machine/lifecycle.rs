#![allow(unused_imports)]
use super::*;

impl HistoricalRehydrationAuthority {
    /// Production constructor: binds the read-time authority to an EXISTING
    /// locked head (`prior_coordinate` = `Some`, `next_entry_seq >= 2`). The
    /// head's `next_entry_seq` becomes the strict upper bound for historical
    /// control-entry seqs.
    #[allow(dead_code)]
    pub(crate) fn from_locked_head(
        head: &LockedConversationHeadGuard,
    ) -> Result<Self, StateMachineError> {
        if head.prior_coordinate().is_none() || head.next_entry_seq() < 2 {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            expected_conversation_id: *head.conversation_id().as_bytes(),
            head_next_entry_seq: head.next_entry_seq(),
        })
    }

    /// Test seam mirroring `HydrationAuthority::new`. `head_next_entry_seq` is
    /// the strict upper bound the control-entry path enforces.
    #[cfg(test)]
    pub(crate) fn new(
        expected_conversation_id: [u8; 16],
        head_next_entry_seq: u64,
    ) -> Result<Self, StateMachineError> {
        if !is_uuid_v4(&expected_conversation_id) || head_next_entry_seq < 2 {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            expected_conversation_id,
            head_next_entry_seq,
        })
    }

    /// Re-mints a persisted non-control signed request for the historical graph.
    /// Mirrors `HydrationAuthority::hydrate_persisted_signed_request`
    /// (state_machine.rs) EXACTLY, minus the append-time
    /// `received_at == locked_at` head-binding check: the stored `received_at`
    /// (which participates in the frozen row digest) is re-derived from the
    /// entry itself. Signed requests carry no entry seq, so the `seq < head`
    /// constraint does not apply here. Drift fence: the cfg(test)
    /// `historical_signed_request_matches_append_time_per_kind` equivalence test.
    #[allow(dead_code)]
    pub(crate) fn hydrate_historical_signed_request(
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
        let evidence =
            historical_signed_request_evidence(envelope, mutation, &self.expected_conversation_id)?;
        if evidence.durable_row_digest != durable_row_digest {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(evidence)
    }

    /// Production loader entry point for a HISTORICAL NON-control signed request —
    /// the signed-path analogue of `hydrate_historical_control_from_durable_bytes`.
    /// Re-hydrates directly from a durable projection row's own bytes
    /// (`signed_request_bytes` as the raw wrapper, `requested_at`/`received_at` as
    /// the canonical stored instant) under the historical signing key JOINed from
    /// `chat.device_keys`.
    ///
    /// The `durable_row_digest` is derived, not independently stored. Mint once
    /// from the verified mutation with the SAME head-binding-free minter as the
    /// independent row path, then retain `PersistedSignedRequestRow::new`'s
    /// canonical timestamp, UUID, and nonzero-digest checks. Re-decoding the same
    /// bytes would only compare this derived digest with itself.
    /// Drift fence: `historical_signed_request_from_durable_bytes_matches_row_path`.
    #[allow(dead_code)]
    pub(crate) fn hydrate_historical_signed_request_from_durable_bytes(
        &self,
        conversation_id: [u8; 16],
        received_at: &str,
        raw_signed_request: &[u8],
        historical_public_key: &[u8],
    ) -> Result<RequestEvidence, StateMachineError> {
        let parsed = CanonicalTimestamp::parse(received_at)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let mutation = decode_and_verify_signed_mutation(raw_signed_request, historical_public_key)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let envelope = DurableSignedRequestEnvelope {
            conversation_id,
            received_at: canonical_server_timestamp(&parsed)?,
        };
        let evidence =
            historical_signed_request_evidence(envelope, mutation, &self.expected_conversation_id)?;
        PersistedSignedRequestRow::new(conversation_id, received_at, evidence.durable_row_digest)?;
        Ok(evidence)
    }

    /// Exact durable-row companion for signed terminal requests. In addition to
    /// re-running the certified signed-request hydration path, this verifies the
    /// projection table's separately persisted transcript, digest, and signature
    /// byte-for-byte against the decoded wrapper. A caller cannot relabel or
    /// partially bind a valid signed wrapper by supplying divergent row columns.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn hydrate_historical_signed_request_from_exact_durable_fields(
        &self,
        conversation_id: [u8; 16],
        received_at: &str,
        raw_signed_request: &[u8],
        signing_transcript_bytes: &[u8],
        request_digest: [u8; 32],
        signature: [u8; 64],
        historical_public_key: &[u8],
    ) -> Result<RequestEvidence, StateMachineError> {
        let mutation = decode_and_verify_signed_mutation(raw_signed_request, historical_public_key)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        if mutation.accepted_wrapper_bytes() != Some(raw_signed_request)
            || mutation.transcript_bytes() != signing_transcript_bytes
            || mutation.request_digest() != &request_digest
            || mutation.signature() != &signature
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.hydrate_historical_signed_request_from_durable_bytes(
            conversation_id,
            received_at,
            raw_signed_request,
            historical_public_key,
        )
    }

    /// Re-mints a persisted CONTROL-entry row for the historical graph. Mirrors
    /// `HydrationAuthority::hydrate_persisted_control` (state_machine.rs) EXACTLY
    /// through the shared crypto — `decode_and_verify_control_entry`
    /// (transcript.rs) + the four frozen outer-row equality checks
    /// (conversation_id / outer projection / outer fingerprint / server-fields
    /// DAG-CBOR) + `rebind_persisted_control_entry` (transcript.rs) — then
    /// dispatches to the head-binding-free `historical_control_request_evidence`
    /// / `historical_transition_evidence` duplicates instead of the append-time
    /// minters. This is the ONLY reader of `head_next_entry_seq`: a control
    /// entry's own signature-covered `seq` must be STRICTLY below the locked
    /// head's `next_entry_seq` (a historical row cannot be at or after the head).
    /// Drift fence: the cfg(test)
    /// `historical_control_matches_append_time_per_kind` equivalence test.
    #[allow(dead_code)]
    pub(crate) fn hydrate_historical_control(
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
        // Global under-lock constraint (control entries only — they carry a seq):
        // a historical control entry MUST sit strictly below the locked head.
        if entry.seq() >= self.head_next_entry_seq {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        match entry.mutation().projection() {
            VerifiedMutationProjection::ResetRequest(_)
            | VerifiedMutationProjection::LeaveRequest(_)
            | VerifiedMutationProjection::LeaveCancellation(_) => {
                let evidence =
                    historical_control_request_evidence(entry, &self.expected_conversation_id)?;
                if evidence.durable_row_digest != durable_row_digest {
                    return Err(StateMachineError::InvalidHydrationAuthority);
                }
                Ok(PersistedControlAuthority::Request(evidence))
            }
            _ => {
                let evidence =
                    historical_transition_evidence(&entry, &self.expected_conversation_id)?;
                if evidence.durable_row_digest != durable_row_digest {
                    return Err(StateMachineError::InvalidHydrationAuthority);
                }
                Ok(PersistedControlAuthority::Transition(evidence))
            }
        }
    }

    /// Production loader entry point: re-hydrates a HISTORICAL control entry
    /// directly from its durable `chat.entries` bytes — `accepted_payload_bytes`
    /// as the public row JSON, `signed_request_bytes` as the raw signed wrapper —
    /// under the historical signing key JOINed from `chat.device_keys`.
    ///
    /// The frozen outer-row material and durable digest are derived here, not
    /// independently supplied. Decode the public row and rebind its separately
    /// persisted signed wrapper once, retaining all signed/outer/server splice
    /// comparisons in `rebind_persisted_control_entry`. Mint from that verified
    /// entry only after checking the expected conversation and strict `seq < head`
    /// bound, and retain `PersistedControlRow::new`'s size/nonzero checks.
    /// Independently supplied frozen fields still use `hydrate_historical_control`.
    /// Drift fence: `historical_control_from_durable_bytes_matches_row_path_per_kind`.
    #[allow(dead_code)]
    pub(crate) fn hydrate_historical_control_from_durable_bytes(
        &self,
        public_row_json: Vec<u8>,
        raw_signed_wrapper: Vec<u8>,
        historical_public_key: &[u8],
    ) -> Result<PersistedControlAuthority, StateMachineError> {
        let decoded = decode_and_verify_control_entry(&public_row_json, historical_public_key)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        if decoded.conversation_id().as_bytes() != &self.expected_conversation_id {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let outer_control_projection = decoded.outer_control_projection().to_vec();
        let outer_entry_fingerprint = *decoded.outer_control_fingerprint();
        let server_fields_dag_cbor = decoded
            .server_fields_dag_cbor()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let entry =
            rebind_persisted_control_entry(decoded, &raw_signed_wrapper, historical_public_key)
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        if entry.seq() >= self.head_next_entry_seq {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let evidence = match entry.mutation().projection() {
            VerifiedMutationProjection::ResetRequest(_)
            | VerifiedMutationProjection::LeaveRequest(_)
            | VerifiedMutationProjection::LeaveCancellation(_) => {
                PersistedControlAuthority::Request(historical_control_request_evidence(
                    entry,
                    &self.expected_conversation_id,
                )?)
            }
            _ => PersistedControlAuthority::Transition(historical_transition_evidence(
                &entry,
                &self.expected_conversation_id,
            )?),
        };
        let durable_row_digest = match &evidence {
            PersistedControlAuthority::Request(evidence) => evidence.durable_row_digest,
            PersistedControlAuthority::Transition(evidence) => evidence.durable_row_digest,
        };
        PersistedControlRow::new(
            public_row_json,
            raw_signed_wrapper,
            outer_control_projection,
            server_fields_dag_cbor,
            outer_entry_fingerprint,
            durable_row_digest,
        )?;
        Ok(evidence)
    }

    /// Production loader entry point for a coordinator's `directRequestEntry`
    /// whose opening ciphertext was pruned (O7). The redacted row keeps every
    /// signed field except the ciphertext, which it replaces by that ciphertext's
    /// SHA-256, so the publication binds the same coordinates, recipient, devices
    /// and metadata as before. The sender signature over the erased bytes cannot
    /// be re-verified: the caller has bound the redacted body to the sequencer's
    /// own signed publication receipt and supplies the row's immutable request
    /// digest and outer fingerprint. Same conversation and strict `seq < head`
    /// bounds as every other historical control entry.
    #[allow(dead_code)]
    pub(crate) fn hydrate_pruned_direct_request_opening(
        &self,
        redacted_row_json: Vec<u8>,
        historical_public_key: &[u8],
        request_digest: [u8; 32],
        outer_entry_fingerprint: [u8; 32],
    ) -> Result<PersistedControlAuthority, StateMachineError> {
        let entry = crate::chat_protocol::transcript::decode_pruned_direct_request_entry(
            &redacted_row_json,
            historical_public_key,
            request_digest,
            outer_entry_fingerprint,
        )
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        if entry.conversation_id().as_bytes() != &self.expected_conversation_id
            || entry.seq() >= self.head_next_entry_seq
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let evidence = historical_transition_evidence(&entry, &self.expected_conversation_id)?;
        PersistedControlRow::new(
            redacted_row_json,
            entry
                .mutation()
                .accepted_wrapper_bytes()
                .ok_or(StateMachineError::InvalidHydrationAuthority)?
                .to_vec(),
            entry.outer_control_projection().to_vec(),
            entry
                .server_fields_dag_cbor()
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
            outer_entry_fingerprint,
            evidence.durable_row_digest,
        )?;
        Ok(PersistedControlAuthority::Transition(evidence))
    }
}

/// Head-binding-free duplicate of `HydrationAuthority::signed_request`
/// (state_machine.rs) — the request-kind match + embedded-conversation check +
/// evidence minting, MINUS the append-time head guards (`received_at ==
/// locked_at`; `prior == expected_prior`). Every helper (`closed_*`,
/// `durable_signed_request_row_digest`, `request_evidence_from_verified`) is the
/// same certified free fn the original calls. The trailing `_ =>` wildcard
/// mirrors the original (sm `signed_request`, which is not exhaustive over
/// `VerifiedMutationProjection`); drift is fenced by the per-kind cfg(test)
/// equivalence test, not by exhaustiveness. Read-time only; NEVER used at append
/// time (that path keeps its head binding).
#[allow(dead_code)]
pub(in crate::chat_protocol::state_machine) fn historical_signed_request_evidence(
    envelope: DurableSignedRequestEnvelope,
    mutation: VerifiedSignedMutation,
    expected_conversation_id: &[u8; 16],
) -> Result<RequestEvidence, StateMachineError> {
    if &envelope.conversation_id != expected_conversation_id {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let (kind, request_id, body, body_binding) = match mutation.projection() {
        VerifiedMutationProjection::LeafRecoveryRequest(value) => (
            RequestEntryKind::LeafRecoveryRequest,
            *value.recovery_request_id().as_bytes(),
            value.body(),
            RequestBodyBinding::LeafRecoveryRequest {
                prior: closed_coordinate(&value.prior())?,
                kind: match value.recovery_kind() {
                    "add" => LeafRecoveryKind::Add,
                    "replace" => LeafRecoveryKind::Replace,
                    _ => return Err(StateMachineError::InvalidHydrationAuthority),
                },
            },
        ),
        VerifiedMutationProjection::LeafRecoveryCancellation(value) => (
            RequestEntryKind::LeafRecoveryCancellation,
            *value.recovery_request_id().as_bytes(),
            value.body(),
            RequestBodyBinding::LeafRecoveryCancellation,
        ),
        VerifiedMutationProjection::WelcomeAcknowledgement(value) => (
            RequestEntryKind::WelcomeAcknowledgement,
            closed_uuid(&value.body(), "welcomeId")?,
            value.body(),
            RequestBodyBinding::WelcomeResponse {
                coordinates: closed_coordinate_from_field(&value.body(), "coordinates")?,
                transition_seq: closed_integer(&value.body(), "transitionSeq")?,
                rejection_reason: None,
            },
        ),
        VerifiedMutationProjection::WelcomeRejection(value) => (
            RequestEntryKind::WelcomeRejection,
            closed_uuid(&value.body(), "welcomeId")?,
            value.body(),
            RequestBodyBinding::WelcomeResponse {
                coordinates: closed_coordinate_from_field(&value.body(), "coordinates")?,
                transition_seq: closed_integer(&value.body(), "transitionSeq")?,
                rejection_reason: Some(closed_text(&value.body(), "reason")?.to_owned()),
            },
        ),
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let embedded_conversation_id = match kind {
        RequestEntryKind::LeafRecoveryRequest => {
            Some(closed_coordinate_conversation_id(body, "prior")?)
        }
        RequestEntryKind::LeafRecoveryCancellation => None,
        RequestEntryKind::WelcomeAcknowledgement | RequestEntryKind::WelcomeRejection => {
            Some(closed_coordinate_conversation_id(body, "coordinates")?)
        }
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    if embedded_conversation_id
        .is_some_and(|conversation_id| &conversation_id != expected_conversation_id)
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let durable_row_digest =
        durable_signed_request_row_digest(kind, &envelope, &request_id, &mutation)?;
    request_evidence_from_verified(
        kind,
        None,
        &envelope.conversation_id,
        None,
        None,
        None,
        &request_id,
        envelope.received_at,
        durable_row_digest,
        &mutation,
        body_binding,
    )
}

/// Head-binding-free duplicate of `HydrationAuthority::transition_from_control`
/// (state_machine.rs) — the full transition-kind match + route-bind check +
/// evidence minting, MINUS the append-time head guards (`seq ==
/// expected_next_entry_seq`; `received_at == locked_at`; `prior ==
/// expected_prior`). Every helper (`parse_*`, `closed_coordinate`,
/// `checked_artifact_sha256`, `commit_aad_sha256`,
/// `transition_binding_is_route_bound`, `validate_special_server_fields`,
/// `authenticated_entry`, `durable_control_transition_row_digest`) is the same
/// certified free fn the original calls; the evidence fields already use
/// `entry.seq()` / `entry.received_at()` verbatim, so removing the head guards
/// is the ONLY difference. The trailing `_ =>` wildcard mirrors the original
/// (not exhaustive over `VerifiedMutationProjection` — it accepts only
/// transition kinds); drift is fenced by the per-kind cfg(test)
/// `historical_control_matches_append_time_per_kind` equivalence test, not by
/// exhaustiveness. Read-time only; NEVER used at append time.
#[allow(dead_code)]
pub(in crate::chat_protocol::state_machine) fn historical_transition_evidence(
    entry: &VerifiedControlEntry,
    expected_conversation_id: &[u8; 16],
) -> Result<TransitionEvidence, StateMachineError> {
    if entry.conversation_id().as_bytes() != expected_conversation_id {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let (transition_id, body_binding) = match entry.mutation().projection() {
        VerifiedMutationProjection::DirectRequestPublication(value) => {
            let body = value.body();
            (
                closed_uuid(&body, "requestId")?,
                parse_direct_request_publication(&body)?,
            )
        }
        VerifiedMutationProjection::DirectRequestAcceptance(value) => {
            let body = value.body();
            let prior = closed_coordinate_from_field(&body, "prior")?;
            let next = closed_coordinate_from_field(&body, "next")?;
            if coordinate_only_successor(&prior)? != next {
                return Err(StateMachineError::InvalidHydrationAuthority);
            }
            let Some(CanonicalValueRef::Object(invitation)) = body.get("invitationProvenance")
            else {
                return Err(StateMachineError::InvalidHydrationAuthority);
            };
            (
                closed_uuid(&body, "transitionId")?,
                TransitionBodyBinding::DirectRequestAcceptance {
                    request_id: closed_uuid(&body, "requestId")?,
                    prior,
                    next,
                    invitation: parse_invitation(&invitation)?,
                },
            )
        }
        VerifiedMutationProjection::Creation(value) => (
            *value.transition_id().as_bytes(),
            TransitionBodyBinding::Creation {
                kind: parse_conversation_kind(value.conversation_kind())?,
                next: closed_coordinate(&value.next())?,
                manifest: parse_roster_manifest(&value.manifest())?,
                group_info_sha256: checked_artifact_sha256(&value.genesis_group_info())?,
                metadata: parse_metadata_snapshot(&value.metadata_snapshot())?,
            },
        ),
        VerifiedMutationProjection::CommitTransition(value) => (
            *value.transition_id().as_bytes(),
            TransitionBodyBinding::Commit {
                prior: closed_coordinate(&value.prior())?,
                next: closed_coordinate(&value.next())?,
                aad_digest: commit_aad_sha256(&value.aad()),
                manifest: parse_transition_manifest(&value.manifest())?,
                commit_sha256: checked_artifact_sha256(&value.commit())?,
                metadata: parse_metadata_snapshot(&value.metadata_snapshot())?,
            },
        ),
        VerifiedMutationProjection::PolicyTransition(value) => (
            *value.transition_id().as_bytes(),
            TransitionBodyBinding::Policy {
                prior: closed_coordinate(&value.prior())?,
                next: closed_coordinate(&value.next())?,
                participant_changes: parse_participant_changes(value.participant_changes())?,
            },
        ),
        VerifiedMutationProjection::ParticipantAcceptance(value) => (
            *value.transition_id().as_bytes(),
            TransitionBodyBinding::Acceptance {
                prior: closed_coordinate(&value.prior())?,
                next: closed_coordinate(&value.next())?,
                recovery_request_id: *value.recovery_request_id().as_bytes(),
                invitation_provenance: parse_invitation(&value.invitation_provenance())?,
                recovery: parse_acceptance_recovery(&entry.server_fields())?,
            },
        ),
        VerifiedMutationProjection::MetadataTransition(value) => (
            *value.transition_id().as_bytes(),
            TransitionBodyBinding::Metadata {
                prior: closed_coordinate(&value.prior())?,
                next: closed_coordinate(&value.next())?,
                metadata: parse_metadata_snapshot(&value.metadata_snapshot())?,
            },
        ),
        VerifiedMutationProjection::ResetActivation(value) => (
            *value.transition_id().as_bytes(),
            TransitionBodyBinding::ResetActivation {
                kind: parse_conversation_kind(value.conversation_kind())?,
                reset_request_id: *value.reset_request_id().as_bytes(),
                prior: closed_coordinate(&value.prior())?,
                retired: closed_coordinate(&value.retired())?,
                successor: closed_coordinate(&value.successor())?,
                manifest: parse_roster_manifest(&value.manifest())?,
                group_info_sha256: checked_artifact_sha256(&value.genesis_group_info())?,
                metadata: parse_metadata_snapshot(&value.metadata_snapshot())?,
            },
        ),
        VerifiedMutationProjection::LeafRecoveryFulfillment(value) => (
            *value.transition_id().as_bytes(),
            TransitionBodyBinding::LeafRecoveryFulfillment {
                recovery_request_id: *value.recovery_request_id().as_bytes(),
                prior: closed_coordinate(&value.prior())?,
                next: closed_coordinate(&value.next())?,
                aad_digest: commit_aad_sha256(&value.aad()),
                manifest: parse_transition_manifest(&value.manifest())?,
                commit_sha256: checked_artifact_sha256(&value.commit())?,
                metadata: parse_metadata_snapshot(&value.metadata_snapshot())?,
            },
        ),
        VerifiedMutationProjection::ConversationClose(value) => (
            *value.transition_id().as_bytes(),
            TransitionBodyBinding::ConversationClose {
                kind: parse_conversation_kind(value.conversation_kind())?,
                prior: closed_coordinate(&value.prior())?,
                retired: closed_coordinate(&value.retired())?,
            },
        ),
        VerifiedMutationProjection::ZeroLeafLeave(value) => (
            *value.transition_id().as_bytes(),
            TransitionBodyBinding::ZeroLeafLeave {
                prior: closed_coordinate(&value.prior())?,
                next: closed_coordinate(&value.next())?,
            },
        ),
        VerifiedMutationProjection::LeaveCommitFulfillment(value) => (
            *value.transition_id().as_bytes(),
            TransitionBodyBinding::LeaveCommitFulfillment {
                leave_request_id: *value.leave_request_id().as_bytes(),
                prior: closed_coordinate(&value.prior())?,
                next: closed_coordinate(&value.next())?,
                aad_digest: commit_aad_sha256(&value.aad()),
                manifest: parse_transition_manifest(&value.manifest())?,
                commit_sha256: checked_artifact_sha256(&value.commit())?,
                metadata: parse_metadata_snapshot(&value.metadata_snapshot())?,
            },
        ),
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    if !transition_binding_is_route_bound(&body_binding, expected_conversation_id) {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    validate_special_server_fields(entry, &body_binding)?;
    let mut evidence = TransitionEvidence {
        seq: entry.seq(),
        transition_id,
        outer_entry_fingerprint: *entry.outer_control_fingerprint(),
        outer_control_projection: entry.outer_control_projection().to_vec(),
        server_fields_dag_cbor: entry
            .server_fields_dag_cbor()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        durable_row_digest: [0; 32],
        received_at: canonical_server_timestamp(entry.received_at())?,
        authority: Some(authenticated_entry(
            Some(entry.entry_id().as_bytes()),
            Some(entry.conversation_id().as_bytes()),
            entry.mutation(),
        )?),
        body_binding: Some(body_binding),
    };
    evidence.durable_row_digest = durable_control_transition_row_digest(&evidence)?;
    Ok(evidence)
}

/// Head-binding-free duplicate of `HydrationAuthority::control_request`
/// (state_machine.rs) — the request-kind match + evidence minting, MINUS the
/// append-time head guards (`seq == expected_next_entry_seq`; `received_at ==
/// locked_at`; `prior == expected_prior`). Reuses the same certified
/// `request_evidence_from_verified` free fn. The trailing `_ =>` wildcard
/// mirrors the original (not exhaustive over `VerifiedMutationProjection` — it
/// accepts only the three control-request kinds); drift is fenced by the
/// per-kind cfg(test) `historical_control_matches_append_time_per_kind`
/// equivalence test, not by exhaustiveness. Read-time only; NEVER used at append
/// time.
#[allow(dead_code)]
pub(in crate::chat_protocol::state_machine) fn historical_control_request_evidence(
    entry: VerifiedControlEntry,
    expected_conversation_id: &[u8; 16],
) -> Result<RequestEvidence, StateMachineError> {
    if entry.conversation_id().as_bytes() != expected_conversation_id {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let (kind, request_id, body_binding) = match entry.mutation().projection() {
        VerifiedMutationProjection::ResetRequest(value) => (
            RequestEntryKind::ResetRequest,
            value.reset_request_id(),
            RequestBodyBinding::ResetRequest {
                prior: closed_coordinate(&value.prior())?,
            },
        ),
        VerifiedMutationProjection::LeaveRequest(value) => (
            RequestEntryKind::LeaveRequest,
            value.leave_request_id(),
            RequestBodyBinding::LeaveRequest {
                prior: closed_coordinate(&value.prior())?,
            },
        ),
        VerifiedMutationProjection::LeaveCancellation(value) => (
            RequestEntryKind::LeaveCancellation,
            value.leave_request_id(),
            RequestBodyBinding::LeaveCancellation {
                conversation_id: *value.conversation_id().as_bytes(),
            },
        ),
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    request_evidence_from_verified(
        kind,
        Some(entry.entry_id().as_bytes()),
        entry.conversation_id().as_bytes(),
        Some(entry.seq()),
        Some(entry.outer_control_projection().to_vec()),
        Some(
            entry
                .server_fields_dag_cbor()
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        ),
        request_id.as_bytes(),
        canonical_server_timestamp(entry.received_at())?,
        *entry.outer_control_fingerprint(),
        entry.mutation(),
        body_binding,
    )
}

pub(crate) struct PersistedDeviceRevocationRow {
    pub(in crate::chat_protocol::state_machine) accepted_at: CanonicalTimestamp,
    pub(in crate::chat_protocol::state_machine) durable_row_digest: [u8; 32],
}

impl PersistedDeviceRevocationRow {
    pub(crate) fn new(
        accepted_at: &str,
        durable_row_digest: [u8; 32],
    ) -> Result<Self, StateMachineError> {
        if durable_row_digest == [0; 32] {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            accepted_at: CanonicalTimestamp::parse(accepted_at)
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
            durable_row_digest,
        })
    }
}

impl PersistedSignedRequestRow {
    pub(crate) fn new(
        conversation_id: [u8; 16],
        received_at: &str,
        durable_row_digest: [u8; 32],
    ) -> Result<Self, StateMachineError> {
        if !is_uuid_v4(&conversation_id) || durable_row_digest == [0; 32] {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            conversation_id,
            received_at: CanonicalTimestamp::parse(received_at)
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
            durable_row_digest,
        })
    }
}

pub(crate) struct DurableSignedRequestEnvelope {
    pub(in crate::chat_protocol::state_machine) conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) received_at: ServerTimestamp,
}

#[derive(Debug)]
pub(crate) enum WelcomeTerminalPlan {
    Planned(PlannedTransition),
    DueExpiry(PlannedTransition),
    Terminal {
        classification: LockedWelcomeTerminal,
        exact_replay: bool,
    },
}

impl DurableSignedRequestEnvelope {
    pub(crate) fn new(
        conversation_id: [u8; 16],
        received_at: &TrustedRequestInstant,
    ) -> Result<Self, StateMachineError> {
        if !is_uuid_v4(&conversation_id) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            conversation_id,
            received_at: ServerTimestamp::from_trusted_request_instant(received_at)?,
        })
    }
}

pub(in crate::chat_protocol::state_machine) fn authenticated_entry(
    control_entry_id: Option<&[u8; 16]>,
    control_conversation_id: Option<&[u8; 16]>,
    mutation: &VerifiedSignedMutation,
) -> Result<AuthenticatedEntryEvidence, StateMachineError> {
    let key_id: [u8; 32] = URL_SAFE_NO_PAD
        .decode(mutation.key_id().as_str())
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
        .try_into()
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
    let signed_request_bytes = mutation
        .accepted_wrapper_bytes()
        .filter(|bytes| !bytes.is_empty())
        .ok_or(StateMachineError::InvalidHydrationAuthority)?
        .to_vec();
    Ok(AuthenticatedEntryEvidence {
        kind: mutation.kind(),
        type_id: mutation.type_id(),
        domain: mutation.domain().to_vec(),
        control_entry_id: control_entry_id.copied(),
        control_conversation_id: control_conversation_id.copied(),
        actor: DeviceIdentity::new(
            PrincipalId::new(mutation.actor_did().as_str().as_bytes().to_vec())?,
            *mutation.actor_device_id().as_bytes(),
        )?,
        key_id,
        auth_generation: mutation.auth_generation(),
        signed_at: canonical_server_timestamp(mutation.signed_at())?,
        request_digest: *mutation.request_digest(),
        signature: *mutation.signature(),
        signed_request_bytes,
        canonical_projection: mutation.canonical_projection().to_vec(),
        transcript_bytes: mutation.transcript_bytes().to_vec(),
    })
}

#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine) fn request_evidence_from_verified(
    kind: RequestEntryKind,
    control_entry_id: Option<&[u8; 16]>,
    conversation_id: &[u8; 16],
    control_seq: Option<u64>,
    control_outer_projection: Option<Vec<u8>>,
    control_server_fields_dag_cbor: Option<Vec<u8>>,
    request_id: &[u8; 16],
    received_at: ServerTimestamp,
    durable_row_digest: [u8; 32],
    mutation: &VerifiedSignedMutation,
    body_binding: RequestBodyBinding,
) -> Result<RequestEvidence, StateMachineError> {
    let authority = authenticated_entry(
        control_entry_id,
        control_entry_id.map(|_| conversation_id),
        mutation,
    )?;
    let signed_request_bytes = authority.signed_request_bytes.clone();
    let mut evidence = RequestEvidence {
        kind,
        control_entry_id: control_entry_id.copied(),
        conversation_id: *conversation_id,
        control_seq,
        control_outer_entry_fingerprint: control_entry_id.map(|_| durable_row_digest),
        control_outer_projection,
        control_server_fields_dag_cbor,
        request_id: *request_id,
        actor: authority.actor.clone(),
        key_id: authority.key_id,
        auth_generation: authority.auth_generation,
        request_digest: authority.request_digest,
        signature: authority.signature,
        signed_request_bytes,
        durable_row_digest,
        received_at,
        authority: Some(authority),
        body_binding: Some(body_binding),
    };
    if evidence.control_entry_id.is_some() {
        evidence.durable_row_digest = durable_control_request_row_digest(&evidence)?;
    }
    Ok(evidence)
}

pub(in crate::chat_protocol::state_machine) fn canonical_server_timestamp(
    value: &crate::chat_protocol::validation::CanonicalTimestamp,
) -> Result<ServerTimestamp, StateMachineError> {
    ServerTimestamp::from_unix_millis(value.datetime().timestamp_millis())
}

pub(in crate::chat_protocol::state_machine) fn parse_direct_request_publication(
    body: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> Result<TransitionBodyBinding, StateMachineError> {
    let next = closed_coordinate_from_field(body, "next")?;
    let recipient = closed_principal(body, "recipientDid")?;
    let actor = closed_device(body, "actorDid", "actorDeviceId")?;
    let Some(CanonicalValueRef::Object(origin)) = body.get("origin") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    let prior = match closed_text(&origin, "$type")? {
        "blue.catbird.chat.defs#freshDirectOrigin" => None,
        "blue.catbird.chat.defs#legacyPendingDirectOrigin" => {
            Some(closed_coordinate_from_field(&origin, "exactPrior")?)
        }
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    if next.state_version() != 1
        || next.epoch() != 1
        || next.lifecycle() != PublicGroupSnapshotLifecycle::Active
        || next.conversation_id() != &closed_uuid(body, "conversationId")?
        || actor.principal() == &recipient
        || prior.as_ref().map_or(next.generation() != 0, |p| {
            p.conversation_id() != next.conversation_id()
                || p.generation().checked_add(1) != Some(next.generation())
                || p.group_id() == next.group_id()
                || p.lifecycle() != PublicGroupSnapshotLifecycle::Active
        })
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let Some(CanonicalValueRef::Object(artifacts)) = body.get("artifacts") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    let Some(CanonicalValueRef::Object(metadata)) = artifacts.get("metadataSnapshot") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    let metadata = parse_metadata_snapshot(&metadata)?;
    let Some(CanonicalValueRef::Object(welcome)) = artifacts.get("welcome") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    let Some(CanonicalValueRef::Array(deliveries)) = welcome.get("deliveries") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    let mut devices = vec![actor.clone()];
    for i in 0..deliveries.len() {
        let Some(CanonicalValueRef::Object(delivery)) = deliveries.get(i) else {
            return Err(StateMachineError::InvalidHydrationAuthority);
        };
        let device = closed_device(&delivery, "recipientDid", "recipientDeviceId")?;
        if device.principal() != actor.principal() && device.principal() != &recipient {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        devices.push(device);
    }
    devices.sort();
    if devices.len() < 2
        || devices.len() > MAX_LEAVES
        || devices.windows(2).any(|p| p[0] == p[1])
        || !devices.iter().any(|d| d.principal() == &recipient)
        || !metadata_coordinate_matches(&metadata, &next)
        || metadata.origin_transition_id != closed_uuid(body, "requestId")?
        || metadata.metadata_version != 1
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(TransitionBodyBinding::DirectRequestPublication {
        prior,
        next,
        recipient,
        devices,
        metadata,
    })
}

pub(in crate::chat_protocol::state_machine) fn closed_uuid(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<[u8; 16], StateMachineError> {
    match object.get(name) {
        Some(CanonicalValueRef::Uuid(value)) => Ok(*value.as_bytes()),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

pub(in crate::chat_protocol::state_machine) fn closed_integer(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<u64, StateMachineError> {
    match object.get(name) {
        Some(CanonicalValueRef::Integer(value)) => Ok(value),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

pub(in crate::chat_protocol::state_machine) fn closed_text<'a>(
    object: &'a crate::chat_protocol::transcript::ClosedObjectRef<'a>,
    name: &str,
) -> Result<&'a str, StateMachineError> {
    match object.get(name) {
        Some(CanonicalValueRef::Text(value)) => Ok(value),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

pub(in crate::chat_protocol::state_machine) fn closed_principal(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<PrincipalId, StateMachineError> {
    match object.get(name) {
        Some(CanonicalValueRef::Did(value)) => PrincipalId::new(value.as_str().as_bytes().to_vec()),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

pub(in crate::chat_protocol::state_machine) fn closed_key_id(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<[u8; 32], StateMachineError> {
    let value = match object.get(name) {
        Some(CanonicalValueRef::Thumbprint(value)) => value.as_str(),
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
        .try_into()
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)
}

pub(in crate::chat_protocol::state_machine) fn closed_timestamp(
    object: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<ServerTimestamp, StateMachineError> {
    match object.get(name) {
        Some(CanonicalValueRef::Timestamp(value)) => canonical_server_timestamp(value),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}
