#![allow(unused_imports)]
// Deterministic transition planning for `blue.catbird.chat` protocol "1".
//
// Every function borrows the authoritative state immutably and returns a
// complete successor plan. Persistence must compare `expected_prior` in one
// full-coordinate CAS and apply the returned state/effects atomically. No
// function in this module writes storage or calls a legacy MLS handler.

#[path = "state_machine/direct_request.rs"]
pub(crate) mod direct_request;

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::relationship_policy::{
    AdmissionOperation, AdmissionRequest, ProjectionOperationScope, PublicTransport,
    RelationshipAuthority, RelationshipProjection,
};

use super::repository::auth::{BusinessAuthorityGuard, RepositoryAuthorityClass};
use super::repository::core::{
    LockedConversationHeadGuard, LockedConversationStateGuard, LockedDirectConversationLookupGuard,
    LockedDirectLookupOutcome, LockedInvitationQuotaGuard, LockedRecoveryPackageGuard,
    LockedRecoveryPackageStatus, LockedRecoveryPackageUse, LockedWelcomeGuard,
    LockedWelcomeTerminal,
};
use super::repository::core::{
    LockedRevocationFanoutGuard, LockedRevocationPackageGuard, LockedRevocationTargetGuard,
    LockedRevocationTargetStatus,
};
use super::repository::prelude::RecoveryPreludePrewriteWitness;
use super::repository::prelude::{OperationCompletionGuard, ScopeBoundBusinessAuthority};
use super::repository::recovery::{
    RecoveryCancellationPlanInput, RecoveryClientExpiryPlanInput, RecoveryClientTerminalError,
    RecoveryFulfillmentPlanInput, RecoveryPersistenceWitness, RecoveryRequestPlanInput,
    RecoverySchedulerExpiryPlanInput,
};
use super::repository::relationship::{
    consume_locked_acceptance_projection, consume_locked_creation_projection,
    consume_locked_pending_add_projection, consume_locked_recovery_projection,
    LockedNoPendingAdmissionGuard, LockedRelationshipDecisionGuard, RelationshipConsumptionError,
};

use super::{
    public_state::{
        process_commit, rebind_active_snapshot, verify_genesis_group_info, verify_recovery_welcome,
        verify_reset_successor_group_info, ActivePublicState, GenesisGroupInfoExpectations,
        PublicStateError, ResetSuccessorGroupInfoExpectations, VerifiedCommitPublicState,
        VerifiedRecoveryWelcome,
    },
    snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle, MAX_PROTOCOL_INTEGER},
    transcript::{
        build_verified_control_entry, decode_and_verify_control_entry,
        decode_and_verify_signed_mutation, rebind_persisted_control_entry,
        CanonicalControlEntryProducts, CanonicalControlServerFields, CanonicalValueRef,
        ControlEntryKind, SignedMutationKind, VerifiedControlEntry, VerifiedMutationProjection,
        VerifiedSignedMutation,
    },
    validation::{
        ed25519_key_id, BareDid, CanonicalTimestamp, CanonicalUuidV4, KeyThumbprint,
        TrustedRequestInstant, ValidatedChatNsid,
    },
    wire::{
        trusted_unix_millis_to_seconds, validate_key_package, KeyPackageValidationPolicy,
        MAX_GROUP_INFO_WIRE_BYTES, MAX_KEY_PACKAGE_WIRE_BYTES, MAX_WELCOME_WIRE_BYTES,
    },
};

#[path = "state_machine/creation.rs"]
mod creation;
use self::creation::{
    is_uuid_v4, relationship_consumption_error, AcceptanceRecoveryBinding, InvitationBinding,
    ManifestLeafChange, ManifestParticipantChange, ManifestWelcomeBinding,
    MetadataAuthorProofBinding, MetadataCryptoCoordinate, RequestBodyBinding,
    RosterManifestBinding, RosterParticipantBinding, TransitionBodyBinding,
    TransitionManifestBinding, COMMIT_AAD_DOMAIN, CONSENT_TTL_MILLIS, MAX_LEAVES,
    MAX_LEAVES_PER_PRINCIPAL, MAX_PARTICIPANTS, RECOVERY_RESERVATION_TTL_MILLIS,
};
pub(crate) use self::creation::{
    AuthenticatedEntryEvidence, CloseKind, ConversationKind, DeviceIdentity,
    DeviceRevocationEvidence, InvitationProvenance, LeafRecord, MetadataAvatarDescriptorBinding,
    MetadataSnapshotBinding, OpeningKind, ParticipantRecord, ParticipantRole, ParticipantStatus,
    PrincipalId, RequestEntryKind, RequestEvidence, ServerTimestamp, StateMachineError,
    TransitionEvidence,
};
#[path = "state_machine/transitions.rs"]
mod transitions;
pub(crate) use self::transitions::HydrationAuthority;
use self::transitions::{historical_actor, LockedHydrationBinding};
pub(in crate::chat_protocol) use self::transitions::{
    HistoricalPlanWitness, PlannedClientRecoveryExpiry, PlannedRecoveryMutation,
    PlannedSchedulerRecoveryExpiry, RecoveryPlannedKind,
};
#[path = "state_machine/direct_requests.rs"]
mod direct_requests;
#[path = "state_machine/messages.rs"]
mod messages;
#[path = "state_machine/metadata.rs"]
mod metadata;
#[path = "state_machine/recovery.rs"]
mod recovery;
pub(crate) use self::metadata::{
    acceptance_recovery_package_artifact_matches, classify_acceptance, classify_invitation,
    classify_role_producer, HistoricalRehydrationAuthority, PersistedControlAuthority,
    PersistedControlRow, PersistedSignedRequestRow,
};
#[path = "state_machine/lifecycle.rs"]
mod lifecycle;
use self::lifecycle::{
    authenticated_entry, canonical_server_timestamp, closed_integer, closed_key_id,
    closed_principal, closed_text, closed_timestamp, closed_uuid,
    historical_control_request_evidence, historical_signed_request_evidence,
    historical_transition_evidence, parse_direct_request_publication,
    request_evidence_from_verified,
};
pub(crate) use self::lifecycle::{
    DurableSignedRequestEnvelope, PersistedDeviceRevocationRow, WelcomeTerminalPlan,
};
#[path = "state_machine/types.rs"]
mod types;
#[cfg(test)]
use self::types::registration_row_digest;
#[cfg(test)]
use self::types::registration_row_digest_fields;
#[cfg(test)]
pub(crate) use self::types::PersistedRegistrationRow;
pub(crate) use self::types::{
    checked_artifact_bytes, closed_coordinate, commit_aad_bytes, PersistedRegistrationStatus,
};
use self::types::{
    checked_artifact_sha256, checked_metadata_snapshot_digest, closed_coordinate_conversation_id,
    closed_coordinate_from_field, closed_device, closed_fixed_bytes, commit_aad_sha256,
    device_revocation_row_digest, durable_signed_request_row_digest, manifest_change_principal,
    metadata_coordinate_matches, parse_acceptance_recovery, parse_conversation_kind,
    parse_invitation, parse_metadata_snapshot, parse_participant_changes, parse_participant_role,
    parse_participant_status, parse_roster_manifest, parse_transition_manifest,
    sealed_object_digest, transition_binding_is_route_bound, transition_body_prior,
    validate_device_revocation_evidence, validate_special_server_fields,
};
#[path = "state_machine/evidence.rs"]
mod evidence;
#[cfg(test)]
use self::evidence::coordinate_digest;
#[cfg(test)]
use self::evidence::recovery_reservation_selection_digest;
#[cfg(test)]
use self::evidence::recovery_reservation_selection_digest_fields;
#[cfg(test)]
use self::evidence::uuid_from_test_byte;
#[cfg(test)]
pub(crate) use self::evidence::PersistedRecoveryReservationSelectionRow;
use self::evidence::{
    durable_control_request_row_digest, durable_control_row_digest,
    durable_control_transition_row_digest, durable_signed_request_evidence_digest,
    require_leaf_recovery_request_binding, require_request_prior, validate_request_evidence,
    WorkTerminalEvidence,
};
pub(crate) use self::evidence::{
    historical_available_package_cas, reserved_package_cas_for_request,
    FederatedOperationAdmission, LockedRecoveryReservationProjection,
};
#[path = "state_machine/hydration_entries.rs"]
mod hydration_entries;
#[cfg(test)]
pub(crate) use self::hydration_entries::LeaveFulfillmentTestMutation;
use self::hydration_entries::{
    request_entry_signed_kind, require_request_coordinate_binding, RecoveryOriginEvidence,
};
pub(crate) use self::hydration_entries::{
    AccessInterval, AccessIntervalEnd, ConversationState, ConversationStateHydration,
    IntervalEndHydrationRow, IntervalHydrationRow, InvitationHydrationRow, LeafHydrationRow,
    LeafRecoveryKind, LeaveRequest, LeaveRequestHydrationRow, LeaveRequestStatus,
    ParticipantHydrationRow, ParticipantRemovalEvidence, RecoveryOriginHydrationRow,
    RecoveryRequest, RecoveryRequestHydrationRow, RecoveryRequestStatus, RecoveryReservation,
    RecoveryReservationHydrationRow, RecoverySource, ReservationStatus, ResetRequest,
    ResetRequestHydrationRow, ResetRequestStatus, ScheduleTerminalProof, TerminalProofHydrationRow,
    WelcomeHydrationRow, WelcomeStatus, WelcomeWork, WorkTerminalHydrationRow,
};
#[path = "state_machine/hydration_requests.rs"]
mod hydration_requests;
pub(crate) use self::hydration_requests::{
    hydrate_conversation_state, PackageStatus, PackageTransition, PlanKind,
};
use self::hydration_requests::{work_terminal_from_hydration, work_terminal_to_hydration};
#[path = "state_machine/historical.rs"]
mod historical;
use self::historical::{
    recovery_package_cas_authority_digest, welcome_cas_seal, welcome_status_code,
};
pub(crate) use self::historical::{
    ConversationHeadCasBinding, InvitationQuotaCasBinding, InvitationQuotaRecipientCasFact,
    PlanAuthority, RecoveryExpiryPlanAuthority, RecoveryPackageCasBinding,
    RevocationPackageCasBinding, RevocationTargetCasBinding, StateChange, StateCounts,
    TransitionEffects, WelcomeCasBinding, WelcomeExpiryAuthority,
};
#[path = "state_machine/registration.rs"]
mod registration;
use self::registration::{
    classify_recovery_plan_shape, complete_effects, diff_by_key, package_cas_bijection_valid,
    package_transitions, recovery_plan_class_code, revocation_package_cas_bijection_valid,
    state_counts, work_terminal_time,
};
pub(crate) use self::registration::{
    recovery_plan_fingerprint, ConversationPersistencePlan, PlannedTransition, RecoveryPlanClass,
    RecoveryPlanFingerprint, RecoveryPlanFingerprintError,
};
#[path = "state_machine/state_graph.rs"]
mod state_graph;
use self::state_graph::{
    exact_recovery_request_edge, exact_reservation_edge,
    fulfillment_fingerprint_families_are_closed, RecoveryPlanEncoder,
};
#[path = "state_machine/hydration_rows.rs"]
mod hydration_rows;
use self::hydration_rows::{
    close_kind_code, conversation_kind_code, invitation_quota_recipient_facts_valid,
    leave_request_status_code, opening_kind_code, package_status_code, participant_role_code,
    participant_status_code, plan_kind_code, recovery_kind_code, recovery_request_status_code,
    recovery_source_code, registration_status_code, request_kind_code, reservation_status_code,
    reset_request_status_code, signed_mutation_kind_code,
};
#[path = "state_machine/effects.rs"]
mod effects;
use self::effects::{
    canonical_pair, existing_direct_pair, singleton_genesis_leaf, validate_creation_command,
};
pub(crate) use self::effects::{
    plan_creation_inner, CreationCommand, CreationDecision, PolicyCommand,
};
#[path = "state_machine/recovery_fingerprint.rs"]
mod recovery_fingerprint;
use self::recovery_fingerprint::{
    invitation_quota_cas_from_guard, plan_leaf_recovery_cancellation_inner,
    plan_leaf_recovery_expiry_inner, plan_leaf_recovery_request_inner, plan_metadata_inner,
    plan_welcome_expiry, plan_welcome_response, recovery_expiry, recovery_expiry_plan_authority,
    sort_leave_requests, sort_recovery_requests, sort_recovery_reservations, sort_reset_requests,
    welcome_cas_from_guard, welcome_endpoint_matches, welcome_response_reason_matches,
};
pub(crate) use self::recovery_fingerprint::{
    plan_accept_conversation_inner, plan_policy_transition, AcceptConversation,
    LeafRecoveryCancellation, LeafRecoveryRequestCommand, MetadataCommand,
};
#[path = "state_machine/recovery_encoder.rs"]
mod recovery_encoder;
use self::recovery_encoder::{
    materialize_next_leaves, plan_commit_inner, plan_device_revocation_inner,
    plan_leave_cancellation_inner, plan_leave_request_inner, plan_reset_activation_inner,
    plan_reset_request_inner, plan_zero_leaf_leave_inner, verify_commit_actor,
};
pub(crate) use self::recovery_encoder::{
    plan_leaf_recovery_fulfillment_inner, CommitCommand, LeafRecoveryFulfillment,
    LeaveCancellation, LeaveFulfillment, LeaveRequestCommand, ResetActivation, ResetRequestCommand,
    ZeroLeafLeave,
};
#[path = "state_machine/planned_transition.rs"]
mod planned_transition;
pub(crate) use self::planned_transition::CloseConversation;
use self::planned_transition::{plan_close_inner, plan_leave_fulfillment_inner};
#[path = "state_machine/commands.rs"]
mod commands;
#[cfg(test)]
pub(crate) use self::commands::device_revocation_plan_for_test;
#[cfg(test)]
use self::commands::dummy_principal;
#[cfg(test)]
pub(crate) use self::commands::persistence_plan_for_test;
#[cfg(test)]
pub(crate) use self::commands::plan_accept_conversation;
#[cfg(test)]
pub(crate) use self::commands::plan_creation;
#[cfg(test)]
pub(crate) use self::commands::plan_device_revocation;
#[cfg(test)]
pub(crate) use self::commands::plan_leaf_recovery_cancellation;
#[cfg(test)]
pub(crate) use self::commands::plan_leaf_recovery_expiry;
#[cfg(test)]
pub(crate) use self::commands::plan_leaf_recovery_fulfillment;
#[cfg(test)]
pub(crate) use self::commands::plan_leaf_recovery_request;
#[cfg(test)]
pub(crate) use self::commands::plan_metadata;
#[cfg(test)]
pub(crate) use self::commands::plan_policy;
#[cfg(test)]
pub(crate) use self::commands::PolicyPlanMutation;
#[path = "state_machine/planners.rs"]
mod planners;
#[cfg(test)]
pub(crate) use self::planners::plan_close;
#[cfg(test)]
pub(crate) use self::planners::plan_commit;
#[cfg(test)]
pub(crate) use self::planners::plan_leave_cancellation;
#[cfg(test)]
pub(crate) use self::planners::plan_leave_fulfillment;
#[cfg(test)]
pub(crate) use self::planners::plan_leave_request;
#[cfg(test)]
pub(crate) use self::planners::plan_reset_activation;
#[cfg(test)]
pub(crate) use self::planners::plan_reset_request;
#[cfg(test)]
pub(crate) use self::planners::plan_welcome_expiry_for_test;
#[cfg(test)]
pub(crate) use self::planners::plan_welcome_response_for_test;
#[cfg(test)]
pub(crate) use self::planners::plan_zero_leaf_leave;
pub(crate) use self::planners::retired_coordinate;
use self::planners::{
    acceptance_matches_participant, close_open_interval, coordinate_only_successor,
    current_state_producer_matches, ensure_active, expire_due_leave_requests,
    initial_participant_role, invitation_matches_participant, metadata_provenance_matches,
    open_interval, participant_provenance_matches, participant_role_provenance_matches,
    pending_request_leaf_is_bound, require_transition_kind, resolve_prior_bound_work,
    sort_intervals, validate_participants, validate_state, validate_terminal_state,
    validate_transition_evidence,
};
#[path = "state_machine/invariants.rs"]
mod invariants;
pub(crate) use self::invariants::metadata_binding_of_transition;
use self::invariants::{
    commit_metadata_matches, creation_manifest_matches, metadata_author_matches_evidence,
    require_acceptance_body, require_commit_body, require_commit_manifest,
    require_coordinate_only_body, require_creation_body, require_metadata_body,
    require_reset_activation_body, require_transition_actor, reset_manifest_matches,
    reset_metadata_matches, transition_has_one_of_kinds, transition_metadata, validate_intervals,
    CommitManifestForm,
};
#[path = "state_machine/membership_rules.rs"]
mod membership_rules;
use self::membership_rules::{
    acceptance_origin_matches_recovery, commit_coordinate_edge, coordinate_after_opening,
    coordinate_is_in_lineage, end_matches_interval, exact_expiry,
    leave_fulfillment_matches_request, opening_matches_interval,
    recovery_fulfillment_binding_matches, recovery_fulfillment_matches_request,
    reset_activation_matches_request, reset_successor_edge, transition_consumes_coordinate,
    transition_follows_origin, validate_terminal_proofs, validate_work,
};
pub(crate) use self::membership_rules::{
    recovery_cancellation_terminal_matches, recovery_fulfillment_terminal_matches,
    recovery_supersession_terminal_matches,
};
#[path = "state_machine/work_validation.rs"]
mod work_validation;
use self::work_validation::{
    recovery_origin_received_at, recovery_origin_request_digest, revocation_supersedes_request,
    validate_leave_work, validate_recovery_work, validate_reset_work, validate_welcome_work,
    would_remove_last_active_admin,
};
#[cfg(test)]
#[path = "state_machine/inline_unit_tests.rs"]
mod inline_unit_tests;

/// Non-cloneable sealed registration projection. It is exact-device, exact-key
/// and auth-generation bound and records the trusted instant at which the row
/// was read under the planner's transaction.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LockedRegistrationProjection {
    conversation_id: [u8; 16],
    actor: DeviceIdentity,
    key_id: [u8; 32],
    registered_mls_signature_key: [u8; 32],
    auth_generation: u64,
    status: PersistedRegistrationStatus,
    trusted_read_at: ServerTimestamp,
    durable_row_digest: [u8; 32],
    transaction_id: String,
    authority_scope_digest: [u8; 32],
}

impl LockedRegistrationProjection {
    pub(in crate::chat_protocol::state_machine) fn authorizes(
        &self,
        evidence: &RequestEvidence,
    ) -> bool {
        self.status == PersistedRegistrationStatus::Active
            && self.conversation_id == evidence.conversation_id
            && self.actor == evidence.actor
            && self.key_id == evidence.key_id
            && self.auth_generation == evidence.auth_generation
            && self.trusted_read_at >= evidence.received_at
            && self.durable_row_digest != [0; 32]
    }

    pub(in crate::chat_protocol::state_machine) fn authorizes_transition(
        &self,
        evidence: &TransitionEvidence,
    ) -> bool {
        let Some(authority) = evidence.authority.as_ref() else {
            return false;
        };
        self.status == PersistedRegistrationStatus::Active
            && authority.control_conversation_id == Some(self.conversation_id)
            && self.actor == authority.actor
            && self.key_id == authority.key_id
            && self.auth_generation == authority.auth_generation
            && self.trusted_read_at >= evidence.received_at
            && self.durable_row_digest != [0; 32]
    }

    pub(in crate::chat_protocol::state_machine) fn authorizes_revocation(
        &self,
        evidence: &DeviceRevocationEvidence,
    ) -> bool {
        self.status == PersistedRegistrationStatus::Active
            && self.actor == evidence.actor
            && self.key_id == evidence.actor_key_id
            && self.auth_generation == evidence.actor_auth_generation
            && self.trusted_read_at == evidence.accepted_at
            && self.durable_row_digest != [0; 32]
            && self.authority_scope_digest != [0; 32]
    }

    pub(crate) fn actor(&self) -> &DeviceIdentity {
        &self.actor
    }

    pub(crate) fn registered_mls_signature_key(&self) -> &[u8; 32] {
        &self.registered_mls_signature_key
    }

    pub(crate) fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    pub(crate) fn auth_generation(&self) -> u64 {
        self.auth_generation
    }

    pub(crate) fn status(&self) -> PersistedRegistrationStatus {
        self.status
    }

    pub(crate) fn trusted_read_at(&self) -> ServerTimestamp {
        self.trusted_read_at
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(crate) fn conversation_id(&self) -> &[u8; 16] {
        &self.conversation_id
    }

    pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
        &self.durable_row_digest
    }

    pub(crate) fn authority_scope_digest(&self) -> &[u8; 32] {
        &self.authority_scope_digest
    }
}

/// One atomic global revocation write. The target registration CAS occurs
/// exactly once; every conversation/work/package member was proven complete
/// by the consumed repository fanout manifest and is committed in the same
/// transaction or the entire batch rolls back.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DeviceRevocationBatchPersistencePlan {
    authority: DeviceRevocationEvidence,
    target_cas: RevocationTargetCasBinding,
    revoked_packages: Vec<RevocationPackageCasBinding>,
    authority_scope_digest: [u8; 32],
    fanout_manifest_digest: [u8; 32],
    conversations: Vec<ConversationPersistencePlan>,
}

impl HydrationAuthority {
    pub(crate) fn plan_recovery_fulfillment_input<T: PublicTransport>(
        input: RecoveryFulfillmentPlanInput,
        relationship_authority: &RelationshipAuthority<T>,
    ) -> Result<PlannedRecoveryMutation, StateMachineError> {
        let parts = input.into_planner_parts();
        let request_id = match parts.mutation.projection() {
            VerifiedMutationProjection::LeafRecoveryFulfillment(value) => {
                Uuid::from_bytes(*value.recovery_request_id().as_bytes())
            }
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if parts.prelude.scope_authority().trusted_instant()
            != parts.trusted_request_instant.datetime()
            || parts.transition_id.get_version_num() != 4
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let hydration = HydrationAuthority::from_locked_conversation(&parts.aggregate)?;
        let actor_registration =
            hydration.locked_registration_from_scope_authority(parts.prelude.scope_authority())?;
        let target_registration = hydration.locked_registration_for_scoped_device(
            parts.prelude.scope_authority(),
            parts.execution_package.target_did(),
            parts.execution_package.target_device_id(),
            parts.execution_package.target_key_id(),
            parts.execution_package.target_auth_generation(),
        )?;
        let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.submitTransition")
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let entry = build_verified_control_entry(
            parts.mutation,
            &endpoint,
            CanonicalUuidV4::parse(&parts.transition_id.hyphenated().to_string())
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
            CanonicalUuidV4::parse(
                &parts
                    .aggregate
                    .head()
                    .conversation_id()
                    .hyphenated()
                    .to_string(),
            )
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
            parts.aggregate.head().next_entry_seq(),
            &parts.trusted_request_instant,
            CanonicalControlServerFields::empty(ControlEntryKind::LeafRecoveryFulfillment)
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        )
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let control_products = CanonicalControlEntryProducts::mint(&entry)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let accepted_control_entry_bytes = control_products.durable_json().to_vec();
        let canonical_response_entry_bytes = control_products.canonical_response_json().to_vec();
        let transition = hydration.plan_recovery_fulfillment_entry(
            &parts.aggregate,
            entry,
            &actor_registration,
            &target_registration,
            parts.execution_package,
            parts.terminal_packages,
            &parts.relationship,
            relationship_authority,
            &parts.relationship_decision,
            &parts.trusted_request_instant,
        )?;
        let (scope_authority, completion, prewrite) = parts.prelude.into_recovery_execution_parts();
        Ok(PlannedRecoveryMutation {
            transition,
            scope_authority,
            completion,
            prewrite,
            accepted_control_entry_bytes: Some(accepted_control_entry_bytes),
            canonical_response_entry_bytes: Some(canonical_response_entry_bytes),
            persistence_witness: parts.persistence_witness,
            kind: RecoveryPlannedKind::Fulfillment {
                recovery_request_id: request_id,
                transition_id: parts.transition_id,
            },
        })
    }

    /// Consume the device-first lock set exactly once and plan every affected
    /// conversation as one all-or-nothing transaction batch. The repository
    /// fanout manifest proves completeness, including the legal empty case;
    /// callers cannot omit a conversation, request, Welcome, or reserved
    /// package and still obtain a persistence plan.
    pub(crate) fn plan_device_revocation_batch(
        mutation: VerifiedSignedMutation,
        actor_registration: LockedRegistrationProjection,
        target_guard: LockedRevocationTargetGuard,
        fanout_guard: LockedRevocationFanoutGuard,
        mut live_package_guards: Vec<LockedRevocationPackageGuard>,
        mut locked_conversations: Vec<LockedConversationStateGuard>,
    ) -> Result<DeviceRevocationBatchPersistencePlan, StateMachineError> {
        let transaction_id = actor_registration.transaction_id();
        let accepted_at = actor_registration.trusted_read_at();
        let locked_at = target_guard.locked_at();
        if transaction_id != target_guard.transaction_id()
            || transaction_id != fanout_guard.transaction_id()
            || locked_at != target_guard.locked_at()
            || locked_at != fanout_guard.locked_at()
            || ServerTimestamp::from_unix_millis(locked_at.timestamp_millis())? != accepted_at
            || target_guard.status() != LockedRevocationTargetStatus::Active
            || target_guard.durable_row_digest() == &[0; 32]
            || fanout_guard.durable_manifest_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let evidence = Self::device_revocation_at(mutation, accepted_at)?;
        if !actor_registration.authorizes_revocation(&evidence)
            || target_guard.target_did().as_bytes() != evidence.target.principal().as_bytes()
            || target_guard.target_device_id().as_bytes() != evidence.target.device_id()
            || target_guard.target_auth_generation() != evidence.expected_target_auth_generation
            || fanout_guard.target_did() != target_guard.target_did()
            || fanout_guard.target_device_id() != target_guard.target_device_id()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }

        live_package_guards
            .sort_by(|left, right| left.key_package_ref().cmp(right.key_package_ref()));
        if live_package_guards.len() != fanout_guard.live_packages().len()
            || live_package_guards
                .windows(2)
                .any(|pair| pair[0].key_package_ref() >= pair[1].key_package_ref())
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let mut revoked_packages = Vec::with_capacity(live_package_guards.len());
        for (guard, manifest) in live_package_guards
            .into_iter()
            .zip(fanout_guard.live_packages())
        {
            let target_key_id: [u8; 32] = KeyThumbprint::parse(guard.target_key_id())
                .ok()
                .and_then(|value| URL_SAFE_NO_PAD.decode(value.as_str()).ok())
                .and_then(|value| value.try_into().ok())
                .ok_or(StateMachineError::InvalidHydrationAuthority)?;
            let expected_status = match guard.status() {
                LockedRecoveryPackageStatus::Available => PackageStatus::Available,
                LockedRecoveryPackageStatus::Reserved => PackageStatus::Reserved,
                _ => return Err(StateMachineError::InvalidHydrationAuthority),
            };
            if guard.transaction_id() != transaction_id
                || guard.locked_at() != locked_at
                || guard.target_did().as_bytes() != evidence.target.principal().as_bytes()
                || guard.target_device_id().as_bytes() != evidence.target.device_id()
                || guard.target_auth_generation() != evidence.expected_target_auth_generation
                || guard.key_package_ref() != manifest.key_package_ref()
                || guard.status() != manifest.status()
                || guard.conversation_id() != manifest.conversation_id()
                || guard.request_id() != manifest.request_id()
                || guard.durable_row_digest() != manifest.locked_row_digest()
                || guard.wrapper_sha256() == &[0; 32]
            {
                return Err(StateMachineError::InvalidHydrationAuthority);
            }
            revoked_packages.push(RevocationPackageCasBinding {
                transaction_id: transaction_id.to_owned(),
                target: evidence.target.clone(),
                target_key_id,
                target_auth_generation: evidence.expected_target_auth_generation,
                key_package_ref: *guard.key_package_ref(),
                wrapper_sha256: *guard.wrapper_sha256(),
                package_not_after: ServerTimestamp::from_unix_millis(
                    guard.not_after().timestamp_millis(),
                )?,
                expected_status,
                successor_status: PackageStatus::Revoked,
                conversation_id: guard.conversation_id().map(|value| *value.as_bytes()),
                request_id: guard.request_id().map(|value| *value.as_bytes()),
                revocation_id: evidence.revocation_id,
                revoked_at: evidence.accepted_at,
                revocation_request_digest: evidence.request_digest,
                revocation_row_digest: evidence.durable_row_digest,
                locked_row_digest: *guard.durable_row_digest(),
            });
        }

        locked_conversations.sort_by(|left, right| {
            left.state()
                .coordinate()
                .conversation_id()
                .cmp(right.state().coordinate().conversation_id())
        });
        if locked_conversations.len() != fanout_guard.conversations().len()
            || locked_conversations.windows(2).any(|pair| {
                pair[0].state().coordinate().conversation_id()
                    >= pair[1].state().coordinate().conversation_id()
            })
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }

        let mut conversations = Vec::with_capacity(locked_conversations.len());
        let mut attached_reserved_package_refs = BTreeSet::new();
        for (locked, manifest) in locked_conversations
            .into_iter()
            .zip(fanout_guard.conversations())
        {
            let prior = locked.state();
            let head = locked.head();
            if head.transaction_id() != transaction_id
                || head.locked_at() != locked_at
                || head.conversation_id() != manifest.conversation_id()
                || head.durable_row_digest() != manifest.locked_head_digest()
            {
                return Err(StateMachineError::InvalidHydrationAuthority);
            }
            let mut open_request_ids = prior
                .recovery_requests
                .iter()
                .filter(|request| {
                    request.target == evidence.target
                        && request.status == RecoveryRequestStatus::Open
                })
                .map(|request| Uuid::from_bytes(request.request_id))
                .collect::<Vec<_>>();
            open_request_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            let mut pending_welcome_ids = prior
                .welcomes
                .iter()
                .filter(|welcome| {
                    welcome.recipient == evidence.target && welcome.status == WelcomeStatus::Pending
                })
                .map(|welcome| Uuid::from_bytes(welcome.welcome_id))
                .collect::<Vec<_>>();
            pending_welcome_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            let mut reserved_package_refs = open_request_ids
                .iter()
                .map(|request_id| {
                    let request_id_bytes = *request_id.as_bytes();
                    let request = prior
                        .recovery_request(&request_id_bytes)
                        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
                    let reservation = prior
                        .recovery_reservation(&request_id_bytes)
                        .filter(|reservation| {
                            reservation.status == ReservationStatus::Active
                                && reservation.target == evidence.target
                                && reservation.key_package_ref == request.key_package_ref
                        })
                        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
                    Ok(reservation.key_package_ref)
                })
                .collect::<Result<Vec<_>, StateMachineError>>()?;
            reserved_package_refs.sort();
            if open_request_ids != manifest.open_recovery_request_ids()
                || pending_welcome_ids != manifest.pending_welcome_ids()
                || reserved_package_refs != manifest.reserved_package_refs()
            {
                return Err(StateMachineError::InvalidHydrationAuthority);
            }

            let mut package_cas = Vec::with_capacity(reserved_package_refs.len());
            for key_package_ref in reserved_package_refs {
                let binding = revoked_packages
                    .iter()
                    .find(|binding| {
                        binding.key_package_ref == key_package_ref
                            && binding.expected_status == PackageStatus::Reserved
                            && binding.conversation_id
                                == Some(*manifest.conversation_id().as_bytes())
                    })
                    .cloned()
                    .ok_or(StateMachineError::InvalidHydrationAuthority)?;
                let request_id = binding
                    .request_id
                    .ok_or(StateMachineError::InvalidHydrationAuthority)?;
                let request = prior
                    .recovery_request(&request_id)
                    .filter(|request| {
                        request.target == evidence.target
                            && request.status == RecoveryRequestStatus::Open
                            && request.key_package_ref == key_package_ref
                    })
                    .ok_or(StateMachineError::InvalidHydrationAuthority)?;
                if !attached_reserved_package_refs.insert(key_package_ref)
                    || request.request_id != request_id
                {
                    return Err(StateMachineError::InvalidHydrationAuthority);
                }
                package_cas.push(binding);
            }

            let mut plan = plan_device_revocation_inner(prior, evidence.clone())?
                .bind_device_revocation_authority(
                    evidence.clone(),
                    head,
                    transaction_id,
                    accepted_at,
                )?;
            for binding in package_cas {
                plan = plan.bind_revocation_package_cas(binding)?;
            }
            conversations.push(plan.into_revocation_batch_member_plan()?);
        }

        // Conversation-bound Reserved packages must be attached to exactly one
        // locked conversation plan; conversation-less ones (request-scope held
        // or retired packages) are revoked by the device-global batch prefix.
        if revoked_packages.iter().any(|binding| {
            binding.expected_status == PackageStatus::Reserved
                && binding.conversation_id.is_some()
                && !attached_reserved_package_refs.contains(&binding.key_package_ref)
        }) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }

        let target_cas = RevocationTargetCasBinding {
            transaction_id: transaction_id.to_owned(),
            target: evidence.target.clone(),
            expected_auth_generation: target_guard.target_auth_generation(),
            expected_status: PersistedRegistrationStatus::Active,
            successor_status: PersistedRegistrationStatus::Revoked,
            locked_at: accepted_at,
            locked_row_digest: *target_guard.durable_row_digest(),
        };
        Ok(DeviceRevocationBatchPersistencePlan {
            authority: evidence,
            target_cas,
            revoked_packages,
            authority_scope_digest: *actor_registration.authority_scope_digest(),
            fanout_manifest_digest: *fanout_guard.durable_manifest_digest(),
            conversations,
        })
    }

    pub(crate) fn locked_registration_from_scope_authority(
        &self,
        scope: &ScopeBoundBusinessAuthority,
    ) -> Result<LockedRegistrationProjection, StateMachineError> {
        self.locked_registration_from_scope_authority_at(scope, scope.trusted_instant())
    }

    /// Same projection as [`Self::locked_registration_from_scope_authority`] but
    /// with an explicit trusted-read instant. Remote commit transitions use the
    /// client's `signedAt` (validated ±5min at admission and fixed by the signed
    /// request) so the mailbox and sequencer canonicalize byte-identical
    /// registration material across retries.
    pub(crate) fn locked_registration_from_scope_authority_at(
        &self,
        scope: &ScopeBoundBusinessAuthority,
        trusted_read_at_instant: DateTime<Utc>,
    ) -> Result<LockedRegistrationProjection, StateMachineError> {
        if scope.actor_class() != RepositoryAuthorityClass::ExistingDevice
            || scope.actor_device_id().get_version_num() != 4
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
            ServerTimestamp::from_unix_millis(trusted_read_at_instant.timestamp_millis())?;

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
            transaction_id: scope.transaction_id().to_owned(),
            authority_scope_digest: *scope.scope_digest(),
        })
    }

    pub(crate) fn locked_recovery_reservation(
        &self,
        guard: LockedRecoveryPackageGuard,
        registration: &LockedRegistrationProjection,
    ) -> Result<LockedRecoveryReservationProjection, StateMachineError> {
        let conversation_id = *guard.conversation_id().as_bytes();
        let request_id = *guard.request_id().as_bytes();
        let target_did = BareDid::parse(guard.target_did())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let target = DeviceIdentity::new(
            PrincipalId::new(target_did.as_str().as_bytes().to_vec())?,
            *guard.target_device_id().as_bytes(),
        )?;
        let target_key = KeyThumbprint::parse(guard.target_key_id())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let target_key_id: [u8; 32] = URL_SAFE_NO_PAD
            .decode(target_key.as_str())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let target_auth_generation = u64::try_from(guard.target_auth_generation())
            .ok()
            .filter(|value| *value > 0 && *value <= MAX_PROTOCOL_INTEGER)
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let claimed_at = ServerTimestamp::from_unix_millis(guard.claimed_at().timestamp_millis())?;
        let package_not_before =
            ServerTimestamp::from_unix_millis(guard.not_before().timestamp_millis())?;
        let package_not_after =
            ServerTimestamp::from_unix_millis(guard.not_after().timestamp_millis())?;
        if conversation_id != self.expected_conversation_id
            || guard.bound_coordinate().conversation_id() != &conversation_id
            || target != registration.actor
            || target_key_id != registration.key_id
            || target_auth_generation != registration.auth_generation
            || registration.status != PersistedRegistrationStatus::Active
            || registration.transaction_id() != guard.transaction_id()
            || registration.trusted_read_at != claimed_at
            || guard.status() != LockedRecoveryPackageStatus::Available
            || guard.use_kind() != LockedRecoveryPackageUse::AvailableSelection
            || package_not_before >= claimed_at
            || claimed_at >= package_not_after
            || <[u8; 32]>::from(Sha256::digest(guard.wrapper_bytes())) != *guard.wrapper_sha256()
            || guard.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let now_unix_seconds = trusted_unix_millis_to_seconds(claimed_at.unix_millis())
            .ok_or(StateMachineError::InvalidServerTime)?;
        let validated = validate_key_package(
            guard.wrapper_bytes(),
            KeyPackageValidationPolicy {
                expected_basic_credential: &target.basic_credential(),
                expected_signature_key: registration.registered_mls_signature_key(),
                now_unix_seconds,
                max_bytes: MAX_KEY_PACKAGE_WIRE_BYTES,
            },
        )
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let validated_not_before = i64::try_from(validated.not_before())
            .ok()
            .and_then(|value| value.checked_mul(1_000))
            .and_then(|value| ServerTimestamp::from_unix_millis(value).ok());
        let validated_not_after = i64::try_from(validated.not_after())
            .ok()
            .and_then(|value| value.checked_mul(1_000))
            .and_then(|value| ServerTimestamp::from_unix_millis(value).ok());
        if validated.key_package_ref() != guard.key_package_ref()
            || validated_not_before != Some(package_not_before)
            || validated_not_after != Some(package_not_after)
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(LockedRecoveryReservationProjection {
            conversation_id,
            request_id,
            target,
            target_key_id,
            target_auth_generation,
            bound_coordinate: *guard.bound_coordinate(),
            key_package_ref: *guard.key_package_ref(),
            key_package_wrapper: guard.wrapper_bytes().to_vec(),
            key_package_wrapper_sha256: *guard.wrapper_sha256(),
            package_not_after,
            claimed_at,
            durable_row_digest: *guard.durable_row_digest(),
            transaction_id: guard.transaction_id().to_owned(),
        })
    }
}

//
//

pub(crate) use executor::{
    apply_conversation_persistence_plan, apply_prepared_device_revocation_members,
    apply_prepared_device_revocation_prefix, prepare_device_revocation_batch_members,
    AppliedTransition, ControlEntryContent, EventChainCursorError, EventFanout, ExecutionActor,
    ExecutionAuthority, ExecutorError, HistoricalExecutionWriteAuthority, LeafPersistenceColumns,
    MetadataAuthorColumns, MetadataAvatarPersistence, PreparedDeviceRevocationBatchMembers,
    RecoveryOpenContext, ResetRequestRow, SpineArtifacts, WelcomeDispositionInput,
    WelcomeExpiryContext, WelcomeRejectionWork, WelcomeResponseContext,
};
#[cfg(test)]
pub(crate) use executor::{
    apply_conversation_persistence_plan_unscoped_for_test,
    apply_device_revocation_batch_unscoped_for_test, DropSafetyProbe, DropSafetyProbeMode,
    ExecutionContext,
};
pub(crate) use executor::{
    batch_transaction_bindings_match, plan_transaction_bindings_match,
    PreparedConversationExecution,
};

#[path = "state_machine/executor.rs"]
pub(in crate::chat_protocol) mod executor;
