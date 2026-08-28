//! Historical remote-prefix repository and execution authority.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::core;
use super::execution_context::{
    hydrate_historical_execution_context, ExecutionContextHydrationError,
};
use crate::chat_protocol::state_machine::executor::{
    apply_conversation_persistence_plan, ExecutionContext,
};
use crate::chat_protocol::state_machine::{
    checked_artifact_bytes, AppliedTransition, ConversationPersistencePlan, ExecutorError,
    HistoricalExecutionWriteAuthority, HistoricalPlanWitness, HydrationAuthority,
};
use crate::chat_protocol::transcript::{
    decode_and_verify_control_entry, decode_canonical_signed_mutation,
    rebind_persisted_control_entry, CanonicalValueRef, CleanEntryKind, VerifiedControlEntry,
    VerifiedMutationProjection,
};
use crate::federation::bootstrap::{
    compute_bootstrap_advisory_lock_key, QuarantineReason, RemotePrefixApplyOutcome,
    RemotePrefixBootstrapError, RemotePrefixBootstrapSelector, VerifiedRemotePrefixAdmission,
};
use crate::federation::reconciliation::StrictCleanRemoteEvent;
use crate::federation::{peer_policy, reconciliation};
use crate::identity::canonical_did;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Closed enumeration of deterministic destination-local identifier categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BootstrapLocalIdLabel {
    ParticipantPeriod,
    LeafPeriod,
    MetadataSnapshot,
}

impl BootstrapLocalIdLabel {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::ParticipantPeriod => "participant-period",
            Self::LeafPeriod => "leaf-period",
            Self::MetadataSnapshot => "metadata-snapshot",
        }
    }
}

/// Derive a deterministic destination-local UUIDv4 from the canonical transcript.
///
/// Transcript format:
/// `SHA-256("CATBIRD-CLEAN-REMOTE-BOOTSTRAP-LOCAL-ID-V1\0" || conversation_uuid[16] || source_entry_uuid[16] || u16be(label_len) || fixed_ascii_label || u32be(entity_key_len) || canonical_entity_key)`
///
/// Sets RFC 4122 variant and UUIDv4 version bits on the first 16 digest bytes.
pub(crate) fn derive_bootstrap_local_id(
    conversation_id: Uuid,
    source_entry_id: Uuid,
    label: BootstrapLocalIdLabel,
    entity_key: &[u8],
) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"CATBIRD-CLEAN-REMOTE-BOOTSTRAP-LOCAL-ID-V1\0");
    hasher.update(conversation_id.as_bytes());
    hasher.update(source_entry_id.as_bytes());
    let label_str = label.as_str();
    hasher.update((label_str.len() as u16).to_be_bytes());
    hasher.update(label_str.as_bytes());
    hasher.update((entity_key.len() as u32).to_be_bytes());
    hasher.update(entity_key);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Set UUIDv4 version (0100xxxx)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set RFC 4122 variant (10xxxxxx)
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[derive(Debug)]
pub(crate) struct HistoricalWriteWitness {
    _sealed: (),
}

enum HistoricalLockedHead {
    Creation(core::LockedConversationHeadGuard),
    Existing(core::LockedConversationStateGuard),
}

enum HistoricalPackageGuard {
    Available(core::LockedRecoveryPackageGuard),
    Reserved(core::LockedRecoveryPackageGuard),
}

/// Move-only authority for one historical prefix step.
struct HistoricalPrefixAuthority<'borrow, 'conn> {
    transaction: &'borrow mut Transaction<'conn, Postgres>,
    plan_witness: HistoricalPlanWitness,
    write_witness: HistoricalExecutionWriteAuthority,
    admission_digest: [u8; 32],
    selector: RemotePrefixBootstrapSelector,
    participant_routes: BTreeMap<String, Option<String>>,
    source_entry_id: Uuid,
    source_entry_kind: CleanEntryKind,
    source_entry_sha256: [u8; 32],
    outer_fingerprint: [u8; 32],
    received_at: DateTime<Utc>,
    actor_signature_key: Vec<u8>,
    locked_head: HistoricalLockedHead,
    package_guard: Option<HistoricalPackageGuard>,
}

impl<'borrow, 'conn> HistoricalPrefixAuthority<'borrow, 'conn> {
    /// Bind authority for an event under the current database transaction.
    ///
    /// Verifies the signer's registration and active keys in `chat.devices` /
    /// `chat.device_keys` under transaction locks.
    async fn verify_and_bind_for_event(
        transaction: &'borrow mut Transaction<'conn, Postgres>,
        admission_digest: &[u8; 32],
        closing_last_seq: i64,
        selector: &RemotePrefixBootstrapSelector,
        participant_routes: &BTreeMap<String, Option<String>>,
        event: &StrictCleanRemoteEvent,
    ) -> Result<Self, RemotePrefixBootstrapError> {
        if admission_digest == &[0; 32] {
            return Err(RemotePrefixBootstrapError::Authority);
        }

        let entry_id = event.entry_id();
        let entry_kind = event.entry_kind();
        let received_at = event.received_at();

        // 1. Read the canonical signer tuple from the exact signed wrapper.
        let (actor_did, actor_device_id, key_id_expected, auth_gen_expected) =
            canonical_event_signer(event)?;

        // 2. Lock and verify the signer's identity in the database.
        let row: Option<(
            String,
            i64,
            String,
            i64,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Vec<u8>,
        )> = sqlx::query_as(
            r#"
            SELECT d.user_did,
                   d.auth_generation,
                   d.status,
                   k.enrollment_auth_generation,
                   d.revoked_at,
                   k.revoked_at AS key_revoked_at,
                   k.signing_public_key
              FROM chat.devices d
              JOIN chat.device_keys k
                ON k.user_did = d.user_did AND k.device_id = d.device_id
             WHERE d.user_did = $1 AND d.device_id = $2 AND k.key_id = $3
             FOR SHARE
            "#,
        )
        .bind(&actor_did)
        .bind(actor_device_id)
        .bind(&key_id_expected)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?;

        let (
            user_did,
            dev_auth_gen,
            status,
            key_enrollment_gen,
            dev_revoked,
            key_revoked,
            signing_public_key,
        ) = row.ok_or(RemotePrefixBootstrapError::Authority)?;

        if status != "active" || dev_revoked.is_some() || key_revoked.is_some() {
            return Err(RemotePrefixBootstrapError::Authority);
        }
        if dev_auth_gen < 1
            || dev_auth_gen != auth_gen_expected
            || dev_auth_gen != key_enrollment_gen
            || user_did != actor_did
        {
            return Err(RemotePrefixBootstrapError::Authority);
        }

        // 3. Cryptographically verify and rebind the control entry with the locked public key.
        let verified_control = decode_and_rebind_control_entry(event, &signing_public_key)?;

        let orig_mutation = verified_control.mutation();
        if orig_mutation.actor_did().as_str() != actor_did.as_str()
            || orig_mutation.actor_device_id().as_bytes() != actor_device_id.as_bytes()
            || orig_mutation.key_id().as_str() != key_id_expected.as_str()
            || u64::try_from(auth_gen_expected).ok() != Some(orig_mutation.auth_generation())
        {
            return Err(RemotePrefixBootstrapError::Authority);
        }
        if verified_control.conversation_id().as_bytes() != selector.conversation_id().as_bytes() {
            return Err(RemotePrefixBootstrapError::Authority);
        }

        let mut package_guard = None;
        let locked_head = match entry_kind {
            CleanEntryKind::Creation => {
                if verified_control.seq() != 1 {
                    return Err(RemotePrefixBootstrapError::Authority);
                }
                let creation_head = core::hydrate_locked_creation_head(
                    transaction,
                    selector.conversation_id(),
                    received_at,
                )
                .await
                .map_err(map_hydration_error)?;
                HistoricalLockedHead::Creation(creation_head)
            }
            CleanEntryKind::Policy => {
                let locked_convo = core::hydrate_locked_conversation_state(
                    transaction,
                    selector.conversation_id(),
                    received_at,
                )
                .await
                .map_err(map_hydration_error)?;
                if verified_control.seq() != locked_convo.head().next_entry_seq() {
                    return Err(RemotePrefixBootstrapError::Authority);
                }
                let changes = match verified_control.mutation().projection() {
                    VerifiedMutationProjection::PolicyTransition(policy) => {
                        match policy.participant_changes() {
                            CanonicalValueRef::Array(changes) if !changes.is_empty() => changes,
                            _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
                        }
                    }
                    _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
                };
                for index in 0..changes.len() {
                    let Some(CanonicalValueRef::Object(change)) = changes.get(index) else {
                        return Err(RemotePrefixBootstrapError::InvalidEvent);
                    };
                    let is_exact_add = matches!(
                        change.get("$type"),
                        Some(CanonicalValueRef::Text(
                            "blue.catbird.chat.defs#addParticipant"
                        ))
                    );
                    let is_pending = matches!(
                        change.get("status"),
                        Some(CanonicalValueRef::Text("pending"))
                    );
                    let is_member_role =
                        matches!(change.get("role"), Some(CanonicalValueRef::Text("member")));
                    let has_provenance = matches!(
                        change.get("invitationProvenance"),
                        Some(CanonicalValueRef::Object(_))
                    );
                    if !is_exact_add || !is_pending || !is_member_role || !has_provenance {
                        return Err(RemotePrefixBootstrapError::Authority);
                    }
                }
                HistoricalLockedHead::Existing(locked_convo)
            }

            CleanEntryKind::ParticipantAcceptance => {
                let locked_convo = core::hydrate_locked_conversation_state(
                    transaction,
                    selector.conversation_id(),
                    received_at,
                )
                .await
                .map_err(map_hydration_error)?;
                if verified_control.seq() != locked_convo.head().next_entry_seq() {
                    return Err(RemotePrefixBootstrapError::Authority);
                }
                let request_id = match verified_control.mutation().projection() {
                    VerifiedMutationProjection::ParticipantAcceptance(a) => {
                        Uuid::from_bytes(*a.recovery_request_id().as_bytes())
                    }
                    _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
                };
                let (accepted_pkg_ref, accepted_pkg_bytes, accepted_pkg_sha) =
                    acceptance_package_material(&verified_control)?;

                let pkg_guard = core::hydrate_locked_available_acceptance_package(
                    transaction,
                    locked_convo.head(),
                    request_id,
                    &actor_did,
                    actor_device_id,
                    &key_id_expected,
                    dev_auth_gen,
                )
                .await
                .map_err(map_hydration_error)?;
                if pkg_guard.key_package_ref() != &accepted_pkg_ref
                    || pkg_guard.wrapper_bytes() != accepted_pkg_bytes.as_slice()
                    || pkg_guard.wrapper_sha256() != &accepted_pkg_sha
                {
                    return Err(RemotePrefixBootstrapError::Authority);
                }

                package_guard = Some(HistoricalPackageGuard::Available(pkg_guard));
                HistoricalLockedHead::Existing(locked_convo)
            }
            CleanEntryKind::LeafRecoveryFulfillment => {
                let locked_convo = core::hydrate_locked_conversation_state(
                    transaction,
                    selector.conversation_id(),
                    received_at,
                )
                .await
                .map_err(map_hydration_error)?;
                if verified_control.seq() != locked_convo.head().next_entry_seq() {
                    return Err(RemotePrefixBootstrapError::Authority);
                }
                let request_id = match verified_control.mutation().projection() {
                    VerifiedMutationProjection::LeafRecoveryFulfillment(v) => {
                        Uuid::from_bytes(*v.recovery_request_id().as_bytes())
                    }
                    _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
                };
                if locked_convo
                    .state()
                    .recovery_request(request_id.as_bytes())
                    .is_none()
                {
                    return Err(RemotePrefixBootstrapError::Authority);
                }

                let reserved_guard = core::hydrate_locked_reserved_recovery_package(
                    transaction,
                    locked_convo.head(),
                    request_id,
                )
                .await
                .map_err(map_hydration_error)?;
                if reserved_guard.request_id() != request_id {
                    return Err(RemotePrefixBootstrapError::Authority);
                }
                package_guard = Some(HistoricalPackageGuard::Reserved(reserved_guard));
                HistoricalLockedHead::Existing(locked_convo)
            }
            _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
        };

        let plan_witness =
            HistoricalPlanWitness::new(HistoricalWriteWitness { _sealed: () }, entry_id);
        let write_witness = HistoricalExecutionWriteAuthority::new(
            HistoricalWriteWitness { _sealed: () },
            *admission_digest,
            entry_id,
            entry_kind.type_id(),
            *event.accepted_payload_sha256(),
            *event.outer_fingerprint(),
        );

        Ok(Self {
            transaction,
            plan_witness,
            write_witness,
            admission_digest: *admission_digest,
            selector: selector.clone(),
            participant_routes: participant_routes.clone(),
            source_entry_id: entry_id,
            source_entry_kind: entry_kind,
            source_entry_sha256: *event.accepted_payload_sha256(),
            outer_fingerprint: *event.outer_fingerprint(),
            received_at,
            actor_signature_key: signing_public_key,
            locked_head,
            package_guard,
        })
    }

    /// Fail closed unless `event` is exactly the event this authority was bound to.
    fn check_bound_event(
        &self,
        event: &StrictCleanRemoteEvent,
        expected_kind: CleanEntryKind,
    ) -> Result<(), RemotePrefixBootstrapError> {
        if event.entry_id() != self.source_entry_id
            || event.entry_kind() != self.source_entry_kind
            || event.entry_kind() != expected_kind
            || event.accepted_payload_sha256() != &self.source_entry_sha256
            || event.outer_fingerprint() != &self.outer_fingerprint
            || event.received_at() != self.received_at
            || self.admission_digest == [0; 32]
        {
            return Err(RemotePrefixBootstrapError::Authority);
        }
        Ok(())
    }

    /// Sequencer + routing artifacts the historical hydrator consumes.
    fn artifacts(
        &self,
        event: &StrictCleanRemoteEvent,
        genesis_group_info_bytes: Option<Vec<u8>>,
    ) -> HistoricalArtifacts {
        HistoricalArtifacts {
            accepted_control_entry_bytes: event.accepted_payload_bytes().to_vec(),
            genesis_group_info_bytes,
            is_remote: true,
            sequencer_ds: Some(self.selector.configured_sequencer_did().to_string()),
            sequencer_term: self.selector.configured_sequencer_term(),
            participant_ds_dids: self.participant_routes.clone().into_iter().collect(),
        }
    }
}

fn canonical_event_signer(
    event: &StrictCleanRemoteEvent,
) -> Result<(String, Uuid, String, i64), RemotePrefixBootstrapError> {
    let mutation = decode_canonical_signed_mutation(event.signed_request())
        .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
    let auth_generation = i64::try_from(mutation.auth_generation())
        .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
    Ok((
        mutation.actor_did().as_str().to_string(),
        Uuid::from_bytes(*mutation.actor_device_id().as_bytes()),
        mutation.key_id().as_str().to_string(),
        auth_generation,
    ))
}

fn decode_and_rebind_control_entry(
    event: &StrictCleanRemoteEvent,
    signing_public_key: &[u8],
) -> Result<VerifiedControlEntry, RemotePrefixBootstrapError> {
    let decoded =
        decode_and_verify_control_entry(event.accepted_payload_bytes(), signing_public_key)
            .map_err(|_| RemotePrefixBootstrapError::Authority)?;
    rebind_persisted_control_entry(decoded, event.signed_request(), signing_public_key)
        .map_err(|_| RemotePrefixBootstrapError::Authority)
}

fn acceptance_package_material(
    entry: &VerifiedControlEntry,
) -> Result<([u8; 32], Vec<u8>, [u8; 32]), RemotePrefixBootstrapError> {
    let server_fields = entry.server_fields();
    let recovery = match server_fields.get("recovery") {
        Some(CanonicalValueRef::Object(value)) => value,
        _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
    };
    let reservation = match recovery.get("reservation") {
        Some(CanonicalValueRef::Object(value)) => value,
        _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
    };
    let package_ref = match reservation.get("keyPackageRef") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?,
        _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
    };
    let package = match reservation.get("keyPackage") {
        Some(CanonicalValueRef::Object(value)) => value,
        _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
    };
    let package_bytes = match package.get("bytes") {
        Some(CanonicalValueRef::Bytes(value)) => value.to_vec(),
        _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
    };
    let package_sha256 = match package.get("sha256") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?,
        _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
    };
    Ok((package_ref, package_bytes, package_sha256))
}

/// Executor artifacts for one historical prefix step.
struct HistoricalArtifacts {
    accepted_control_entry_bytes: Vec<u8>,
    genesis_group_info_bytes: Option<Vec<u8>>,
    is_remote: bool,
    sequencer_ds: Option<String>,
    sequencer_term: i64,
    participant_ds_dids: HashMap<String, Option<String>>,
}

fn map_hydration_error<E: std::error::Error + 'static>(err: E) -> RemotePrefixBootstrapError {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(&err);
    while let Some(e) = current {
        if e.is::<sqlx::Error>() {
            return RemotePrefixBootstrapError::Database;
        }
        current = e.source();
    }
    RemotePrefixBootstrapError::Authority
}

/// Prepared single-use capsule for applying one historical prefix step.
struct PreparedHistoricalPrefixStep<'borrow, 'conn> {
    transaction: &'borrow mut Transaction<'conn, Postgres>,
    plan: ConversationPersistencePlan,
    artifacts: HistoricalArtifacts,
    historical_authority: HistoricalExecutionWriteAuthority,
}

impl<'borrow, 'conn> PreparedHistoricalPrefixStep<'borrow, 'conn> {
    /// Consume the step and apply it atomically inside the caller's transaction.
    async fn apply(self) -> Result<AppliedTransition, ExecutorError> {
        let prepared = hydrate_historical_execution_context(
            self.transaction,
            &self.plan,
            self.artifacts.accepted_control_entry_bytes,
            self.artifacts.genesis_group_info_bytes,
            self.artifacts.is_remote,
            self.artifacts.sequencer_ds,
            self.artifacts.sequencer_term,
            self.artifacts.participant_ds_dids,
            self.historical_authority,
        )
        .await
        .map_err(|err| match err {
            ExecutionContextHydrationError::Database(e) => ExecutorError::HydrationDatabase(e),
            _ => ExecutorError::MissingContext("historical hydration failed"),
        })?;

        apply_conversation_persistence_plan(prepared).await
    }
}

/// Closed planner for historical conversation creation entry.
async fn plan_historical_creation_entry<'borrow, 'conn>(
    authority: HistoricalPrefixAuthority<'borrow, 'conn>,
    event: &StrictCleanRemoteEvent,
) -> Result<PreparedHistoricalPrefixStep<'borrow, 'conn>, RemotePrefixBootstrapError> {
    authority.check_bound_event(event, CleanEntryKind::Creation)?;

    let HistoricalLockedHead::Creation(creation_head) = &authority.locked_head else {
        return Err(RemotePrefixBootstrapError::Authority);
    };
    let hydration_auth = HydrationAuthority::from_locked_creation_head(creation_head)
        .map_err(|_| RemotePrefixBootstrapError::Authority)?;
    let control_entry = decode_and_rebind_control_entry(event, &authority.actor_signature_key)?;
    let genesis_group_info_bytes = match control_entry.mutation().projection() {
        VerifiedMutationProjection::Creation(c) => checked_artifact_bytes(&c.genesis_group_info())
            .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?,
        _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
    };
    let artifacts = authority.artifacts(event, Some(genesis_group_info_bytes));
    let plan = hydration_auth
        .plan_historical_creation(authority.plan_witness, control_entry, creation_head)
        .map_err(|_| RemotePrefixBootstrapError::Authority)?;

    Ok(PreparedHistoricalPrefixStep {
        transaction: authority.transaction,
        plan,
        artifacts,
        historical_authority: authority.write_witness,
    })
}

/// Closed planner for historical policy add entry.
async fn plan_historical_policy_add_entry<'borrow, 'conn>(
    authority: HistoricalPrefixAuthority<'borrow, 'conn>,
    event: &StrictCleanRemoteEvent,
) -> Result<PreparedHistoricalPrefixStep<'borrow, 'conn>, RemotePrefixBootstrapError> {
    authority.check_bound_event(event, CleanEntryKind::Policy)?;

    let artifacts = authority.artifacts(event, None);
    let HistoricalLockedHead::Existing(locked_convo) = &authority.locked_head else {
        return Err(RemotePrefixBootstrapError::Authority);
    };
    let hydration_auth = HydrationAuthority::from_locked_conversation(locked_convo)
        .map_err(|_| RemotePrefixBootstrapError::Authority)?;
    let control_entry = decode_and_rebind_control_entry(event, &authority.actor_signature_key)?;
    let plan = hydration_auth
        .plan_historical_policy_add(authority.plan_witness, locked_convo, control_entry)
        .map_err(|_| RemotePrefixBootstrapError::Authority)?;

    Ok(PreparedHistoricalPrefixStep {
        transaction: authority.transaction,
        plan,
        artifacts,
        historical_authority: authority.write_witness,
    })
}

/// Closed planner for historical participant acceptance entry.
async fn plan_historical_acceptance_entry<'borrow, 'conn>(
    authority: HistoricalPrefixAuthority<'borrow, 'conn>,
    event: &StrictCleanRemoteEvent,
) -> Result<PreparedHistoricalPrefixStep<'borrow, 'conn>, RemotePrefixBootstrapError> {
    authority.check_bound_event(event, CleanEntryKind::ParticipantAcceptance)?;

    let artifacts = authority.artifacts(event, None);
    let HistoricalLockedHead::Existing(locked_convo) = &authority.locked_head else {
        return Err(RemotePrefixBootstrapError::Authority);
    };
    let Some(HistoricalPackageGuard::Available(package_guard)) = authority.package_guard else {
        return Err(RemotePrefixBootstrapError::Authority);
    };

    let hydration_auth = HydrationAuthority::from_locked_conversation(locked_convo)
        .map_err(|_| RemotePrefixBootstrapError::Authority)?;
    let control_entry = decode_and_rebind_control_entry(event, &authority.actor_signature_key)?;
    let plan = hydration_auth
        .plan_historical_acceptance(
            authority.plan_witness,
            locked_convo,
            control_entry,
            package_guard,
        )
        .map_err(|_| RemotePrefixBootstrapError::Authority)?;

    Ok(PreparedHistoricalPrefixStep {
        transaction: authority.transaction,
        plan,
        artifacts,
        historical_authority: authority.write_witness,
    })
}

/// Closed planner for historical leaf recovery fulfillment entry.
async fn plan_historical_recovery_fulfillment_entry<'borrow, 'conn>(
    authority: HistoricalPrefixAuthority<'borrow, 'conn>,
    event: &StrictCleanRemoteEvent,
) -> Result<PreparedHistoricalPrefixStep<'borrow, 'conn>, RemotePrefixBootstrapError> {
    authority.check_bound_event(event, CleanEntryKind::LeafRecoveryFulfillment)?;

    let artifacts = authority.artifacts(event, None);
    let HistoricalLockedHead::Existing(locked_convo) = &authority.locked_head else {
        return Err(RemotePrefixBootstrapError::Authority);
    };
    let Some(HistoricalPackageGuard::Reserved(reserved_guard)) = authority.package_guard else {
        return Err(RemotePrefixBootstrapError::Authority);
    };

    let hydration_auth = HydrationAuthority::from_locked_conversation(locked_convo)
        .map_err(|_| RemotePrefixBootstrapError::Authority)?;
    let control_entry = decode_and_rebind_control_entry(event, &authority.actor_signature_key)?;
    let plan = hydration_auth
        .plan_historical_recovery_fulfillment(
            authority.plan_witness,
            locked_convo,
            control_entry,
            reserved_guard,
        )
        .map_err(|_| RemotePrefixBootstrapError::Authority)?;

    Ok(PreparedHistoricalPrefixStep {
        transaction: authority.transaction,
        plan,
        artifacts,
        historical_authority: authority.write_witness,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapPhase {
    ExpectCreation,
    PolicyOrAcceptance,
    ExpectFulfillment,
    ApplicationTail,
}

async fn bootstrap_projection_ids_match(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let participant_rows: Vec<(Uuid, String, Uuid)> = sqlx::query_as(
        r#"
        SELECT p.participant_period_id, p.user_did, e.entry_id
          FROM chat.participants p
          JOIN chat.entries e
            ON e.conversation_id = p.conversation_id
           AND e.transition_id = p.role_transition_id
         WHERE p.conversation_id = $1
         ORDER BY p.user_did, p.participant_period_id
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **tx)
    .await?;
    for (actual, did, source_entry_id) in participant_rows {
        if actual
            != derive_bootstrap_local_id(
                conversation_id,
                source_entry_id,
                BootstrapLocalIdLabel::ParticipantPeriod,
                did.as_bytes(),
            )
        {
            return Ok(false);
        }
    }

    let leaf_rows: Vec<(Uuid, String, Uuid, Uuid)> = sqlx::query_as(
        r#"
        SELECT m.leaf_period_id, m.user_did, m.device_id, e.entry_id
          FROM chat.member_devices m
          JOIN chat.entries e
            ON e.conversation_id = m.conversation_id
           AND e.transition_id = m.joined_transition_id
         WHERE m.conversation_id = $1
         ORDER BY m.user_did, m.device_id, m.leaf_period_id
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **tx)
    .await?;
    for (actual, did, device_id, source_entry_id) in leaf_rows {
        let entity_key = [did.as_bytes(), &[0], device_id.as_bytes()].concat();
        if actual
            != derive_bootstrap_local_id(
                conversation_id,
                source_entry_id,
                BootstrapLocalIdLabel::LeafPeriod,
                &entity_key,
            )
        {
            return Ok(false);
        }
    }

    let metadata_rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        r#"
        SELECT m.metadata_snapshot_id, e.entry_id
          FROM chat.metadata_snapshots m
          JOIN chat.entries e
            ON e.conversation_id = m.conversation_id
           AND e.transition_id = m.producing_transition_id
         WHERE m.conversation_id = $1
         ORDER BY m.generation, m.state_version, m.metadata_snapshot_id
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **tx)
    .await?;
    for (actual, source_entry_id) in metadata_rows {
        if actual
            != derive_bootstrap_local_id(
                conversation_id,
                source_entry_id,
                BootstrapLocalIdLabel::MetadataSnapshot,
                b"",
            )
        {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Record a sticky quarantine marker from the current local digest state and
/// yield the matching outcome. Writes the marker row only.
async fn quarantine_from_local_state(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    sequencer_did: &str,
    sequencer_term: i64,
    reason: QuarantineReason,
    first_mismatch_seq: i64,
) -> Result<RemotePrefixApplyOutcome, RemotePrefixBootstrapError> {
    let local_state = reconciliation::local_clean_digest_state_tx(tx, conversation_id)
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?;
    let digest_bytes: [u8; 32] = hex::decode(&local_state.digest_sha256)
        .map_err(|_| RemotePrefixBootstrapError::Database)?
        .try_into()
        .map_err(|_| RemotePrefixBootstrapError::Database)?;

    core::record_conversation_quarantine(
        tx,
        conversation_id,
        sequencer_did,
        sequencer_term,
        local_state.last_seq,
        local_state.last_epoch,
        &digest_bytes,
        reason.as_str(),
        first_mismatch_seq,
    )
    .await
    .map_err(|_| RemotePrefixBootstrapError::Database)?;

    Ok(RemotePrefixApplyOutcome::Quarantined {
        conversation_id,
        first_mismatch_seq,
        reason,
    })
}

/// Atomically apply, replay, or quarantine one sealed remote clean prefix under the caller's transaction.
pub(crate) async fn apply_remote_clean_prefix(
    tx: &mut Transaction<'_, Postgres>,
    admission: VerifiedRemotePrefixAdmission,
) -> Result<RemotePrefixApplyOutcome, RemotePrefixBootstrapError> {
    let (selector, _destination, digest_anchor, events, participant_routes, _material_bytes) =
        admission.into_parts();
    let conversation_id = selector.conversation_id();
    let sequencer_did = selector.configured_sequencer_did().to_string();
    let sequencer_term = selector.configured_sequencer_term();

    let last_event = events
        .last()
        .ok_or(RemotePrefixBootstrapError::InvalidEvent)?;

    // 1. Transaction-scoped advisory lock
    let lock_key = compute_bootstrap_advisory_lock_key(conversation_id);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut **tx)
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?;

    // 2. Recheck outbound peer policy under transaction (FOR SHARE)
    peer_policy::enforce_outbound_peer_policy_tx(tx, &sequencer_did)
        .await
        .map_err(|_| RemotePrefixBootstrapError::PeerDenied)?;

    // 3. Inspect existing conversation
    let existing_convo: Option<(bool, Option<String>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT is_remote, sequencer_ds, sequencer_term, historical_bootstrap_last_seq FROM chat.conversations WHERE conversation_id = $1 FOR UPDATE",
    )
    .bind(conversation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| RemotePrefixBootstrapError::Database)?;

    if let Some((is_remote, existing_seq_ds, existing_seq_term, existing_cutoff)) = existing_convo {
        // Conversation already exists
        if !is_remote
            || canonical_did(&existing_seq_ds.unwrap_or_default()) != canonical_did(&sequencer_did)
            || existing_seq_term != sequencer_term
        {
            // Existing local or differently routed/termed conversation -> generic conflict, no quarantine
            return Err(RemotePrefixBootstrapError::Conflict);
        }

        // Return an existing sticky quarantine marker without changing it.
        let sync_row: Option<(String, Option<String>, Option<i64>, i64, i64, i64, String)> =
            sqlx::query_as(
                r#"
            SELECT status, quarantine_reason, first_mismatch_seq,
                   sequencer_term, last_seq, last_epoch, last_digest
              FROM federation_sync_state
             WHERE convo_id = $1 AND sequencer_ds_did = $2
             FOR SHARE
            "#,
            )
            .bind(conversation_id.to_string())
            .bind(canonical_did(&sequencer_did))
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| RemotePrefixBootstrapError::Database)?;

        if let Some((status, reason, mismatch_seq, ..)) = sync_row.as_ref() {
            if status == "quarantined" {
                let reason = match reason.as_deref() {
                    Some("prefix_mismatch") => QuarantineReason::PrefixMismatch,
                    Some("local_ahead") => QuarantineReason::LocalAhead,
                    _ => return Err(RemotePrefixBootstrapError::Authority),
                };
                let mismatch_seq = mismatch_seq
                    .filter(|value| *value > 0)
                    .ok_or(RemotePrefixBootstrapError::Authority)?;
                return Ok(RemotePrefixApplyOutcome::Quarantined {
                    conversation_id,
                    first_mismatch_seq: mismatch_seq,
                    reason,
                });
            }
        }

        // Retrieve canonical receivedAt of the local head
        let local_head_received_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT received_at FROM chat.entries WHERE conversation_id = $1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(conversation_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?;

        let Some(local_head_time) = local_head_received_at else {
            return Err(RemotePrefixBootstrapError::Conflict);
        };

        // Hydrate the locked local graph BEFORE deciding mismatch/local-ahead/shorter/replay.
        // A corrupt local graph must fail closed, not be quarantined.
        let _locked_local_convo =
            core::hydrate_locked_conversation_state(tx, conversation_id, local_head_time)
                .await
                .map_err(map_hydration_error)?;

        // Correctly routed existing remote conversation: check every source-bound clean row field
        let local_entries: Vec<(
            i64,
            i64,
            Uuid,
            String,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            DateTime<Utc>,
            Option<Uuid>,
        )> = sqlx::query_as(
            r#"
            SELECT CAST(seq AS BIGINT),
                   CAST(COALESCE(generation, 0) AS BIGINT),
                   entry_id,
                   entry_kind,
                   accepted_payload_bytes,
                   accepted_payload_sha256,
                   signed_request_bytes,
                   outer_entry_fingerprint,
                   received_at,
                   message_id
              FROM chat.entries
             WHERE conversation_id = $1
             ORDER BY seq ASC
            "#,
        )
        .bind(conversation_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?;

        let local_count = local_entries.len();
        let remote_count = events.len();

        let mut first_mismatch_seq: Option<i64> = None;
        for (local, r_event) in local_entries.iter().zip(&events) {
            let (
                l_seq,
                l_gen,
                l_entry_id,
                l_kind,
                l_payload_bytes,
                l_payload_sha,
                l_signed_req,
                l_outer_fp,
                l_received_at,
                l_message_id,
            ) = local;

            let expected_message_id = match r_event.entry_kind() {
                CleanEntryKind::Application => {
                    let mutation = decode_canonical_signed_mutation(r_event.signed_request())
                        .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
                    let op_id = mutation
                        .operation_id()
                        .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
                    Some(Uuid::from_bytes(*op_id.as_bytes()))
                }
                _ => None,
            };

            if *l_seq != r_event.seq()
                || *l_gen != r_event.generation()
                || *l_entry_id != r_event.entry_id()
                || l_kind.as_str() != r_event.entry_kind().type_id()
                || l_payload_bytes.as_slice() != r_event.accepted_payload_bytes()
                || l_payload_sha.as_slice() != r_event.accepted_payload_sha256().as_slice()
                || l_signed_req.as_slice() != r_event.signed_request()
                || l_outer_fp.as_slice() != r_event.outer_fingerprint().as_slice()
                || l_received_at.timestamp_millis() != r_event.received_at().timestamp_millis()
                || *l_message_id != expected_message_id
            {
                first_mismatch_seq = Some(r_event.seq());
                break;
            }
        }
        if let Some(mismatch_seq) = first_mismatch_seq {
            // Correctly routed remote overlap mismatch -> sticky prefix_mismatch marker only
            return quarantine_from_local_state(
                tx,
                conversation_id,
                &sequencer_did,
                sequencer_term,
                QuarantineReason::PrefixMismatch,
                mismatch_seq,
            )
            .await;
        }

        if local_count > remote_count {
            // Correctly routed remote local-ahead -> sticky local_ahead marker only.
            let local_ahead_seq = digest_anchor
                .last_seq()
                .checked_add(1)
                .ok_or(RemotePrefixBootstrapError::Authority)?;
            return quarantine_from_local_state(
                tx,
                conversation_id,
                &sequencer_did,
                sequencer_term,
                QuarantineReason::LocalAhead,
                local_ahead_seq,
            )
            .await;
        }

        if local_count < remote_count {
            // Existing shorter exact remote prefix -> zero-write error; ordinary reconciliation owns suffixes
            return Err(RemotePrefixBootstrapError::Conflict);
        }

        let Some((
            status,
            quarantine_reason,
            first_mismatch_seq,
            sync_term,
            sync_last_seq,
            sync_last_epoch,
            sync_last_digest,
        )) = sync_row
        else {
            return Err(RemotePrefixBootstrapError::Conflict);
        };
        if status != "healthy"
            || quarantine_reason.is_some()
            || first_mismatch_seq.is_some()
            || sync_term != sequencer_term
            || sync_last_seq != digest_anchor.last_seq()
            || sync_last_epoch != digest_anchor.last_generation()
            || sync_last_digest != hex::encode(digest_anchor.digest_sha256())
        {
            return Err(RemotePrefixBootstrapError::Conflict);
        }

        let local_state = reconciliation::local_clean_digest_state_tx(tx, conversation_id)
            .await
            .map_err(|_| RemotePrefixBootstrapError::Database)?;
        if local_state.digest_sha256 != hex::encode(digest_anchor.digest_sha256())
            || local_state.last_seq != digest_anchor.last_seq()
            || local_state.event_count != digest_anchor.event_count()
            || local_state.last_epoch != digest_anchor.last_generation()
        {
            return Err(RemotePrefixBootstrapError::Conflict);
        }

        let expected_next_seq = u64::try_from(digest_anchor.last_seq())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(RemotePrefixBootstrapError::Conflict)?;
        let locked_convo =
            core::hydrate_locked_conversation_state(tx, conversation_id, last_event.received_at())
                .await
                .map_err(map_hydration_error)?;
        let head_coordinate = locked_convo
            .head()
            .prior_coordinate()
            .ok_or(RemotePrefixBootstrapError::Conflict)?;
        if locked_convo.head().next_entry_seq() != expected_next_seq
            || i64::try_from(head_coordinate.generation()).ok()
                != Some(digest_anchor.last_generation())
            || !bootstrap_projection_ids_match(tx, conversation_id)
                .await
                .map_err(|_| RemotePrefixBootstrapError::Database)?
        {
            return Err(RemotePrefixBootstrapError::Conflict);
        }
        if existing_cutoff != Some(digest_anchor.last_seq()) {
            return Err(RemotePrefixBootstrapError::Conflict);
        }

        return Ok(RemotePrefixApplyOutcome::ExactReplay {
            conversation_id,
            sequencer_term,
            last_seq: digest_anchor.last_seq(),
            digest_sha256: *digest_anchor.digest_sha256(),
        });
    }

    // Absent mailbox: bootstrap clean prefix
    // 4. Closed grammar validation starting at ExpectCreation
    let mut phase = BootstrapPhase::ExpectCreation;
    let mut control_indices = Vec::new();
    let mut tail_start = None;

    for (i, event) in events.iter().enumerate() {
        if event.seq() != (i + 1) as i64 {
            return Err(RemotePrefixBootstrapError::InvalidEvent);
        }

        phase = match (phase, event.entry_kind()) {
            (BootstrapPhase::ExpectCreation, CleanEntryKind::Creation) => {
                control_indices.push(i);
                BootstrapPhase::PolicyOrAcceptance
            }
            (BootstrapPhase::PolicyOrAcceptance, CleanEntryKind::Policy) => {
                control_indices.push(i);
                BootstrapPhase::PolicyOrAcceptance
            }
            (BootstrapPhase::PolicyOrAcceptance, CleanEntryKind::ParticipantAcceptance) => {
                control_indices.push(i);
                BootstrapPhase::ExpectFulfillment
            }
            (BootstrapPhase::ExpectFulfillment, CleanEntryKind::LeafRecoveryFulfillment) => {
                control_indices.push(i);
                BootstrapPhase::ApplicationTail
            }
            (BootstrapPhase::ApplicationTail, CleanEntryKind::Application) => {
                if tail_start.is_none() {
                    tail_start = Some(i);
                }
                BootstrapPhase::ApplicationTail
            }
            _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
        };
    }

    if phase != BootstrapPhase::ApplicationTail {
        return Err(RemotePrefixBootstrapError::InvalidEvent);
    }

    // Canonical locking order before execution:
    // 1. Collect all distinct (user_did, device_id) pairs across local routes and event actors
    let mut canonical_devices: BTreeSet<(String, Uuid)> = BTreeSet::new();

    for (did, route) in &participant_routes {
        if route.is_none() {
            let local_device_ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT device_id FROM chat.devices WHERE user_did = $1 AND status = 'active' AND revoked_at IS NULL",
            )
            .bind(did)
            .fetch_all(&mut **tx)
            .await
            .map_err(|_| RemotePrefixBootstrapError::Database)?;

            for dev_id in local_device_ids {
                canonical_devices.insert((did.clone(), dev_id));
            }
        }
    }

    if canonical_devices.is_empty() {
        return Err(RemotePrefixBootstrapError::NoLocalParticipant);
    }

    // Collect exact signed-wrapper signer tuples before taking identity locks.
    let mut canonical_keys: BTreeSet<(String, Uuid, String)> = BTreeSet::new();
    for event in &events {
        let (actor_did, actor_device_id, key_id, _) = canonical_event_signer(event)?;
        canonical_devices.insert((actor_did.clone(), actor_device_id));
        canonical_keys.insert((actor_did, actor_device_id, key_id));
    }

    // Lock all devices in canonical order FOR SHARE
    for (user_did, device_id) in &canonical_devices {
        let device_row: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT status, revoked_at FROM chat.devices WHERE user_did = $1 AND device_id = $2 FOR SHARE",
        )
        .bind(user_did)
        .bind(device_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?;

        let Some((d_status, d_revoked)) = device_row else {
            return Err(RemotePrefixBootstrapError::Authority);
        };
        if d_status != "active" || d_revoked.is_some() {
            return Err(RemotePrefixBootstrapError::Authority);
        }
    }

    // Lock all device keys in canonical order and retain their verified bytes for
    // acceptance-package discovery.
    let mut signing_public_keys = HashMap::new();
    for (user_did, device_id, key_id) in &canonical_keys {
        let key_row: Option<(String, Option<DateTime<Utc>>, Vec<u8>)> = sqlx::query_as(
            "SELECT key_id, revoked_at, signing_public_key FROM chat.device_keys WHERE user_did = $1 AND device_id = $2 AND key_id = $3 FOR SHARE",
        )
        .bind(user_did)
        .bind(device_id)
        .bind(key_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?;

        let Some((locked_key_id, key_revoked, signing_public_key)) = key_row else {
            return Err(RemotePrefixBootstrapError::Authority);
        };
        if locked_key_id != *key_id || key_revoked.is_some() {
            return Err(RemotePrefixBootstrapError::Authority);
        }
        signing_public_keys.insert(
            (user_did.clone(), *device_id, key_id.clone()),
            signing_public_key,
        );
    }

    let mut canonical_packages = BTreeSet::new();
    for event in &events {
        if event.entry_kind() != CleanEntryKind::ParticipantAcceptance {
            continue;
        }
        let (actor_did, actor_device_id, key_id, _) = canonical_event_signer(event)?;
        let signing_public_key = signing_public_keys
            .get(&(actor_did, actor_device_id, key_id))
            .ok_or(RemotePrefixBootstrapError::Authority)?;
        let verified_control = decode_and_rebind_control_entry(event, signing_public_key)?;
        let (package_ref, _, _) = acceptance_package_material(&verified_control)?;
        canonical_packages.insert(package_ref);
    }

    // Prelock acceptance KeyPackages exclusively in canonical order because
    // acceptance later transitions the selected package.
    for package_ref in &canonical_packages {
        let package_exists: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM chat.key_packages WHERE key_package_ref = $1 FOR UPDATE",
        )
        .bind(package_ref.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?;
        if package_exists.is_none() {
            return Err(RemotePrefixBootstrapError::Authority);
        }
    }

    // 5. Apply control steps
    for &idx in &control_indices {
        let event = &events[idx];
        let authority = HistoricalPrefixAuthority::verify_and_bind_for_event(
            tx,
            digest_anchor.digest_sha256(),
            digest_anchor.last_seq(),
            &selector,
            &participant_routes,
            event,
        )
        .await?;

        let step = match event.entry_kind() {
            CleanEntryKind::Creation => plan_historical_creation_entry(authority, event).await?,
            CleanEntryKind::Policy => plan_historical_policy_add_entry(authority, event).await?,
            CleanEntryKind::ParticipantAcceptance => {
                plan_historical_acceptance_entry(authority, event).await?
            }
            CleanEntryKind::LeafRecoveryFulfillment => {
                plan_historical_recovery_fulfillment_entry(authority, event).await?
            }
            _ => return Err(RemotePrefixBootstrapError::InvalidEvent),
        };

        step.apply().await.map_err(|err| match err {
            ExecutorError::HydrationDatabase(_) => RemotePrefixBootstrapError::Database,
            _ => RemotePrefixBootstrapError::Authority,
        })?;
    }

    // 6. Apply application tail
    if let Some(start) = tail_start {
        let prior_head_seq = events[start - 1].seq();
        let tail_last_seq = last_event.seq();

        reconciliation::apply_remote_clean_events(
            tx,
            conversation_id,
            &events[start..],
            reconciliation::ApplicationImportMode::HistoricalBootstrap,
        )
        .await
        .map_err(|error| match error {
            reconciliation::ApplyRemoteCleanEventsError::Database(_) => {
                RemotePrefixBootstrapError::Database
            }
            reconciliation::ApplyRemoteCleanEventsError::InvalidEvent(_)
            | reconciliation::ApplyRemoteCleanEventsError::Authority(_) => {
                RemotePrefixBootstrapError::Authority
            }
        })?;

        let convo_updated = sqlx::query(
            "UPDATE chat.conversations SET next_entry_seq = $3 + 1 WHERE conversation_id = $1 AND next_entry_seq = $2 + 1",
        )
        .bind(conversation_id)
        .bind(prior_head_seq)
        .bind(tail_last_seq)
        .execute(&mut **tx)
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?
        .rows_affected();

        if convo_updated != 1 {
            return Err(RemotePrefixBootstrapError::Authority);
        }
    }

    // 7. Verify final state before commit
    let local_state = reconciliation::local_clean_digest_state_tx(tx, conversation_id)
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?;

    if local_state.last_seq != digest_anchor.last_seq()
        || local_state.event_count != digest_anchor.event_count()
        || local_state.digest_sha256 != hex::encode(digest_anchor.digest_sha256())
        || local_state.last_epoch != digest_anchor.last_generation()
    {
        return Err(RemotePrefixBootstrapError::Authority);
    }

    let locked_convo =
        core::hydrate_locked_conversation_state(tx, conversation_id, last_event.received_at())
            .await
            .map_err(map_hydration_error)?;
    let expected_next_seq = u64::try_from(digest_anchor.last_seq())
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(RemotePrefixBootstrapError::Authority)?;
    let head_coordinate = locked_convo
        .head()
        .prior_coordinate()
        .ok_or(RemotePrefixBootstrapError::Authority)?;
    if locked_convo.head().next_entry_seq() != expected_next_seq
        || i64::try_from(head_coordinate.generation()).ok() != Some(digest_anchor.last_generation())
        || !bootstrap_projection_ids_match(tx, conversation_id)
            .await
            .map_err(|_| RemotePrefixBootstrapError::Database)?
    {
        return Err(RemotePrefixBootstrapError::Authority);
    }

    // 8. Upsert healthy sync state requiring rows_affected == 1
    let sync_rows = sqlx::query(
        r#"
        INSERT INTO federation_sync_state
            (convo_id, sequencer_ds_did, sequencer_term, last_seq, last_epoch, last_digest, last_reconciled_at, drift_count, updated_at, status)
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), 0, NOW(), 'healthy')
         ON CONFLICT (convo_id, sequencer_ds_did) DO UPDATE SET
            sequencer_term = EXCLUDED.sequencer_term,
            last_seq = EXCLUDED.last_seq,
            last_epoch = EXCLUDED.last_epoch,
            last_digest = EXCLUDED.last_digest,
            last_reconciled_at = NOW(),
            updated_at = NOW()
         WHERE federation_sync_state.status = 'healthy'
        "#,
    )
    .bind(conversation_id.to_string())
    .bind(canonical_did(&sequencer_did))
    .bind(sequencer_term)
    .bind(local_state.last_seq)
    .bind(local_state.last_epoch)
    .bind(hex::encode(digest_anchor.digest_sha256()))
    .execute(&mut **tx)
    .await
    .map_err(|_| RemotePrefixBootstrapError::Database)?
    .rows_affected();

    if sync_rows != 1 {
        return Err(RemotePrefixBootstrapError::Authority);
    }

    // Seal historical bootstrap cutoff after sync-state upsert and before SET CONSTRAINTS
    let sealed_cutoff = sqlx::query(
        "UPDATE chat.conversations SET historical_bootstrap_last_seq = $2 WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .bind(local_state.last_seq)
    .execute(&mut **tx)
    .await
    .map_err(|_| RemotePrefixBootstrapError::Database)?
    .rows_affected();

    if sealed_cutoff != 1 {
        return Err(RemotePrefixBootstrapError::Authority);
    }

    // 9. Execute SET CONSTRAINTS ALL IMMEDIATE
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut **tx)
        .await
        .map_err(|_| RemotePrefixBootstrapError::Database)?;

    Ok(RemotePrefixApplyOutcome::Applied {
        conversation_id,
        sequencer_term,
        last_seq: local_state.last_seq,
        digest_sha256: *digest_anchor.digest_sha256(),
    })
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use crate::federation::reconciliation::RemoteEvent;

    #[derive(Debug, PartialEq, Eq)]
    pub struct HistoricalStepOutcome {
        pub allocated_seq: u64,
        pub event_positions_count: usize,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct HydratedGraphSummary {
        pub next_entry_seq: u64,
        pub generation: u64,
        pub state_version: u64,
        pub epoch: u64,
    }

    pub async fn test_hydrated_graph_summary(
        transaction: &mut Transaction<'_, Postgres>,
        conversation_id: Uuid,
        locked_at: DateTime<Utc>,
    ) -> Result<HydratedGraphSummary, String> {
        let guard =
            core::hydrate_locked_conversation_state(transaction, conversation_id, locked_at)
                .await
                .map_err(|error| error.to_string())?;
        let coordinate = guard.state().coordinate();
        Ok(HydratedGraphSummary {
            next_entry_seq: guard.head().next_entry_seq(),
            generation: coordinate.generation(),
            state_version: coordinate.state_version(),
            epoch: coordinate.epoch(),
        })
    }

    pub fn derive_bootstrap_local_id_for_test(
        conversation_id: Uuid,
        source_entry_id: Uuid,
        label: &str,
        entity_key: &[u8],
    ) -> Uuid {
        let label = match label {
            "participant-period" => BootstrapLocalIdLabel::ParticipantPeriod,
            "leaf-period" => BootstrapLocalIdLabel::LeafPeriod,
            "metadata-snapshot" => BootstrapLocalIdLabel::MetadataSnapshot,
            _ => panic!("invalid bootstrap local id label: {label}"),
        };
        derive_bootstrap_local_id(conversation_id, source_entry_id, label, entity_key)
    }

    /// Decode the strict clean-remote event a facade replays.
    fn strict_event(
        event_json: serde_json::Value,
    ) -> Result<StrictCleanRemoteEvent, RemotePrefixBootstrapError> {
        let remote_event: RemoteEvent = serde_json::from_value(event_json)
            .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)?;
        StrictCleanRemoteEvent::try_from(remote_event)
            .map_err(|_| RemotePrefixBootstrapError::InvalidEvent)
    }

    /// Apply one prepared step and project the outcome the suites assert on.
    async fn apply_step(
        step: PreparedHistoricalPrefixStep<'_, '_>,
    ) -> Result<HistoricalStepOutcome, RemotePrefixBootstrapError> {
        let applied = step.apply().await.map_err(|err| match err {
            ExecutorError::HydrationDatabase(_) => RemotePrefixBootstrapError::Database,
            _ => RemotePrefixBootstrapError::Authority,
        })?;
        Ok(HistoricalStepOutcome {
            allocated_seq: applied.allocated_seq,
            event_positions_count: applied.event_positions.len(),
        })
    }

    /// Test wrapper for executing the atomic remote prefix reducer inside a test transaction.
    pub async fn test_apply_remote_clean_prefix(
        transaction: &mut Transaction<'_, Postgres>,
        admission: VerifiedRemotePrefixAdmission,
    ) -> Result<RemotePrefixApplyOutcome, RemotePrefixBootstrapError> {
        apply_remote_clean_prefix(transaction, admission).await
    }

    /// Test facade for verifying authority binding for an event JSON.
    pub async fn test_verify_historical_authority(
        transaction: &mut Transaction<'_, Postgres>,
        admission_digest: [u8; 32],
        closing_last_seq: i64,
        selector: RemotePrefixBootstrapSelector,
        participant_routes: BTreeMap<String, Option<String>>,
        event_json: serde_json::Value,
    ) -> Result<(), RemotePrefixBootstrapError> {
        let event = strict_event(event_json)?;
        HistoricalPrefixAuthority::verify_and_bind_for_event(
            transaction,
            &admission_digest,
            closing_last_seq,
            &selector,
            &participant_routes,
            &event,
        )
        .await?;
        Ok(())
    }

    /// Test facade for planning and executing a historical creation entry from event JSON.
    pub async fn test_apply_historical_creation_entry(
        transaction: &mut Transaction<'_, Postgres>,
        admission_digest: [u8; 32],
        closing_last_seq: i64,
        selector: RemotePrefixBootstrapSelector,
        participant_routes: BTreeMap<String, Option<String>>,
        event_json: serde_json::Value,
    ) -> Result<HistoricalStepOutcome, RemotePrefixBootstrapError> {
        let event = strict_event(event_json)?;
        let authority = HistoricalPrefixAuthority::verify_and_bind_for_event(
            transaction,
            &admission_digest,
            closing_last_seq,
            &selector,
            &participant_routes,
            &event,
        )
        .await?;
        apply_step(plan_historical_creation_entry(authority, &event).await?).await
    }

    /// Test facade for planning and executing a historical policy entry from event JSON.
    pub async fn test_apply_historical_policy_entry(
        transaction: &mut Transaction<'_, Postgres>,
        admission_digest: [u8; 32],
        closing_last_seq: i64,
        selector: RemotePrefixBootstrapSelector,
        participant_routes: BTreeMap<String, Option<String>>,
        event_json: serde_json::Value,
    ) -> Result<HistoricalStepOutcome, RemotePrefixBootstrapError> {
        let event = strict_event(event_json)?;
        let authority = HistoricalPrefixAuthority::verify_and_bind_for_event(
            transaction,
            &admission_digest,
            closing_last_seq,
            &selector,
            &participant_routes,
            &event,
        )
        .await?;
        apply_step(plan_historical_policy_add_entry(authority, &event).await?).await
    }

    /// Test facade for planning and executing a historical acceptance entry from event JSON.
    pub async fn test_apply_historical_acceptance_entry(
        transaction: &mut Transaction<'_, Postgres>,
        admission_digest: [u8; 32],
        closing_last_seq: i64,
        selector: RemotePrefixBootstrapSelector,
        participant_routes: BTreeMap<String, Option<String>>,
        event_json: serde_json::Value,
    ) -> Result<HistoricalStepOutcome, RemotePrefixBootstrapError> {
        let event = strict_event(event_json)?;
        let authority = HistoricalPrefixAuthority::verify_and_bind_for_event(
            transaction,
            &admission_digest,
            closing_last_seq,
            &selector,
            &participant_routes,
            &event,
        )
        .await?;
        apply_step(plan_historical_acceptance_entry(authority, &event).await?).await
    }

    /// Test facade for planning and executing a historical recovery fulfillment entry from event JSON.
    pub async fn test_apply_historical_recovery_fulfillment_entry(
        transaction: &mut Transaction<'_, Postgres>,
        admission_digest: [u8; 32],
        closing_last_seq: i64,
        selector: RemotePrefixBootstrapSelector,
        participant_routes: BTreeMap<String, Option<String>>,
        event_json: serde_json::Value,
    ) -> Result<HistoricalStepOutcome, RemotePrefixBootstrapError> {
        let event = strict_event(event_json)?;
        let authority = HistoricalPrefixAuthority::verify_and_bind_for_event(
            transaction,
            &admission_digest,
            closing_last_seq,
            &selector,
            &participant_routes,
            &event,
        )
        .await?;
        apply_step(plan_historical_recovery_fulfillment_entry(authority, &event).await?).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_local_id_fixed_vectors_and_variant_version() {
        let convo_id = Uuid::parse_str("00112233-4455-4677-8899-aabbccddeeff").unwrap();
        let source_id = Uuid::parse_str("ffeeddcc-bbaa-4988-8776-554433221100").unwrap();
        let did = "did:plc:abcdefghijklmnopqrstuvwxyz2345";
        let dev_id = Uuid::parse_str("12345678-90ab-4cde-8fab-1234567890ab").unwrap();

        // 1. ParticipantPeriod
        let p_id = derive_bootstrap_local_id(
            convo_id,
            source_id,
            BootstrapLocalIdLabel::ParticipantPeriod,
            did.as_bytes(),
        );
        let p_bytes = p_id.as_bytes();
        assert_eq!(p_bytes[6] & 0xf0, 0x40, "must be UUIDv4 version");
        assert_eq!(p_bytes[8] & 0xc0, 0x80, "must be RFC 4122 variant");
        assert_eq!(
            p_id,
            Uuid::parse_str("f0318acb-e2db-4d81-b2fc-c11d8b5d364d").unwrap(),
            "exact ParticipantPeriod deterministic UUIDv4 vector mismatch"
        );

        // 2. LeafPeriod
        let leaf_key = [did.as_bytes(), &[0x00], dev_id.as_bytes()].concat();
        let l_id = derive_bootstrap_local_id(
            convo_id,
            source_id,
            BootstrapLocalIdLabel::LeafPeriod,
            &leaf_key,
        );
        let l_bytes = l_id.as_bytes();
        assert_eq!(l_bytes[6] & 0xf0, 0x40, "must be UUIDv4 version");
        assert_eq!(l_bytes[8] & 0xc0, 0x80, "must be RFC 4122 variant");
        assert_eq!(
            l_id,
            Uuid::parse_str("72c3107b-5bab-4c0c-81f8-0e6a1bef5d21").unwrap(),
            "exact LeafPeriod deterministic UUIDv4 vector mismatch"
        );

        // 3. MetadataSnapshot
        let m_id = derive_bootstrap_local_id(
            convo_id,
            source_id,
            BootstrapLocalIdLabel::MetadataSnapshot,
            &[],
        );
        let m_bytes = m_id.as_bytes();
        assert_eq!(m_bytes[6] & 0xf0, 0x40, "must be UUIDv4 version");
        assert_eq!(m_bytes[8] & 0xc0, 0x80, "must be RFC 4122 variant");
        assert_eq!(
            m_id,
            Uuid::parse_str("0bf6a712-6719-4950-ab27-77378ba32928").unwrap(),
            "exact MetadataSnapshot deterministic UUIDv4 vector mismatch"
        );

        // Assert all 3 derived IDs are pairwise distinct
        assert_ne!(p_id, l_id);
        assert_ne!(p_id, m_id);
        assert_ne!(l_id, m_id);

        // Assert determinism across repeated derivations
        for _ in 0..10 {
            assert_eq!(
                p_id,
                derive_bootstrap_local_id(
                    convo_id,
                    source_id,
                    BootstrapLocalIdLabel::ParticipantPeriod,
                    did.as_bytes(),
                )
            );
            assert_eq!(
                l_id,
                derive_bootstrap_local_id(
                    convo_id,
                    source_id,
                    BootstrapLocalIdLabel::LeafPeriod,
                    &leaf_key,
                )
            );
            assert_eq!(
                m_id,
                derive_bootstrap_local_id(
                    convo_id,
                    source_id,
                    BootstrapLocalIdLabel::MetadataSnapshot,
                    &[],
                )
            );
        }
    }
}
