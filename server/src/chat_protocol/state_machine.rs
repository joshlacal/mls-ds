// Deterministic transition planning for `blue.catbird.chat` protocol "1".
//
// Every function borrows the authoritative state immutably and returns a
// complete successor plan. Persistence must compare `expected_prior` in one
// full-coordinate CAS and apply the returned state/effects atomically. No
// function in this module writes storage or calls a legacy MLS handler.

use std::{cmp::Ordering, collections::BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

#[cfg(not(test))]
use super::relationship_policy::{
    consume_admission_projection, consume_block_projection, AdmissionOperation, AdmissionRequest,
    ProjectionOperationScope, PublicTransport, RelationshipAuthority, RelationshipProjection,
    TrustedRelationshipDecisionInstant,
};

#[cfg(not(test))]
use super::repository::auth::{BusinessAuthorityGuard, RepositoryAuthorityClass};
#[cfg(not(test))]
use super::repository::core::{
    LockedConversationHeadGuard, LockedConversationStateGuard, LockedDirectConversationLookupGuard,
    LockedDirectLookupOutcome, LockedInvitationQuotaGuard, LockedRecoveryPackageGuard,
    LockedRecoveryPackageStatus, LockedRecoveryPackageUse, LockedRevocationFanoutGuard,
    LockedRevocationPackageGuard, LockedRevocationTargetGuard, LockedRevocationTargetStatus,
    LockedWelcomeGuard,
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
        decode_and_verify_control_entry, decode_and_verify_signed_mutation,
        rebind_persisted_control_entry, CanonicalValueRef, SignedMutationKind,
        VerifiedControlEntry, VerifiedMutationProjection, VerifiedSignedMutation,
    },
    validation::{
        ed25519_key_id, BareDid, CanonicalTimestamp, CanonicalUuidV4, KeyThumbprint,
        TrustedRequestInstant,
    },
    wire::{
        validate_key_package, KeyPackageValidationPolicy, MAX_GROUP_INFO_WIRE_BYTES,
        MAX_KEY_PACKAGE_WIRE_BYTES, MAX_WELCOME_WIRE_BYTES,
    },
};

const MAX_PARTICIPANTS: usize = 100;
const MAX_LEAVES: usize = 100;
const MAX_LEAVES_PER_PRINCIPAL: usize = 20;
const RECOVERY_RESERVATION_TTL_MILLIS: i64 = 300_000;
const CONSENT_TTL_MILLIS: i64 = 86_400_000;
const COMMIT_AAD_DOMAIN: &[u8] = b"CATBIRD-CHAT-MLS-AAD-COMMIT\0";

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StateMachineError {
    #[error("state principal is outside the checked authority seam")]
    InvalidPrincipal,
    #[error("device id is not a canonical UUIDv4 value")]
    InvalidDeviceId,
    #[error("transition evidence is invalid")]
    InvalidTransition,
    #[error("creation shape is invalid")]
    InvalidCreation,
    #[error("creation conflicts with an unrelated existing conversation")]
    ExistingConversationConflict,
    #[error("the supplied full coordinate is stale")]
    StaleCoordinates,
    #[error("a protocol coordinate would overflow")]
    CoordinateOverflow,
    #[error("verified public state is inconsistent with the transition")]
    InvalidPublicState,
    #[error("direct participants and roles are immutable")]
    DirectParticipantMutationForbidden,
    #[error("actor is not a logical participant")]
    NotParticipant,
    #[error("actor is not an active logical participant")]
    NotMember,
    #[error("active administrator authority is required")]
    AdminRequired,
    #[error("invitation is absent or no longer pending")]
    InvitationNotPending,
    #[error("leaf-recovery request already exists for this exact device")]
    LeafRecoveryAlreadyOpen,
    #[error("leaf-recovery request is absent")]
    LeafRecoveryNotFound,
    #[error("leaf-recovery request is bound to an older coordinate")]
    LeafRecoverySuperseded,
    #[error("recovery kind does not match current exact-device leaf state")]
    RecoveryKindMismatch,
    #[error("fulfillment does not target the request's exact device")]
    RecoveryDeviceMismatch,
    #[error("Commit effects do not exactly match the closed transition form")]
    InvalidCommitEffects,
    #[error("Commit Welcome is not the exact request-bound delivery")]
    InvalidWelcomeMapping,
    #[error("reset request already exists")]
    ResetAlreadyPending,
    #[error("reset request is absent")]
    ResetRequestNotFound,
    #[error("reset request is stale")]
    ResetRequestStale,
    #[error("reset successor is not the exact fresh epoch-zero generation")]
    ResetSuccessorMismatch,
    #[error("the operation would remove the last active administrator")]
    LastAdminRequired,
    #[error("conversation close authority is not satisfied")]
    ConversationCloseNotAllowed,
    #[error("conversation is already terminal")]
    ConversationClosed,
    #[error("application interval boundary or proof is invalid")]
    InvalidIntervalBoundary,
    #[error("leave request already exists")]
    LeaveAlreadyPending,
    #[error("leave request is absent or stale")]
    LeaveRequestNotFound,
    #[error("request, reservation, or Welcome is expired at the captured server instant")]
    WorkExpired,
    #[error("server time or a derived expiry is outside the supported range")]
    InvalidServerTime,
    #[error("durable state is not bound to sealed transcript authority")]
    InvalidHydrationAuthority,
    #[error("participant/leaf/application interval invariants would be violated")]
    InvariantViolation,
    #[error("sealed relationship-policy authority does not match the resulting roster")]
    InvalidPolicyAuthority,
    #[error("metadata snapshot is not the exact authorized successor")]
    InvalidMetadataAuthority,
    #[error("metadata version would overflow")]
    MetadataVersionOverflow,
}

/// One captured trusted server instant represented at canonical millisecond
/// precision. Request admission constructs this once and every planner derives
/// expiry from this same value rather than from client `signedAt`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ServerTimestamp(i64);

impl ServerTimestamp {
    fn from_unix_millis(value: i64) -> Result<Self, StateMachineError> {
        if value < 0 {
            return Err(StateMachineError::InvalidServerTime);
        }
        Ok(Self(value))
    }

    pub(crate) fn from_trusted_request_instant(
        value: &TrustedRequestInstant,
    ) -> Result<Self, StateMachineError> {
        Self::from_unix_millis(value.datetime().timestamp_millis())
    }

    pub(crate) fn from_canonical_stored(value: &str) -> Result<Self, StateMachineError> {
        let value = CanonicalTimestamp::parse(value)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        Self::from_unix_millis(value.datetime().timestamp_millis())
    }

    #[cfg(test)]
    pub(crate) fn from_unix_millis_for_test(value: i64) -> Result<Self, StateMachineError> {
        Self::from_unix_millis(value)
    }

    pub(crate) fn unix_millis(self) -> i64 {
        self.0
    }

    fn checked_add_millis(self, millis: i64) -> Result<Self, StateMachineError> {
        self.0
            .checked_add(millis)
            .and_then(|value| (value >= 0).then_some(Self(value)))
            .ok_or(StateMachineError::InvalidServerTime)
    }
}

impl From<PublicStateError> for StateMachineError {
    fn from(_value: PublicStateError) -> Self {
        Self::InvalidPublicState
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PrincipalId(Vec<u8>);

impl PrincipalId {
    /// `validation.rs` owns the full DID grammar. This seam still enforces the
    /// frozen byte bounds and ASCII round-trip before identity can enter state.
    pub(crate) fn new(bytes: Vec<u8>) -> Result<Self, StateMachineError> {
        if !(12..=261).contains(&bytes.len()) || !bytes.is_ascii() {
            return Err(StateMachineError::InvalidPrincipal);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DeviceIdentity {
    principal: PrincipalId,
    device_id: [u8; 16],
}

impl Ord for DeviceIdentity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.principal
            .cmp(&other.principal)
            .then_with(|| self.device_id.cmp(&other.device_id))
    }
}

impl PartialOrd for DeviceIdentity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl DeviceIdentity {
    pub(crate) fn new(
        principal: PrincipalId,
        device_id: [u8; 16],
    ) -> Result<Self, StateMachineError> {
        if !is_uuid_v4(&device_id) {
            return Err(StateMachineError::InvalidDeviceId);
        }
        Ok(Self {
            principal,
            device_id,
        })
    }

    pub(crate) fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub(crate) fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    pub(crate) fn basic_credential(&self) -> Vec<u8> {
        let mut value = self.principal.as_bytes().to_vec();
        value.push(b'#');
        value.extend_from_slice(
            Uuid::from_bytes(self.device_id)
                .hyphenated()
                .to_string()
                .as_bytes(),
        );
        value
    }
}

fn is_uuid_v4(value: &[u8; 16]) -> bool {
    value[6] & 0xf0 == 0x40 && value[8] & 0xc0 == 0x80
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConversationKind {
    Direct,
    Group,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParticipantStatus {
    Pending,
    Active,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParticipantRole {
    Member,
    Admin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvitationProvenance {
    transition: TransitionEvidence,
    inviter: DeviceIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParticipantRecord {
    principal: PrincipalId,
    status: ParticipantStatus,
    role: ParticipantRole,
    /// The latest sealed policy transition that established `role`.  `None`
    /// means the role is still the one established by creation/invitation.
    role_producer: Option<TransitionEvidence>,
    invitation: Option<InvitationProvenance>,
    acceptance: Option<TransitionEvidence>,
}

impl ParticipantRecord {
    pub(crate) fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub(crate) fn status(&self) -> ParticipantStatus {
        self.status
    }

    pub(crate) fn role(&self) -> ParticipantRole {
        self.role
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.status == ParticipantStatus::Pending
    }

    pub(crate) fn is_active(&self) -> bool {
        self.status == ParticipantStatus::Active
    }

    /// Retained invitation consent source used by the transaction-bound
    /// acceptance relationship scope. Callers cannot substitute an inviter.
    pub(crate) fn invitation_inviter(&self) -> Option<&DeviceIdentity> {
        self.invitation
            .as_ref()
            .map(|invitation| &invitation.inviter)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeafRecord {
    device: DeviceIdentity,
    leaf_index: u32,
    basic_credential: Vec<u8>,
    signature_key: Vec<u8>,
    encryption_key: Vec<u8>,
    key_package_ref: Option<[u8; 32]>,
}

impl LeafRecord {
    pub(crate) fn device(&self) -> &DeviceIdentity {
        &self.device
    }

    pub(crate) fn leaf_index(&self) -> u32 {
        self.leaf_index
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpeningKind {
    Creation,
    Add,
    Reset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseKind {
    Remove,
    Replace,
    Reset,
    Terminal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedEntryEvidence {
    kind: SignedMutationKind,
    type_id: &'static str,
    domain: Vec<u8>,
    control_entry_id: Option<[u8; 16]>,
    control_conversation_id: Option<[u8; 16]>,
    actor: DeviceIdentity,
    key_id: [u8; 32],
    auth_generation: u64,
    signed_at: ServerTimestamp,
    request_digest: [u8; 32],
    signature: [u8; 64],
    signed_request_bytes: Vec<u8>,
    canonical_projection: Vec<u8>,
    transcript_bytes: Vec<u8>,
}

impl AuthenticatedEntryEvidence {
    pub(crate) fn kind(&self) -> SignedMutationKind {
        self.kind
    }
    pub(crate) fn type_id(&self) -> &str {
        self.type_id
    }
    pub(crate) fn domain(&self) -> &[u8] {
        &self.domain
    }
    pub(crate) fn control_entry_id(&self) -> Option<&[u8; 16]> {
        self.control_entry_id.as_ref()
    }
    pub(crate) fn control_conversation_id(&self) -> Option<&[u8; 16]> {
        self.control_conversation_id.as_ref()
    }
    pub(crate) fn actor(&self) -> &DeviceIdentity {
        &self.actor
    }
    pub(crate) fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }
    pub(crate) fn auth_generation(&self) -> u64 {
        self.auth_generation
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
    pub(crate) fn canonical_projection(&self) -> &[u8] {
        &self.canonical_projection
    }
    pub(crate) fn transcript_bytes(&self) -> &[u8] {
        &self.transcript_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TransitionBodyBinding {
    Creation {
        kind: ConversationKind,
        next: PublicGroupSnapshotCoordinate,
        manifest: RosterManifestBinding,
        group_info_sha256: [u8; 32],
        metadata: MetadataSnapshotBinding,
    },
    Commit {
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        aad_digest: [u8; 32],
        manifest: TransitionManifestBinding,
        commit_sha256: [u8; 32],
        metadata: MetadataSnapshotBinding,
    },
    Policy {
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        participant_changes: Vec<ManifestParticipantChange>,
    },
    Acceptance {
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        recovery_request_id: [u8; 16],
        invitation_provenance: InvitationBinding,
        recovery: AcceptanceRecoveryBinding,
    },
    Metadata {
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        metadata: MetadataSnapshotBinding,
    },
    ResetActivation {
        kind: ConversationKind,
        reset_request_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        retired: PublicGroupSnapshotCoordinate,
        successor: PublicGroupSnapshotCoordinate,
        manifest: RosterManifestBinding,
        group_info_sha256: [u8; 32],
        metadata: MetadataSnapshotBinding,
    },
    LeafRecoveryFulfillment {
        recovery_request_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        aad_digest: [u8; 32],
        manifest: TransitionManifestBinding,
        commit_sha256: [u8; 32],
        metadata: MetadataSnapshotBinding,
    },
    ConversationClose {
        kind: ConversationKind,
        prior: PublicGroupSnapshotCoordinate,
        retired: PublicGroupSnapshotCoordinate,
    },
    ZeroLeafLeave {
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
    },
    LeaveCommitFulfillment {
        leave_request_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        aad_digest: [u8; 32],
        manifest: TransitionManifestBinding,
        commit_sha256: [u8; 32],
        metadata: MetadataSnapshotBinding,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MetadataSnapshotBinding {
    coordinate: MetadataCryptoCoordinate,
    origin_transition_id: [u8; 16],
    metadata_version: u64,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    ciphertext_sha256: [u8; 32],
    avatar_binding_digest: Option<[u8; 32]>,
    author_proof: MetadataAuthorProofBinding,
    canonical_snapshot: Vec<u8>,
    digest: [u8; 32],
}

impl MetadataSnapshotBinding {
    pub(crate) fn canonical_snapshot(&self) -> &[u8] {
        &self.canonical_snapshot
    }

    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn metadata_version(&self) -> u64 {
        self.metadata_version
    }

    pub(crate) fn origin_transition_id(&self) -> &[u8; 16] {
        &self.origin_transition_id
    }

    pub(crate) fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    pub(crate) fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub(crate) fn ciphertext_sha256(&self) -> &[u8; 32] {
        &self.ciphertext_sha256
    }

    pub(crate) fn avatar_binding_digest(&self) -> Option<&[u8; 32]> {
        self.avatar_binding_digest.as_ref()
    }

    pub(crate) fn coordinate_conversation_id(&self) -> &[u8; 16] {
        &self.coordinate.conversation_id
    }

    pub(crate) fn coordinate_generation(&self) -> u64 {
        self.coordinate.generation
    }

    pub(crate) fn coordinate_epoch(&self) -> u64 {
        self.coordinate.epoch
    }

    pub(crate) fn coordinate_group_context_hash(&self) -> &[u8; 32] {
        &self.coordinate.group_context_hash
    }

    pub(crate) fn author(&self) -> &DeviceIdentity {
        &self.author_proof.author
    }

    pub(crate) fn author_key_id(&self) -> &[u8; 32] {
        &self.author_proof.author_key_id
    }

    pub(crate) fn signature_public_key(&self) -> &[u8; 32] {
        &self.author_proof.signature_public_key
    }

    pub(crate) fn author_auth_generation_at_origin(&self) -> u64 {
        self.author_proof.auth_generation_at_origin
    }

    pub(crate) fn author_origin_transition_id(&self) -> &[u8; 16] {
        &self.author_proof.origin_transition_id
    }

    pub(crate) fn author_origin_seq(&self) -> u64 {
        self.author_proof.origin_seq
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MetadataCryptoCoordinate {
    conversation_id: [u8; 16],
    generation: u64,
    epoch: u64,
    group_context_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MetadataAuthorProofBinding {
    author: DeviceIdentity,
    author_key_id: [u8; 32],
    signature_public_key: [u8; 32],
    auth_generation_at_origin: u64,
    origin_transition_id: [u8; 16],
    origin_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RosterManifestBinding {
    participants: Vec<RosterParticipantBinding>,
    actor_leaf: DeviceIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RosterParticipantBinding {
    principal: PrincipalId,
    status: ParticipantStatus,
    role: ParticipantRole,
    invitation: Option<InvitationBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InvitationBinding {
    transition_id: [u8; 16],
    inviter: DeviceIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AcceptanceRecoveryBinding {
    request_id: [u8; 16],
    conversation_id: [u8; 16],
    target: DeviceIdentity,
    kind: LeafRecoveryKind,
    bound_coordinate: PublicGroupSnapshotCoordinate,
    requester_key_id: [u8; 32],
    requester_auth_generation: u64,
    key_package_ref: [u8; 32],
    key_package_wrapper: Vec<u8>,
    key_package_wrapper_sha256: [u8; 32],
    requested_at: ServerTimestamp,
    expires_at: ServerTimestamp,
    canonical_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransitionManifestBinding {
    participant_changes: Vec<ManifestParticipantChange>,
    leaf_changes: Vec<ManifestLeafChange>,
    leaf_recovery_request_id: Option<[u8; 16]>,
    welcome: Option<ManifestWelcomeBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ManifestParticipantChange {
    Add(PrincipalId),
    Remove(PrincipalId),
    ChangeRole(PrincipalId, ParticipantRole),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ManifestLeafChange {
    Add {
        device: DeviceIdentity,
        recovery_request_id: [u8; 16],
        key_package_ref: [u8; 32],
    },
    Remove(DeviceIdentity),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManifestWelcomeBinding {
    welcome_id: [u8; 16],
    opaque_welcome: Vec<u8>,
    sha256: [u8; 32],
    recipient: DeviceIdentity,
    recovery_request_id: [u8; 16],
    key_package_ref: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransitionEvidence {
    seq: u64,
    transition_id: [u8; 16],
    outer_entry_fingerprint: [u8; 32],
    outer_control_projection: Vec<u8>,
    server_fields_dag_cbor: Vec<u8>,
    durable_row_digest: [u8; 32],
    received_at: ServerTimestamp,
    authority: Option<AuthenticatedEntryEvidence>,
    body_binding: Option<TransitionBodyBinding>,
}

impl TransitionEvidence {
    /// Test-only seam. Production evidence is issued only while adapting a
    /// transcript-verified, variant-specific outer control authority.
    #[cfg(test)]
    pub(crate) fn new(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
    ) -> Result<Self, StateMachineError> {
        Self::for_test_at(
            seq,
            transition_id,
            outer_entry_fingerprint,
            ServerTimestamp::from_unix_millis_for_test((seq as i64) * 1_000)?,
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test_at(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
    ) -> Result<Self, StateMachineError> {
        if seq == 0 || seq > MAX_PROTOCOL_INTEGER || !is_uuid_v4(&transition_id) {
            return Err(StateMachineError::InvalidTransition);
        }
        Ok(Self {
            seq,
            transition_id,
            outer_entry_fingerprint,
            outer_control_projection: Vec::new(),
            server_fields_dag_cbor: Vec::new(),
            durable_row_digest: outer_entry_fingerprint,
            received_at,
            authority: None,
            body_binding: None,
        })
    }

    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }

    pub(crate) fn transition_id(&self) -> &[u8; 16] {
        &self.transition_id
    }

    pub(crate) fn outer_entry_fingerprint(&self) -> &[u8; 32] {
        &self.outer_entry_fingerprint
    }

    pub(crate) fn outer_control_projection(&self) -> &[u8] {
        &self.outer_control_projection
    }

    pub(crate) fn server_fields_dag_cbor(&self) -> &[u8] {
        &self.server_fields_dag_cbor
    }

    pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
        &self.durable_row_digest
    }

    pub(crate) fn received_at(&self) -> ServerTimestamp {
        self.received_at
    }

    pub(crate) fn signed_authority(&self) -> Option<&AuthenticatedEntryEvidence> {
        self.authority.as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestEntryKind {
    LeafRecoveryRequest,
    LeafRecoveryCancellation,
    ResetRequest,
    LeaveRequest,
    LeaveCancellation,
    WelcomeAcknowledgement,
    WelcomeRejection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RequestBodyBinding {
    LeafRecoveryRequest {
        prior: PublicGroupSnapshotCoordinate,
        kind: LeafRecoveryKind,
    },
    LeafRecoveryCancellation,
    ResetRequest {
        prior: PublicGroupSnapshotCoordinate,
    },
    LeaveRequest {
        prior: PublicGroupSnapshotCoordinate,
    },
    LeaveCancellation {
        conversation_id: [u8; 16],
    },
    WelcomeResponse {
        coordinates: PublicGroupSnapshotCoordinate,
        transition_seq: u64,
    },
}

/// Authenticated immutable outer evidence for a non-coordinate signed request.
/// Production construction is intentionally absent until transcript.rs has
/// verified the closed body, historical key, row/body bindings, and signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestEvidence {
    kind: RequestEntryKind,
    control_entry_id: Option<[u8; 16]>,
    conversation_id: [u8; 16],
    control_seq: Option<u64>,
    control_outer_entry_fingerprint: Option<[u8; 32]>,
    control_outer_projection: Option<Vec<u8>>,
    control_server_fields_dag_cbor: Option<Vec<u8>>,
    request_id: [u8; 16],
    actor: DeviceIdentity,
    key_id: [u8; 32],
    auth_generation: u64,
    request_digest: [u8; 32],
    signature: [u8; 64],
    /// Exact accepted signed wrapper. Non-control requests have no synthetic
    /// control-entry identity or sequence; this immutable byte string and its
    /// signature/digest are their durable identity.
    signed_request_bytes: Vec<u8>,
    /// Internal digest of the complete durable request row. This is not the
    /// fingerprint of a protocol control entry.
    durable_row_digest: [u8; 32],
    received_at: ServerTimestamp,
    authority: Option<AuthenticatedEntryEvidence>,
    body_binding: Option<RequestBodyBinding>,
}

/// Exact same-DID signed device-revocation authority. It is deliberately
/// independent of conversation entry sequencing: one global revocation can
/// release request/package work in several conversations while leaving their
/// signed MLS leaves untouched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeviceRevocationEvidence {
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
    durable_row_digest: [u8; 32],
}

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

    /// A signed, NON-control welcome-response `RequestEvidence` (acknowledge /
    /// reject): entry-less (`control_entry_id`/`control_seq` = None) with the
    /// `WelcomeResponse` body binding `plan_welcome_response` requires to match the
    /// pending welcome's coordinate + `transition_seq`. `request_id` = the welcome
    /// id, actor = the recipient.
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
        });
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

    pub(crate) fn signed_authority(&self) -> Option<&AuthenticatedEntryEvidence> {
        self.authority.as_ref()
    }
}

/// Route-bound authority used by persistence adapters to project sealed auth
/// results into cloneable state evidence. It accepts no raw signatures, body
/// maps, caller-selected domains, or caller-selected type identifiers.
pub(crate) struct HydrationAuthority {
    expected_conversation_id: [u8; 16],
    #[cfg(not(test))]
    locked: LockedHydrationBinding,
}

#[cfg(not(test))]
struct LockedHydrationBinding {
    transaction_id: String,
    expected_prior: Option<PublicGroupSnapshotCoordinate>,
    expected_next_entry_seq: u64,
    locked_at: ServerTimestamp,
    locked_head_digest: [u8; 32],
    locked_graph_digest: Option<[u8; 32]>,
    locked_snapshot_digest: Option<[u8; 32]>,
}

impl HydrationAuthority {
    #[cfg(test)]
    pub(crate) fn new(expected_conversation_id: [u8; 16]) -> Result<Self, StateMachineError> {
        if !is_uuid_v4(&expected_conversation_id) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            expected_conversation_id,
        })
    }

    #[cfg(not(test))]
    pub(crate) fn from_locked_conversation(
        locked: &LockedConversationStateGuard,
    ) -> Result<Self, StateMachineError> {
        let head = locked.head();
        if head.durable_row_digest() == &[0; 32]
            || locked.state().coordinate().conversation_id() != head.conversation_id().as_bytes()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            expected_conversation_id: *head.conversation_id().as_bytes(),
            locked: LockedHydrationBinding {
                transaction_id: head.transaction_id().to_owned(),
                expected_prior: head.prior_coordinate().copied(),
                expected_next_entry_seq: head.next_entry_seq(),
                locked_at: ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?,
                locked_head_digest: *head.durable_row_digest(),
                locked_graph_digest: Some(*locked.locked_graph_digest()),
                locked_snapshot_digest: locked.locked_snapshot_digest().copied(),
            },
        })
    }

    #[cfg(not(test))]
    pub(crate) fn from_locked_creation_head(
        head: &LockedConversationHeadGuard,
    ) -> Result<Self, StateMachineError> {
        if head.prior_coordinate().is_some()
            || head.next_entry_seq() != 1
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            expected_conversation_id: *head.conversation_id().as_bytes(),
            locked: LockedHydrationBinding {
                transaction_id: head.transaction_id().to_owned(),
                expected_prior: None,
                expected_next_entry_seq: head.next_entry_seq(),
                locked_at: ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?,
                locked_head_digest: *head.durable_row_digest(),
                locked_graph_digest: None,
                locked_snapshot_digest: None,
            },
        })
    }

    /// Bootstraps the hydration authority from an EXISTING conversation's
    /// locked head (`prior_coordinate` = `Some`, `next_entry_seq >= 2`). This is
    /// the read-time counterpart of `from_locked_creation_head`: the aggregate
    /// hydrator needs an authority carrying the locked head binding BEFORE the
    /// `LockedConversationStateGuard` exists, so `from_locked_conversation`
    /// (which reads the finished guard's `locked_graph_digest`) cannot serve —
    /// it is circular. The graph/snapshot digests are therefore `None` here;
    /// they are only known once the aggregate has been assembled and sealed.
    /// The historical graph rows are re-verified by the DISTINCT read-time
    /// `HistoricalRehydrationAuthority`, never by this append-time authority.
    #[cfg(not(test))]
    #[allow(dead_code)]
    pub(crate) fn from_locked_existing_head(
        head: &LockedConversationHeadGuard,
    ) -> Result<Self, StateMachineError> {
        if head.prior_coordinate().is_none()
            || head.next_entry_seq() < 2
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            expected_conversation_id: *head.conversation_id().as_bytes(),
            locked: LockedHydrationBinding {
                transaction_id: head.transaction_id().to_owned(),
                expected_prior: head.prior_coordinate().copied(),
                expected_next_entry_seq: head.next_entry_seq(),
                locked_at: ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?,
                locked_head_digest: *head.durable_row_digest(),
                locked_graph_digest: None,
                locked_snapshot_digest: None,
            },
        })
    }

    #[cfg(not(test))]
    fn require_same_locked_conversation(
        &self,
        locked: &LockedConversationStateGuard,
    ) -> Result<(), StateMachineError> {
        let head = locked.head();
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        if head.transaction_id() != self.locked.transaction_id
            || head.conversation_id().as_bytes() != &self.expected_conversation_id
            || head.prior_coordinate() != self.locked.expected_prior.as_ref()
            || head.next_entry_seq() != self.locked.expected_next_entry_seq
            || locked_at != self.locked.locked_at
            || head.durable_row_digest() != &self.locked.locked_head_digest
            || self.locked.locked_graph_digest != Some(*locked.locked_graph_digest())
            || self.locked.locked_snapshot_digest != locked.locked_snapshot_digest().copied()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn require_same_locked_head(
        &self,
        head: &LockedConversationHeadGuard,
    ) -> Result<(), StateMachineError> {
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        if head.transaction_id() != self.locked.transaction_id
            || head.conversation_id().as_bytes() != &self.expected_conversation_id
            || head.prior_coordinate() != self.locked.expected_prior.as_ref()
            || head.next_entry_seq() != self.locked.expected_next_entry_seq
            || locked_at != self.locked.locked_at
            || head.durable_row_digest() != &self.locked.locked_head_digest
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(())
    }

    fn transition_from_control(
        &self,
        entry: &VerifiedControlEntry,
    ) -> Result<TransitionEvidence, StateMachineError> {
        if entry.conversation_id().as_bytes() != &self.expected_conversation_id {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        #[cfg(not(test))]
        if entry.seq() != self.locked.expected_next_entry_seq
            || canonical_server_timestamp(entry.received_at())? != self.locked.locked_at
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let (transition_id, body_binding) = match entry.mutation().projection() {
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
        if !transition_binding_is_route_bound(&body_binding, &self.expected_conversation_id) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        #[cfg(not(test))]
        if transition_body_prior(&body_binding) != self.locked.expected_prior.as_ref() {
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

    /// Test/persistence hydration seam. Mutation planning in production uses
    /// the variant-specific methods below so evidence cannot be paired with a
    /// separately selected body or MLS artifact.
    #[cfg(test)]
    pub(crate) fn control_transition(
        &self,
        entry: VerifiedControlEntry,
    ) -> Result<TransitionEvidence, StateMachineError> {
        self.transition_from_control(&entry)
    }

    #[cfg(not(test))]
    pub(crate) fn plan_creation<T: PublicTransport>(
        &self,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        head: Option<&LockedConversationHeadGuard>,
        direct_lookup: Option<LockedDirectConversationLookupGuard>,
        relationship: &RelationshipProjection,
        relationship_authority: &RelationshipAuthority<T>,
        quota_guard: LockedInvitationQuotaGuard,
        relationship_decision: &TrustedRelationshipDecisionInstant,
        trusted_now: &TrustedRequestInstant,
    ) -> Result<CreationDecision, StateMachineError> {
        let group_info_bytes = match entry.mutation().projection() {
            VerifiedMutationProjection::Creation(value) => {
                checked_artifact_bytes(&value.genesis_group_info())?
            }
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let (kind, next, manifest) = match transition.body_binding.as_ref() {
            Some(TransitionBodyBinding::Creation {
                kind,
                next,
                manifest,
                ..
            }) => (*kind, *next, manifest),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if manifest.actor_leaf != *registration.actor() {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let invitees = manifest
            .participants
            .iter()
            .filter(|participant| participant.principal != *registration.actor().principal())
            .map(|participant| participant.principal.clone())
            .collect::<Vec<_>>();
        let trusted_at = ServerTimestamp::from_trusted_request_instant(trusted_now)?;
        let head = match (kind, direct_lookup, head) {
            (ConversationKind::Direct, Some(lookup), maybe_head) => {
                let [invitee] = invitees.as_slice() else {
                    return Err(StateMachineError::InvalidCreation);
                };
                let (low, high) = canonical_pair(registration.actor().principal(), invitee);
                if lookup.transaction_id() != registration.transaction_id()
                    || ServerTimestamp::from_unix_millis(lookup.locked_at().timestamp_millis())?
                        != trusted_at
                    || lookup.did_low().as_bytes() != low.as_bytes()
                    || lookup.did_high().as_bytes() != high.as_bytes()
                    || lookup.durable_row_digest() == &[0; 32]
                {
                    return Err(StateMachineError::InvalidHydrationAuthority);
                }
                match lookup.outcome() {
                    LockedDirectLookupOutcome::Existing {
                        conversation_id,
                        coordinate,
                        ..
                    } if maybe_head.is_none()
                        && coordinate.lifecycle() == PublicGroupSnapshotLifecycle::Active =>
                    {
                        return Ok(CreationDecision::ExistingDirect {
                            conversation_id: *conversation_id.as_bytes(),
                            coordinate: *coordinate,
                        });
                    }
                    LockedDirectLookupOutcome::Absent => {
                        maybe_head.ok_or(StateMachineError::InvalidHydrationAuthority)?
                    }
                    _ => return Err(StateMachineError::InvalidHydrationAuthority),
                }
            }
            (ConversationKind::Group, None, Some(head)) => head,
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        self.require_same_locked_head(head)?;
        let public_state = verify_genesis_group_info(
            &group_info_bytes,
            GenesisGroupInfoExpectations {
                coordinate: next,
                expected_basic_credential: &registration.actor().basic_credential(),
                expected_signature_key: registration.registered_mls_signature_key(),
                now_unix_seconds: u64::try_from(transition.received_at.unix_millis() / 1_000)
                    .map_err(|_| StateMachineError::InvalidServerTime)?,
                max_wire_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_members: MAX_PARTICIPANTS,
            },
        )?;
        let authority = transition.clone();
        let decision = plan_creation_inner(
            None,
            CreationCommand {
                kind,
                creator: registration.actor().clone(),
                invitees,
                transition,
                public_state,
            },
        )?;
        let CreationDecision::Create(plan) = decision else {
            return Ok(decision);
        };
        let roster = plan
            .state
            .participants
            .iter()
            .map(|participant| {
                String::from_utf8(participant.principal.as_bytes().to_vec())
                    .map_err(|_| StateMachineError::InvalidPolicyAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pending_recipients = plan
            .state
            .participants
            .iter()
            .filter(|participant| participant.status == ParticipantStatus::Pending)
            .map(|participant| {
                String::from_utf8(participant.principal.as_bytes().to_vec())
                    .map_err(|_| StateMachineError::InvalidPolicyAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let request = AdmissionRequest {
            inviter: String::from_utf8(registration.actor().principal().as_bytes().to_vec())
                .map_err(|_| StateMachineError::InvalidPolicyAuthority)?,
            roster,
            pending_recipients,
            operation: if kind == ConversationKind::Direct {
                AdmissionOperation::Direct
            } else {
                AdmissionOperation::Group
            },
        };
        let quota_cas = invitation_quota_cas_from_guard(
            &quota_guard,
            registration.actor().principal(),
            &request.pending_recipients,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?;
        consume_admission_projection(
            relationship,
            ProjectionOperationScope::Creation,
            &request,
            relationship_authority,
            relationship_decision,
            quota_guard.would_exceed(),
        )
        .map_err(|_| StateMachineError::InvalidPolicyAuthority)?;
        if registration.trusted_read_at()
            != ServerTimestamp::from_trusted_request_instant(trusted_now)?
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(CreationDecision::Create(
            plan.bind_transition_authority(
                authority,
                head,
                registration.transaction_id(),
                registration.trusted_read_at(),
            )?
            .bind_invitation_quota_cas(quota_cas)?,
        ))
    }

    /// Consume the exact signed Policy body and the complete relationship
    /// projection under the conversation lock. No caller-selected roster or
    /// participant-change command crosses this seam.
    #[cfg(not(test))]
    pub(crate) fn plan_policy<T: PublicTransport>(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
        relationship: &RelationshipProjection,
        relationship_authority: &RelationshipAuthority<T>,
        quota_guard: LockedInvitationQuotaGuard,
        relationship_decision: &TrustedRelationshipDecisionInstant,
        trusted_now: &TrustedRequestInstant,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let actor = registration.actor().clone();
        let authority = transition.clone();
        let plan = plan_policy_transition(
            prior,
            PolicyCommand {
                actor: actor.clone(),
                transition,
                relationship_evidence_digest: relationship.evidence_digest(),
            },
        )?;
        let roster = plan
            .state
            .participants
            .iter()
            .map(|participant| {
                String::from_utf8(participant.principal.as_bytes().to_vec())
                    .map_err(|_| StateMachineError::InvalidPolicyAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pending_recipients = plan
            .effects
            .participant_changes
            .iter()
            .filter_map(|change| match (&change.before, &change.after) {
                (None, Some(after)) if after.status == ParticipantStatus::Pending => {
                    String::from_utf8(after.principal.as_bytes().to_vec()).ok()
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let request = AdmissionRequest {
            inviter: String::from_utf8(actor.principal().as_bytes().to_vec())
                .map_err(|_| StateMachineError::InvalidPolicyAuthority)?,
            roster,
            pending_recipients,
            operation: AdmissionOperation::Group,
        };
        let quota_cas = invitation_quota_cas_from_guard(
            &quota_guard,
            actor.principal(),
            &request.pending_recipients,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?;
        consume_admission_projection(
            relationship,
            ProjectionOperationScope::PendingAdd,
            &request,
            relationship_authority,
            relationship_decision,
            quota_guard.would_exceed(),
        )
        .map_err(|_| StateMachineError::InvalidPolicyAuthority)?;
        if registration.trusted_read_at()
            != ServerTimestamp::from_trusted_request_instant(trusted_now)?
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_invitation_quota_cas(quota_cas)?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    /// Consume the exact ParticipantAcceptance control row together with the
    /// locked active registration, the exact locked KeyPackage selection, and
    /// the acceptance-scoped relationship projection.  The retained inviter
    /// remains the consent source and the accepting principal is the sole
    /// declaration recipient even though the successor marks them active.
    #[cfg(not(test))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_acceptance_entry<T: PublicTransport>(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: LockedRegistrationProjection,
        reservation: LockedRecoveryReservationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
        relationship: &RelationshipProjection,
        relationship_authority: &RelationshipAuthority<T>,
        relationship_decision: &TrustedRelationshipDecisionInstant,
        trusted_now: &TrustedRequestInstant,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition)
            || !reservation.authorizes_acceptance(&transition)
            || registration.transaction_id() != reservation.transaction_id()
            || registration.trusted_read_at()
                != ServerTimestamp::from_trusted_request_instant(trusted_now)?
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let (recovery_request_id, invitation) = match transition.body_binding.as_ref() {
            Some(TransitionBodyBinding::Acceptance {
                recovery_request_id,
                invitation_provenance,
                ..
            }) => (*recovery_request_id, invitation_provenance),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let actor = registration.actor().clone();
        let retained_invitation = prior
            .participant(actor.principal())
            .and_then(|participant| participant.invitation.as_ref())
            .ok_or(StateMachineError::InvitationNotPending)?;
        if retained_invitation.transition.transition_id != invitation.transition_id
            || retained_invitation.inviter != invitation.inviter
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let inviter =
            String::from_utf8(retained_invitation.inviter.principal().as_bytes().to_vec())
                .map_err(|_| StateMachineError::InvalidPolicyAuthority)?;
        let accepting_principal = String::from_utf8(actor.principal().as_bytes().to_vec())
            .map_err(|_| StateMachineError::InvalidPolicyAuthority)?;
        let key_package_ref = *reservation.key_package_ref();
        let package_not_after = reservation.package_not_after();
        let package_cas = reservation.available_package_cas();
        let relationship_evidence_digest = relationship.evidence_digest();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let authority = transition.clone();
        let plan = plan_accept_conversation_inner(
            prior,
            AcceptConversation {
                actor,
                transition,
                recovery_request_id,
                key_package_ref,
                package_not_after,
                registration,
                reservation,
                relationship_evidence_digest,
            },
        )?;
        let roster = plan
            .state
            .participants
            .iter()
            .map(|participant| {
                String::from_utf8(participant.principal.as_bytes().to_vec())
                    .map_err(|_| StateMachineError::InvalidPolicyAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        consume_admission_projection(
            relationship,
            ProjectionOperationScope::Acceptance,
            &AdmissionRequest {
                inviter,
                roster,
                pending_recipients: vec![accepting_principal],
                operation: if prior.kind == ConversationKind::Direct {
                    AdmissionOperation::Direct
                } else {
                    AdmissionOperation::Group
                },
            },
            relationship_authority,
            relationship_decision,
            false,
        )
        .map_err(|_| StateMachineError::InvalidPolicyAuthority)?;
        plan.bind_transition_authority(authority, head, &transaction_id, trusted_read_at)?
            .bind_recovery_package_cas(package_cas)?
            .bind_terminal_package_guards(prior, terminal_packages, &transaction_id)
    }

    /// Process only the generic Commit variant. Recovery and leave
    /// fulfillments have distinct sealed entry points below so their extra
    /// package, target-registration, consent, and work-row authorities cannot
    /// be bypassed by variant dispatch.
    #[cfg(not(test))]
    pub(crate) fn plan_commit_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let (commit_bytes, aad, next) = match entry.mutation().projection() {
            VerifiedMutationProjection::CommitTransition(value) => (
                checked_artifact_bytes(&value.commit())?,
                commit_aad_bytes(&value.aad()),
                closed_coordinate(&value.next())?,
            ),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = transition.clone();
        let commit = process_commit(
            prior.public_state(),
            &commit_bytes,
            &aad,
            next,
            u64::try_from(transition.received_at.unix_millis() / 1_000)
                .map_err(|_| StateMachineError::InvalidServerTime)?,
            MAX_PARTICIPANTS,
        )?;
        let plan = plan_commit_inner(
            prior,
            CommitCommand {
                actor: registration.actor().clone(),
                transition,
                commit,
            },
        )?;
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    /// Final recovery Add: bind the committing actor, the target's current
    /// active registration, the exact reserved KeyPackage row, and a fresh
    /// complete block-only roster projection in one transaction.
    #[cfg(not(test))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_recovery_fulfillment_entry<T: PublicTransport>(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        actor_registration: &LockedRegistrationProjection,
        target_registration: &LockedRegistrationProjection,
        reserved_package: LockedRecoveryPackageGuard,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
        relationship: &RelationshipProjection,
        relationship_authority: &RelationshipAuthority<T>,
        relationship_decision: &TrustedRelationshipDecisionInstant,
        trusted_now: &TrustedRequestInstant,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let (request_id, commit_bytes, aad, next) = match entry.mutation().projection() {
            VerifiedMutationProjection::LeafRecoveryFulfillment(value) => (
                *value.recovery_request_id().as_bytes(),
                checked_artifact_bytes(&value.commit())?,
                commit_aad_bytes(&value.aad()),
                closed_coordinate(&value.next())?,
            ),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let transition = self.transition_from_control(&entry)?;
        if !actor_registration.authorizes_transition(&transition)
            || actor_registration.transaction_id() != target_registration.transaction_id()
            || actor_registration.trusted_read_at() != target_registration.trusted_read_at()
            || actor_registration.trusted_read_at()
                != ServerTimestamp::from_trusted_request_instant(trusted_now)?
            || target_registration.status() != PersistedRegistrationStatus::Active
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let request = prior
            .recovery_request(&request_id)
            .filter(|request| request.status == RecoveryRequestStatus::Open)
            .ok_or(StateMachineError::LeafRecoveryNotFound)?;
        let reservation = prior
            .recovery_reservation(&request_id)
            .filter(|reservation| reservation.status == ReservationStatus::Active)
            .ok_or(StateMachineError::LeafRecoveryNotFound)?;
        let package_cas = reserved_package_cas_for_request(
            reserved_package,
            request,
            reservation,
            actor_registration.transaction_id(),
            PackageStatus::Consumed,
        )?;
        if target_registration.actor() != &request.target
            || target_registration.key_id() != package_cas.target_key_id()
            || target_registration.auth_generation() != package_cas.target_auth_generation()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let commit = process_commit(
            prior.public_state(),
            &commit_bytes,
            &aad,
            next,
            u64::try_from(transition.received_at.unix_millis() / 1_000)
                .map_err(|_| StateMachineError::InvalidServerTime)?,
            MAX_PARTICIPANTS,
        )?;
        let signed_welcome = match transition.body_binding.as_ref() {
            Some(TransitionBodyBinding::LeafRecoveryFulfillment { manifest, .. }) => manifest
                .welcome
                .as_ref()
                .ok_or(StateMachineError::InvalidWelcomeMapping)?,
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let welcome = verify_recovery_welcome(
            &signed_welcome.opaque_welcome,
            request.key_package_ref,
            MAX_WELCOME_WIRE_BYTES,
        )?;
        let authority = transition.clone();
        let mut plan = plan_leaf_recovery_fulfillment_inner(
            prior,
            LeafRecoveryFulfillment {
                actor: actor_registration.actor().clone(),
                target: request.target.clone(),
                recovery_request_id: request_id,
                welcome_id: signed_welcome.welcome_id,
                transition,
                commit,
                welcome,
            },
        )?;
        let roster = plan
            .state
            .participants
            .iter()
            .map(|participant| {
                String::from_utf8(participant.principal.as_bytes().to_vec())
                    .map_err(|_| StateMachineError::InvalidPolicyAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        consume_block_projection(
            relationship,
            ProjectionOperationScope::RecoveryFulfillment,
            &roster,
            relationship_authority,
            relationship_decision,
        )
        .map_err(|_| StateMachineError::InvalidPolicyAuthority)?;
        plan.effects.policy_evidence_digest = Some(relationship.evidence_digest());
        plan.bind_transition_authority(
            authority,
            head,
            actor_registration.transaction_id(),
            actor_registration.trusted_read_at(),
        )?
        .bind_recovery_package_cas(package_cas)?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            actor_registration.transaction_id(),
        )
    }

    #[cfg(not(test))]
    pub(crate) fn plan_leave_fulfillment_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let (request_id, commit_bytes, aad, next) = match entry.mutation().projection() {
            VerifiedMutationProjection::LeaveCommitFulfillment(value) => (
                *value.leave_request_id().as_bytes(),
                checked_artifact_bytes(&value.commit())?,
                commit_aad_bytes(&value.aad()),
                closed_coordinate(&value.next())?,
            ),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let request = prior
            .leave_request(&request_id)
            .ok_or(StateMachineError::LeaveRequestNotFound)?;
        let commit = process_commit(
            prior.public_state(),
            &commit_bytes,
            &aad,
            next,
            u64::try_from(transition.received_at.unix_millis() / 1_000)
                .map_err(|_| StateMachineError::InvalidServerTime)?,
            MAX_PARTICIPANTS,
        )?;
        let authority = transition.clone();
        let plan = plan_leave_fulfillment_inner(
            prior,
            LeaveFulfillment {
                actor: registration.actor().clone(),
                requester: request.requester.principal().clone(),
                leave_request_id: request_id,
                transition,
                commit,
            },
        )?;
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    #[cfg(not(test))]
    pub(crate) fn plan_reset_activation_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let (request_id, successor, group_info_bytes) = match entry.mutation().projection() {
            VerifiedMutationProjection::ResetActivation(value) => (
                *value.reset_request_id().as_bytes(),
                closed_coordinate(&value.successor())?,
                checked_artifact_bytes(&value.genesis_group_info())?,
            ),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = transition.clone();
        let successor_public_state = verify_reset_successor_group_info(
            &group_info_bytes,
            &prior.coordinate,
            ResetSuccessorGroupInfoExpectations {
                coordinate: successor,
                expected_basic_credential: &registration.actor().basic_credential(),
                expected_signature_key: registration.registered_mls_signature_key(),
                now_unix_seconds: u64::try_from(transition.received_at.unix_millis() / 1_000)
                    .map_err(|_| StateMachineError::InvalidServerTime)?,
                max_wire_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_members: MAX_PARTICIPANTS,
            },
        )?;
        let plan = plan_reset_activation_inner(
            prior,
            ResetActivation {
                actor: registration.actor().clone(),
                reset_request_id: request_id,
                transition,
                successor_public_state,
            },
        )?;
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    #[cfg(not(test))]
    pub(crate) fn plan_metadata_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let transition = self.transition_from_control(&entry)?;
        if !matches!(
            transition.body_binding.as_ref(),
            Some(TransitionBodyBinding::Metadata { .. })
        ) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let actor = registration.actor().clone();
        let authority = transition.clone();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let plan = plan_metadata_inner(
            prior,
            MetadataCommand {
                actor,
                transition,
                registration,
            },
        )?;
        plan.bind_transition_authority(authority, head, &transaction_id, trusted_read_at)?
            .bind_terminal_package_guards(prior, terminal_packages, &transaction_id)
    }

    #[cfg(not(test))]
    pub(crate) fn plan_zero_leaf_leave_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition)
            || !matches!(
                transition.body_binding.as_ref(),
                Some(TransitionBodyBinding::ZeroLeafLeave { .. })
            )
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = transition.clone();
        let plan = plan_zero_leaf_leave_inner(
            prior,
            ZeroLeafLeave {
                actor: registration.actor().clone(),
                transition,
            },
        )?;
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    #[cfg(not(test))]
    pub(crate) fn plan_close_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition)
            || !matches!(
                transition.body_binding.as_ref(),
                Some(TransitionBodyBinding::ConversationClose { .. })
            )
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = transition.clone();
        let plan = plan_close_inner(
            prior,
            CloseConversation {
                actor: registration.actor().clone(),
                transition,
            },
        )?;
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    pub(crate) fn control_request(
        &self,
        entry: VerifiedControlEntry,
    ) -> Result<RequestEvidence, StateMachineError> {
        if entry.conversation_id().as_bytes() != &self.expected_conversation_id {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        #[cfg(not(test))]
        if entry.seq() != self.locked.expected_next_entry_seq
            || canonical_server_timestamp(entry.received_at())? != self.locked.locked_at
        {
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
        #[cfg(not(test))]
        if matches!(
            &body_binding,
            RequestBodyBinding::ResetRequest { prior }
                | RequestBodyBinding::LeaveRequest { prior }
                if Some(prior) != self.locked.expected_prior.as_ref()
        ) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
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

    #[cfg(not(test))]
    pub(crate) fn plan_reset_request_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: LockedRegistrationProjection,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let evidence = self.control_request(entry)?;
        if evidence.kind != RequestEntryKind::ResetRequest || !registration.authorizes(&evidence) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = evidence.clone();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let plan = plan_reset_request_inner(
            prior,
            ResetRequestCommand {
                actor: evidence.actor.clone(),
                reset_request_id: evidence.request_id,
                received_at: evidence.received_at,
                evidence,
                registration,
            },
        )?;
        plan.bind_control_request_authority(authority, head, &transaction_id, trusted_read_at)
    }

    #[cfg(not(test))]
    pub(crate) fn plan_leave_request_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: LockedRegistrationProjection,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let evidence = self.control_request(entry)?;
        if evidence.kind != RequestEntryKind::LeaveRequest || !registration.authorizes(&evidence) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = evidence.clone();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let plan = plan_leave_request_inner(
            prior,
            LeaveRequestCommand {
                actor: evidence.actor.clone(),
                leave_request_id: evidence.request_id,
                received_at: evidence.received_at,
                evidence,
                registration,
            },
        )?;
        plan.bind_control_request_authority(authority, head, &transaction_id, trusted_read_at)
    }

    #[cfg(not(test))]
    pub(crate) fn plan_leave_cancellation_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: LockedRegistrationProjection,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let evidence = self.control_request(entry)?;
        if evidence.kind != RequestEntryKind::LeaveCancellation
            || !registration.authorizes(&evidence)
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = evidence.clone();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let plan = plan_leave_cancellation_inner(
            prior,
            LeaveCancellation {
                actor: evidence.actor.clone(),
                leave_request_id: evidence.request_id,
                received_at: evidence.received_at,
                evidence,
                registration,
            },
        )?;
        plan.bind_control_request_authority(authority, head, &transaction_id, trusted_read_at)
    }

    pub(crate) fn signed_request(
        &self,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
    ) -> Result<RequestEvidence, StateMachineError> {
        if envelope.conversation_id != self.expected_conversation_id {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        #[cfg(not(test))]
        if envelope.received_at != self.locked.locked_at {
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
                },
            ),
            VerifiedMutationProjection::WelcomeRejection(value) => (
                RequestEntryKind::WelcomeRejection,
                closed_uuid(&value.body(), "welcomeId")?,
                value.body(),
                RequestBodyBinding::WelcomeResponse {
                    coordinates: closed_coordinate_from_field(&value.body(), "coordinates")?,
                    transition_seq: closed_integer(&value.body(), "transitionSeq")?,
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
            .is_some_and(|conversation_id| conversation_id != self.expected_conversation_id)
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        #[cfg(not(test))]
        if match &body_binding {
            RequestBodyBinding::LeafRecoveryRequest { prior, .. } => {
                Some(prior) != self.locked.expected_prior.as_ref()
            }
            RequestBodyBinding::WelcomeResponse { coordinates, .. } => {
                Some(coordinates) != self.locked.expected_prior.as_ref()
            }
            RequestBodyBinding::LeafRecoveryCancellation => false,
            _ => true,
        } {
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

    /// Admit a non-control leaf-recovery request using the exact signed
    /// wrapper, active device row, transaction-bound KeyPackage selection,
    /// and the complete block-only relationship projection for the current
    /// logical roster. No artificial control entry ID or sequence is minted.
    #[cfg(not(test))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_leaf_recovery_request_entry<T: PublicTransport>(
        &self,
        locked: &LockedConversationStateGuard,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
        registration: LockedRegistrationProjection,
        reservation: LockedRecoveryReservationProjection,
        relationship: &RelationshipProjection,
        relationship_authority: &RelationshipAuthority<T>,
        relationship_decision: &TrustedRelationshipDecisionInstant,
        trusted_now: &TrustedRequestInstant,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let evidence = self.signed_request(envelope, mutation)?;
        let kind = match evidence.body_binding.as_ref() {
            Some(RequestBodyBinding::LeafRecoveryRequest { kind, .. }) => *kind,
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if !registration.authorizes(&evidence)
            || !reservation.authorizes_request(&evidence, kind)
            || registration.transaction_id() != reservation.transaction_id()
            || registration.trusted_read_at()
                != ServerTimestamp::from_trusted_request_instant(trusted_now)?
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let actor = registration.actor().clone();
        let recovery_request_id = *evidence.request_id();
        let received_at = evidence.received_at();
        let key_package_ref = *reservation.key_package_ref();
        let package_not_after = reservation.package_not_after();
        let package_cas = reservation.available_package_cas();
        let relationship_evidence_digest = relationship.evidence_digest();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let authority = evidence.clone();
        let plan = plan_leaf_recovery_request_inner(
            prior,
            LeafRecoveryRequestCommand {
                actor,
                recovery_request_id,
                kind,
                key_package_ref,
                received_at,
                package_not_after,
                evidence,
                registration,
                reservation,
                relationship_evidence_digest,
            },
        )?;
        let roster = plan
            .state
            .participants
            .iter()
            .map(|participant| {
                String::from_utf8(participant.principal.as_bytes().to_vec())
                    .map_err(|_| StateMachineError::InvalidPolicyAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        consume_block_projection(
            relationship,
            ProjectionOperationScope::RecoveryReservation,
            &roster,
            relationship_authority,
            relationship_decision,
        )
        .map_err(|_| StateMachineError::InvalidPolicyAuthority)?;
        plan.bind_non_control_request_authority(authority, head, &transaction_id, trusted_read_at)?
            .bind_recovery_package_cas(package_cas)
    }

    #[cfg(not(test))]
    pub(crate) fn plan_leaf_recovery_cancellation_entry(
        &self,
        locked: &LockedConversationStateGuard,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
        registration: LockedRegistrationProjection,
        reserved_package: LockedRecoveryPackageGuard,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let evidence = self.signed_request(envelope, mutation)?;
        if evidence.kind != RequestEntryKind::LeafRecoveryCancellation
            || !registration.authorizes(&evidence)
            || registration.transaction_id() != head.transaction_id()
            || registration.trusted_read_at() != evidence.received_at
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let request = prior
            .recovery_request(evidence.request_id())
            .filter(|request| request.status == RecoveryRequestStatus::Open)
            .ok_or(StateMachineError::LeafRecoveryNotFound)?;
        let reservation = prior
            .recovery_reservation(evidence.request_id())
            .filter(|reservation| reservation.status == ReservationStatus::Active)
            .ok_or(StateMachineError::LeafRecoveryNotFound)?;
        let successor_status = if evidence.received_at >= reservation.package_not_after {
            PackageStatus::Expired
        } else {
            PackageStatus::Available
        };
        let package_cas = reserved_package_cas_for_request(
            reserved_package,
            request,
            reservation,
            registration.transaction_id(),
            successor_status,
        )?;
        let authority = evidence.clone();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let plan = plan_leaf_recovery_cancellation_inner(
            prior,
            LeafRecoveryCancellation {
                actor: evidence.actor.clone(),
                recovery_request_id: evidence.request_id,
                received_at: evidence.received_at,
                evidence,
                registration,
            },
        )?;
        plan.bind_non_control_request_authority(authority, head, &transaction_id, trusted_read_at)?
            .bind_recovery_package_cas(package_cas)
    }

    /// Consume a signed, non-control Welcome acknowledgement together with
    /// the recipient's active registration and the exact Pending Welcome row.
    #[cfg(not(test))]
    pub(crate) fn plan_welcome_acknowledgement_entry(
        &self,
        locked: &LockedConversationStateGuard,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
        registration: LockedRegistrationProjection,
        welcome_guard: LockedWelcomeGuard,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.plan_welcome_response_entry(
            locked,
            envelope,
            mutation,
            registration,
            welcome_guard,
            RequestEntryKind::WelcomeAcknowledgement,
            WelcomeStatus::Acknowledged,
        )
    }

    /// Consume a signed, non-control Welcome rejection under the same exact
    /// row/registration authority used by acknowledgement.
    #[cfg(not(test))]
    pub(crate) fn plan_welcome_rejection_entry(
        &self,
        locked: &LockedConversationStateGuard,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
        registration: LockedRegistrationProjection,
        welcome_guard: LockedWelcomeGuard,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.plan_welcome_response_entry(
            locked,
            envelope,
            mutation,
            registration,
            welcome_guard,
            RequestEntryKind::WelcomeRejection,
            WelcomeStatus::Rejected,
        )
    }

    #[cfg(not(test))]
    #[allow(clippy::too_many_arguments)]
    fn plan_welcome_response_entry(
        &self,
        locked: &LockedConversationStateGuard,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
        registration: LockedRegistrationProjection,
        welcome_guard: LockedWelcomeGuard,
        expected_kind: RequestEntryKind,
        successor_status: WelcomeStatus,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let evidence = self.signed_request(envelope, mutation)?;
        if evidence.kind != expected_kind
            || !registration.authorizes(&evidence)
            || registration.transaction_id() != head.transaction_id()
            || registration.transaction_id() != welcome_guard.transaction_id()
            || registration.trusted_read_at() != evidence.received_at
            || ServerTimestamp::from_unix_millis(welcome_guard.locked_at().timestamp_millis())?
                != evidence.received_at
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let welcome_cas = welcome_cas_from_guard(prior, &welcome_guard, successor_status)?;
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let authority = evidence.clone();
        plan_welcome_response(prior, evidence, successor_status)?
            .bind_non_control_request_authority(authority, head, &transaction_id, trusted_read_at)?
            .bind_welcome_cas(welcome_cas)
    }

    /// Expiry workers must first identify a due row, then lock the
    /// conversation/head and that exact Pending Welcome in canonical order.
    /// The consumed guard proves both due time and immutable delivery bytes;
    /// there is no direct SQL writer outside this state-machine route.
    #[cfg(not(test))]
    pub(crate) fn plan_welcome_expiry_entry(
        &self,
        locked: &LockedConversationStateGuard,
        welcome_guard: LockedWelcomeGuard,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        if head.transaction_id() != welcome_guard.transaction_id()
            || head.locked_at() != welcome_guard.locked_at()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let welcome_cas = welcome_cas_from_guard(prior, &welcome_guard, WelcomeStatus::Expired)?;
        let observed_at =
            ServerTimestamp::from_unix_millis(welcome_guard.locked_at().timestamp_millis())?;
        if observed_at < welcome_cas.expires_at {
            return Err(StateMachineError::WorkExpired);
        }
        let authority = WelcomeExpiryAuthority {
            welcome_id: welcome_cas.welcome_id,
            recipient: welcome_cas.recipient.clone(),
            coordinate: welcome_cas.coordinate,
            transition_seq: welcome_cas.transition_seq,
            terminal_at: welcome_cas.expires_at,
            observed_at,
            locked_row_digest: welcome_cas.locked_row_digest,
        };
        plan_welcome_expiry(prior, welcome_cas.welcome_id)?
            .bind_welcome_expiry_authority(authority, head, welcome_guard.transaction_id())?
            .bind_welcome_cas(welcome_cas)
    }

    pub(crate) fn device_revocation(
        &self,
        mutation: VerifiedSignedMutation,
        accepted_at: &TrustedRequestInstant,
    ) -> Result<DeviceRevocationEvidence, StateMachineError> {
        Self::device_revocation_at(
            mutation,
            ServerTimestamp::from_trusted_request_instant(accepted_at)?,
        )
    }

    fn device_revocation_at(
        mutation: VerifiedSignedMutation,
        accepted_at: ServerTimestamp,
    ) -> Result<DeviceRevocationEvidence, StateMachineError> {
        let body = match mutation.projection() {
            VerifiedMutationProjection::DeviceRevocation(value) => value.body(),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let actor = DeviceIdentity::new(
            PrincipalId::new(mutation.actor_did().as_str().as_bytes().to_vec())?,
            *mutation.actor_device_id().as_bytes(),
        )?;
        let target = DeviceIdentity::new(
            actor.principal().clone(),
            closed_uuid(&body, "targetDeviceId")?,
        )?;
        let expected_target_auth_generation = closed_integer(&body, "targetAuthGeneration")?;
        let revocation_id = closed_uuid(&body, "idempotencyKey")?;
        let actor_key_id: [u8; 32] = URL_SAFE_NO_PAD
            .decode(mutation.key_id().as_str())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let signed_at = canonical_server_timestamp(mutation.signed_at())?;
        let signed_request_bytes = mutation
            .accepted_wrapper_bytes()
            .filter(|bytes| !bytes.is_empty())
            .ok_or(StateMachineError::InvalidHydrationAuthority)?
            .to_vec();
        if expected_target_auth_generation == 0
            || expected_target_auth_generation > MAX_PROTOCOL_INTEGER
            || signed_at > accepted_at
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let mut evidence = DeviceRevocationEvidence {
            revocation_id,
            actor,
            target,
            actor_key_id,
            actor_auth_generation: mutation.auth_generation(),
            expected_target_auth_generation,
            signed_at,
            accepted_at,
            request_digest: *mutation.request_digest(),
            signature: *mutation.signature(),
            signed_request_bytes,
            signing_transcript_bytes: mutation.transcript_bytes().to_vec(),
            durable_row_digest: [0; 32],
        };
        evidence.durable_row_digest = device_revocation_row_digest(&evidence);
        if !validate_device_revocation_evidence(&evidence) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(evidence)
    }

    /// Consume the device-first lock set exactly once and plan every affected
    /// conversation as one all-or-nothing transaction batch. The repository
    /// fanout manifest proves completeness, including the legal empty case;
    /// callers cannot omit a conversation, request, Welcome, or reserved
    /// package and still obtain a persistence plan.
    #[cfg(not(test))]
    pub(crate) fn plan_device_revocation_batch(
        mutation: VerifiedSignedMutation,
        actor_guard: BusinessAuthorityGuard,
        target_guard: LockedRevocationTargetGuard,
        fanout_guard: LockedRevocationFanoutGuard,
        mut live_package_guards: Vec<LockedRevocationPackageGuard>,
        mut locked_conversations: Vec<LockedConversationStateGuard>,
    ) -> Result<DeviceRevocationBatchPersistencePlan, StateMachineError> {
        let transaction_id = actor_guard.transaction_id();
        let locked_at = actor_guard.trusted_instant();
        if actor_guard.class() != RepositoryAuthorityClass::ExistingDevice
            || transaction_id != target_guard.transaction_id()
            || transaction_id != fanout_guard.transaction_id()
            || locked_at != target_guard.locked_at()
            || locked_at != fanout_guard.locked_at()
            || target_guard.status() != LockedRevocationTargetStatus::Active
            || target_guard.durable_row_digest() == &[0; 32]
            || fanout_guard.durable_manifest_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let accepted_at = ServerTimestamp::from_unix_millis(locked_at.timestamp_millis())?;
        let evidence = Self::device_revocation_at(mutation, accepted_at)?;
        let actor_key_id: [u8; 32] = actor_guard
            .stored_key_id()
            .and_then(|value| KeyThumbprint::parse(value).ok())
            .and_then(|value| URL_SAFE_NO_PAD.decode(value.as_str()).ok())
            .and_then(|value| value.try_into().ok())
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let actor_auth_generation = actor_guard
            .stored_auth_generation()
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| (1..=MAX_PROTOCOL_INTEGER).contains(value))
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if actor_guard.subject().as_bytes() != evidence.actor.principal().as_bytes()
            || actor_guard.device_id().as_bytes() != evidence.actor.device_id()
            || actor_key_id != evidence.actor_key_id
            || actor_auth_generation != evidence.actor_auth_generation
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

        if revoked_packages.iter().any(|binding| {
            binding.expected_status == PackageStatus::Reserved
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
            fanout_manifest_digest: *fanout_guard.durable_manifest_digest(),
            conversations,
        })
    }

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
        })
    }

    #[cfg(not(test))]
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
        })
    }

    #[cfg(not(test))]
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
        let now_unix_seconds = u64::try_from(claimed_at.unix_millis() / 1_000)
            .map_err(|_| StateMachineError::InvalidServerTime)?;
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

/// Untrusted durable-row DTO for a non-control signed request. Its timestamp is
/// parsed with the same reject-rather-than-normalize canonical grammar used by
/// the signed protocol, but authority is issued only after raw signature and
/// stored-row digest verification.
pub(crate) struct PersistedSignedRequestRow {
    conversation_id: [u8; 16],
    received_at: CanonicalTimestamp,
    durable_row_digest: [u8; 32],
}

/// Untrusted durable control-row material. Authority is issued only after the
/// public row and separately retained exact signed wrapper both verify under
/// the historical key, and every frozen outer-row byte/digest agrees.
pub(crate) struct PersistedControlRow {
    public_row_json: Vec<u8>,
    raw_signed_wrapper: Vec<u8>,
    outer_control_projection: Vec<u8>,
    server_fields_dag_cbor: Vec<u8>,
    outer_entry_fingerprint: [u8; 32],
    durable_row_digest: [u8; 32],
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
        Some(TransitionBodyBinding::Creation { .. }) => Ok(None),
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
        Some(TransitionBodyBinding::Acceptance { .. })
    ) && evidence.authority.as_ref().is_some_and(|authority| {
        authority.kind == SignedMutationKind::ParticipantAcceptance
            && authority.actor.principal() == principal
    });
    if !records_acceptance {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(evidence)
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
    expected_conversation_id: [u8; 16],
    /// Upper bound for the control-entry `seq < head` global constraint. Read
    /// only by the control-entry path (`hydrate_historical_control`); unused by
    /// the signed-request path (signed requests carry no entry seq).
    head_next_entry_seq: u64,
}

impl HistoricalRehydrationAuthority {
    /// Production constructor: binds the read-time authority to an EXISTING
    /// locked head (`prior_coordinate` = `Some`, `next_entry_seq >= 2`). The
    /// head's `next_entry_seq` becomes the strict upper bound for historical
    /// control-entry seqs.
    #[cfg(not(test))]
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
    /// The `durable_row_digest` is NOT a stored column on the signed-request
    /// projection tables (`chat.leaf_recovery_requests` etc.); it is DERIVED here by
    /// minting candidate evidence through the SAME head-binding-free minter
    /// (`historical_signed_request_evidence`) that `hydrate_historical_signed_request`
    /// dispatches to, then the assembled `PersistedSignedRequestRow` is re-verified
    /// by `hydrate_historical_signed_request` itself — whose independent re-decode +
    /// `durable_row_digest` equality are the loader-consistency guards over this
    /// derivation (the digest is derived, not independently stored, so that equality
    /// is self-consistency — the integrity boundary is the ed25519 verification
    /// re-run inside `decode_and_verify_signed_mutation`, which is NEVER skipped).
    /// Forced into state_machine.rs because the digest minter is module-private;
    /// additive companion to `hydrate_historical_signed_request`, touching no
    /// existing fn. Drift fence: the cfg(test)
    /// `historical_signed_request_from_durable_bytes_matches_row_path` equivalence
    /// test (byte-equal to the `hydrate_historical_signed_request` row path).
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
        // Candidate digest via the SAME dispatch `hydrate_historical_signed_request`
        // uses (same conversation_id + received_at envelope + mutation bytes), so
        // the digest re-computed inside the re-verification below is identical.
        let envelope = DurableSignedRequestEnvelope {
            conversation_id,
            received_at: canonical_server_timestamp(&parsed)?,
        };
        let durable_row_digest =
            historical_signed_request_evidence(envelope, mutation, &self.expected_conversation_id)?
                .durable_row_digest;
        let row = PersistedSignedRequestRow::new(conversation_id, received_at, durable_row_digest)?;
        self.hydrate_historical_signed_request(row, raw_signed_request, historical_public_key)
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
    /// The frozen outer-row material (`outer_control_projection` /
    /// `outer_entry_fingerprint` / `server_fields_dag_cbor`) and the
    /// `durable_row_digest` are NOT stored as `chat.entries` columns; they are
    /// DERIVED here — the outer material by decoding the public row, the digest by
    /// minting evidence through the SAME head-binding-free minters
    /// (`historical_control_request_evidence` / `historical_transition_evidence`)
    /// that `hydrate_historical_control` dispatches to. The assembled
    /// `PersistedControlRow` is then re-verified by `hydrate_historical_control`
    /// itself, whose independent re-decode + `durable_row_digest` equality are the
    /// loader-consistency guards over this derivation (the digest column is
    /// derived, not independently stored, so that equality is self-consistency —
    /// the integrity boundary is the ed25519 verification re-run inside
    /// `decode_and_verify_control_entry` + `rebind_persisted_control_entry`, which
    /// is NEVER skipped). Forced into state_machine.rs because the digest minters
    /// are module-private; additive companion to `hydrate_historical_control`,
    /// touching no existing fn. Drift fence: the cfg(test)
    /// `historical_control_from_durable_bytes_matches_row_path_per_kind`
    /// equivalence test (byte-equal to the `hydrate_historical_control` row path
    /// for every control-entry kind).
    #[allow(dead_code)]
    pub(crate) fn hydrate_historical_control_from_durable_bytes(
        &self,
        public_row_json: Vec<u8>,
        raw_signed_wrapper: Vec<u8>,
        historical_public_key: &[u8],
    ) -> Result<PersistedControlAuthority, StateMachineError> {
        let decoded = decode_and_verify_control_entry(&public_row_json, historical_public_key)
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let outer_control_projection = decoded.outer_control_projection().to_vec();
        let outer_entry_fingerprint = *decoded.outer_control_fingerprint();
        let server_fields_dag_cbor = decoded
            .server_fields_dag_cbor()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let entry =
            rebind_persisted_control_entry(decoded, &raw_signed_wrapper, historical_public_key)
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        // Candidate digest via the SAME dispatch `hydrate_historical_control`
        // uses. The `seq < head` global constraint and the authoritative
        // re-verification are re-run by `hydrate_historical_control` below.
        let durable_row_digest = match entry.mutation().projection() {
            VerifiedMutationProjection::ResetRequest(_)
            | VerifiedMutationProjection::LeaveRequest(_)
            | VerifiedMutationProjection::LeaveCancellation(_) => {
                historical_control_request_evidence(entry, &self.expected_conversation_id)?
                    .durable_row_digest
            }
            _ => {
                historical_transition_evidence(&entry, &self.expected_conversation_id)?
                    .durable_row_digest
            }
        };
        let row = PersistedControlRow::new(
            public_row_json,
            raw_signed_wrapper,
            outer_control_projection,
            server_fields_dag_cbor,
            outer_entry_fingerprint,
            durable_row_digest,
        )?;
        self.hydrate_historical_control(row, historical_public_key)
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
fn historical_signed_request_evidence(
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
            },
        ),
        VerifiedMutationProjection::WelcomeRejection(value) => (
            RequestEntryKind::WelcomeRejection,
            closed_uuid(&value.body(), "welcomeId")?,
            value.body(),
            RequestBodyBinding::WelcomeResponse {
                coordinates: closed_coordinate_from_field(&value.body(), "coordinates")?,
                transition_seq: closed_integer(&value.body(), "transitionSeq")?,
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
fn historical_transition_evidence(
    entry: &VerifiedControlEntry,
    expected_conversation_id: &[u8; 16],
) -> Result<TransitionEvidence, StateMachineError> {
    if entry.conversation_id().as_bytes() != expected_conversation_id {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let (transition_id, body_binding) = match entry.mutation().projection() {
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
fn historical_control_request_evidence(
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
    accepted_at: CanonicalTimestamp,
    durable_row_digest: [u8; 32],
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
    conversation_id: [u8; 16],
    received_at: ServerTimestamp,
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

fn authenticated_entry(
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
fn request_evidence_from_verified(
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

fn canonical_server_timestamp(
    value: &super::validation::CanonicalTimestamp,
) -> Result<ServerTimestamp, StateMachineError> {
    ServerTimestamp::from_unix_millis(value.datetime().timestamp_millis())
}

fn closed_uuid(
    object: &super::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<[u8; 16], StateMachineError> {
    match object.get(name) {
        Some(CanonicalValueRef::Uuid(value)) => Ok(*value.as_bytes()),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

fn closed_integer(
    object: &super::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<u64, StateMachineError> {
    match object.get(name) {
        Some(CanonicalValueRef::Integer(value)) => Ok(value),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

fn closed_text<'a>(
    object: &'a super::transcript::ClosedObjectRef<'a>,
    name: &str,
) -> Result<&'a str, StateMachineError> {
    match object.get(name) {
        Some(CanonicalValueRef::Text(value)) => Ok(value),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

fn closed_principal(
    object: &super::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<PrincipalId, StateMachineError> {
    match object.get(name) {
        Some(CanonicalValueRef::Did(value)) => PrincipalId::new(value.as_str().as_bytes().to_vec()),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

fn closed_key_id(
    object: &super::transcript::ClosedObjectRef<'_>,
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

fn closed_timestamp(
    object: &super::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<ServerTimestamp, StateMachineError> {
    match object.get(name) {
        Some(CanonicalValueRef::Timestamp(value)) => canonical_server_timestamp(value),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

fn closed_coordinate(
    object: &super::transcript::ClosedObjectRef<'_>,
) -> Result<PublicGroupSnapshotCoordinate, StateMachineError> {
    let conversation_id = closed_uuid(object, "conversationId")?;
    let generation = closed_integer(object, "generation")?;
    let state_version = closed_integer(object, "stateVersion")?;
    let group_id = match object.get("groupId") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let epoch = closed_integer(object, "epoch")?;
    let group_context_hash = match object.get("groupContextHash") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let confirmation_tag = match object.get("confirmationTag") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let lifecycle = match closed_text(object, "lifecycle")? {
        "active" => PublicGroupSnapshotLifecycle::Active,
        "superseded" => PublicGroupSnapshotLifecycle::Superseded,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    Ok(PublicGroupSnapshotCoordinate::new(
        conversation_id,
        generation,
        state_version,
        group_id,
        epoch,
        group_context_hash,
        confirmation_tag,
        lifecycle,
    ))
}

fn closed_coordinate_from_field(
    object: &super::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<PublicGroupSnapshotCoordinate, StateMachineError> {
    let Some(CanonicalValueRef::Object(coordinates)) = object.get(name) else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    closed_coordinate(&coordinates)
}

fn parse_conversation_kind(value: &str) -> Result<ConversationKind, StateMachineError> {
    match value {
        "direct" => Ok(ConversationKind::Direct),
        "group" => Ok(ConversationKind::Group),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

fn sealed_object_digest(object: &super::transcript::ClosedObjectRef<'_>) -> [u8; 32] {
    Sha256::digest(object.canonical_dag_cbor()).into()
}

fn commit_aad_bytes(object: &super::transcript::ClosedObjectRef<'_>) -> Vec<u8> {
    let encoded = object.canonical_dag_cbor();
    let mut aad = Vec::with_capacity(COMMIT_AAD_DOMAIN.len() + encoded.len());
    aad.extend_from_slice(COMMIT_AAD_DOMAIN);
    aad.extend_from_slice(&encoded);
    aad
}

fn commit_aad_sha256(object: &super::transcript::ClosedObjectRef<'_>) -> [u8; 32] {
    Sha256::digest(commit_aad_bytes(object)).into()
}

fn checked_artifact_sha256(
    object: &super::transcript::ClosedObjectRef<'_>,
) -> Result<[u8; 32], StateMachineError> {
    let bytes = match object.get("bytes") {
        Some(CanonicalValueRef::Bytes(value)) => value,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let declared: [u8; 32] = match object.get("sha256") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if declared != actual {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(actual)
}

fn checked_artifact_bytes(
    object: &super::transcript::ClosedObjectRef<'_>,
) -> Result<Vec<u8>, StateMachineError> {
    let bytes = match object.get("bytes") {
        Some(CanonicalValueRef::Bytes(value)) => value,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let declared = closed_fixed_bytes::<32>(object, "sha256")?;
    if <[u8; 32]>::from(Sha256::digest(bytes)) != declared {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(bytes.to_vec())
}

fn checked_metadata_snapshot_digest(
    object: &super::transcript::ClosedObjectRef<'_>,
) -> Result<[u8; 32], StateMachineError> {
    let ciphertext = match object.get("ciphertext") {
        Some(CanonicalValueRef::Bytes(value)) => value,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let declared_sha256: [u8; 32] = match object.get("ciphertextSha256") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    if closed_integer(object, "ciphertextSize")? != ciphertext.len() as u64
        || <[u8; 32]>::from(Sha256::digest(ciphertext)) != declared_sha256
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(sealed_object_digest(object))
}

fn parse_metadata_snapshot(
    object: &super::transcript::ClosedObjectRef<'_>,
) -> Result<MetadataSnapshotBinding, StateMachineError> {
    let ciphertext = match object.get("ciphertext") {
        Some(CanonicalValueRef::Bytes(value)) => value.to_vec(),
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let ciphertext_sha256 = closed_fixed_bytes::<32>(object, "ciphertextSha256")?;
    if closed_integer(object, "ciphertextSize")? != ciphertext.len() as u64
        || <[u8; 32]>::from(Sha256::digest(&ciphertext)) != ciphertext_sha256
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let nonce = closed_fixed_bytes::<12>(object, "nonce")?;
    let origin_transition_id = closed_uuid(object, "originTransitionId")?;
    let metadata_version = closed_integer(object, "metadataVersion")?;
    if metadata_version == 0 || metadata_version > MAX_PROTOCOL_INTEGER {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let Some(CanonicalValueRef::Object(coordinate)) = object.get("coordinate") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    let coordinate = MetadataCryptoCoordinate {
        // The metadata crypto context binds conversationId as the compact 16-byte
        // form (lexicon `#identifierBytes`: "Exact 16 UUID bytes corresponding to
        // the canonical outer UUIDv4 text"), NOT the canonical text `#operationId`
        // that transport coordinates (`#conversationCoordinates`) carry — so it
        // projects to `CanonicalValueRef::Bytes`, not `Uuid`, and must be read as
        // exact-16 bytes (reading it with `closed_uuid` never matched and left
        // parse_metadata_snapshot unable to admit any metadata snapshot). The
        // required correspondence — these 16 bytes ARE the outer conversation's
        // UUIDv4 — is enforced bytes-to-bytes downstream by
        // `metadata_coordinate_matches` (see `metadata.coordinate.conversation_id
        // == *coordinate.conversation_id()`), so no re-check is needed here.
        conversation_id: closed_fixed_bytes::<16>(&coordinate, "conversationId")?,
        generation: closed_integer(&coordinate, "generation")?,
        epoch: closed_integer(&coordinate, "epoch")?,
        group_context_hash: closed_fixed_bytes(&coordinate, "groupContextHash")?,
    };
    let Some(CanonicalValueRef::Object(proof)) = object.get("authorProof") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    if closed_text(&proof, "roleAtOrigin")? != "admin"
        || closed_text(&proof, "deviceStatusAtOrigin")? != "active"
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let signature_public_key = closed_fixed_bytes::<32>(&proof, "signaturePublicKey")?;
    let author_key = match proof.get("authorKeyId") {
        Some(CanonicalValueRef::Thumbprint(value)) => value,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    if ed25519_key_id(&signature_public_key)
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
        != *author_key
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let author_key_id: [u8; 32] = URL_SAFE_NO_PAD
        .decode(author_key.as_str())
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
        .try_into()
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
    let author_proof = MetadataAuthorProofBinding {
        author: closed_device(&proof, "authorDid", "authorDeviceId")?,
        author_key_id,
        signature_public_key,
        auth_generation_at_origin: closed_integer(&proof, "authGenerationAtOrigin")?,
        origin_transition_id: closed_uuid(&proof, "originTransitionId")?,
        origin_seq: closed_integer(&proof, "originSeq")?,
    };
    if author_proof.auth_generation_at_origin == 0
        || author_proof.auth_generation_at_origin > MAX_PROTOCOL_INTEGER
        || author_proof.origin_seq == 0
        || author_proof.origin_seq > MAX_PROTOCOL_INTEGER
        || author_proof.origin_transition_id != origin_transition_id
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let avatar_binding_digest = match object.get("avatarBinding") {
        None => None,
        Some(CanonicalValueRef::Object(value)) => Some(sealed_object_digest(&value)),
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let canonical_snapshot = object.canonical_dag_cbor();
    let digest = Sha256::digest(&canonical_snapshot).into();
    Ok(MetadataSnapshotBinding {
        coordinate,
        origin_transition_id,
        metadata_version,
        nonce,
        ciphertext,
        ciphertext_sha256,
        avatar_binding_digest,
        author_proof,
        canonical_snapshot,
        digest,
    })
}

fn metadata_coordinate_matches(
    metadata: &MetadataSnapshotBinding,
    coordinate: &PublicGroupSnapshotCoordinate,
) -> bool {
    metadata.coordinate.conversation_id == *coordinate.conversation_id()
        && metadata.coordinate.generation == coordinate.generation()
        && metadata.coordinate.epoch == coordinate.epoch()
        && metadata.coordinate.group_context_hash == *coordinate.group_context_hash()
}

fn transition_binding_is_route_bound(
    binding: &TransitionBodyBinding,
    conversation_id: &[u8; 16],
) -> bool {
    let coordinate_matches = |coordinate: &PublicGroupSnapshotCoordinate| {
        coordinate.conversation_id() == conversation_id
    };
    match binding {
        TransitionBodyBinding::Creation { next, .. } => coordinate_matches(next),
        TransitionBodyBinding::Commit { prior, next, .. }
        | TransitionBodyBinding::Policy { prior, next, .. }
        | TransitionBodyBinding::Acceptance { prior, next, .. }
        | TransitionBodyBinding::Metadata { prior, next, .. }
        | TransitionBodyBinding::LeafRecoveryFulfillment { prior, next, .. }
        | TransitionBodyBinding::ZeroLeafLeave { prior, next }
        | TransitionBodyBinding::LeaveCommitFulfillment { prior, next, .. } => {
            coordinate_matches(prior) && coordinate_matches(next)
        }
        TransitionBodyBinding::ResetActivation {
            prior,
            retired,
            successor,
            ..
        } => {
            coordinate_matches(prior)
                && coordinate_matches(retired)
                && coordinate_matches(successor)
        }
        TransitionBodyBinding::ConversationClose { prior, retired, .. } => {
            coordinate_matches(prior) && coordinate_matches(retired)
        }
    }
}

fn transition_body_prior(
    binding: &TransitionBodyBinding,
) -> Option<&PublicGroupSnapshotCoordinate> {
    match binding {
        TransitionBodyBinding::Creation { .. } => None,
        TransitionBodyBinding::Commit { prior, .. }
        | TransitionBodyBinding::Policy { prior, .. }
        | TransitionBodyBinding::Acceptance { prior, .. }
        | TransitionBodyBinding::Metadata { prior, .. }
        | TransitionBodyBinding::ResetActivation { prior, .. }
        | TransitionBodyBinding::LeafRecoveryFulfillment { prior, .. }
        | TransitionBodyBinding::ConversationClose { prior, .. }
        | TransitionBodyBinding::ZeroLeafLeave { prior, .. }
        | TransitionBodyBinding::LeaveCommitFulfillment { prior, .. } => Some(prior),
    }
}

fn validate_special_server_fields(
    entry: &VerifiedControlEntry,
    binding: &TransitionBodyBinding,
) -> Result<(), StateMachineError> {
    match binding {
        TransitionBodyBinding::ConversationClose { kind, retired, .. } => {
            let fields = entry.server_fields();
            let Some(CanonicalValueRef::Object(tombstone)) = fields.get("tombstone") else {
                return Err(StateMachineError::InvalidHydrationAuthority);
            };
            let closed_at = match tombstone.get("closedAt") {
                Some(CanonicalValueRef::Timestamp(value)) => value,
                _ => return Err(StateMachineError::InvalidHydrationAuthority),
            };
            let closed_by = closed_device(&tombstone, "closedByDid", "closedByDeviceId")?;
            let signed_retired = match tombstone.get("retired") {
                Some(CanonicalValueRef::Object(value)) => closed_coordinate(&value)?,
                _ => return Err(StateMachineError::InvalidHydrationAuthority),
            };
            let signed_actor = DeviceIdentity::new(
                PrincipalId::new(entry.mutation().actor_did().as_str().as_bytes().to_vec())?,
                *entry.mutation().actor_device_id().as_bytes(),
            )?;
            if closed_uuid(&tombstone, "conversationId")? != *entry.conversation_id().as_bytes()
                || parse_conversation_kind(closed_text(&tombstone, "conversationKind")?)? != *kind
                || signed_retired != *retired
                || closed_by != signed_actor
                || closed_integer(&tombstone, "terminalSeq")? != entry.seq()
                || closed_at.as_str() != entry.received_at().as_str()
            {
                return Err(StateMachineError::InvalidHydrationAuthority);
            }
        }
        TransitionBodyBinding::Acceptance { recovery, .. } => {
            if recovery.canonical_digest == [0; 32] {
                return Err(StateMachineError::InvalidHydrationAuthority);
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_acceptance_recovery(
    server_fields: &super::transcript::ClosedObjectRef<'_>,
) -> Result<AcceptanceRecoveryBinding, StateMachineError> {
    let Some(CanonicalValueRef::Object(recovery)) = server_fields.get("recovery") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    if closed_text(&recovery, "status")? != "open" {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let request_id = closed_uuid(&recovery, "recoveryRequestId")?;
    let conversation_id = closed_uuid(&recovery, "conversationId")?;
    let target = closed_device(&recovery, "requesterDid", "requesterDeviceId")?;
    let kind = match closed_text(&recovery, "recoveryKind")? {
        "add" => LeafRecoveryKind::Add,
        "replace" => LeafRecoveryKind::Replace,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let bound_coordinate = closed_coordinate_from_field(&recovery, "boundCoordinate")?;
    let requested_at = closed_timestamp(&recovery, "requestedAt")?;
    let expires_at = closed_timestamp(&recovery, "expiresAt")?;
    let Some(CanonicalValueRef::Object(reservation)) = recovery.get("reservation") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    if closed_text(&reservation, "cipherSuite")? != "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
        || closed_text(&reservation, "purpose")? != "leafRecovery"
        || closed_text(&reservation, "status")? != "active"
        || closed_uuid(&reservation, "recoveryRequestId")? != request_id
        || closed_uuid(&reservation, "conversationId")? != conversation_id
        || closed_device(&reservation, "requesterDid", "requesterDeviceId")? != target
        || closed_coordinate_from_field(&reservation, "boundCoordinate")? != bound_coordinate
        || closed_timestamp(&reservation, "expiresAt")? != expires_at
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let requester_key_id = closed_key_id(&reservation, "requesterKeyId")?;
    let requester_auth_generation = closed_integer(&reservation, "requesterAuthGeneration")?;
    let key_package_ref = closed_fixed_bytes::<32>(&reservation, "keyPackageRef")?;
    let Some(CanonicalValueRef::Object(package)) = reservation.get("keyPackage") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    if closed_text(&package, "framing")? != "mlsMessage"
        || closed_text(&package, "contentType")? != "keyPackage"
        || closed_fixed_bytes::<32>(&package, "keyPackageRef")? != key_package_ref
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let key_package_wrapper = match package.get("bytes") {
        Some(CanonicalValueRef::Bytes(bytes)) if !bytes.is_empty() => bytes.to_vec(),
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let key_package_wrapper_sha256 = closed_fixed_bytes::<32>(&package, "sha256")?;
    if <[u8; 32]>::from(Sha256::digest(&key_package_wrapper)) != key_package_wrapper_sha256 {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(AcceptanceRecoveryBinding {
        request_id,
        conversation_id,
        target,
        kind,
        bound_coordinate,
        requester_key_id,
        requester_auth_generation,
        key_package_ref,
        key_package_wrapper,
        key_package_wrapper_sha256,
        requested_at,
        expires_at,
        canonical_digest: sealed_object_digest(&recovery),
    })
}

fn closed_fixed_bytes<const N: usize>(
    object: &super::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<[u8; N], StateMachineError> {
    match object.get(name) {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

fn closed_device(
    object: &super::transcript::ClosedObjectRef<'_>,
    did_field: &str,
    device_field: &str,
) -> Result<DeviceIdentity, StateMachineError> {
    let principal = closed_principal(object, did_field)?;
    let device_id = closed_uuid(object, device_field)?;
    DeviceIdentity::new(principal, device_id)
}

fn parse_participant_role(value: &str) -> Result<ParticipantRole, StateMachineError> {
    match value {
        "admin" => Ok(ParticipantRole::Admin),
        "member" => Ok(ParticipantRole::Member),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

fn parse_participant_status(value: &str) -> Result<ParticipantStatus, StateMachineError> {
    match value {
        "pending" => Ok(ParticipantStatus::Pending),
        "active" => Ok(ParticipantStatus::Active),
        _ => Err(StateMachineError::InvalidHydrationAuthority),
    }
}

fn parse_invitation(
    value: &super::transcript::ClosedObjectRef<'_>,
) -> Result<InvitationBinding, StateMachineError> {
    Ok(InvitationBinding {
        transition_id: closed_uuid(value, "invitationTransitionId")?,
        inviter: closed_device(value, "invitedByDid", "invitedByDeviceId")?,
    })
}

fn parse_roster_manifest(
    manifest: &super::transcript::ClosedObjectRef<'_>,
) -> Result<RosterManifestBinding, StateMachineError> {
    let participants = match manifest.get("participants") {
        Some(CanonicalValueRef::Array(values)) => values,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let mut parsed = Vec::with_capacity(participants.len());
    for index in 0..participants.len() {
        let Some(CanonicalValueRef::Object(participant)) = participants.get(index) else {
            return Err(StateMachineError::InvalidHydrationAuthority);
        };
        let invitation = match participant.get("invitationProvenance") {
            None => None,
            Some(CanonicalValueRef::Object(value)) => Some(parse_invitation(&value)?),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        parsed.push(RosterParticipantBinding {
            principal: closed_principal(&participant, "userDid")?,
            status: parse_participant_status(closed_text(&participant, "status")?)?,
            role: parse_participant_role(closed_text(&participant, "role")?)?,
            invitation,
        });
    }
    if parsed.is_empty()
        || parsed
            .windows(2)
            .any(|pair| pair[0].principal >= pair[1].principal)
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let Some(CanonicalValueRef::Object(actor_leaf)) = manifest.get("actorLeaf") else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    if closed_text(&actor_leaf, "leafOrigin")? != "genesis"
        || actor_leaf.get("joinKeyPackageRef").is_some()
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(RosterManifestBinding {
        participants: parsed,
        actor_leaf: closed_device(&actor_leaf, "userDid", "deviceId")?,
    })
}

fn parse_participant_changes(
    value: CanonicalValueRef<'_>,
) -> Result<Vec<ManifestParticipantChange>, StateMachineError> {
    let CanonicalValueRef::Array(values) = value else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    let mut changes = Vec::with_capacity(values.len());
    for index in 0..values.len() {
        let Some(CanonicalValueRef::Object(change)) = values.get(index) else {
            return Err(StateMachineError::InvalidHydrationAuthority);
        };
        let principal = closed_principal(&change, "userDid")?;
        changes.push(match closed_text(&change, "$type")? {
            "blue.catbird.chat.defs#addParticipant" => ManifestParticipantChange::Add(principal),
            "blue.catbird.chat.defs#removeParticipant" => {
                ManifestParticipantChange::Remove(principal)
            }
            "blue.catbird.chat.defs#changeParticipantRole" => {
                ManifestParticipantChange::ChangeRole(
                    principal,
                    parse_participant_role(closed_text(&change, "role")?)?,
                )
            }
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        });
    }
    if changes.is_empty()
        || changes
            .windows(2)
            .any(|pair| manifest_change_principal(&pair[0]) >= manifest_change_principal(&pair[1]))
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(changes)
}

fn manifest_change_principal(change: &ManifestParticipantChange) -> &PrincipalId {
    match change {
        ManifestParticipantChange::Add(value)
        | ManifestParticipantChange::Remove(value)
        | ManifestParticipantChange::ChangeRole(value, _) => value,
    }
}

fn parse_transition_manifest(
    manifest: &super::transcript::ClosedObjectRef<'_>,
) -> Result<TransitionManifestBinding, StateMachineError> {
    let participant_values = match manifest.get("participantChanges") {
        Some(CanonicalValueRef::Array(values)) => values,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let mut participant_changes = Vec::with_capacity(participant_values.len());
    for index in 0..participant_values.len() {
        let Some(CanonicalValueRef::Object(change)) = participant_values.get(index) else {
            return Err(StateMachineError::InvalidHydrationAuthority);
        };
        let principal = closed_principal(&change, "userDid")?;
        participant_changes.push(match closed_text(&change, "$type")? {
            "blue.catbird.chat.defs#addParticipant" => ManifestParticipantChange::Add(principal),
            "blue.catbird.chat.defs#removeParticipant" => {
                ManifestParticipantChange::Remove(principal)
            }
            "blue.catbird.chat.defs#changeParticipantRole" => {
                ManifestParticipantChange::ChangeRole(
                    principal,
                    parse_participant_role(closed_text(&change, "role")?)?,
                )
            }
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        });
    }

    let leaf_values = match manifest.get("leafChanges") {
        Some(CanonicalValueRef::Array(values)) => values,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let mut leaf_changes = Vec::with_capacity(leaf_values.len());
    for index in 0..leaf_values.len() {
        let Some(CanonicalValueRef::Object(change)) = leaf_values.get(index) else {
            return Err(StateMachineError::InvalidHydrationAuthority);
        };
        let device = closed_device(&change, "userDid", "deviceId")?;
        leaf_changes.push(match closed_text(&change, "$type")? {
            "blue.catbird.chat.defs#addLeafByRecovery" => ManifestLeafChange::Add {
                device,
                recovery_request_id: closed_uuid(&change, "recoveryRequestId")?,
                key_package_ref: closed_fixed_bytes(&change, "keyPackageRef")?,
            },
            "blue.catbird.chat.defs#removeLeaf" => ManifestLeafChange::Remove(device),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        });
    }

    let leaf_recovery_request_id = match manifest.get("leafRecoveryRequestId") {
        None => None,
        Some(CanonicalValueRef::Uuid(value)) => Some(*value.as_bytes()),
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let welcome = match manifest.get("welcomeBundle") {
        None => None,
        Some(CanonicalValueRef::Object(bundle)) => {
            let opaque_welcome = match bundle.get("opaqueWelcome") {
                Some(CanonicalValueRef::Bytes(value)) => value.to_vec(),
                _ => return Err(StateMachineError::InvalidHydrationAuthority),
            };
            let sha256 = closed_fixed_bytes(&bundle, "sha256")?;
            if <[u8; 32]>::from(Sha256::digest(&opaque_welcome)) != sha256 {
                return Err(StateMachineError::InvalidHydrationAuthority);
            }
            let deliveries = match bundle.get("deliveries") {
                Some(CanonicalValueRef::Array(values)) if values.len() == 1 => values,
                _ => return Err(StateMachineError::InvalidHydrationAuthority),
            };
            let Some(CanonicalValueRef::Object(delivery)) = deliveries.get(0) else {
                return Err(StateMachineError::InvalidHydrationAuthority);
            };
            let Some(CanonicalValueRef::Object(provenance)) = delivery.get("provenance") else {
                return Err(StateMachineError::InvalidHydrationAuthority);
            };
            Some(ManifestWelcomeBinding {
                welcome_id: closed_uuid(&bundle, "welcomeId")?,
                opaque_welcome,
                sha256,
                recipient: closed_device(&delivery, "recipientDid", "recipientDeviceId")?,
                recovery_request_id: closed_uuid(&provenance, "recoveryRequestId")?,
                key_package_ref: closed_fixed_bytes(&provenance, "keyPackageRef")?,
            })
        }
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    Ok(TransitionManifestBinding {
        participant_changes,
        leaf_changes,
        leaf_recovery_request_id,
        welcome,
    })
}

fn closed_coordinate_conversation_id(
    body: super::transcript::ClosedObjectRef<'_>,
    coordinate_field: &str,
) -> Result<[u8; 16], StateMachineError> {
    let Some(CanonicalValueRef::Object(coordinates)) = body.get(coordinate_field) else {
        return Err(StateMachineError::InvalidHydrationAuthority);
    };
    closed_uuid(&coordinates, "conversationId")
}

fn durable_signed_request_row_digest(
    kind: RequestEntryKind,
    envelope: &DurableSignedRequestEnvelope,
    request_id: &[u8; 16],
    mutation: &VerifiedSignedMutation,
) -> Result<[u8; 32], StateMachineError> {
    let signed_request = mutation
        .accepted_wrapper_bytes()
        .filter(|bytes| !bytes.is_empty())
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-DURABLE-SIGNED-ROW\0");
    digest.update([kind as u8]);
    digest.update(envelope.conversation_id);
    digest.update(request_id);
    digest.update(envelope.received_at.unix_millis().to_be_bytes());
    digest.update(mutation.request_digest());
    digest.update(mutation.signature());
    digest.update((signed_request.len() as u64).to_be_bytes());
    digest.update(signed_request);
    Ok(digest.finalize().into())
}

fn device_revocation_row_digest(evidence: &DeviceRevocationEvidence) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-DURABLE-DEVICE-REVOCATION\0");
    digest.update(evidence.revocation_id);
    digest.update((evidence.actor.principal().as_bytes().len() as u64).to_be_bytes());
    digest.update(evidence.actor.principal().as_bytes());
    digest.update(evidence.actor.device_id());
    digest.update(evidence.target.device_id());
    digest.update(evidence.actor_key_id);
    digest.update(evidence.actor_auth_generation.to_be_bytes());
    digest.update(evidence.expected_target_auth_generation.to_be_bytes());
    digest.update(evidence.signed_at.unix_millis().to_be_bytes());
    digest.update(evidence.accepted_at.unix_millis().to_be_bytes());
    digest.update(evidence.request_digest);
    digest.update(evidence.signature);
    digest.update((evidence.signed_request_bytes.len() as u64).to_be_bytes());
    digest.update(&evidence.signed_request_bytes);
    digest.update((evidence.signing_transcript_bytes.len() as u64).to_be_bytes());
    digest.update(&evidence.signing_transcript_bytes);
    digest.finalize().into()
}

fn validate_device_revocation_evidence(evidence: &DeviceRevocationEvidence) -> bool {
    is_uuid_v4(&evidence.revocation_id)
        && evidence.actor.principal() == evidence.target.principal()
        // Self-revoke (actor device == target device) is a first-class spec
        // operation (CHAT_PROTOCOL.md L56: "Completed first-enroll, self-revoke,
        // and rebind operations have one narrow response-loss path"), and the DB
        // schema accepts it (device_revocations positive fixture, and
        // assert_device_revocation_mapping's actor.revoked_at >= accepted_at
        // tolerance). Same-DID is already required above; both self-revoke and
        // sibling-revoke are permitted. Do NOT reintroduce an actor != target
        // requirement — it makes a single-device user unable to revoke their only
        // device and contradicts the DB authority.
        && evidence.actor_key_id != [0; 32]
        && evidence.actor_auth_generation > 0
        && evidence.actor_auth_generation <= MAX_PROTOCOL_INTEGER
        && evidence.expected_target_auth_generation > 0
        && evidence.expected_target_auth_generation <= MAX_PROTOCOL_INTEGER
        && evidence.signed_at <= evidence.accepted_at
        && evidence.request_digest != [0; 32]
        && evidence.signature != [0; 64]
        && !evidence.signed_request_bytes.is_empty()
        && !evidence.signing_transcript_bytes.is_empty()
        && evidence.durable_row_digest == device_revocation_row_digest(evidence)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PersistedRegistrationStatus {
    Active,
    Revoked,
}

/// Canonically typed device/key registration row supplied by persistence.
/// The constructor accepts only values that already passed the shared exact
/// DID, UUID, and thumbprint grammars and independently checks its stored row
/// digest when authority is sealed.
#[cfg(test)]
pub(crate) struct PersistedRegistrationRow {
    conversation_id: [u8; 16],
    actor: DeviceIdentity,
    key_id: [u8; 32],
    registered_mls_signature_key: [u8; 32],
    auth_generation: u64,
    status: PersistedRegistrationStatus,
    durable_row_digest: [u8; 32],
}

#[cfg(test)]
impl PersistedRegistrationRow {
    pub(crate) fn new(
        conversation_id: [u8; 16],
        actor_did: BareDid,
        device_id: CanonicalUuidV4,
        key_id: KeyThumbprint,
        registered_mls_signature_key: [u8; 32],
        auth_generation: u64,
        status: PersistedRegistrationStatus,
        durable_row_digest: [u8; 32],
    ) -> Result<Self, StateMachineError> {
        let key_id: [u8; 32] = URL_SAFE_NO_PAD
            .decode(key_id.as_str())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        if !is_uuid_v4(&conversation_id)
            || auth_generation == 0
            || auth_generation > MAX_PROTOCOL_INTEGER
            || registered_mls_signature_key == [0; 32]
            || durable_row_digest == [0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            conversation_id,
            actor: DeviceIdentity::new(
                PrincipalId::new(actor_did.as_str().as_bytes().to_vec())?,
                *device_id.as_bytes(),
            )?,
            key_id,
            registered_mls_signature_key,
            auth_generation,
            status,
            durable_row_digest,
        })
    }

    /// Deterministic value persistence stores beside the canonical row.
    pub(crate) fn expected_digest(
        conversation_id: [u8; 16],
        actor: &DeviceIdentity,
        key_id: [u8; 32],
        registered_mls_signature_key: [u8; 32],
        auth_generation: u64,
        status: PersistedRegistrationStatus,
    ) -> [u8; 32] {
        registration_row_digest_fields(
            &conversation_id,
            actor,
            &key_id,
            &registered_mls_signature_key,
            auth_generation,
            status,
        )
    }
}

#[cfg(test)]
fn registration_row_digest(row: &PersistedRegistrationRow) -> [u8; 32] {
    registration_row_digest_fields(
        &row.conversation_id,
        &row.actor,
        &row.key_id,
        &row.registered_mls_signature_key,
        row.auth_generation,
        row.status,
    )
}

#[cfg(test)]
fn registration_row_digest_fields(
    conversation_id: &[u8; 16],
    actor: &DeviceIdentity,
    key_id: &[u8; 32],
    registered_mls_signature_key: &[u8; 32],
    auth_generation: u64,
    status: PersistedRegistrationStatus,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-DURABLE-REGISTRATION-ROW\0");
    digest.update(conversation_id);
    digest.update((actor.principal().as_bytes().len() as u64).to_be_bytes());
    digest.update(actor.principal().as_bytes());
    digest.update(actor.device_id());
    digest.update(key_id);
    digest.update(registered_mls_signature_key);
    digest.update(auth_generation.to_be_bytes());
    digest.update([match status {
        PersistedRegistrationStatus::Active => 1,
        PersistedRegistrationStatus::Revoked => 2,
    }]);
    digest.finalize().into()
}

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
    #[cfg(not(test))]
    transaction_id: String,
}

impl LockedRegistrationProjection {
    fn authorizes(&self, evidence: &RequestEvidence) -> bool {
        self.status == PersistedRegistrationStatus::Active
            && self.conversation_id == evidence.conversation_id
            && self.actor == evidence.actor
            && self.key_id == evidence.key_id
            && self.auth_generation == evidence.auth_generation
            && self.trusted_read_at >= evidence.received_at
            && self.durable_row_digest != [0; 32]
    }

    fn authorizes_transition(&self, evidence: &TransitionEvidence) -> bool {
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

    fn authorizes_revocation(&self, evidence: &DeviceRevocationEvidence) -> bool {
        self.status == PersistedRegistrationStatus::Active
            && self.actor == evidence.actor
            && self.key_id == evidence.actor_key_id
            && self.auth_generation == evidence.actor_auth_generation
            && self.trusted_read_at == evidence.accepted_at
            && self.durable_row_digest != [0; 32]
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

    #[cfg(not(test))]
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(crate) fn conversation_id(&self) -> &[u8; 16] {
        &self.conversation_id
    }

    pub(crate) fn durable_row_digest(&self) -> &[u8; 32] {
        &self.durable_row_digest
    }

    #[cfg(test)]
    pub(crate) fn for_test(evidence: &RequestEvidence) -> Self {
        Self {
            conversation_id: evidence.conversation_id,
            actor: evidence.actor.clone(),
            key_id: evidence.key_id,
            registered_mls_signature_key: [0x71; 32],
            auth_generation: evidence.auth_generation,
            status: PersistedRegistrationStatus::Active,
            trusted_read_at: evidence.received_at,
            durable_row_digest: [0x7a; 32],
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_status(
        evidence: &RequestEvidence,
        status: PersistedRegistrationStatus,
    ) -> Self {
        let mut projection = Self::for_test(evidence);
        projection.status = status;
        projection
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_key(evidence: &RequestEvidence, key_id: [u8; 32]) -> Self {
        let mut projection = Self::for_test(evidence);
        projection.key_id = key_id;
        projection
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_auth_generation(
        evidence: &RequestEvidence,
        auth_generation: u64,
    ) -> Self {
        let mut projection = Self::for_test(evidence);
        projection.auth_generation = auth_generation;
        projection
    }
}

/// Exact available KeyPackage selection read under the same transaction that
/// will reserve it. The row is untrusted until `HydrationAuthority` validates
/// its digest, current registration binding, MLS wire, lifetime, and captured
/// server instant.
#[cfg(test)]
pub(crate) struct PersistedRecoveryReservationSelectionRow {
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
    conversation_id: [u8; 16],
    request_id: [u8; 16],
    target: DeviceIdentity,
    target_key_id: [u8; 32],
    target_auth_generation: u64,
    bound_coordinate: PublicGroupSnapshotCoordinate,
    key_package_ref: [u8; 32],
    key_package_wrapper: Vec<u8>,
    key_package_wrapper_sha256: [u8; 32],
    package_not_after: ServerTimestamp,
    claimed_at: ServerTimestamp,
    durable_row_digest: [u8; 32],
    #[cfg(not(test))]
    transaction_id: String,
}

impl LockedRecoveryReservationProjection {
    fn authorizes_acceptance(&self, transition: &TransitionEvidence) -> bool {
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

    fn authorizes_request(&self, evidence: &RequestEvidence, kind: LeafRecoveryKind) -> bool {
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

    #[cfg(not(test))]
    fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    #[cfg(not(test))]
    fn available_package_cas(&self) -> RecoveryPackageCasBinding {
        RecoveryPackageCasBinding {
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
        }
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
        }
    }
}

#[cfg(not(test))]
fn reserved_package_cas_for_request(
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
    Ok(RecoveryPackageCasBinding {
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
    })
}

#[cfg(test)]
fn recovery_reservation_selection_digest(
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
fn recovery_reservation_selection_digest_fields(
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
fn coordinate_digest(coordinate: &PublicGroupSnapshotCoordinate) -> [u8; 32] {
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
fn uuid_from_test_byte(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x40 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum WorkTerminalEvidence {
    Transition(TransitionEvidence),
    Request(RequestEvidence),
    DeviceRevocation(DeviceRevocationEvidence),
    Expiry(ServerTimestamp),
}

fn validate_request_evidence(
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

fn durable_signed_request_evidence_digest(evidence: &RequestEvidence) -> [u8; 32] {
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

fn durable_control_transition_row_digest(
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

fn durable_control_request_row_digest(
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
fn durable_control_row_digest(
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

fn require_request_prior(
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

fn require_leaf_recovery_request_binding(
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

fn require_request_coordinate_binding(
    evidence: &RequestEvidence,
    expected_conversation_id: &[u8; 16],
) -> Result<(), StateMachineError> {
    if evidence.body_binding.as_ref().is_some_and(|binding| {
        matches!(binding, RequestBodyBinding::LeaveCancellation { conversation_id }
            if conversation_id != expected_conversation_id)
    }) {
        return Err(StateMachineError::StaleCoordinates);
    }
    Ok(())
}

fn request_entry_signed_kind(kind: RequestEntryKind) -> SignedMutationKind {
    match kind {
        RequestEntryKind::LeafRecoveryRequest => SignedMutationKind::LeafRecoveryRequest,
        RequestEntryKind::LeafRecoveryCancellation => SignedMutationKind::LeafRecoveryCancellation,
        RequestEntryKind::ResetRequest => SignedMutationKind::ResetRequest,
        RequestEntryKind::LeaveRequest => SignedMutationKind::LeaveRequest,
        RequestEntryKind::LeaveCancellation => SignedMutationKind::LeaveCancellation,
        RequestEntryKind::WelcomeAcknowledgement => SignedMutationKind::WelcomeAcknowledgement,
        RequestEntryKind::WelcomeRejection => SignedMutationKind::WelcomeRejection,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccessIntervalEnd {
    evidence: TransitionEvidence,
    kind: CloseKind,
}

impl AccessIntervalEnd {
    pub(crate) fn seq(&self) -> u64 {
        self.evidence.seq
    }

    pub(crate) fn kind(&self) -> CloseKind {
        self.kind
    }

    pub(crate) fn transition_id(&self) -> &[u8; 16] {
        &self.evidence.transition_id
    }

    pub(crate) fn outer_entry_fingerprint(&self) -> &[u8; 32] {
        &self.evidence.outer_entry_fingerprint
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccessInterval {
    recipient: DeviceIdentity,
    generation: u64,
    opening: TransitionEvidence,
    opening_kind: OpeningKind,
    opening_context: PublicGroupSnapshotCoordinate,
    end: Option<AccessIntervalEnd>,
}

impl AccessInterval {
    pub(crate) fn recipient(&self) -> &DeviceIdentity {
        &self.recipient
    }

    pub(crate) fn opening_seq(&self) -> u64 {
        self.opening.seq
    }

    pub(crate) fn opening_kind(&self) -> OpeningKind {
        self.opening_kind
    }

    pub(crate) fn opening_transition_id(&self) -> &[u8; 16] {
        &self.opening.transition_id
    }

    pub(crate) fn opening_outer_entry_fingerprint(&self) -> &[u8; 32] {
        &self.opening.outer_entry_fingerprint
    }

    pub(crate) fn opening_context(&self) -> &PublicGroupSnapshotCoordinate {
        &self.opening_context
    }

    pub(crate) fn end(&self) -> Option<&AccessIntervalEnd> {
        self.end.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScheduleTerminalProof {
    recipient: DeviceIdentity,
    conversation_id: [u8; 16],
    evidence: TransitionEvidence,
}

impl ScheduleTerminalProof {
    pub(crate) fn recipient(&self) -> &DeviceIdentity {
        &self.recipient
    }

    pub(crate) fn seq(&self) -> u64 {
        self.evidence.seq
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeafRecoveryKind {
    Add,
    Replace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoverySource {
    Request,
    Acceptance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryRequestStatus {
    Open,
    Fulfilled,
    Cancelled,
    Expired,
    Superseded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReservationStatus {
    Active,
    Consumed,
    Expired,
    Released,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RecoveryOriginEvidence {
    Acceptance(TransitionEvidence),
    Request(RequestEvidence),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResetRequestStatus {
    Pending,
    Stale,
    Consumed,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaveRequestStatus {
    Pending,
    Fulfilled,
    Cancelled,
    Expired,
    Stale,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WelcomeStatus {
    Pending,
    Acknowledged,
    Rejected,
    Expired,
    Superseded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryRequest {
    request_id: [u8; 16],
    target: DeviceIdentity,
    kind: LeafRecoveryKind,
    source: RecoverySource,
    bound_coordinate: PublicGroupSnapshotCoordinate,
    key_package_ref: [u8; 32],
    received_at: ServerTimestamp,
    expires_at: ServerTimestamp,
    status: RecoveryRequestStatus,
    origin: RecoveryOriginEvidence,
    terminal: Option<WorkTerminalEvidence>,
}

impl RecoveryRequest {
    pub(crate) fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    pub(crate) fn target(&self) -> &DeviceIdentity {
        &self.target
    }

    pub(crate) fn kind(&self) -> LeafRecoveryKind {
        self.kind
    }

    pub(crate) fn source(&self) -> RecoverySource {
        self.source
    }

    pub(crate) fn bound_coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.bound_coordinate
    }

    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }

    pub(crate) fn received_at(&self) -> &ServerTimestamp {
        &self.received_at
    }

    pub(crate) fn expires_at(&self) -> &ServerTimestamp {
        &self.expires_at
    }

    pub(crate) fn status(&self) -> RecoveryRequestStatus {
        self.status
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryReservation {
    request_id: [u8; 16],
    target: DeviceIdentity,
    bound_coordinate: PublicGroupSnapshotCoordinate,
    key_package_ref: [u8; 32],
    received_at: ServerTimestamp,
    expires_at: ServerTimestamp,
    package_not_after: ServerTimestamp,
    status: ReservationStatus,
    terminal: Option<WorkTerminalEvidence>,
}

impl RecoveryReservation {
    pub(crate) fn status(&self) -> ReservationStatus {
        self.status
    }

    pub(crate) fn expires_at(&self) -> &ServerTimestamp {
        &self.expires_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResetRequest {
    request_id: [u8; 16],
    requester: DeviceIdentity,
    bound_coordinate: PublicGroupSnapshotCoordinate,
    received_at: ServerTimestamp,
    expires_at: ServerTimestamp,
    status: ResetRequestStatus,
    origin: RequestEvidence,
    terminal: Option<WorkTerminalEvidence>,
}

impl ResetRequest {
    pub(crate) fn status(&self) -> ResetRequestStatus {
        self.status
    }

    pub(crate) fn expires_at(&self) -> &ServerTimestamp {
        &self.expires_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeaveRequest {
    request_id: [u8; 16],
    requester: DeviceIdentity,
    bound_coordinate: PublicGroupSnapshotCoordinate,
    received_at: ServerTimestamp,
    expires_at: ServerTimestamp,
    status: LeaveRequestStatus,
    origin: RequestEvidence,
    terminal: Option<WorkTerminalEvidence>,
}

impl LeaveRequest {
    pub(crate) fn requester(&self) -> &DeviceIdentity {
        &self.requester
    }

    pub(crate) fn status(&self) -> LeaveRequestStatus {
        self.status
    }

    pub(crate) fn expires_at(&self) -> &ServerTimestamp {
        &self.expires_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WelcomeWork {
    welcome_id: [u8; 16],
    recipient: DeviceIdentity,
    transition_seq: u64,
    coordinate: PublicGroupSnapshotCoordinate,
    recovery_request_id: [u8; 16],
    key_package_ref: [u8; 32],
    opaque_welcome: Vec<u8>,
    sha256: [u8; 32],
    expires_at: ServerTimestamp,
    status: WelcomeStatus,
    terminal: Option<WorkTerminalEvidence>,
}

impl WelcomeWork {
    pub(crate) fn welcome_id(&self) -> &[u8; 16] {
        &self.welcome_id
    }
    pub(crate) fn recipient(&self) -> &DeviceIdentity {
        &self.recipient
    }
    pub(crate) fn transition_seq(&self) -> u64 {
        self.transition_seq
    }
    pub(crate) fn status(&self) -> WelcomeStatus {
        self.status
    }

    pub(crate) fn coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.coordinate
    }

    pub(crate) fn expires_at(&self) -> ServerTimestamp {
        self.expires_at
    }

    pub(crate) fn recovery_request_id(&self) -> &[u8; 16] {
        &self.recovery_request_id
    }
    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }
    pub(crate) fn opaque_welcome(&self) -> &[u8] {
        &self.opaque_welcome
    }
    pub(crate) fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConversationState {
    kind: ConversationKind,
    coordinate: PublicGroupSnapshotCoordinate,
    producer: TransitionEvidence,
    public_state: Option<ActivePublicState>,
    metadata: Option<MetadataSnapshotBinding>,
    /// Exact signed transition whose body contains the retained metadata
    /// snapshot. This remains stable across coordinate-only transitions.
    metadata_producer: Option<TransitionEvidence>,
    participants: Vec<ParticipantRecord>,
    leaves: Vec<LeafRecord>,
    intervals: Vec<AccessInterval>,
    terminal_proofs: Vec<ScheduleTerminalProof>,
    recovery_requests: Vec<RecoveryRequest>,
    recovery_reservations: Vec<RecoveryReservation>,
    reset_requests: Vec<ResetRequest>,
    leave_requests: Vec<LeaveRequest>,
    welcomes: Vec<WelcomeWork>,
}

/// Adapter-facing durable graph. Every authority-bearing field is already a
/// sealed projection issued by `HydrationAuthority`; raw signature material
/// cannot be inserted into this graph in production.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct ConversationStateHydration {
    pub(crate) kind: ConversationKind,
    pub(crate) coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) producer: TransitionEvidence,
    pub(crate) public_state: Option<ActivePublicState>,
    pub(crate) metadata: Option<MetadataSnapshotBinding>,
    pub(crate) metadata_producer: Option<TransitionEvidence>,
    pub(crate) participants: Vec<ParticipantHydrationRow>,
    pub(crate) leaves: Vec<LeafHydrationRow>,
    pub(crate) intervals: Vec<IntervalHydrationRow>,
    pub(crate) terminal_proofs: Vec<TerminalProofHydrationRow>,
    pub(crate) recovery_requests: Vec<RecoveryRequestHydrationRow>,
    pub(crate) recovery_reservations: Vec<RecoveryReservationHydrationRow>,
    pub(crate) reset_requests: Vec<ResetRequestHydrationRow>,
    pub(crate) leave_requests: Vec<LeaveRequestHydrationRow>,
    pub(crate) welcomes: Vec<WelcomeHydrationRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvitationHydrationRow {
    pub(crate) transition: TransitionEvidence,
    pub(crate) inviter: DeviceIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParticipantHydrationRow {
    pub(crate) principal: PrincipalId,
    pub(crate) status: ParticipantStatus,
    pub(crate) role: ParticipantRole,
    pub(crate) role_producer: Option<TransitionEvidence>,
    pub(crate) invitation: Option<InvitationHydrationRow>,
    pub(crate) acceptance: Option<TransitionEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeafHydrationRow {
    pub(crate) device: DeviceIdentity,
    pub(crate) leaf_index: u32,
    pub(crate) basic_credential: Vec<u8>,
    pub(crate) signature_key: Vec<u8>,
    pub(crate) encryption_key: Vec<u8>,
    pub(crate) key_package_ref: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IntervalEndHydrationRow {
    pub(crate) evidence: TransitionEvidence,
    pub(crate) kind: CloseKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IntervalHydrationRow {
    pub(crate) recipient: DeviceIdentity,
    pub(crate) generation: u64,
    pub(crate) opening: TransitionEvidence,
    pub(crate) opening_kind: OpeningKind,
    pub(crate) opening_context: PublicGroupSnapshotCoordinate,
    pub(crate) end: Option<IntervalEndHydrationRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TerminalProofHydrationRow {
    pub(crate) recipient: DeviceIdentity,
    pub(crate) conversation_id: [u8; 16],
    pub(crate) evidence: TransitionEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WorkTerminalHydrationRow {
    Transition(TransitionEvidence),
    Request(RequestEvidence),
    DeviceRevocation(DeviceRevocationEvidence),
    Expiry(ServerTimestamp),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryOriginHydrationRow {
    Acceptance(TransitionEvidence),
    Request(RequestEvidence),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryRequestHydrationRow {
    pub(crate) request_id: [u8; 16],
    pub(crate) target: DeviceIdentity,
    pub(crate) kind: LeafRecoveryKind,
    pub(crate) source: RecoverySource,
    pub(crate) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) key_package_ref: [u8; 32],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) expires_at: ServerTimestamp,
    pub(crate) status: RecoveryRequestStatus,
    pub(crate) origin: RecoveryOriginHydrationRow,
    pub(crate) terminal: Option<WorkTerminalHydrationRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryReservationHydrationRow {
    pub(crate) request_id: [u8; 16],
    pub(crate) target: DeviceIdentity,
    pub(crate) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) key_package_ref: [u8; 32],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) expires_at: ServerTimestamp,
    pub(crate) package_not_after: ServerTimestamp,
    pub(crate) status: ReservationStatus,
    pub(crate) terminal: Option<WorkTerminalHydrationRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResetRequestHydrationRow {
    pub(crate) request_id: [u8; 16],
    pub(crate) requester: DeviceIdentity,
    pub(crate) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) received_at: ServerTimestamp,
    pub(crate) expires_at: ServerTimestamp,
    pub(crate) status: ResetRequestStatus,
    pub(crate) origin: RequestEvidence,
    pub(crate) terminal: Option<WorkTerminalHydrationRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeaveRequestHydrationRow {
    pub(crate) request_id: [u8; 16],
    pub(crate) requester: DeviceIdentity,
    pub(crate) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) received_at: ServerTimestamp,
    pub(crate) expires_at: ServerTimestamp,
    pub(crate) status: LeaveRequestStatus,
    pub(crate) origin: RequestEvidence,
    pub(crate) terminal: Option<WorkTerminalHydrationRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WelcomeHydrationRow {
    pub(crate) welcome_id: [u8; 16],
    pub(crate) recipient: DeviceIdentity,
    pub(crate) transition_seq: u64,
    pub(crate) coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) recovery_request_id: [u8; 16],
    pub(crate) key_package_ref: [u8; 32],
    pub(crate) opaque_welcome: Vec<u8>,
    pub(crate) sha256: [u8; 32],
    pub(crate) expires_at: ServerTimestamp,
    pub(crate) status: WelcomeStatus,
    pub(crate) terminal: Option<WorkTerminalHydrationRow>,
}

impl ConversationState {
    pub(crate) fn kind(&self) -> ConversationKind {
        self.kind
    }

    pub(crate) fn coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.coordinate
    }

    pub(crate) fn active_public_state(&self) -> Option<&ActivePublicState> {
        self.public_state.as_ref()
    }

    pub(crate) fn metadata(&self) -> Option<&MetadataSnapshotBinding> {
        self.metadata.as_ref()
    }

    pub(crate) fn public_state(&self) -> &ActivePublicState {
        self.public_state
            .as_ref()
            .expect("active state-machine operation requires public state")
    }

    pub(crate) fn participants(&self) -> &[ParticipantRecord] {
        &self.participants
    }

    pub(crate) fn participant(&self, principal: &PrincipalId) -> Option<&ParticipantRecord> {
        self.participants
            .binary_search_by(|candidate| candidate.principal.cmp(principal))
            .ok()
            .map(|index| &self.participants[index])
    }

    pub(crate) fn leaves(&self) -> &[LeafRecord] {
        &self.leaves
    }

    pub(crate) fn leaf(&self, device: &DeviceIdentity) -> Option<&LeafRecord> {
        self.leaves.iter().find(|leaf| &leaf.device == device)
    }

    pub(crate) fn intervals(&self) -> &[AccessInterval] {
        &self.intervals
    }

    pub(crate) fn intervals_for(&self, device: &DeviceIdentity) -> Vec<&AccessInterval> {
        self.intervals
            .iter()
            .filter(|interval| &interval.recipient == device)
            .collect()
    }

    pub(crate) fn terminal_proofs(&self) -> &[ScheduleTerminalProof] {
        &self.terminal_proofs
    }

    pub(crate) fn terminal_proof(&self, device: &DeviceIdentity) -> Option<&ScheduleTerminalProof> {
        self.terminal_proofs
            .iter()
            .find(|proof| &proof.recipient == device)
    }

    pub(crate) fn recovery_request(&self, request_id: &[u8; 16]) -> Option<&RecoveryRequest> {
        self.recovery_requests
            .iter()
            .find(|request| request.request_id == *request_id)
    }

    pub(crate) fn recovery_reservation(
        &self,
        request_id: &[u8; 16],
    ) -> Option<&RecoveryReservation> {
        self.recovery_reservations
            .iter()
            .find(|reservation| reservation.request_id == *request_id)
    }

    pub(crate) fn reset_request(&self, request_id: &[u8; 16]) -> Option<&ResetRequest> {
        self.reset_requests
            .iter()
            .find(|request| request.request_id == *request_id)
    }

    pub(crate) fn leave_request(&self, request_id: &[u8; 16]) -> Option<&LeaveRequest> {
        self.leave_requests
            .iter()
            .find(|request| request.request_id == *request_id)
    }

    pub(crate) fn welcome(&self, welcome_id: &[u8; 16]) -> Option<&WelcomeWork> {
        self.welcomes
            .iter()
            .find(|welcome| welcome.welcome_id == *welcome_id)
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_state_version(
        &self,
        state_version: u64,
    ) -> Result<Self, StateMachineError> {
        let mut state = self.clone();
        let next = PublicGroupSnapshotCoordinate::new(
            *self.coordinate.conversation_id(),
            self.coordinate.generation(),
            state_version,
            *self.coordinate.group_id(),
            self.coordinate.epoch(),
            *self.coordinate.group_context_hash(),
            *self.coordinate.confirmation_tag(),
            PublicGroupSnapshotLifecycle::Active,
        );
        let template = self
            .public_state
            .as_ref()
            .ok_or(StateMachineError::ConversationClosed)?;
        state.public_state = Some(ActivePublicState::for_test(template, next));
        state.coordinate = next;
        Ok(state)
    }

    #[cfg(test)]
    pub(crate) fn for_test_close_leaf_interval(
        &self,
        device: &DeviceIdentity,
        evidence: TransitionEvidence,
        kind: CloseKind,
    ) -> Result<Self, StateMachineError> {
        let mut state = self.clone();
        close_open_interval(&mut state.intervals, device, &evidence, kind)?;
        state.leaves.retain(|leaf| &leaf.device != device);
        Ok(state)
    }

    #[cfg(test)]
    pub(crate) fn for_test_reverse_intervals(&self) -> Self {
        let mut state = self.clone();
        state.intervals.reverse();
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_first_interval_conversation(
        &self,
        conversation_id: [u8; 16],
    ) -> Self {
        let mut state = self.clone();
        let interval = state.intervals.first_mut().expect("test interval");
        let context = interval.opening_context;
        interval.opening_context = PublicGroupSnapshotCoordinate::new(
            conversation_id,
            context.generation(),
            context.state_version(),
            *context.group_id(),
            context.epoch(),
            *context.group_context_hash(),
            *context.confirmation_tag(),
            context.lifecycle(),
        );
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_touch_interval(
        &self,
        device: &DeviceIdentity,
        closing: TransitionEvidence,
        opening: TransitionEvidence,
        close_kind: CloseKind,
        opening_kind: OpeningKind,
    ) -> Result<Self, StateMachineError> {
        let mut state = self.clone();
        close_open_interval(&mut state.intervals, device, &closing, close_kind)?;
        open_interval(
            &mut state.intervals,
            device.clone(),
            opening,
            opening_kind,
            state.coordinate,
        )?;
        sort_intervals(&mut state.intervals);
        Ok(state)
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_touching_opening_transition_id(
        &self,
        device: &DeviceIdentity,
    ) -> Self {
        let mut state = self.clone();
        let interval = state
            .intervals
            .iter_mut()
            .filter(|interval| &interval.recipient == device)
            .max_by_key(|interval| interval.opening.seq)
            .expect("test interval");
        interval.opening.transition_id[0] ^= 0x01;
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_touching_opening_fingerprint(
        &self,
        device: &DeviceIdentity,
    ) -> Self {
        let mut state = self.clone();
        let interval = state
            .intervals
            .iter_mut()
            .filter(|interval| &interval.recipient == device)
            .max_by_key(|interval| interval.opening.seq)
            .expect("test interval");
        interval.opening.outer_entry_fingerprint[0] ^= 0x01;
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_touching_opening_received_at(
        &self,
        device: &DeviceIdentity,
    ) -> Self {
        let mut state = self.clone();
        let interval = state
            .intervals
            .iter_mut()
            .filter(|interval| &interval.recipient == device)
            .max_by_key(|interval| interval.opening.seq)
            .expect("test interval");
        interval.opening.received_at = interval
            .opening
            .received_at
            .checked_add_millis(1)
            .expect("test timestamp");
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_touching_close_kind(&self, device: &DeviceIdentity) -> Self {
        let mut state = self.clone();
        let interval = state
            .intervals
            .iter_mut()
            .filter(|interval| &interval.recipient == device)
            .min_by_key(|interval| interval.opening.seq)
            .expect("test interval");
        interval.end.as_mut().expect("test interval end").kind = CloseKind::Remove;
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_duplicate_terminal_proof(&self) -> Self {
        let mut state = self.clone();
        let proof = state.terminal_proofs.first().expect("test proof").clone();
        state.terminal_proofs.push(proof);
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_first_terminal_proof_conversation(
        &self,
        conversation_id: [u8; 16],
    ) -> Self {
        let mut state = self.clone();
        state
            .terminal_proofs
            .first_mut()
            .expect("test proof")
            .conversation_id = conversation_id;
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_first_terminal_proof_fingerprint(&self) -> Self {
        let mut state = self.clone();
        state
            .terminal_proofs
            .first_mut()
            .expect("test proof")
            .evidence
            .outer_entry_fingerprint[0] ^= 0x01;
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_drop_first_recovery_reservation(&self) -> Self {
        let mut state = self.clone();
        state.recovery_reservations.remove(0);
        state
    }
}

/// The sole state re-entry gate for rows reconstructed from durable storage.
/// Persistence adapters must first re-verify every retained evidence object,
/// then submit the assembled state here before exposing it to a planner.
pub(crate) fn hydrate_conversation_state(
    authority: &HydrationAuthority,
    rows: ConversationStateHydration,
) -> Result<ConversationState, StateMachineError> {
    if rows.coordinate.conversation_id() != &authority.expected_conversation_id {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let candidate = ConversationState {
        kind: rows.kind,
        coordinate: rows.coordinate,
        producer: rows.producer,
        public_state: rows.public_state,
        metadata: rows.metadata,
        metadata_producer: rows.metadata_producer,
        participants: rows
            .participants
            .into_iter()
            .map(|row| ParticipantRecord {
                principal: row.principal,
                status: row.status,
                role: row.role,
                role_producer: row.role_producer,
                invitation: row.invitation.map(|invitation| InvitationProvenance {
                    transition: invitation.transition,
                    inviter: invitation.inviter,
                }),
                acceptance: row.acceptance,
            })
            .collect(),
        leaves: rows
            .leaves
            .into_iter()
            .map(|row| LeafRecord {
                device: row.device,
                leaf_index: row.leaf_index,
                basic_credential: row.basic_credential,
                signature_key: row.signature_key,
                encryption_key: row.encryption_key,
                key_package_ref: row.key_package_ref,
            })
            .collect(),
        intervals: rows
            .intervals
            .into_iter()
            .map(|row| AccessInterval {
                recipient: row.recipient,
                generation: row.generation,
                opening: row.opening,
                opening_kind: row.opening_kind,
                opening_context: row.opening_context,
                end: row.end.map(|end| AccessIntervalEnd {
                    evidence: end.evidence,
                    kind: end.kind,
                }),
            })
            .collect(),
        terminal_proofs: rows
            .terminal_proofs
            .into_iter()
            .map(|row| ScheduleTerminalProof {
                recipient: row.recipient,
                conversation_id: row.conversation_id,
                evidence: row.evidence,
            })
            .collect(),
        recovery_requests: rows
            .recovery_requests
            .into_iter()
            .map(|row| RecoveryRequest {
                request_id: row.request_id,
                target: row.target,
                kind: row.kind,
                source: row.source,
                bound_coordinate: row.bound_coordinate,
                key_package_ref: row.key_package_ref,
                received_at: row.received_at,
                expires_at: row.expires_at,
                status: row.status,
                origin: match row.origin {
                    RecoveryOriginHydrationRow::Acceptance(value) => {
                        RecoveryOriginEvidence::Acceptance(value)
                    }
                    RecoveryOriginHydrationRow::Request(value) => {
                        RecoveryOriginEvidence::Request(value)
                    }
                },
                terminal: row.terminal.map(work_terminal_from_hydration),
            })
            .collect(),
        recovery_reservations: rows
            .recovery_reservations
            .into_iter()
            .map(|row| RecoveryReservation {
                request_id: row.request_id,
                target: row.target,
                bound_coordinate: row.bound_coordinate,
                key_package_ref: row.key_package_ref,
                received_at: row.received_at,
                expires_at: row.expires_at,
                package_not_after: row.package_not_after,
                status: row.status,
                terminal: row.terminal.map(work_terminal_from_hydration),
            })
            .collect(),
        reset_requests: rows
            .reset_requests
            .into_iter()
            .map(|row| ResetRequest {
                request_id: row.request_id,
                requester: row.requester,
                bound_coordinate: row.bound_coordinate,
                received_at: row.received_at,
                expires_at: row.expires_at,
                status: row.status,
                origin: row.origin,
                terminal: row.terminal.map(work_terminal_from_hydration),
            })
            .collect(),
        leave_requests: rows
            .leave_requests
            .into_iter()
            .map(|row| LeaveRequest {
                request_id: row.request_id,
                requester: row.requester,
                bound_coordinate: row.bound_coordinate,
                received_at: row.received_at,
                expires_at: row.expires_at,
                status: row.status,
                origin: row.origin,
                terminal: row.terminal.map(work_terminal_from_hydration),
            })
            .collect(),
        welcomes: rows
            .welcomes
            .into_iter()
            .map(|row| WelcomeWork {
                welcome_id: row.welcome_id,
                recipient: row.recipient,
                transition_seq: row.transition_seq,
                coordinate: row.coordinate,
                recovery_request_id: row.recovery_request_id,
                key_package_ref: row.key_package_ref,
                opaque_welcome: row.opaque_welcome,
                sha256: row.sha256,
                expires_at: row.expires_at,
                status: row.status,
                terminal: row.terminal.map(work_terminal_from_hydration),
            })
            .collect(),
    };
    match candidate.coordinate.lifecycle() {
        PublicGroupSnapshotLifecycle::Active => validate_state(&candidate)?,
        PublicGroupSnapshotLifecycle::Superseded => validate_terminal_state(&candidate)?,
    }
    Ok(candidate)
}

fn work_terminal_from_hydration(row: WorkTerminalHydrationRow) -> WorkTerminalEvidence {
    match row {
        WorkTerminalHydrationRow::Transition(value) => WorkTerminalEvidence::Transition(value),
        WorkTerminalHydrationRow::Request(value) => WorkTerminalEvidence::Request(value),
        WorkTerminalHydrationRow::DeviceRevocation(value) => {
            WorkTerminalEvidence::DeviceRevocation(value)
        }
        WorkTerminalHydrationRow::Expiry(value) => WorkTerminalEvidence::Expiry(value),
    }
}

impl ConversationStateHydration {
    /// Lossless sealed projection used by persistence adapters. Retained
    /// transition/request/revocation evidence is carried verbatim; no row can
    /// be reconstructed from display views or independently selected IDs.
    fn from_state(state: ConversationState) -> Self {
        Self {
            kind: state.kind,
            coordinate: state.coordinate,
            producer: state.producer,
            public_state: state.public_state,
            metadata: state.metadata,
            metadata_producer: state.metadata_producer,
            participants: state
                .participants
                .into_iter()
                .map(|row| ParticipantHydrationRow {
                    principal: row.principal,
                    status: row.status,
                    role: row.role,
                    role_producer: row.role_producer,
                    invitation: row.invitation.map(|invitation| InvitationHydrationRow {
                        transition: invitation.transition,
                        inviter: invitation.inviter,
                    }),
                    acceptance: row.acceptance,
                })
                .collect(),
            leaves: state
                .leaves
                .into_iter()
                .map(|row| LeafHydrationRow {
                    device: row.device,
                    leaf_index: row.leaf_index,
                    basic_credential: row.basic_credential,
                    signature_key: row.signature_key,
                    encryption_key: row.encryption_key,
                    key_package_ref: row.key_package_ref,
                })
                .collect(),
            intervals: state
                .intervals
                .into_iter()
                .map(|row| IntervalHydrationRow {
                    recipient: row.recipient,
                    generation: row.generation,
                    opening: row.opening,
                    opening_kind: row.opening_kind,
                    opening_context: row.opening_context,
                    end: row.end.map(|end| IntervalEndHydrationRow {
                        evidence: end.evidence,
                        kind: end.kind,
                    }),
                })
                .collect(),
            terminal_proofs: state
                .terminal_proofs
                .into_iter()
                .map(|row| TerminalProofHydrationRow {
                    recipient: row.recipient,
                    conversation_id: row.conversation_id,
                    evidence: row.evidence,
                })
                .collect(),
            recovery_requests: state
                .recovery_requests
                .into_iter()
                .map(|row| RecoveryRequestHydrationRow {
                    request_id: row.request_id,
                    target: row.target,
                    kind: row.kind,
                    source: row.source,
                    bound_coordinate: row.bound_coordinate,
                    key_package_ref: row.key_package_ref,
                    received_at: row.received_at,
                    expires_at: row.expires_at,
                    status: row.status,
                    origin: match row.origin {
                        RecoveryOriginEvidence::Acceptance(value) => {
                            RecoveryOriginHydrationRow::Acceptance(value)
                        }
                        RecoveryOriginEvidence::Request(value) => {
                            RecoveryOriginHydrationRow::Request(value)
                        }
                    },
                    terminal: row.terminal.map(work_terminal_to_hydration),
                })
                .collect(),
            recovery_reservations: state
                .recovery_reservations
                .into_iter()
                .map(|row| RecoveryReservationHydrationRow {
                    request_id: row.request_id,
                    target: row.target,
                    bound_coordinate: row.bound_coordinate,
                    key_package_ref: row.key_package_ref,
                    received_at: row.received_at,
                    expires_at: row.expires_at,
                    package_not_after: row.package_not_after,
                    status: row.status,
                    terminal: row.terminal.map(work_terminal_to_hydration),
                })
                .collect(),
            reset_requests: state
                .reset_requests
                .into_iter()
                .map(|row| ResetRequestHydrationRow {
                    request_id: row.request_id,
                    requester: row.requester,
                    bound_coordinate: row.bound_coordinate,
                    received_at: row.received_at,
                    expires_at: row.expires_at,
                    status: row.status,
                    origin: row.origin,
                    terminal: row.terminal.map(work_terminal_to_hydration),
                })
                .collect(),
            leave_requests: state
                .leave_requests
                .into_iter()
                .map(|row| LeaveRequestHydrationRow {
                    request_id: row.request_id,
                    requester: row.requester,
                    bound_coordinate: row.bound_coordinate,
                    received_at: row.received_at,
                    expires_at: row.expires_at,
                    status: row.status,
                    origin: row.origin,
                    terminal: row.terminal.map(work_terminal_to_hydration),
                })
                .collect(),
            welcomes: state
                .welcomes
                .into_iter()
                .map(|row| WelcomeHydrationRow {
                    welcome_id: row.welcome_id,
                    recipient: row.recipient,
                    transition_seq: row.transition_seq,
                    coordinate: row.coordinate,
                    recovery_request_id: row.recovery_request_id,
                    key_package_ref: row.key_package_ref,
                    opaque_welcome: row.opaque_welcome,
                    sha256: row.sha256,
                    expires_at: row.expires_at,
                    status: row.status,
                    terminal: row.terminal.map(work_terminal_to_hydration),
                })
                .collect(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_from_state(state: ConversationState) -> Self {
        Self::from_state(state)
    }
}

fn work_terminal_to_hydration(row: WorkTerminalEvidence) -> WorkTerminalHydrationRow {
    match row {
        WorkTerminalEvidence::Transition(value) => WorkTerminalHydrationRow::Transition(value),
        WorkTerminalEvidence::Request(value) => WorkTerminalHydrationRow::Request(value),
        WorkTerminalEvidence::DeviceRevocation(value) => {
            WorkTerminalHydrationRow::DeviceRevocation(value)
        }
        WorkTerminalEvidence::Expiry(value) => WorkTerminalHydrationRow::Expiry(value),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlanKind {
    Creation,
    Policy,
    Acceptance,
    Metadata,
    Commit,
    RecoveryRequest,
    RecoveryCancellation,
    DeviceRevocation,
    ResetRequest,
    ResetActivation,
    LeaveRequest,
    LeaveCancellation,
    ZeroLeafLeave,
    WelcomeAcknowledgement,
    WelcomeRejection,
    WelcomeExpiry,
    Close,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PackageStatus {
    Available,
    Reserved,
    Consumed,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PackageTransition {
    request_id: [u8; 16],
    key_package_ref: [u8; 32],
    from: PackageStatus,
    to: PackageStatus,
}

/// Exact KeyPackage row authority retained for adapter-side compare-and-set.
/// Unlike `PackageTransition`, this is not a semantic summary: it binds the
/// transaction, owner generation, immutable wrapper, lifetime, coordinate,
/// and locked durable-row digest that authorized the status edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryPackageCasBinding {
    transaction_id: String,
    conversation_id: [u8; 16],
    request_id: [u8; 16],
    target: DeviceIdentity,
    target_key_id: [u8; 32],
    target_auth_generation: u64,
    bound_coordinate: PublicGroupSnapshotCoordinate,
    key_package_ref: [u8; 32],
    key_package_wrapper_sha256: [u8; 32],
    package_not_after: ServerTimestamp,
    claimed_at: ServerTimestamp,
    expected_status: PackageStatus,
    successor_status: PackageStatus,
    locked_row_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RevocationTargetCasBinding {
    transaction_id: String,
    target: DeviceIdentity,
    expected_auth_generation: u64,
    expected_status: PersistedRegistrationStatus,
    successor_status: PersistedRegistrationStatus,
    locked_at: ServerTimestamp,
    locked_row_digest: [u8; 32],
}

/// Exact live KeyPackage -> Revoked CAS with immutable signed revocation
/// provenance. Available packages have no reservation IDs; Reserved packages
/// bind the exact conversation/request edge they terminate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RevocationPackageCasBinding {
    transaction_id: String,
    target: DeviceIdentity,
    target_key_id: [u8; 32],
    target_auth_generation: u64,
    key_package_ref: [u8; 32],
    wrapper_sha256: [u8; 32],
    package_not_after: ServerTimestamp,
    expected_status: PackageStatus,
    successor_status: PackageStatus,
    conversation_id: Option<[u8; 16]>,
    request_id: Option<[u8; 16]>,
    revocation_id: [u8; 16],
    revoked_at: ServerTimestamp,
    revocation_request_digest: [u8; 32],
    revocation_row_digest: [u8; 32],
    locked_row_digest: [u8; 32],
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
    /// `apply_device_revocation_batch` step 3. That arm reads only
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
        Self {
            transaction_id: String::new(),
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
pub(crate) struct InvitationQuotaCasBinding {
    transaction_id: String,
    inviter: PrincipalId,
    new_recipients: Vec<PrincipalId>,
    expected_pending: u64,
    successor_pending: u64,
    quota_limit: u64,
    locked_at: ServerTimestamp,
    locked_row_digest: [u8; 32],
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
    pub(crate) fn expected_pending(&self) -> u64 {
        self.expected_pending
    }
    pub(crate) fn successor_pending(&self) -> u64 {
        self.successor_pending
    }
    pub(crate) fn quota_limit(&self) -> u64 {
        self.quota_limit
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
    transaction_id: String,
    conversation_id: [u8; 16],
    welcome_id: [u8; 16],
    recipient: DeviceIdentity,
    transition_seq: u64,
    coordinate: PublicGroupSnapshotCoordinate,
    recovery_request_id: [u8; 16],
    key_package_ref: [u8; 32],
    opaque_welcome_sha256: [u8; 32],
    expires_at: ServerTimestamp,
    expected_status: WelcomeStatus,
    successor_status: WelcomeStatus,
    locked_at: ServerTimestamp,
    locked_row_digest: [u8; 32],
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
}

/// Repository-issued authority for an unsigned expiry worker decision. The
/// work row itself fixes the terminal instant; `observed_at` only proves the
/// worker ran no earlier than that instant under the conversation lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WelcomeExpiryAuthority {
    welcome_id: [u8; 16],
    recipient: DeviceIdentity,
    coordinate: PublicGroupSnapshotCoordinate,
    transition_seq: u64,
    terminal_at: ServerTimestamp,
    observed_at: ServerTimestamp,
    locked_row_digest: [u8; 32],
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
        Self {
            transaction_id: "e2b7-revocation-test".to_owned(),
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
    before: Option<T>,
    after: Option<T>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PlanAuthority {
    Transition(TransitionEvidence),
    Request(RequestEvidence),
    DeviceRevocation(DeviceRevocationEvidence),
    WelcomeExpiry(WelcomeExpiryAuthority),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConversationHeadCasBinding {
    transaction_id: String,
    conversation_id: [u8; 16],
    expected_prior: Option<PublicGroupSnapshotCoordinate>,
    expected_next_entry_seq: u64,
    allocated_entry_id: Option<[u8; 16]>,
    allocated_seq: Option<u64>,
    successor_next_entry_seq: u64,
    locked_at: ServerTimestamp,
    locked_head_digest: [u8; 32],
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
    participants: usize,
    pending_participants: usize,
    active_participants: usize,
    active_admins: usize,
    leaves: usize,
    intervals: usize,
    open_intervals: usize,
    terminal_proofs: usize,
    open_recovery_requests: usize,
    active_reservations: usize,
    pending_reset_requests: usize,
    pending_leave_requests: usize,
    pending_welcomes: usize,
}

impl StateCounts {
    pub(crate) fn participants(&self) -> usize {
        self.participants
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransitionEffects {
    kind: PlanKind,
    opened_intervals: Vec<DeviceIdentity>,
    closed_intervals: Vec<DeviceIdentity>,
    superseded_recovery_requests: Vec<[u8; 16]>,
    terminal_proof_recipients: Vec<DeviceIdentity>,
    complete: bool,
    before_counts: StateCounts,
    after_counts: StateCounts,
    metadata_change: Option<StateChange<MetadataSnapshotBinding>>,
    policy_evidence_digest: Option<[u8; 32]>,
    participant_changes: Vec<StateChange<ParticipantRecord>>,
    leaf_changes: Vec<StateChange<LeafRecord>>,
    interval_changes: Vec<StateChange<AccessInterval>>,
    terminal_proof_changes: Vec<StateChange<ScheduleTerminalProof>>,
    recovery_request_changes: Vec<StateChange<RecoveryRequest>>,
    reservation_changes: Vec<StateChange<RecoveryReservation>>,
    reset_request_changes: Vec<StateChange<ResetRequest>>,
    leave_request_changes: Vec<StateChange<LeaveRequest>>,
    welcome_changes: Vec<StateChange<WelcomeWork>>,
    package_transitions: Vec<PackageTransition>,
    recovery_package_cas: Vec<RecoveryPackageCasBinding>,
    revocation_package_cas: Vec<RevocationPackageCasBinding>,
    revocation_target_cas: Option<RevocationTargetCasBinding>,
    welcome_cas: Option<WelcomeCasBinding>,
    invitation_quota_cas: Option<InvitationQuotaCasBinding>,
    authority: Option<PlanAuthority>,
    head_cas: Option<ConversationHeadCasBinding>,
}

impl TransitionEffects {
    fn new(kind: PlanKind) -> Self {
        Self {
            kind,
            opened_intervals: Vec::new(),
            closed_intervals: Vec::new(),
            superseded_recovery_requests: Vec::new(),
            terminal_proof_recipients: Vec::new(),
            complete: false,
            before_counts: StateCounts::default(),
            after_counts: StateCounts::default(),
            metadata_change: None,
            policy_evidence_digest: None,
            participant_changes: Vec::new(),
            leaf_changes: Vec::new(),
            interval_changes: Vec::new(),
            terminal_proof_changes: Vec::new(),
            recovery_request_changes: Vec::new(),
            reservation_changes: Vec::new(),
            reset_request_changes: Vec::new(),
            leave_request_changes: Vec::new(),
            welcome_changes: Vec::new(),
            package_transitions: Vec::new(),
            recovery_package_cas: Vec::new(),
            revocation_package_cas: Vec::new(),
            revocation_target_cas: None,
            welcome_cas: None,
            invitation_quota_cas: None,
            authority: None,
            head_cas: None,
        }
    }

    pub(crate) fn kind(&self) -> PlanKind {
        self.kind
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn opened_intervals(&self) -> &[DeviceIdentity] {
        &self.opened_intervals
    }

    pub(crate) fn closed_intervals(&self) -> &[DeviceIdentity] {
        &self.closed_intervals
    }

    pub(crate) fn superseded_recovery_requests(&self) -> &[[u8; 16]] {
        &self.superseded_recovery_requests
    }

    pub(crate) fn terminal_proof_recipients(&self) -> &[DeviceIdentity] {
        &self.terminal_proof_recipients
    }

    pub(crate) fn before_counts(&self) -> &StateCounts {
        &self.before_counts
    }

    pub(crate) fn after_counts(&self) -> &StateCounts {
        &self.after_counts
    }

    pub(crate) fn metadata_change(&self) -> Option<&StateChange<MetadataSnapshotBinding>> {
        self.metadata_change.as_ref()
    }

    pub(crate) fn policy_evidence_digest(&self) -> Option<&[u8; 32]> {
        self.policy_evidence_digest.as_ref()
    }

    pub(crate) fn participant_changes(&self) -> &[StateChange<ParticipantRecord>] {
        &self.participant_changes
    }

    pub(crate) fn leaf_changes(&self) -> &[StateChange<LeafRecord>] {
        &self.leaf_changes
    }

    pub(crate) fn interval_changes(&self) -> &[StateChange<AccessInterval>] {
        &self.interval_changes
    }

    pub(crate) fn terminal_proof_changes(&self) -> &[StateChange<ScheduleTerminalProof>] {
        &self.terminal_proof_changes
    }

    pub(crate) fn recovery_request_changes(&self) -> &[StateChange<RecoveryRequest>] {
        &self.recovery_request_changes
    }

    pub(crate) fn reservation_changes(&self) -> &[StateChange<RecoveryReservation>] {
        &self.reservation_changes
    }

    pub(crate) fn reset_request_changes(&self) -> &[StateChange<ResetRequest>] {
        &self.reset_request_changes
    }

    pub(crate) fn leave_request_changes(&self) -> &[StateChange<LeaveRequest>] {
        &self.leave_request_changes
    }

    pub(crate) fn welcome_changes(&self) -> &[StateChange<WelcomeWork>] {
        &self.welcome_changes
    }

    pub(crate) fn package_transitions(&self) -> &[PackageTransition] {
        &self.package_transitions
    }

    pub(crate) fn recovery_package_cas(&self) -> &[RecoveryPackageCasBinding] {
        &self.recovery_package_cas
    }

    pub(crate) fn revocation_package_cas(&self) -> &[RevocationPackageCasBinding] {
        &self.revocation_package_cas
    }

    pub(crate) fn revocation_target_cas(&self) -> Option<&RevocationTargetCasBinding> {
        self.revocation_target_cas.as_ref()
    }

    pub(crate) fn welcome_cas(&self) -> Option<&WelcomeCasBinding> {
        self.welcome_cas.as_ref()
    }

    pub(crate) fn invitation_quota_cas(&self) -> Option<&InvitationQuotaCasBinding> {
        self.invitation_quota_cas.as_ref()
    }

    pub(crate) fn authority(&self) -> Option<&PlanAuthority> {
        self.authority.as_ref()
    }

    pub(crate) fn head_cas(&self) -> Option<&ConversationHeadCasBinding> {
        self.head_cas.as_ref()
    }

    fn complete(&mut self, before: Option<&ConversationState>, after: &ConversationState) {
        self.before_counts = before.map_or_else(StateCounts::default, state_counts);
        self.after_counts = state_counts(after);
        let before_metadata = before.and_then(|state| state.metadata.clone());
        if before_metadata != after.metadata {
            self.metadata_change = Some(StateChange {
                before: before_metadata,
                after: after.metadata.clone(),
            });
        }
        let empty_participants = &[][..];
        let empty_leaves = &[][..];
        let empty_intervals = &[][..];
        let empty_terminal_proofs = &[][..];
        let empty_recovery = &[][..];
        let empty_reservations = &[][..];
        let empty_resets = &[][..];
        let empty_leaves_requests = &[][..];
        let empty_welcomes = &[][..];
        let before_participants =
            before.map_or(empty_participants, |state| state.participants.as_slice());
        let before_leaves = before.map_or(empty_leaves, |state| state.leaves.as_slice());
        let before_intervals = before.map_or(empty_intervals, |state| state.intervals.as_slice());
        let before_terminal_proofs = before.map_or(empty_terminal_proofs, |state| {
            state.terminal_proofs.as_slice()
        });
        let before_recovery =
            before.map_or(empty_recovery, |state| state.recovery_requests.as_slice());
        let before_reservations = before.map_or(empty_reservations, |state| {
            state.recovery_reservations.as_slice()
        });
        let before_resets = before.map_or(empty_resets, |state| state.reset_requests.as_slice());
        let before_leave_requests = before.map_or(empty_leaves_requests, |state| {
            state.leave_requests.as_slice()
        });
        let before_welcomes = before.map_or(empty_welcomes, |state| state.welcomes.as_slice());

        self.participant_changes = diff_by_key(before_participants, &after.participants, |value| {
            value.principal.clone()
        });
        self.leaf_changes = diff_by_key(before_leaves, &after.leaves, |value| value.device.clone());
        self.interval_changes = diff_by_key(before_intervals, &after.intervals, |value| {
            (value.recipient.clone(), value.opening.seq)
        });
        self.terminal_proof_changes =
            diff_by_key(before_terminal_proofs, &after.terminal_proofs, |value| {
                value.recipient.clone()
            });
        self.recovery_request_changes =
            diff_by_key(before_recovery, &after.recovery_requests, |value| {
                value.request_id
            });
        self.reservation_changes =
            diff_by_key(before_reservations, &after.recovery_reservations, |value| {
                value.request_id
            });
        self.reset_request_changes = diff_by_key(before_resets, &after.reset_requests, |value| {
            value.request_id
        });
        self.leave_request_changes =
            diff_by_key(before_leave_requests, &after.leave_requests, |value| {
                value.request_id
            });
        self.welcome_changes =
            diff_by_key(before_welcomes, &after.welcomes, |value| value.welcome_id);
        self.package_transitions = package_transitions(&self.reservation_changes);
        self.complete = true;
    }
}

fn complete_effects(
    mut effects: TransitionEffects,
    before: Option<&ConversationState>,
    after: &ConversationState,
) -> TransitionEffects {
    effects.complete(before, after);
    effects
}

fn state_counts(state: &ConversationState) -> StateCounts {
    StateCounts {
        participants: state.participants.len(),
        pending_participants: state
            .participants
            .iter()
            .filter(|participant| participant.status == ParticipantStatus::Pending)
            .count(),
        active_participants: state
            .participants
            .iter()
            .filter(|participant| participant.status == ParticipantStatus::Active)
            .count(),
        active_admins: state
            .participants
            .iter()
            .filter(|participant| {
                participant.status == ParticipantStatus::Active
                    && participant.role == ParticipantRole::Admin
            })
            .count(),
        leaves: state.leaves.len(),
        intervals: state.intervals.len(),
        open_intervals: state
            .intervals
            .iter()
            .filter(|interval| interval.end.is_none())
            .count(),
        terminal_proofs: state.terminal_proofs.len(),
        open_recovery_requests: state
            .recovery_requests
            .iter()
            .filter(|request| request.status == RecoveryRequestStatus::Open)
            .count(),
        active_reservations: state
            .recovery_reservations
            .iter()
            .filter(|reservation| reservation.status == ReservationStatus::Active)
            .count(),
        pending_reset_requests: state
            .reset_requests
            .iter()
            .filter(|request| request.status == ResetRequestStatus::Pending)
            .count(),
        pending_leave_requests: state
            .leave_requests
            .iter()
            .filter(|request| request.status == LeaveRequestStatus::Pending)
            .count(),
        pending_welcomes: state
            .welcomes
            .iter()
            .filter(|welcome| welcome.status == WelcomeStatus::Pending)
            .count(),
    }
}

fn diff_by_key<T, K, F>(before: &[T], after: &[T], key: F) -> Vec<StateChange<T>>
where
    T: Clone + PartialEq,
    K: Clone + Ord,
    F: Fn(&T) -> K,
{
    let keys = before
        .iter()
        .map(&key)
        .chain(after.iter().map(&key))
        .collect::<BTreeSet<_>>();
    keys.into_iter()
        .filter_map(|item_key| {
            let before = before.iter().find(|value| key(value) == item_key).cloned();
            let after = after.iter().find(|value| key(value) == item_key).cloned();
            (before != after).then_some(StateChange { before, after })
        })
        .collect()
}

fn package_transitions(
    reservation_changes: &[StateChange<RecoveryReservation>],
) -> Vec<PackageTransition> {
    reservation_changes
        .iter()
        .filter_map(|change| match (&change.before, &change.after) {
            (None, Some(after)) if after.status == ReservationStatus::Active => {
                Some(PackageTransition {
                    request_id: after.request_id,
                    key_package_ref: after.key_package_ref,
                    from: PackageStatus::Available,
                    to: PackageStatus::Reserved,
                })
            }
            (Some(before), Some(after))
                if before.status == ReservationStatus::Active
                    && after.status != ReservationStatus::Active =>
            {
                let terminal_time = after
                    .terminal
                    .as_ref()
                    .map(work_terminal_time)
                    .unwrap_or(after.expires_at);
                let to = match after.status {
                    ReservationStatus::Consumed => PackageStatus::Consumed,
                    ReservationStatus::Expired | ReservationStatus::Released
                        if matches!(
                            after.terminal.as_ref(),
                            Some(WorkTerminalEvidence::DeviceRevocation(_))
                        ) =>
                    {
                        PackageStatus::Revoked
                    }
                    ReservationStatus::Expired | ReservationStatus::Released
                        if terminal_time >= after.package_not_after =>
                    {
                        PackageStatus::Expired
                    }
                    ReservationStatus::Expired | ReservationStatus::Released => {
                        PackageStatus::Available
                    }
                    ReservationStatus::Active => return None,
                };
                Some(PackageTransition {
                    request_id: after.request_id,
                    key_package_ref: after.key_package_ref,
                    from: PackageStatus::Reserved,
                    to,
                })
            }
            _ => None,
        })
        .collect()
}

fn package_cas_bijection_valid(effects: &TransitionEffects) -> bool {
    let Some(head) = effects.head_cas.as_ref() else {
        return false;
    };
    effects.package_transitions.len() == effects.recovery_package_cas.len()
        && effects.package_transitions.iter().all(|edge| {
            effects
                .recovery_package_cas
                .iter()
                .filter(|binding| {
                    binding.transaction_id == head.transaction_id
                        && binding.request_id == edge.request_id
                        && binding.key_package_ref == edge.key_package_ref
                        && binding.expected_status == edge.from
                        && binding.successor_status == edge.to
                })
                .count()
                == 1
        })
        && effects.recovery_package_cas.iter().all(|binding| {
            effects
                .package_transitions
                .iter()
                .filter(|edge| {
                    binding.request_id == edge.request_id
                        && binding.key_package_ref == edge.key_package_ref
                        && binding.expected_status == edge.from
                        && binding.successor_status == edge.to
                })
                .count()
                == 1
        })
}

fn revocation_package_cas_bijection_valid(effects: &TransitionEffects) -> bool {
    let Some(head) = effects.head_cas.as_ref() else {
        return false;
    };
    effects.recovery_package_cas.is_empty()
        && effects.package_transitions.len() == effects.revocation_package_cas.len()
        && effects.package_transitions.iter().all(|edge| {
            edge.from == PackageStatus::Reserved
                && edge.to == PackageStatus::Revoked
                && effects
                    .revocation_package_cas
                    .iter()
                    .filter(|binding| {
                        binding.transaction_id == head.transaction_id
                            && binding.conversation_id == Some(head.conversation_id)
                            && binding.request_id == Some(edge.request_id)
                            && binding.key_package_ref == edge.key_package_ref
                            && binding.expected_status == edge.from
                            && binding.successor_status == edge.to
                    })
                    .count()
                    == 1
        })
        && effects.revocation_package_cas.iter().all(|binding| {
            effects
                .package_transitions
                .iter()
                .filter(|edge| {
                    binding.request_id == Some(edge.request_id)
                        && binding.key_package_ref == edge.key_package_ref
                        && binding.expected_status == edge.from
                        && binding.successor_status == edge.to
                })
                .count()
                == 1
        })
}

fn work_terminal_time(evidence: &WorkTerminalEvidence) -> ServerTimestamp {
    match evidence {
        WorkTerminalEvidence::Transition(value) => value.received_at,
        WorkTerminalEvidence::Request(value) => value.received_at,
        WorkTerminalEvidence::DeviceRevocation(value) => value.accepted_at,
        WorkTerminalEvidence::Expiry(value) => *value,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlannedTransition {
    expected_prior: Option<PublicGroupSnapshotCoordinate>,
    retired_coordinate: Option<PublicGroupSnapshotCoordinate>,
    successor_coordinate: Option<PublicGroupSnapshotCoordinate>,
    state: ConversationState,
    effects: TransitionEffects,
}

/// Exhaustive adapter-facing write plan. The graph projection and its complete
/// delta originate from the same validated successor and must be committed in
/// one transaction after the conversation-head CAS succeeds.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ConversationPersistencePlan {
    expected_prior: Option<PublicGroupSnapshotCoordinate>,
    retired_coordinate: Option<PublicGroupSnapshotCoordinate>,
    successor_coordinate: Option<PublicGroupSnapshotCoordinate>,
    state: ConversationStateHydration,
    effects: TransitionEffects,
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
    fanout_manifest_digest: [u8; 32],
    conversations: Vec<ConversationPersistencePlan>,
}

impl DeviceRevocationBatchPersistencePlan {
    pub(crate) fn authority(&self) -> &DeviceRevocationEvidence {
        &self.authority
    }
    pub(crate) fn target_cas(&self) -> &RevocationTargetCasBinding {
        &self.target_cas
    }
    pub(crate) fn revoked_packages(&self) -> &[RevocationPackageCasBinding] {
        &self.revoked_packages
    }
    pub(crate) fn fanout_manifest_digest(&self) -> &[u8; 32] {
        &self.fanout_manifest_digest
    }
    pub(crate) fn conversations(&self) -> &[ConversationPersistencePlan] {
        &self.conversations
    }
    pub(crate) fn into_parts(
        self,
    ) -> (
        DeviceRevocationEvidence,
        RevocationTargetCasBinding,
        Vec<RevocationPackageCasBinding>,
        [u8; 32],
        Vec<ConversationPersistencePlan>,
    ) {
        (
            self.authority,
            self.target_cas,
            self.revoked_packages,
            self.fanout_manifest_digest,
            self.conversations,
        )
    }

    /// Assemble a batch plan from its parts for the executor batch test (the
    /// production constructor `plan_device_revocation_batch` consumes repository
    /// lock guards). The `fanout_manifest_digest` is a provenance placeholder.
    #[cfg(test)]
    pub(crate) fn for_test(
        authority: DeviceRevocationEvidence,
        target_cas: RevocationTargetCasBinding,
        revoked_packages: Vec<RevocationPackageCasBinding>,
        conversations: Vec<ConversationPersistencePlan>,
    ) -> Self {
        Self {
            authority,
            target_cas,
            revoked_packages,
            fanout_manifest_digest: [1u8; 32],
            conversations,
        }
    }
}

impl ConversationPersistencePlan {
    pub(crate) fn expected_prior(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.expected_prior.as_ref()
    }

    pub(crate) fn retired_coordinate(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.retired_coordinate.as_ref()
    }

    pub(crate) fn successor_coordinate(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.successor_coordinate.as_ref()
    }

    pub(crate) fn state(&self) -> &ConversationStateHydration {
        &self.state
    }

    pub(crate) fn effects(&self) -> &TransitionEffects {
        &self.effects
    }
}

impl PlannedTransition {
    #[cfg(test)]
    pub(crate) fn expected_prior(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.expected_prior.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn retired_coordinate(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.retired_coordinate.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn successor_coordinate(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.successor_coordinate.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn resulting_state(&self) -> &ConversationState {
        &self.state
    }

    #[cfg(test)]
    pub(crate) fn effects(&self) -> &TransitionEffects {
        &self.effects
    }

    #[cfg(test)]
    pub(crate) fn into_state(self) -> ConversationState {
        self.state
    }

    #[cfg(not(test))]
    fn bind_transition_authority(
        mut self,
        evidence: TransitionEvidence,
        head: &LockedConversationHeadGuard,
        registration_transaction_id: &str,
        registration_trusted_at: ServerTimestamp,
    ) -> Result<Self, StateMachineError> {
        let authority = evidence
            .authority
            .as_ref()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let entry_id = authority
            .control_entry_id
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let conversation_id = authority
            .control_conversation_id
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        let successor_next_entry_seq = evidence
            .seq
            .checked_add(1)
            .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
            .ok_or(StateMachineError::CoordinateOverflow)?;

        if head.transaction_id() != registration_transaction_id
            || head.conversation_id().as_bytes() != &conversation_id
            || self.state.coordinate.conversation_id() != &conversation_id
            || head.prior_coordinate() != self.expected_prior.as_ref()
            || head.next_entry_seq() != evidence.seq
            || locked_at != registration_trusted_at
            || locked_at != evidence.received_at
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }

        self.effects.authority = Some(PlanAuthority::Transition(evidence));
        self.effects.head_cas = Some(ConversationHeadCasBinding {
            transaction_id: head.transaction_id().to_owned(),
            conversation_id,
            expected_prior: self.expected_prior,
            expected_next_entry_seq: head.next_entry_seq(),
            allocated_entry_id: Some(entry_id),
            allocated_seq: Some(head.next_entry_seq()),
            successor_next_entry_seq,
            locked_at,
            locked_head_digest: *head.durable_row_digest(),
        });
        Ok(self)
    }

    #[cfg(not(test))]
    fn bind_control_request_authority(
        mut self,
        evidence: RequestEvidence,
        head: &LockedConversationHeadGuard,
        registration_transaction_id: &str,
        registration_trusted_at: ServerTimestamp,
    ) -> Result<Self, StateMachineError> {
        let entry_id = evidence
            .control_entry_id
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let seq = evidence
            .control_seq
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if evidence.authority.is_none() {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        let successor_next_entry_seq = seq
            .checked_add(1)
            .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
            .ok_or(StateMachineError::CoordinateOverflow)?;
        if head.transaction_id() != registration_transaction_id
            || head.conversation_id().as_bytes() != &evidence.conversation_id
            || self.state.coordinate.conversation_id() != &evidence.conversation_id
            || head.prior_coordinate() != self.expected_prior.as_ref()
            || head.next_entry_seq() != seq
            || locked_at != registration_trusted_at
            || locked_at != evidence.received_at
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.authority = Some(PlanAuthority::Request(evidence));
        self.effects.head_cas = Some(ConversationHeadCasBinding {
            transaction_id: head.transaction_id().to_owned(),
            conversation_id: *head.conversation_id().as_bytes(),
            expected_prior: self.expected_prior,
            expected_next_entry_seq: seq,
            allocated_entry_id: Some(entry_id),
            allocated_seq: Some(seq),
            successor_next_entry_seq,
            locked_at,
            locked_head_digest: *head.durable_row_digest(),
        });
        Ok(self)
    }

    #[cfg(not(test))]
    fn bind_non_control_request_authority(
        mut self,
        evidence: RequestEvidence,
        head: &LockedConversationHeadGuard,
        registration_transaction_id: &str,
        registration_trusted_at: ServerTimestamp,
    ) -> Result<Self, StateMachineError> {
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        if evidence.control_entry_id.is_some()
            || evidence.control_seq.is_some()
            || evidence.authority.is_none()
            || evidence.conversation_id != *self.state.coordinate.conversation_id()
            || head.transaction_id() != registration_transaction_id
            || head.conversation_id().as_bytes() != &evidence.conversation_id
            || head.prior_coordinate() != self.expected_prior.as_ref()
            || locked_at != registration_trusted_at
            || locked_at != evidence.received_at
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let conversation_id = evidence.conversation_id;
        self.effects.authority = Some(PlanAuthority::Request(evidence));
        self.effects.head_cas = Some(ConversationHeadCasBinding {
            transaction_id: head.transaction_id().to_owned(),
            conversation_id,
            expected_prior: self.expected_prior,
            expected_next_entry_seq: head.next_entry_seq(),
            allocated_entry_id: None,
            allocated_seq: None,
            successor_next_entry_seq: head.next_entry_seq(),
            locked_at,
            locked_head_digest: *head.durable_row_digest(),
        });
        Ok(self)
    }

    #[cfg(not(test))]
    fn bind_device_revocation_authority(
        mut self,
        evidence: DeviceRevocationEvidence,
        head: &LockedConversationHeadGuard,
        transaction_id: &str,
        locked_at: ServerTimestamp,
    ) -> Result<Self, StateMachineError> {
        let head_locked_at =
            ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        if head.transaction_id() != transaction_id
            || head.conversation_id().as_bytes() != self.state.coordinate.conversation_id()
            || head.prior_coordinate() != self.expected_prior.as_ref()
            || head_locked_at != locked_at
            || head_locked_at != evidence.accepted_at
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.authority = Some(PlanAuthority::DeviceRevocation(evidence));
        self.effects.head_cas = Some(ConversationHeadCasBinding {
            transaction_id: head.transaction_id().to_owned(),
            conversation_id: *head.conversation_id().as_bytes(),
            expected_prior: self.expected_prior,
            expected_next_entry_seq: head.next_entry_seq(),
            allocated_entry_id: None,
            allocated_seq: None,
            successor_next_entry_seq: head.next_entry_seq(),
            locked_at: head_locked_at,
            locked_head_digest: *head.durable_row_digest(),
        });
        Ok(self)
    }

    #[cfg(not(test))]
    fn bind_welcome_expiry_authority(
        mut self,
        evidence: WelcomeExpiryAuthority,
        head: &LockedConversationHeadGuard,
        transaction_id: &str,
    ) -> Result<Self, StateMachineError> {
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        if head.transaction_id() != transaction_id
            || head.conversation_id().as_bytes() != self.state.coordinate.conversation_id()
            || head.prior_coordinate() != self.expected_prior.as_ref()
            || locked_at != evidence.observed_at
            || evidence.observed_at < evidence.terminal_at
            || evidence.locked_row_digest == [0; 32]
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.authority = Some(PlanAuthority::WelcomeExpiry(evidence));
        self.effects.head_cas = Some(ConversationHeadCasBinding {
            transaction_id: head.transaction_id().to_owned(),
            conversation_id: *head.conversation_id().as_bytes(),
            expected_prior: self.expected_prior,
            expected_next_entry_seq: head.next_entry_seq(),
            allocated_entry_id: None,
            allocated_seq: None,
            successor_next_entry_seq: head.next_entry_seq(),
            locked_at,
            locked_head_digest: *head.durable_row_digest(),
        });
        Ok(self)
    }

    #[cfg(not(test))]
    fn bind_welcome_cas(mut self, binding: WelcomeCasBinding) -> Result<Self, StateMachineError> {
        let exact_edge = self.effects.welcome_changes.iter().any(|change| {
            matches!(
                (change.before.as_ref(), change.after.as_ref()),
                (Some(before), Some(after))
                    if before.welcome_id == binding.welcome_id
                        && before.status == binding.expected_status
                        && after.status == binding.successor_status
                        && before.recipient == binding.recipient
                        && before.transition_seq == binding.transition_seq
                        && before.coordinate == binding.coordinate
                        && before.recovery_request_id == binding.recovery_request_id
                        && before.key_package_ref == binding.key_package_ref
                        && before.sha256 == binding.opaque_welcome_sha256
                        && before.expires_at == binding.expires_at
            )
        });
        if !exact_edge
            || self.effects.welcome_changes.len() != 1
            || self.effects.welcome_cas.is_some()
            || binding.expected_status != WelcomeStatus::Pending
            || binding.locked_row_digest == [0; 32]
            || self.effects.head_cas.as_ref().is_none_or(|head| {
                head.transaction_id != binding.transaction_id
                    || head.conversation_id != binding.conversation_id
                    || head.locked_at != binding.locked_at
            })
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.welcome_cas = Some(binding);
        Ok(self)
    }

    #[cfg(not(test))]
    fn bind_invitation_quota_cas(
        mut self,
        binding: InvitationQuotaCasBinding,
    ) -> Result<Self, StateMachineError> {
        let mut exact_new_recipients = self
            .effects
            .participant_changes
            .iter()
            .filter_map(
                |change| match (change.before.as_ref(), change.after.as_ref()) {
                    (None, Some(after)) if after.status == ParticipantStatus::Pending => {
                        Some(after.principal.clone())
                    }
                    _ => None,
                },
            )
            .collect::<Vec<_>>();
        exact_new_recipients.sort();
        if !matches!(self.effects.kind, PlanKind::Creation | PlanKind::Policy)
            || self.effects.invitation_quota_cas.is_some()
            || exact_new_recipients != binding.new_recipients
            || binding.successor_pending
                != binding
                    .expected_pending
                    .checked_add(binding.new_recipients.len() as u64)
                    .ok_or(StateMachineError::InvalidHydrationAuthority)?
            || binding.successor_pending > binding.quota_limit
            || binding.locked_row_digest == [0; 32]
            || self.effects.head_cas.as_ref().is_none_or(|head| {
                head.transaction_id != binding.transaction_id || head.locked_at != binding.locked_at
            })
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.invitation_quota_cas = Some(binding);
        Ok(self)
    }

    #[cfg(not(test))]
    fn into_revocation_batch_member_plan(
        self,
    ) -> Result<ConversationPersistencePlan, StateMachineError> {
        if !matches!(
            self.effects.authority.as_ref(),
            Some(PlanAuthority::DeviceRevocation(_))
        ) || self.effects.head_cas.is_none()
            || !revocation_package_cas_bijection_valid(&self.effects)
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(ConversationPersistencePlan {
            expected_prior: self.expected_prior,
            retired_coordinate: self.retired_coordinate,
            successor_coordinate: self.successor_coordinate,
            state: ConversationStateHydration::from_state(self.state),
            effects: self.effects,
        })
    }

    #[cfg(not(test))]
    fn bind_revocation_package_cas(
        mut self,
        binding: RevocationPackageCasBinding,
    ) -> Result<Self, StateMachineError> {
        let matches_semantic_edge = binding.expected_status == PackageStatus::Reserved
            && binding.successor_status == PackageStatus::Revoked
            && binding.conversation_id.is_some()
            && binding.request_id.is_some()
            && self.effects.package_transitions.iter().any(|edge| {
                Some(edge.request_id) == binding.request_id
                    && edge.key_package_ref == binding.key_package_ref
                    && edge.from == binding.expected_status
                    && edge.to == binding.successor_status
            });
        if !matches_semantic_edge
            || binding.revocation_request_digest == [0; 32]
            || binding.revocation_row_digest == [0; 32]
            || binding.locked_row_digest == [0; 32]
            || self.effects.head_cas.as_ref().is_none_or(|head| {
                head.transaction_id != binding.transaction_id
                    || Some(head.conversation_id) != binding.conversation_id
                    || head.locked_at != binding.revoked_at
            })
            || !matches!(
                self.effects.authority.as_ref(),
                Some(PlanAuthority::DeviceRevocation(evidence))
                    if evidence.target == binding.target
                        && evidence.expected_target_auth_generation
                            == binding.target_auth_generation
                        && evidence.revocation_id == binding.revocation_id
                        && evidence.accepted_at == binding.revoked_at
                        && evidence.request_digest == binding.revocation_request_digest
                        && evidence.durable_row_digest == binding.revocation_row_digest
            )
            || self.effects.revocation_package_cas.iter().any(|existing| {
                existing.key_package_ref == binding.key_package_ref
                    || existing.request_id == binding.request_id
            })
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.revocation_package_cas.push(binding);
        Ok(self)
    }

    #[cfg(not(test))]
    fn bind_recovery_package_cas(
        mut self,
        binding: RecoveryPackageCasBinding,
    ) -> Result<Self, StateMachineError> {
        let matches_semantic_edge = self.effects.package_transitions.iter().any(|edge| {
            edge.request_id == binding.request_id
                && edge.key_package_ref == binding.key_package_ref
                && edge.from == binding.expected_status
                && edge.to == binding.successor_status
        });
        if !matches_semantic_edge
            || self
                .effects
                .head_cas
                .as_ref()
                .is_some_and(|head| head.transaction_id != binding.transaction_id)
            || binding.locked_row_digest == [0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.recovery_package_cas.push(binding);
        Ok(self)
    }

    #[cfg(not(test))]
    fn bind_terminal_package_guards(
        mut self,
        prior: &ConversationState,
        mut guards: Vec<LockedRecoveryPackageGuard>,
        transaction_id: &str,
    ) -> Result<Self, StateMachineError> {
        guards.sort_by(|left, right| {
            left.request_id()
                .as_bytes()
                .cmp(right.request_id().as_bytes())
        });
        let missing_edges = self
            .effects
            .package_transitions
            .iter()
            .filter(|edge| {
                edge.from == PackageStatus::Reserved
                    && !self.effects.recovery_package_cas.iter().any(|binding| {
                        binding.request_id == edge.request_id
                            && binding.key_package_ref == edge.key_package_ref
                            && binding.expected_status == edge.from
                            && binding.successor_status == edge.to
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        if missing_edges.len() != guards.len() {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        for guard in guards {
            let request_id = *guard.request_id().as_bytes();
            let edge = missing_edges
                .iter()
                .find(|edge| edge.request_id == request_id)
                .ok_or(StateMachineError::InvalidHydrationAuthority)?;
            let request = prior
                .recovery_request(&request_id)
                .ok_or(StateMachineError::InvalidHydrationAuthority)?;
            let reservation = prior
                .recovery_reservation(&request_id)
                .ok_or(StateMachineError::InvalidHydrationAuthority)?;
            let binding = reserved_package_cas_for_request(
                guard,
                request,
                reservation,
                transaction_id,
                edge.to,
            )?;
            self.effects.recovery_package_cas.push(binding);
        }
        if !package_cas_bijection_valid(&self.effects) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(self)
    }

    #[cfg(not(test))]
    pub(crate) fn into_persistence_plan(
        self,
    ) -> Result<ConversationPersistencePlan, StateMachineError> {
        let welcome_authority_valid =
            match self.effects.kind {
                PlanKind::WelcomeAcknowledgement => {
                    matches!(
                        self.effects.authority.as_ref(),
                        Some(PlanAuthority::Request(evidence))
                            if evidence.kind == RequestEntryKind::WelcomeAcknowledgement
                    ) && self.effects.welcome_cas.as_ref().is_some_and(|binding| {
                        binding.successor_status == WelcomeStatus::Acknowledged
                    })
                }
                PlanKind::WelcomeRejection => {
                    matches!(
                        self.effects.authority.as_ref(),
                        Some(PlanAuthority::Request(evidence))
                            if evidence.kind == RequestEntryKind::WelcomeRejection
                    ) && self
                        .effects
                        .welcome_cas
                        .as_ref()
                        .is_some_and(|binding| binding.successor_status == WelcomeStatus::Rejected)
                }
                PlanKind::WelcomeExpiry => {
                    matches!(
                        self.effects.authority.as_ref(),
                        Some(PlanAuthority::WelcomeExpiry(_))
                    ) && self
                        .effects
                        .welcome_cas
                        .as_ref()
                        .is_some_and(|binding| binding.successor_status == WelcomeStatus::Expired)
                }
                _ => self.effects.welcome_cas.is_none(),
            };
        let invitation_quota_valid = match self.effects.kind {
            PlanKind::Creation | PlanKind::Policy => self.effects.invitation_quota_cas.is_some(),
            _ => self.effects.invitation_quota_cas.is_none(),
        };
        if self.effects.authority.is_none()
            || self.effects.head_cas.is_none()
            || !package_cas_bijection_valid(&self.effects)
            || !welcome_authority_valid
            || !invitation_quota_valid
            || (matches!(
                self.effects.authority.as_ref(),
                Some(PlanAuthority::DeviceRevocation(_))
            ) && self.effects.revocation_target_cas.is_none())
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(ConversationPersistencePlan {
            expected_prior: self.expected_prior,
            retired_coordinate: self.retired_coordinate,
            successor_coordinate: self.successor_coordinate,
            state: ConversationStateHydration::from_state(self.state),
            effects: self.effects,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CreationDecision {
    Create(PlannedTransition),
    ExistingDirect {
        conversation_id: [u8; 16],
        coordinate: PublicGroupSnapshotCoordinate,
    },
}

pub(crate) struct CreationCommand {
    pub(crate) kind: ConversationKind,
    pub(crate) creator: DeviceIdentity,
    pub(crate) invitees: Vec<PrincipalId>,
    pub(crate) transition: TransitionEvidence,
    pub(crate) public_state: ActivePublicState,
}

fn plan_creation_inner(
    existing_direct: Option<&ConversationState>,
    command: CreationCommand,
) -> Result<CreationDecision, StateMachineError> {
    require_transition_kind(&command.transition, SignedMutationKind::Creation)?;
    require_transition_actor(&command.transition, &command.creator)?;
    validate_creation_command(&command)?;
    require_creation_body(
        &command.transition,
        command.kind,
        &command.creator,
        &command.invitees,
        &command.public_state,
    )?;
    let proposed_pair = if command.kind == ConversationKind::Direct {
        Some(canonical_pair(
            command.creator.principal(),
            command
                .invitees
                .first()
                .ok_or(StateMachineError::InvalidCreation)?,
        ))
    } else {
        None
    };

    if let Some(existing) = existing_direct {
        if existing.kind == ConversationKind::Direct
            && existing.coordinate.lifecycle() == PublicGroupSnapshotLifecycle::Active
            && existing_direct_pair(existing).as_ref() == proposed_pair.as_ref()
        {
            return Ok(CreationDecision::ExistingDirect {
                conversation_id: *existing.coordinate.conversation_id(),
                coordinate: existing.coordinate,
            });
        }
        if existing.coordinate.lifecycle() == PublicGroupSnapshotLifecycle::Active {
            return Err(StateMachineError::ExistingConversationConflict);
        }
    }

    let creator_leaf = singleton_genesis_leaf(&command.public_state, &command.creator)?;
    let invitation = InvitationProvenance {
        transition: command.transition.clone(),
        inviter: command.creator.clone(),
    };
    let mut participants = Vec::with_capacity(command.invitees.len() + 1);
    participants.push(ParticipantRecord {
        principal: command.creator.principal.clone(),
        status: ParticipantStatus::Active,
        role: ParticipantRole::Admin,
        role_producer: None,
        invitation: None,
        acceptance: None,
    });
    participants.extend(
        command
            .invitees
            .into_iter()
            .map(|principal| ParticipantRecord {
                principal,
                status: ParticipantStatus::Pending,
                role: if command.kind == ConversationKind::Direct {
                    ParticipantRole::Admin
                } else {
                    ParticipantRole::Member
                },
                role_producer: None,
                invitation: Some(invitation.clone()),
                acceptance: None,
            }),
    );
    participants.sort_by(|left, right| left.principal.cmp(&right.principal));

    let coordinate = *command.public_state.coordinate();
    let intervals = vec![AccessInterval {
        recipient: command.creator.clone(),
        generation: coordinate.generation(),
        opening: command.transition.clone(),
        opening_kind: OpeningKind::Creation,
        opening_context: coordinate,
        end: None,
    }];
    let metadata = transition_metadata(&command.transition).cloned();
    let state = ConversationState {
        kind: command.kind,
        coordinate,
        producer: command.transition.clone(),
        public_state: Some(command.public_state),
        metadata_producer: metadata.as_ref().map(|_| command.transition.clone()),
        metadata,
        participants,
        leaves: vec![creator_leaf],
        intervals,
        terminal_proofs: Vec::new(),
        recovery_requests: Vec::new(),
        recovery_reservations: Vec::new(),
        reset_requests: Vec::new(),
        leave_requests: Vec::new(),
        welcomes: Vec::new(),
    };
    validate_state(&state)?;
    let mut effects = TransitionEffects::new(PlanKind::Creation);
    effects.opened_intervals.push(command.creator);
    effects.complete(None, &state);
    Ok(CreationDecision::Create(PlannedTransition {
        expected_prior: None,
        retired_coordinate: None,
        successor_coordinate: Some(coordinate),
        state,
        effects,
    }))
}

fn validate_creation_command(command: &CreationCommand) -> Result<(), StateMachineError> {
    let coordinate = command.public_state.coordinate();
    if coordinate.generation() != 0
        || coordinate.state_version() != 0
        || coordinate.epoch() != 0
        || coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
        || command.invitees.len() + 1 > MAX_PARTICIPANTS
        || command.invitees.windows(2).any(|pair| pair[0] >= pair[1])
        || command
            .invitees
            .iter()
            .any(|invitee| invitee == command.creator.principal())
        || (command.kind == ConversationKind::Direct && command.invitees.len() != 1)
    {
        return Err(StateMachineError::InvalidCreation);
    }
    Ok(())
}

fn canonical_pair(left: &PrincipalId, right: &PrincipalId) -> (PrincipalId, PrincipalId) {
    if left <= right {
        (left.clone(), right.clone())
    } else {
        (right.clone(), left.clone())
    }
}

fn existing_direct_pair(state: &ConversationState) -> Option<(PrincipalId, PrincipalId)> {
    let [left, right] = state.participants.as_slice() else {
        return None;
    };
    Some(canonical_pair(&left.principal, &right.principal))
}

fn singleton_genesis_leaf(
    public_state: &ActivePublicState,
    actor: &DeviceIdentity,
) -> Result<LeafRecord, StateMachineError> {
    let [leaf] = public_state.binding().tree_summary().leaves() else {
        return Err(StateMachineError::InvalidPublicState);
    };
    if leaf.basic_credential() != actor.basic_credential() {
        return Err(StateMachineError::InvalidPublicState);
    }
    Ok(LeafRecord {
        device: actor.clone(),
        leaf_index: leaf.leaf_index(),
        basic_credential: leaf.basic_credential().to_vec(),
        signature_key: leaf.signature_key().to_vec(),
        encryption_key: leaf.encryption_key().to_vec(),
        key_package_ref: None,
    })
}

struct PolicyCommand {
    actor: DeviceIdentity,
    transition: TransitionEvidence,
    relationship_evidence_digest: [u8; 32],
}

fn plan_policy_transition(
    prior: &ConversationState,
    command: PolicyCommand,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(&command.transition, SignedMutationKind::PolicyTransition)?;
    require_transition_actor(&command.transition, &command.actor)?;
    if prior.kind != ConversationKind::Group {
        return Err(StateMachineError::DirectParticipantMutationForbidden);
    }
    let actor = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if actor.status != ParticipantStatus::Active || actor.role != ParticipantRole::Admin {
        return Err(StateMachineError::AdminRequired);
    }
    let next_coordinate = coordinate_only_successor(&prior.coordinate)?;
    let changes = match command.transition.body_binding.as_ref() {
        Some(TransitionBodyBinding::Policy {
            prior: signed_prior,
            next: signed_next,
            participant_changes,
        }) if signed_prior == &prior.coordinate && signed_next == &next_coordinate => {
            participant_changes.clone()
        }
        _ => return Err(StateMachineError::InvalidTransition),
    };

    let mut state = prior.clone();
    for change in changes {
        match change {
            ManifestParticipantChange::Add(principal) => {
                if state.participant(&principal).is_some()
                    || state.participants.len() >= MAX_PARTICIPANTS
                {
                    return Err(StateMachineError::InvariantViolation);
                }
                state.participants.push(ParticipantRecord {
                    principal,
                    status: ParticipantStatus::Pending,
                    role: ParticipantRole::Member,
                    role_producer: None,
                    invitation: Some(InvitationProvenance {
                        transition: command.transition.clone(),
                        inviter: command.actor.clone(),
                    }),
                    acceptance: None,
                });
                state
                    .participants
                    .sort_by(|left, right| left.principal.cmp(&right.principal));
            }
            ManifestParticipantChange::Remove(principal) => {
                if principal == *command.actor.principal()
                    || state
                        .leaves
                        .iter()
                        .any(|leaf| leaf.device.principal() == &principal)
                    || would_remove_last_active_admin(&state, &principal)
                {
                    return Err(StateMachineError::InvalidPolicyAuthority);
                }
                let index = state
                    .participants
                    .binary_search_by(|participant| participant.principal.cmp(&principal))
                    .map_err(|_| StateMachineError::NotParticipant)?;
                state.participants.remove(index);
            }
            ManifestParticipantChange::ChangeRole(principal, role) => {
                let index = state
                    .participants
                    .binary_search_by(|participant| participant.principal.cmp(&principal))
                    .map_err(|_| StateMachineError::NotParticipant)?;
                if state.participants[index].status != ParticipantStatus::Active
                    || (state.participants[index].role == ParticipantRole::Admin
                        && role == ParticipantRole::Member
                        && would_remove_last_active_admin(&state, &principal))
                {
                    return Err(StateMachineError::LastAdminRequired);
                }
                state.participants[index].role = role;
                state.participants[index].role_producer = Some(command.transition.clone());
            }
        }
    }
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        None,
        None,
        None,
    );
    state.coordinate = next_coordinate;
    state.producer = command.transition.clone();
    state.public_state = Some(rebind_active_snapshot(
        prior.public_state(),
        next_coordinate,
    )?);
    validate_state(&state)?;
    let mut effects = TransitionEffects::new(PlanKind::Policy);
    effects.policy_evidence_digest = Some(command.relationship_evidence_digest);
    effects.complete(Some(prior), &state);
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(next_coordinate),
        state,
        effects,
    })
}

pub(crate) struct AcceptConversation {
    pub(crate) actor: DeviceIdentity,
    pub(crate) transition: TransitionEvidence,
    pub(crate) recovery_request_id: [u8; 16],
    pub(crate) key_package_ref: [u8; 32],
    pub(crate) package_not_after: ServerTimestamp,
    #[cfg(not(test))]
    registration: LockedRegistrationProjection,
    #[cfg(not(test))]
    reservation: LockedRecoveryReservationProjection,
    #[cfg(not(test))]
    relationship_evidence_digest: [u8; 32],
}

fn plan_accept_conversation_inner(
    prior: &ConversationState,
    command: AcceptConversation,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(
        &command.transition,
        SignedMutationKind::ParticipantAcceptance,
    )?;
    require_transition_actor(&command.transition, &command.actor)?;
    #[cfg(not(test))]
    if !command
        .registration
        .authorizes_transition(&command.transition)
        || !command
            .reservation
            .authorizes_acceptance(&command.transition)
        || command.reservation.request_id != command.recovery_request_id
        || command.reservation.target != command.actor
        || command.reservation.key_package_ref != command.key_package_ref
        || command.reservation.package_not_after != command.package_not_after
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    if !is_uuid_v4(&command.recovery_request_id) {
        return Err(StateMachineError::InvalidTransition);
    }
    let participant_index = prior
        .participants
        .binary_search_by(|participant| participant.principal.cmp(command.actor.principal()))
        .map_err(|_| StateMachineError::NotParticipant)?;
    if prior.participants[participant_index].status != ParticipantStatus::Pending {
        return Err(StateMachineError::InvitationNotPending);
    }
    if prior.recovery_requests.iter().any(|request| {
        request.target == command.actor && request.status == RecoveryRequestStatus::Open
    }) {
        return Err(StateMachineError::LeafRecoveryAlreadyOpen);
    }

    let received_at = command.transition.received_at;
    let expires_at = recovery_expiry(received_at, command.package_not_after)?;
    let next_coordinate = coordinate_only_successor(&prior.coordinate)?;
    #[cfg(not(test))]
    if command.reservation.bound_coordinate != next_coordinate {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    require_acceptance_body(
        &command.transition,
        &prior.coordinate,
        &next_coordinate,
        &command.recovery_request_id,
        &command.actor,
        prior.participants[participant_index].invitation.as_ref(),
    )?;
    let public_state = rebind_active_snapshot(prior.public_state(), next_coordinate)?;
    let mut state = prior.clone();
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        None,
        None,
        None,
    );
    state.coordinate = next_coordinate;
    state.producer = command.transition.clone();
    state.public_state = Some(public_state);
    state.participants[participant_index].status = ParticipantStatus::Active;
    state.participants[participant_index].acceptance = Some(command.transition.clone());
    state.recovery_requests.push(RecoveryRequest {
        request_id: command.recovery_request_id,
        target: command.actor.clone(),
        kind: LeafRecoveryKind::Add,
        source: RecoverySource::Acceptance,
        bound_coordinate: next_coordinate,
        key_package_ref: command.key_package_ref,
        received_at,
        expires_at,
        status: RecoveryRequestStatus::Open,
        origin: RecoveryOriginEvidence::Acceptance(command.transition.clone()),
        terminal: None,
    });
    state.recovery_reservations.push(RecoveryReservation {
        request_id: command.recovery_request_id,
        target: command.actor,
        bound_coordinate: next_coordinate,
        key_package_ref: command.key_package_ref,
        received_at,
        expires_at,
        package_not_after: command.package_not_after,
        status: ReservationStatus::Active,
        terminal: None,
    });
    sort_recovery_requests(&mut state.recovery_requests);
    sort_recovery_reservations(&mut state.recovery_reservations);
    validate_state(&state)?;
    let mut effects = complete_effects(
        TransitionEffects::new(PlanKind::Acceptance),
        Some(prior),
        &state,
    );
    #[cfg(not(test))]
    {
        effects.policy_evidence_digest = Some(command.relationship_evidence_digest);
    }
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(next_coordinate),
        effects,
        state,
    })
}

pub(crate) struct MetadataCommand {
    pub(crate) actor: DeviceIdentity,
    pub(crate) transition: TransitionEvidence,
    pub(crate) registration: LockedRegistrationProjection,
}

fn plan_metadata_inner(
    prior: &ConversationState,
    command: MetadataCommand,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(&command.transition, SignedMutationKind::MetadataTransition)?;
    require_transition_actor(&command.transition, &command.actor)?;
    if !command
        .registration
        .authorizes_transition(&command.transition)
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let participant = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if participant.status != ParticipantStatus::Active || participant.role != ParticipantRole::Admin
    {
        return Err(StateMachineError::AdminRequired);
    }
    let next_coordinate = coordinate_only_successor(&prior.coordinate)?;
    let metadata = require_metadata_body(prior, &command.transition, &next_coordinate)?.clone();
    let public_state = rebind_active_snapshot(prior.public_state(), next_coordinate)?;
    let mut state = prior.clone();
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        None,
        None,
        None,
    );
    state.coordinate = next_coordinate;
    state.producer = command.transition.clone();
    state.public_state = Some(public_state);
    state.metadata = Some(metadata);
    state.metadata_producer = Some(command.transition.clone());
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(next_coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::Metadata),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(crate) struct LeafRecoveryRequestCommand {
    pub(crate) actor: DeviceIdentity,
    pub(crate) recovery_request_id: [u8; 16],
    pub(crate) kind: LeafRecoveryKind,
    pub(crate) key_package_ref: [u8; 32],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) package_not_after: ServerTimestamp,
    pub(crate) evidence: RequestEvidence,
    #[cfg(not(test))]
    registration: LockedRegistrationProjection,
    #[cfg(not(test))]
    reservation: LockedRecoveryReservationProjection,
    #[cfg(not(test))]
    relationship_evidence_digest: [u8; 32],
}

fn plan_leaf_recovery_request_inner(
    prior: &ConversationState,
    command: LeafRecoveryRequestCommand,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    validate_request_evidence(
        &command.evidence,
        RequestEntryKind::LeafRecoveryRequest,
        prior.coordinate.conversation_id(),
        &command.recovery_request_id,
        &command.actor,
        command.received_at,
    )?;
    require_leaf_recovery_request_binding(&command.evidence, &prior.coordinate, command.kind)?;
    #[cfg(not(test))]
    if !command.registration.authorizes(&command.evidence)
        || !command
            .reservation
            .authorizes_request(&command.evidence, command.kind)
        || command.reservation.request_id != command.recovery_request_id
        || command.reservation.target != command.actor
        || command.reservation.key_package_ref != command.key_package_ref
        || command.reservation.package_not_after != command.package_not_after
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    if !is_uuid_v4(&command.recovery_request_id) {
        return Err(StateMachineError::InvalidTransition);
    }
    let participant = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if !participant.is_active() {
        return Err(StateMachineError::NotMember);
    }
    if prior.recovery_requests.iter().any(|request| {
        request.target == command.actor && request.status == RecoveryRequestStatus::Open
    }) {
        return Err(StateMachineError::LeafRecoveryAlreadyOpen);
    }
    let has_leaf = prior.leaf(&command.actor).is_some();
    if (command.kind == LeafRecoveryKind::Add && has_leaf)
        || (command.kind == LeafRecoveryKind::Replace && !has_leaf)
    {
        return Err(StateMachineError::RecoveryKindMismatch);
    }
    let expires_at = recovery_expiry(command.received_at, command.package_not_after)?;
    let mut state = prior.clone();
    state.recovery_requests.push(RecoveryRequest {
        request_id: command.recovery_request_id,
        target: command.actor.clone(),
        kind: command.kind,
        source: RecoverySource::Request,
        bound_coordinate: prior.coordinate,
        key_package_ref: command.key_package_ref,
        received_at: command.received_at,
        expires_at,
        status: RecoveryRequestStatus::Open,
        origin: RecoveryOriginEvidence::Request(command.evidence),
        terminal: None,
    });
    state.recovery_reservations.push(RecoveryReservation {
        request_id: command.recovery_request_id,
        target: command.actor,
        bound_coordinate: prior.coordinate,
        key_package_ref: command.key_package_ref,
        received_at: command.received_at,
        expires_at,
        package_not_after: command.package_not_after,
        status: ReservationStatus::Active,
        terminal: None,
    });
    sort_recovery_requests(&mut state.recovery_requests);
    sort_recovery_reservations(&mut state.recovery_reservations);
    validate_state(&state)?;
    let mut effects = complete_effects(
        TransitionEffects::new(PlanKind::RecoveryRequest),
        Some(prior),
        &state,
    );
    #[cfg(not(test))]
    {
        effects.policy_evidence_digest = Some(command.relationship_evidence_digest);
    }
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects,
        state,
    })
}

fn sort_recovery_requests(requests: &mut [RecoveryRequest]) {
    requests.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.request_id.cmp(&right.request_id))
    });
}

fn sort_recovery_reservations(reservations: &mut [RecoveryReservation]) {
    reservations.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.request_id.cmp(&right.request_id))
    });
}

fn sort_reset_requests(requests: &mut [ResetRequest]) {
    requests.sort_by_key(|request| request.request_id);
}

fn sort_leave_requests(requests: &mut [LeaveRequest]) {
    requests.sort_by(|left, right| {
        left.requester
            .cmp(&right.requester)
            .then_with(|| left.request_id.cmp(&right.request_id))
    });
}

fn recovery_expiry(
    received_at: ServerTimestamp,
    package_not_after: ServerTimestamp,
) -> Result<ServerTimestamp, StateMachineError> {
    if package_not_after <= received_at {
        return Err(StateMachineError::WorkExpired);
    }
    Ok(received_at
        .checked_add_millis(RECOVERY_RESERVATION_TTL_MILLIS)?
        .min(package_not_after))
}

pub(crate) struct LeafRecoveryCancellation {
    pub(crate) actor: DeviceIdentity,
    pub(crate) recovery_request_id: [u8; 16],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) evidence: RequestEvidence,
    #[cfg(not(test))]
    registration: LockedRegistrationProjection,
}

fn plan_leaf_recovery_cancellation_inner(
    prior: &ConversationState,
    command: LeafRecoveryCancellation,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    validate_request_evidence(
        &command.evidence,
        RequestEntryKind::LeafRecoveryCancellation,
        prior.coordinate.conversation_id(),
        &command.recovery_request_id,
        &command.actor,
        command.received_at,
    )?;
    #[cfg(not(test))]
    if !command.registration.authorizes(&command.evidence) {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    if command
        .evidence
        .body_binding
        .as_ref()
        .is_some_and(|binding| !matches!(binding, RequestBodyBinding::LeafRecoveryCancellation))
    {
        return Err(StateMachineError::InvalidTransition);
    }
    let request = prior
        .recovery_request(&command.recovery_request_id)
        .filter(|request| request.status == RecoveryRequestStatus::Open)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    if request.target != command.actor {
        return Err(StateMachineError::RecoveryDeviceMismatch);
    }
    if request.bound_coordinate != prior.coordinate {
        return Err(StateMachineError::LeafRecoverySuperseded);
    }
    if command.received_at >= request.expires_at {
        return Err(StateMachineError::WorkExpired);
    }
    if command.evidence.received_at <= recovery_origin_received_at(&request.origin)
        || command.evidence.request_digest == recovery_origin_request_digest(&request.origin)
    {
        return Err(StateMachineError::InvalidTransition);
    }
    let reservation = prior
        .recovery_reservation(&command.recovery_request_id)
        .filter(|reservation| reservation.status == ReservationStatus::Active)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    if reservation.target != request.target
        || reservation.bound_coordinate != request.bound_coordinate
        || reservation.key_package_ref != request.key_package_ref
        || reservation.expires_at != request.expires_at
    {
        return Err(StateMachineError::LeafRecoverySuperseded);
    }

    let mut state = prior.clone();
    let evidence = WorkTerminalEvidence::Request(command.evidence);
    let request = state
        .recovery_requests
        .iter_mut()
        .find(|request| request.request_id == command.recovery_request_id)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    request.status = RecoveryRequestStatus::Cancelled;
    request.terminal = Some(evidence.clone());
    let reservation = state
        .recovery_reservations
        .iter_mut()
        .find(|reservation| reservation.request_id == command.recovery_request_id)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    reservation.status = ReservationStatus::Released;
    reservation.terminal = Some(evidence);
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::RecoveryCancellation),
            Some(prior),
            &state,
        ),
        state,
    })
}

fn plan_welcome_response(
    prior: &ConversationState,
    evidence: RequestEvidence,
    successor_status: WelcomeStatus,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    let expected_kind = match successor_status {
        WelcomeStatus::Acknowledged => RequestEntryKind::WelcomeAcknowledgement,
        WelcomeStatus::Rejected => RequestEntryKind::WelcomeRejection,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let welcome = prior
        .welcome(&evidence.request_id)
        .filter(|welcome| welcome.status == WelcomeStatus::Pending)
        .ok_or(StateMachineError::InvalidWelcomeMapping)?;
    validate_request_evidence(
        &evidence,
        expected_kind,
        prior.coordinate.conversation_id(),
        &welcome.welcome_id,
        &welcome.recipient,
        evidence.received_at,
    )?;
    match evidence.body_binding.as_ref() {
        Some(RequestBodyBinding::WelcomeResponse {
            coordinates,
            transition_seq,
        }) if coordinates == &welcome.coordinate && *transition_seq == welcome.transition_seq => {}
        _ => return Err(StateMachineError::InvalidWelcomeMapping),
    }
    if evidence.received_at >= welcome.expires_at {
        return Err(StateMachineError::WorkExpired);
    }
    let mut state = prior.clone();
    let welcome = state
        .welcomes
        .iter_mut()
        .find(|welcome| welcome.welcome_id == evidence.request_id)
        .ok_or(StateMachineError::InvalidWelcomeMapping)?;
    welcome.status = successor_status;
    welcome.terminal = Some(WorkTerminalEvidence::Request(evidence));
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(match successor_status {
                WelcomeStatus::Acknowledged => PlanKind::WelcomeAcknowledgement,
                WelcomeStatus::Rejected => PlanKind::WelcomeRejection,
                _ => unreachable!("status checked above"),
            }),
            Some(prior),
            &state,
        ),
        state,
    })
}

fn plan_welcome_expiry(
    prior: &ConversationState,
    welcome_id: [u8; 16],
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    let welcome = prior
        .welcome(&welcome_id)
        .filter(|welcome| welcome.status == WelcomeStatus::Pending)
        .ok_or(StateMachineError::InvalidWelcomeMapping)?;
    let terminal_at = welcome.expires_at;
    let mut state = prior.clone();
    let welcome = state
        .welcomes
        .iter_mut()
        .find(|welcome| welcome.welcome_id == welcome_id)
        .ok_or(StateMachineError::InvalidWelcomeMapping)?;
    welcome.status = WelcomeStatus::Expired;
    welcome.terminal = Some(WorkTerminalEvidence::Expiry(terminal_at));
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::WelcomeExpiry),
            Some(prior),
            &state,
        ),
        state,
    })
}

#[cfg(not(test))]
fn welcome_cas_from_guard(
    prior: &ConversationState,
    guard: &LockedWelcomeGuard,
    successor_status: WelcomeStatus,
) -> Result<WelcomeCasBinding, StateMachineError> {
    let welcome_id = *guard.welcome_id().as_bytes();
    let welcome = prior
        .welcome(&welcome_id)
        .filter(|welcome| welcome.status == WelcomeStatus::Pending)
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
    let expires_at = ServerTimestamp::from_unix_millis(guard.expires_at().timestamp_millis())?;
    let locked_at = ServerTimestamp::from_unix_millis(guard.locked_at().timestamp_millis())?;
    if guard.conversation_id().as_bytes() != prior.coordinate.conversation_id()
        || guard.recipient_did().as_bytes() != welcome.recipient.principal().as_bytes()
        || guard.recipient_device_id().as_bytes() != welcome.recipient.device_id()
        || guard.transition_seq() != welcome.transition_seq
        || guard.coordinate() != &welcome.coordinate
        || guard.recovery_request_id().as_bytes() != &welcome.recovery_request_id
        || guard.key_package_ref() != &welcome.key_package_ref
        || guard.opaque_welcome() != welcome.opaque_welcome
        || guard.opaque_welcome_sha256() != &welcome.sha256
        || expires_at != welcome.expires_at
        || guard.durable_row_digest() == &[0; 32]
        || !matches!(
            successor_status,
            WelcomeStatus::Acknowledged | WelcomeStatus::Rejected | WelcomeStatus::Expired
        )
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(WelcomeCasBinding {
        transaction_id: guard.transaction_id().to_owned(),
        conversation_id: *guard.conversation_id().as_bytes(),
        welcome_id,
        recipient: welcome.recipient.clone(),
        transition_seq: welcome.transition_seq,
        coordinate: welcome.coordinate,
        recovery_request_id: welcome.recovery_request_id,
        key_package_ref: welcome.key_package_ref,
        opaque_welcome_sha256: welcome.sha256,
        expires_at,
        expected_status: WelcomeStatus::Pending,
        successor_status,
        locked_at,
        locked_row_digest: *guard.durable_row_digest(),
    })
}

#[cfg(not(test))]
fn invitation_quota_cas_from_guard(
    guard: &LockedInvitationQuotaGuard,
    expected_inviter: &PrincipalId,
    expected_new_recipients: &[String],
    transaction_id: &str,
    trusted_at: ServerTimestamp,
) -> Result<InvitationQuotaCasBinding, StateMachineError> {
    let locked_at = ServerTimestamp::from_unix_millis(guard.locked_at().timestamp_millis())?;
    if guard.transaction_id() != transaction_id
        || guard.inviter_did().as_bytes() != expected_inviter.as_bytes()
        || guard.new_recipient_dids() != expected_new_recipients
        || locked_at != trusted_at
        || guard.durable_row_digest() == &[0; 32]
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let successor_pending = guard
        .current_pending()
        .checked_add(guard.new_recipient_dids().len() as u64)
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
    let new_recipients = guard
        .new_recipient_dids()
        .iter()
        .map(|did| PrincipalId::new(did.as_bytes().to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(InvitationQuotaCasBinding {
        transaction_id: transaction_id.to_owned(),
        inviter: expected_inviter.clone(),
        new_recipients,
        expected_pending: guard.current_pending(),
        successor_pending,
        quota_limit: guard.quota_limit(),
        locked_at,
        locked_row_digest: *guard.durable_row_digest(),
    })
}

fn plan_device_revocation_inner(
    prior: &ConversationState,
    evidence: DeviceRevocationEvidence,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    if !validate_device_revocation_evidence(&evidence) {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let has_target_leaf = prior.leaf(&evidence.target).is_some();
    let target_request_indices = prior
        .recovery_requests
        .iter()
        .enumerate()
        .filter(|(_, request)| {
            request.target == evidence.target && request.status == RecoveryRequestStatus::Open
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if !has_target_leaf && target_request_indices.is_empty() {
        return Err(StateMachineError::RecoveryDeviceMismatch);
    }
    for index in &target_request_indices {
        let request = &prior.recovery_requests[*index];
        let target_generation = match &request.origin {
            RecoveryOriginEvidence::Acceptance(origin) => origin
                .authority
                .as_ref()
                .map(|authority| authority.auth_generation),
            RecoveryOriginEvidence::Request(origin) => Some(origin.auth_generation),
        }
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if target_generation != evidence.expected_target_auth_generation
            || evidence.accepted_at < request.received_at
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
    }

    let mut state = prior.clone();
    for index in target_request_indices {
        let request_id = state.recovery_requests[index].request_id;
        let terminal = if evidence.accepted_at >= state.recovery_requests[index].expires_at {
            WorkTerminalEvidence::Expiry(state.recovery_requests[index].expires_at)
        } else {
            WorkTerminalEvidence::DeviceRevocation(evidence.clone())
        };
        state.recovery_requests[index].status = match terminal {
            WorkTerminalEvidence::Expiry(_) => RecoveryRequestStatus::Expired,
            _ => RecoveryRequestStatus::Superseded,
        };
        state.recovery_requests[index].terminal = Some(terminal.clone());
        let reservation = state
            .recovery_reservations
            .iter_mut()
            .find(|reservation| {
                reservation.request_id == request_id
                    && reservation.status == ReservationStatus::Active
            })
            .ok_or(StateMachineError::LeafRecoveryNotFound)?;
        reservation.status = ReservationStatus::Released;
        reservation.terminal = Some(WorkTerminalEvidence::DeviceRevocation(evidence.clone()));
    }
    for welcome in state.welcomes.iter_mut().filter(|welcome| {
        welcome.recipient == evidence.target && welcome.status == WelcomeStatus::Pending
    }) {
        if evidence.accepted_at >= welcome.expires_at {
            welcome.status = WelcomeStatus::Expired;
            welcome.terminal = Some(WorkTerminalEvidence::Expiry(welcome.expires_at));
        } else {
            welcome.status = WelcomeStatus::Superseded;
            welcome.terminal = Some(WorkTerminalEvidence::DeviceRevocation(evidence.clone()));
        }
    }
    // Device authentication revocation is immediate authority/delivery state,
    // but it never fabricates an MLS Remove or closes an application interval.
    debug_assert_eq!(state.leaves, prior.leaves);
    debug_assert_eq!(state.intervals, prior.intervals);
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::DeviceRevocation),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(crate) struct LeafRecoveryFulfillment {
    pub(crate) actor: DeviceIdentity,
    pub(crate) target: DeviceIdentity,
    pub(crate) recovery_request_id: [u8; 16],
    pub(crate) welcome_id: [u8; 16],
    pub(crate) transition: TransitionEvidence,
    pub(crate) commit: VerifiedCommitPublicState,
    pub(crate) welcome: VerifiedRecoveryWelcome,
}

fn plan_leaf_recovery_fulfillment_inner(
    prior: &ConversationState,
    command: LeafRecoveryFulfillment,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(
        &command.transition,
        SignedMutationKind::LeafRecoveryFulfillment,
    )?;
    require_transition_actor(&command.transition, &command.actor)?;
    if !is_uuid_v4(&command.welcome_id) {
        return Err(StateMachineError::InvalidTransition);
    }
    if command.commit.prior_coordinate() != &prior.coordinate {
        return Err(StateMachineError::StaleCoordinates);
    }
    require_commit_body(
        &command.transition,
        SignedMutationKind::LeafRecoveryFulfillment,
        prior,
        &command.commit,
        Some(&command.recovery_request_id),
    )?;
    let request = prior
        .recovery_request(&command.recovery_request_id)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    if request.status != RecoveryRequestStatus::Open {
        return Err(StateMachineError::LeafRecoveryNotFound);
    }
    if request.bound_coordinate != prior.coordinate {
        return Err(StateMachineError::LeafRecoverySuperseded);
    }
    if command.transition.received_at >= request.expires_at {
        return Err(StateMachineError::WorkExpired);
    }
    let reservation = prior
        .recovery_reservation(&command.recovery_request_id)
        .filter(|reservation| reservation.status == ReservationStatus::Active)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    if reservation.bound_coordinate != request.bound_coordinate
        || reservation.target != request.target
        || reservation.key_package_ref != request.key_package_ref
        || reservation.expires_at != request.expires_at
        || reservation.package_not_after <= command.transition.received_at
    {
        return Err(StateMachineError::LeafRecoverySuperseded);
    }
    require_commit_manifest(
        prior,
        &command.transition,
        &command.commit,
        CommitManifestForm::Recovery {
            target: &command.target,
            recovery_request_id: &command.recovery_request_id,
            key_package_ref: &request.key_package_ref,
            welcome_id: &command.welcome_id,
            welcome: &command.welcome,
        },
    )?;
    if request.target != command.target {
        return Err(StateMachineError::RecoveryDeviceMismatch);
    }
    if prior.leaf(&command.actor).is_none() || command.actor == command.target {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    let target_participant = prior
        .participant(command.target.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if !target_participant.is_active() {
        return Err(StateMachineError::NotMember);
    }
    let [add] = command.commit.adds() else {
        return Err(StateMachineError::InvalidCommitEffects);
    };
    if add.basic_credential() != command.target.basic_credential()
        || add.key_package_ref() != &request.key_package_ref
        || command.welcome.key_package_ref() != &request.key_package_ref
    {
        return Err(StateMachineError::InvalidWelcomeMapping);
    }
    match request.kind {
        LeafRecoveryKind::Add => {
            if prior.leaf(&command.target).is_some() || !command.commit.removes().is_empty() {
                return Err(StateMachineError::InvalidCommitEffects);
            }
        }
        LeafRecoveryKind::Replace => {
            let [removed] = command.commit.removes() else {
                return Err(StateMachineError::InvalidCommitEffects);
            };
            let existing = prior
                .leaf(&command.target)
                .ok_or(StateMachineError::RecoveryKindMismatch)?;
            if removed.leaf_index() != existing.leaf_index
                || removed.basic_credential() != existing.basic_credential
                || removed.signature_key() != existing.signature_key
            {
                return Err(StateMachineError::InvalidCommitEffects);
            }
        }
    }
    verify_commit_actor(prior, &command.actor, &command.commit)?;
    let welcome_bytes = command.welcome.wire_bytes().to_vec();
    let welcome_sha256: [u8; 32] = Sha256::digest(&welcome_bytes).into();
    let welcome_expires_at = reservation.package_not_after;

    let mut state = prior.clone();
    let mut effects = TransitionEffects::new(PlanKind::Commit);
    if request.kind == LeafRecoveryKind::Replace {
        close_open_interval(
            &mut state.intervals,
            &command.target,
            &command.transition,
            CloseKind::Replace,
        )?;
        effects.closed_intervals.push(command.target.clone());
    }
    state.leaves = materialize_next_leaves(prior, &command.commit, Some(&command.target))?;
    open_interval(
        &mut state.intervals,
        command.target.clone(),
        command.transition.clone(),
        OpeningKind::Add,
        *command.commit.next().coordinate(),
    )?;
    effects.opened_intervals.push(command.target);
    effects.superseded_recovery_requests = state
        .recovery_requests
        .iter()
        .filter(|pending| {
            pending.status == RecoveryRequestStatus::Open
                && pending.request_id != command.recovery_request_id
        })
        .map(|request| request.request_id)
        .collect();
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        Some(command.recovery_request_id),
        None,
        None,
    );
    state.coordinate = *command.commit.next().coordinate();
    state.producer = command.transition.clone();
    state.metadata = transition_metadata(&command.transition).cloned();
    state.metadata_producer = state.metadata.as_ref().map(|_| command.transition.clone());
    state.public_state = Some(command.commit.into_next());
    state.welcomes.push(WelcomeWork {
        welcome_id: command.welcome_id,
        recipient: request.target.clone(),
        transition_seq: command.transition.seq,
        coordinate: state.coordinate,
        recovery_request_id: command.recovery_request_id,
        key_package_ref: request.key_package_ref,
        opaque_welcome: welcome_bytes,
        sha256: welcome_sha256,
        expires_at: welcome_expires_at,
        status: WelcomeStatus::Pending,
        terminal: None,
    });
    state
        .welcomes
        .sort_by(|left, right| left.welcome_id.cmp(&right.welcome_id));
    sort_intervals(&mut state.intervals);
    validate_state(&state)?;
    effects.complete(Some(prior), &state);

    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(state.coordinate),
        state,
        effects,
    })
}

pub(crate) struct CommitCommand {
    pub(crate) actor: DeviceIdentity,
    pub(crate) transition: TransitionEvidence,
    pub(crate) commit: VerifiedCommitPublicState,
}

/// Plan a generic Commit. Adds are forbidden here; removals and the mandatory
/// sender update must exactly equal the verified public MLS effects.
fn plan_commit_inner(
    prior: &ConversationState,
    command: CommitCommand,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(&command.transition, SignedMutationKind::CommitTransition)?;
    require_transition_actor(&command.transition, &command.actor)?;
    if command.commit.prior_coordinate() != &prior.coordinate {
        return Err(StateMachineError::StaleCoordinates);
    }
    require_commit_body(
        &command.transition,
        SignedMutationKind::CommitTransition,
        prior,
        &command.commit,
        None,
    )?;
    if !command.commit.adds().is_empty() {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    require_commit_manifest(
        prior,
        &command.transition,
        &command.commit,
        CommitManifestForm::Generic,
    )?;
    verify_commit_actor(prior, &command.actor, &command.commit)?;
    for removed in command.commit.removes() {
        let leaf = prior
            .leaves
            .iter()
            .find(|leaf| leaf.leaf_index == removed.leaf_index())
            .ok_or(StateMachineError::InvalidCommitEffects)?;
        if leaf.device == command.actor
            || leaf.basic_credential != removed.basic_credential()
            || leaf.signature_key != removed.signature_key()
        {
            return Err(StateMachineError::InvalidCommitEffects);
        }
    }

    let mut state = prior.clone();
    let removed_devices = command
        .commit
        .removes()
        .iter()
        .filter_map(|removed| {
            prior
                .leaves
                .iter()
                .find(|leaf| leaf.leaf_index == removed.leaf_index())
                .map(|leaf| leaf.device.clone())
        })
        .collect::<Vec<_>>();
    for device in &removed_devices {
        close_open_interval(
            &mut state.intervals,
            device,
            &command.transition,
            CloseKind::Remove,
        )?;
    }
    state.leaves = materialize_next_leaves(prior, &command.commit, None)?;
    if state.leaves.is_empty() {
        return Err(StateMachineError::InvariantViolation);
    }
    let mut effects = TransitionEffects::new(PlanKind::Commit);
    effects.closed_intervals = removed_devices;
    effects.superseded_recovery_requests = state
        .recovery_requests
        .iter()
        .filter(|request| {
            request.status == RecoveryRequestStatus::Open
                && request.bound_coordinate == prior.coordinate
        })
        .map(|request| request.request_id)
        .collect();
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        None,
        None,
        None,
    );
    state.coordinate = *command.commit.next().coordinate();
    state.producer = command.transition.clone();
    state.metadata = transition_metadata(&command.transition).cloned();
    state.metadata_producer = state.metadata.as_ref().map(|_| command.transition.clone());
    state.public_state = Some(command.commit.into_next());
    validate_state(&state)?;
    effects.complete(Some(prior), &state);
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(state.coordinate),
        state,
        effects,
    })
}

fn verify_commit_actor(
    prior: &ConversationState,
    actor: &DeviceIdentity,
    commit: &VerifiedCommitPublicState,
) -> Result<(), StateMachineError> {
    let actor_leaf = prior
        .leaf(actor)
        .ok_or(StateMachineError::InvalidCommitEffects)?;
    let sender = commit.sender_update();
    if sender.leaf_index() != actor_leaf.leaf_index
        || sender.basic_credential() != actor_leaf.basic_credential
        || sender.signature_key() != actor_leaf.signature_key
        || sender.prior_encryption_key() != actor_leaf.encryption_key
    {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    Ok(())
}

fn materialize_next_leaves(
    prior: &ConversationState,
    commit: &VerifiedCommitPublicState,
    added_target: Option<&DeviceIdentity>,
) -> Result<Vec<LeafRecord>, StateMachineError> {
    let removed_indices = commit
        .removes()
        .iter()
        .map(|remove| remove.leaf_index())
        .collect::<BTreeSet<_>>();
    let sender_index = commit.sender_update().leaf_index();
    let mut expected = prior
        .leaves
        .iter()
        .filter(|leaf| !removed_indices.contains(&leaf.leaf_index))
        .cloned()
        .collect::<Vec<_>>();
    for leaf in &mut expected {
        if leaf.leaf_index == sender_index {
            leaf.encryption_key = commit.sender_update().next_encryption_key().to_vec();
        }
    }
    if let Some(target) = added_target {
        let [add] = commit.adds() else {
            return Err(StateMachineError::InvalidCommitEffects);
        };
        expected.push(LeafRecord {
            device: target.clone(),
            leaf_index: add.leaf_index(),
            basic_credential: add.basic_credential().to_vec(),
            signature_key: add.signature_key().to_vec(),
            encryption_key: add.encryption_key().to_vec(),
            key_package_ref: Some(*add.key_package_ref()),
        });
    } else if !commit.adds().is_empty() {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    expected.sort_by_key(|leaf| leaf.leaf_index);

    let summary = commit.next().binding().tree_summary().leaves();
    if expected.len() != summary.len()
        || !expected.iter().zip(summary).all(|(expected, actual)| {
            expected.leaf_index == actual.leaf_index()
                && expected.basic_credential == actual.basic_credential()
                && expected.signature_key == actual.signature_key()
                && expected.encryption_key == actual.encryption_key()
        })
    {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    Ok(expected)
}

pub(crate) struct ResetRequestCommand {
    pub(crate) actor: DeviceIdentity,
    pub(crate) reset_request_id: [u8; 16],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) evidence: RequestEvidence,
    #[cfg(not(test))]
    registration: LockedRegistrationProjection,
}

fn plan_reset_request_inner(
    prior: &ConversationState,
    command: ResetRequestCommand,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    validate_request_evidence(
        &command.evidence,
        RequestEntryKind::ResetRequest,
        prior.coordinate.conversation_id(),
        &command.reset_request_id,
        &command.actor,
        command.received_at,
    )?;
    require_request_prior(&command.evidence, &prior.coordinate)?;
    #[cfg(not(test))]
    if !command.registration.authorizes(&command.evidence) {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    if !is_uuid_v4(&command.reset_request_id) {
        return Err(StateMachineError::InvalidTransition);
    }
    let participant = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if !participant.is_active() {
        return Err(StateMachineError::NotMember);
    }
    if prior
        .reset_requests
        .iter()
        .any(|request| request.status == ResetRequestStatus::Pending)
    {
        return Err(StateMachineError::ResetAlreadyPending);
    }
    let expires_at = command.received_at.checked_add_millis(CONSENT_TTL_MILLIS)?;
    let mut state = prior.clone();
    state.reset_requests.push(ResetRequest {
        request_id: command.reset_request_id,
        requester: command.actor,
        bound_coordinate: prior.coordinate,
        received_at: command.received_at,
        expires_at,
        status: ResetRequestStatus::Pending,
        origin: command.evidence,
        terminal: None,
    });
    sort_reset_requests(&mut state.reset_requests);
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::ResetRequest),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(crate) struct ResetActivation {
    pub(crate) actor: DeviceIdentity,
    pub(crate) reset_request_id: [u8; 16],
    pub(crate) transition: TransitionEvidence,
    pub(crate) successor_public_state: ActivePublicState,
}

fn plan_reset_activation_inner(
    prior: &ConversationState,
    command: ResetActivation,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(&command.transition, SignedMutationKind::ResetActivation)?;
    require_transition_actor(&command.transition, &command.actor)?;
    let request = prior
        .reset_requests
        .iter()
        .find(|request| {
            request.request_id == command.reset_request_id
                && request.status == ResetRequestStatus::Pending
        })
        .ok_or(StateMachineError::ResetRequestNotFound)?;
    if request.bound_coordinate != prior.coordinate {
        return Err(StateMachineError::ResetRequestStale);
    }
    if command.transition.received_at >= request.expires_at {
        return Err(StateMachineError::WorkExpired);
    }
    let actor = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if actor.status != ParticipantStatus::Active || actor.role != ParticipantRole::Admin {
        return Err(StateMachineError::AdminRequired);
    }
    let retired = retired_coordinate(&prior.coordinate)?;
    let successor = *command.successor_public_state.coordinate();
    let expected_generation = prior
        .coordinate
        .generation()
        .checked_add(1)
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(StateMachineError::CoordinateOverflow)?;
    if successor.conversation_id() != prior.coordinate.conversation_id()
        || successor.generation() != expected_generation
        || successor.state_version() != 0
        || successor.epoch() != 0
        || successor.lifecycle() != PublicGroupSnapshotLifecycle::Active
        || successor.group_id() == prior.coordinate.group_id()
    {
        return Err(StateMachineError::ResetSuccessorMismatch);
    }
    require_reset_activation_body(
        &command.transition,
        &command.reset_request_id,
        prior,
        &retired,
        &command.actor,
        &command.successor_public_state,
    )?;
    let actor_leaf = singleton_genesis_leaf(&command.successor_public_state, &command.actor)
        .map_err(|_| StateMachineError::ResetSuccessorMismatch)?;

    let mut state = prior.clone();
    let mut effects = TransitionEffects::new(PlanKind::ResetActivation);
    let open_devices = state
        .intervals
        .iter()
        .filter(|interval| interval.end.is_none())
        .map(|interval| interval.recipient.clone())
        .collect::<Vec<_>>();
    for device in &open_devices {
        close_open_interval(
            &mut state.intervals,
            device,
            &command.transition,
            CloseKind::Reset,
        )?;
    }
    effects.closed_intervals = open_devices;
    open_interval(
        &mut state.intervals,
        command.actor.clone(),
        command.transition.clone(),
        OpeningKind::Reset,
        successor,
    )?;
    effects.opened_intervals.push(command.actor);
    effects.superseded_recovery_requests = state
        .recovery_requests
        .iter()
        .filter(|request| {
            request.status == RecoveryRequestStatus::Open
                && request.bound_coordinate == prior.coordinate
        })
        .map(|request| request.request_id)
        .collect();
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        None,
        Some(command.reset_request_id),
        None,
    );
    state.coordinate = successor;
    state.producer = command.transition.clone();
    state.metadata = transition_metadata(&command.transition).cloned();
    state.metadata_producer = state.metadata.as_ref().map(|_| command.transition.clone());
    state.public_state = Some(command.successor_public_state);
    state.leaves = vec![actor_leaf];
    sort_intervals(&mut state.intervals);
    validate_state(&state)?;
    effects.complete(Some(prior), &state);
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: Some(retired),
        successor_coordinate: Some(successor),
        state,
        effects,
    })
}

pub(crate) struct ZeroLeafLeave {
    pub(crate) actor: DeviceIdentity,
    pub(crate) transition: TransitionEvidence,
}

fn plan_zero_leaf_leave_inner(
    prior: &ConversationState,
    command: ZeroLeafLeave,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(&command.transition, SignedMutationKind::ZeroLeafLeave)?;
    require_transition_actor(&command.transition, &command.actor)?;
    if prior.kind == ConversationKind::Direct {
        return Err(StateMachineError::DirectParticipantMutationForbidden);
    }
    let participant_index = prior
        .participants
        .binary_search_by(|participant| participant.principal.cmp(command.actor.principal()))
        .map_err(|_| StateMachineError::NotParticipant)?;
    if prior
        .leaves
        .iter()
        .any(|leaf| leaf.device.principal() == command.actor.principal())
    {
        return Err(StateMachineError::InvariantViolation);
    }
    if would_remove_last_active_admin(prior, command.actor.principal()) {
        return Err(StateMachineError::LastAdminRequired);
    }
    let next_coordinate = coordinate_only_successor(&prior.coordinate)?;
    require_coordinate_only_body(
        &command.transition,
        SignedMutationKind::ZeroLeafLeave,
        prior.kind,
        &prior.coordinate,
        &next_coordinate,
    )?;
    let public_state = rebind_active_snapshot(prior.public_state(), next_coordinate)?;
    let mut state = prior.clone();
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        None,
        None,
        None,
    );
    state.participants.remove(participant_index);
    state.coordinate = next_coordinate;
    state.producer = command.transition.clone();
    state.public_state = Some(public_state);
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(next_coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::ZeroLeafLeave),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(crate) struct LeaveRequestCommand {
    pub(crate) actor: DeviceIdentity,
    pub(crate) leave_request_id: [u8; 16],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) evidence: RequestEvidence,
    pub(crate) registration: LockedRegistrationProjection,
}

fn plan_leave_request_inner(
    prior: &ConversationState,
    command: LeaveRequestCommand,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    validate_request_evidence(
        &command.evidence,
        RequestEntryKind::LeaveRequest,
        prior.coordinate.conversation_id(),
        &command.leave_request_id,
        &command.actor,
        command.received_at,
    )?;
    require_request_prior(&command.evidence, &prior.coordinate)?;
    if !command.registration.authorizes(&command.evidence) {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    if prior.kind == ConversationKind::Direct {
        return Err(StateMachineError::DirectParticipantMutationForbidden);
    }
    if !is_uuid_v4(&command.leave_request_id) {
        return Err(StateMachineError::InvalidTransition);
    }
    let participant = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if !participant.is_active()
        || !prior
            .leaves
            .iter()
            .any(|leaf| leaf.device.principal() == command.actor.principal())
    {
        return Err(StateMachineError::NotMember);
    }
    if would_remove_last_active_admin(prior, command.actor.principal()) {
        return Err(StateMachineError::LastAdminRequired);
    }
    if prior.leave_requests.iter().any(|request| {
        request.requester.principal() == command.actor.principal()
            && request.status == LeaveRequestStatus::Pending
    }) {
        return Err(StateMachineError::LeaveAlreadyPending);
    }
    let expires_at = command.received_at.checked_add_millis(CONSENT_TTL_MILLIS)?;
    let mut state = prior.clone();
    state.leave_requests.push(LeaveRequest {
        request_id: command.leave_request_id,
        requester: command.actor,
        bound_coordinate: prior.coordinate,
        received_at: command.received_at,
        expires_at,
        status: LeaveRequestStatus::Pending,
        origin: command.evidence,
        terminal: None,
    });
    sort_leave_requests(&mut state.leave_requests);
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::LeaveRequest),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(crate) struct LeaveCancellation {
    pub(crate) actor: DeviceIdentity,
    pub(crate) leave_request_id: [u8; 16],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) evidence: RequestEvidence,
    pub(crate) registration: LockedRegistrationProjection,
}

fn plan_leave_cancellation_inner(
    prior: &ConversationState,
    command: LeaveCancellation,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    validate_request_evidence(
        &command.evidence,
        RequestEntryKind::LeaveCancellation,
        prior.coordinate.conversation_id(),
        &command.leave_request_id,
        &command.actor,
        command.received_at,
    )?;
    require_request_coordinate_binding(&command.evidence, prior.coordinate.conversation_id())?;
    if !command.registration.authorizes(&command.evidence) {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let index = prior
        .leave_requests
        .iter()
        .position(|request| {
            request.request_id == command.leave_request_id
                && request.status == LeaveRequestStatus::Pending
        })
        .ok_or(StateMachineError::LeaveRequestNotFound)?;
    let request = &prior.leave_requests[index];
    if request.requester.principal() != command.actor.principal()
        || request.bound_coordinate != prior.coordinate
    {
        return Err(StateMachineError::LeaveRequestNotFound);
    }
    if command.received_at >= request.expires_at {
        return Err(StateMachineError::WorkExpired);
    }
    let Some(cancellation_seq) = command.evidence.control_seq else {
        return Err(StateMachineError::InvalidTransition);
    };
    let Some(origin_seq) = request.origin.control_seq else {
        return Err(StateMachineError::InvariantViolation);
    };
    if cancellation_seq <= origin_seq
        || command.evidence.control_entry_id == request.origin.control_entry_id
    {
        return Err(StateMachineError::InvalidTransition);
    }
    let mut state = prior.clone();
    state.leave_requests[index].status = LeaveRequestStatus::Cancelled;
    state.leave_requests[index].terminal = Some(WorkTerminalEvidence::Request(command.evidence));
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::LeaveCancellation),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(crate) struct LeaveFulfillment {
    pub(crate) actor: DeviceIdentity,
    pub(crate) requester: PrincipalId,
    pub(crate) leave_request_id: [u8; 16],
    pub(crate) transition: TransitionEvidence,
    pub(crate) commit: VerifiedCommitPublicState,
}

/// Fulfill retained group-leave consent with a different-DID current leaf.
/// The Commit must remove every and only requester leaf and contain no Add.
fn plan_leave_fulfillment_inner(
    prior: &ConversationState,
    command: LeaveFulfillment,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(
        &command.transition,
        SignedMutationKind::LeaveCommitFulfillment,
    )?;
    require_transition_actor(&command.transition, &command.actor)?;
    if prior.kind == ConversationKind::Direct {
        return Err(StateMachineError::DirectParticipantMutationForbidden);
    }
    let request = prior
        .leave_requests
        .iter()
        .find(|request| {
            request.request_id == command.leave_request_id
                && request.status == LeaveRequestStatus::Pending
        })
        .ok_or(StateMachineError::LeaveRequestNotFound)?;
    if request.bound_coordinate != prior.coordinate
        || request.requester.principal() != &command.requester
    {
        return Err(StateMachineError::LeaveRequestNotFound);
    }
    if command.transition.received_at >= request.expires_at {
        return Err(StateMachineError::WorkExpired);
    }
    if command.actor.principal() == &command.requester || prior.leaf(&command.actor).is_none() {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    if command.commit.prior_coordinate() != &prior.coordinate {
        return Err(StateMachineError::StaleCoordinates);
    }
    require_commit_body(
        &command.transition,
        SignedMutationKind::LeaveCommitFulfillment,
        prior,
        &command.commit,
        Some(&command.leave_request_id),
    )?;
    if !command.commit.adds().is_empty() {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    require_commit_manifest(
        prior,
        &command.transition,
        &command.commit,
        CommitManifestForm::Leave {
            requester: &command.requester,
        },
    )?;
    let requester = prior
        .participant(&command.requester)
        .ok_or(StateMachineError::NotParticipant)?;
    if !requester.is_active() {
        return Err(StateMachineError::NotMember);
    }
    if would_remove_last_active_admin(prior, &command.requester) {
        return Err(StateMachineError::LastAdminRequired);
    }
    verify_commit_actor(prior, &command.actor, &command.commit)?;

    let requester_leaves = prior
        .leaves
        .iter()
        .filter(|leaf| leaf.device.principal() == &command.requester)
        .collect::<Vec<_>>();
    if requester_leaves.is_empty() || requester_leaves.len() != command.commit.removes().len() {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    let expected_indices = requester_leaves
        .iter()
        .map(|leaf| leaf.leaf_index)
        .collect::<BTreeSet<_>>();
    let removed_indices = command
        .commit
        .removes()
        .iter()
        .map(|effect| effect.leaf_index())
        .collect::<BTreeSet<_>>();
    if expected_indices != removed_indices {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    for effect in command.commit.removes() {
        let leaf = requester_leaves
            .iter()
            .find(|leaf| leaf.leaf_index == effect.leaf_index())
            .ok_or(StateMachineError::InvalidCommitEffects)?;
        if effect.basic_credential() != leaf.basic_credential
            || effect.signature_key() != leaf.signature_key
        {
            return Err(StateMachineError::InvalidCommitEffects);
        }
    }

    let mut state = prior.clone();
    let mut effects = TransitionEffects::new(PlanKind::Commit);
    for leaf in &requester_leaves {
        close_open_interval(
            &mut state.intervals,
            &leaf.device,
            &command.transition,
            CloseKind::Remove,
        )?;
        effects.closed_intervals.push(leaf.device.clone());
    }
    state.leaves = materialize_next_leaves(prior, &command.commit, None)?;
    state
        .participants
        .retain(|participant| participant.principal != command.requester);
    effects.superseded_recovery_requests = state
        .recovery_requests
        .iter()
        .filter(|request| {
            request.status == RecoveryRequestStatus::Open
                && request.bound_coordinate == prior.coordinate
        })
        .map(|request| request.request_id)
        .collect();
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        None,
        None,
        Some(command.leave_request_id),
    );
    state.coordinate = *command.commit.next().coordinate();
    state.producer = command.transition.clone();
    state.metadata = transition_metadata(&command.transition).cloned();
    state.metadata_producer = state.metadata.as_ref().map(|_| command.transition.clone());
    state.public_state = Some(command.commit.into_next());
    validate_state(&state)?;
    effects.complete(Some(prior), &state);
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(state.coordinate),
        state,
        effects,
    })
}

pub(crate) struct CloseConversation {
    pub(crate) actor: DeviceIdentity,
    pub(crate) transition: TransitionEvidence,
}

fn plan_close_inner(
    prior: &ConversationState,
    command: CloseConversation,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(&command.transition, SignedMutationKind::ConversationClose)?;
    require_transition_actor(&command.transition, &command.actor)?;
    let actor = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    match prior.kind {
        ConversationKind::Direct => {}
        ConversationKind::Group
            if prior.participants.len() == 1
                && actor.status == ParticipantStatus::Active
                && actor.role == ParticipantRole::Admin => {}
        ConversationKind::Group => return Err(StateMachineError::ConversationCloseNotAllowed),
    }
    let latest_historical_seq = prior
        .intervals
        .iter()
        .map(|interval| {
            interval
                .end
                .as_ref()
                .map_or(interval.opening.seq, |end| end.evidence.seq)
        })
        .max()
        .ok_or(StateMachineError::InvalidIntervalBoundary)?;
    if command.transition.seq <= latest_historical_seq {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    let retired = retired_coordinate(&prior.coordinate)?;
    require_coordinate_only_body(
        &command.transition,
        SignedMutationKind::ConversationClose,
        prior.kind,
        &prior.coordinate,
        &retired,
    )?;
    let mut state = prior.clone();
    let mut effects = TransitionEffects::new(PlanKind::Close);
    let open_devices = state
        .intervals
        .iter()
        .filter(|interval| interval.end.is_none())
        .map(|interval| interval.recipient.clone())
        .collect::<Vec<_>>();
    for device in &open_devices {
        close_open_interval(
            &mut state.intervals,
            device,
            &command.transition,
            CloseKind::Terminal,
        )?;
    }
    effects.closed_intervals = open_devices;

    let historical_devices = state
        .intervals
        .iter()
        .map(|interval| interval.recipient.clone())
        .collect::<BTreeSet<_>>();
    if historical_devices
        .iter()
        .any(|device| state.terminal_proof(device).is_some())
    {
        return Err(StateMachineError::ConversationClosed);
    }
    state.terminal_proofs = historical_devices
        .iter()
        .cloned()
        .map(|recipient| ScheduleTerminalProof {
            recipient,
            conversation_id: *prior.coordinate.conversation_id(),
            evidence: command.transition.clone(),
        })
        .collect();
    effects.terminal_proof_recipients = historical_devices.into_iter().collect();
    effects.superseded_recovery_requests = state
        .recovery_requests
        .iter()
        .filter(|request| {
            request.status == RecoveryRequestStatus::Open
                && request.bound_coordinate == prior.coordinate
        })
        .map(|request| request.request_id)
        .collect();
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        None,
        None,
        None,
    );
    state.coordinate = retired;
    state.producer = command.transition.clone();
    state.public_state = None;
    state.leaves.clear();
    validate_terminal_state(&state)?;
    effects.complete(Some(prior), &state);
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: Some(retired),
        successor_coordinate: None,
        state,
        effects,
    })
}

// ---------------------------------------------------------------------------
// Task E2b-3 test-support: build a metadata-bearing creation
// `ConversationPersistencePlan` from the pure planner + a synthesized head CAS,
// so the executor's end-to-end COMMIT path can be exercised from the integration
// harness. These are the minimal `pub(crate)` seams the E2b-2 report anticipated.
//
// FAITHFULNESS: production creation evidence (authenticated) carries a
// `Creation` body whose metadata has `metadata_version == 1`,
// `origin_transition_id == transitionId`, `author == actor`, and
// `roleAtOrigin/deviceStatusAtOrigin == admin/active` (validated during
// `decode_metadata_snapshot`, and re-checked by `require_creation_body` +
// `metadata_author_matches_evidence` whenever `authority.is_some()`). The
// constructors below reproduce exactly that shape. `require_creation_body` skips
// the manifest/author cross-checks when `authority.is_none()` (the test-seam
// case), so a bare roster manifest is legal here; the metadata itself is still
// built to the production shape the COMMIT-time trigger demands. No production
// path (`plan_*`, `require_creation_body`, the decode) is modified.
// ---------------------------------------------------------------------------
#[cfg(test)]
impl MetadataSnapshotBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_creation(
        conversation_id: [u8; 16],
        generation: u64,
        epoch: u64,
        group_context_hash: [u8; 32],
        transition_id: [u8; 16],
        origin_seq: u64,
        author: DeviceIdentity,
        author_key_id: [u8; 32],
        signature_public_key: [u8; 32],
        auth_generation: u64,
        metadata_version: u64,
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    ) -> Self {
        let ciphertext_sha256: [u8; 32] = Sha256::digest(&ciphertext).into();
        // The canonical snapshot/digest are not persisted by the executor for a
        // self-origin snapshot (the DB stores nonce/ciphertext/hash + author cols);
        // use a stable, self-consistent placeholder so equality/debug hold.
        let canonical_snapshot = ciphertext.clone();
        let digest: [u8; 32] = Sha256::digest(&canonical_snapshot).into();
        Self {
            coordinate: MetadataCryptoCoordinate {
                conversation_id,
                generation,
                epoch,
                group_context_hash,
            },
            origin_transition_id: transition_id,
            metadata_version,
            nonce,
            ciphertext,
            ciphertext_sha256,
            avatar_binding_digest: None,
            author_proof: MetadataAuthorProofBinding {
                author,
                author_key_id,
                signature_public_key,
                auth_generation_at_origin: auth_generation,
                origin_transition_id: transition_id,
                origin_seq,
            },
            canonical_snapshot,
            digest,
        }
    }
}

#[cfg(test)]
impl TransitionEvidence {
    /// A creation `TransitionEvidence` carrying the exact `Creation` body a real
    /// creation produces, including the metadata snapshot the COMMIT-time
    /// `assert_metadata_snapshot_mapping` demands. `authority` stays `None` (the
    /// test seam), which the pure planner accepts; the metadata is nevertheless
    /// built to the production shape.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_creation_with_metadata(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        kind: ConversationKind,
        next: PublicGroupSnapshotCoordinate,
        creator: DeviceIdentity,
        metadata: MetadataSnapshotBinding,
    ) -> Result<Self, StateMachineError> {
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::Creation {
            kind,
            next,
            manifest: RosterManifestBinding {
                participants: Vec::new(),
                actor_leaf: creator,
            },
            group_info_sha256: [0u8; 32],
            metadata,
        });
        Ok(evidence)
    }

    /// A `resetActivation` `TransitionEvidence` carrying the exact `ResetActivation`
    /// body a real activation produces (matching kind/reset_request_id/prior/
    /// retired/successor coordinates + the successor metadata snapshot).
    /// `authority` stays `None`, which `require_reset_activation_body` accepts
    /// while still requiring those coordinate fields to match.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_reset_activation_with_metadata(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        kind: ConversationKind,
        reset_request_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        retired: PublicGroupSnapshotCoordinate,
        successor: PublicGroupSnapshotCoordinate,
        activator: DeviceIdentity,
        metadata: MetadataSnapshotBinding,
    ) -> Result<Self, StateMachineError> {
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::ResetActivation {
            kind,
            reset_request_id,
            prior,
            retired,
            successor,
            manifest: RosterManifestBinding {
                participants: Vec::new(),
                actor_leaf: activator,
            },
            group_info_sha256: [0u8; 32],
            metadata,
        });
        Ok(evidence)
    }

    /// An `acceptConversation` `TransitionEvidence` carrying the exact `Acceptance`
    /// body a real acceptance produces: the coordinate-only successor `next`, the
    /// `add` recovery binding bound to `next`, and the retained-invitation
    /// provenance (which must match the pending participant's invitation).
    /// `authority` stays `None`, which `require_acceptance_body` accepts while
    /// still enforcing the request-id / conversation / target / kind /
    /// bound-coordinate fields.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_acceptance(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        prior: PublicGroupSnapshotCoordinate,
        recovery_request_id: [u8; 16],
        acceptor: DeviceIdentity,
        invitation_transition_id: [u8; 16],
        inviter: DeviceIdentity,
        key_package_ref: [u8; 32],
        requester_key_id: [u8; 32],
        requester_auth_generation: u64,
        package_not_after: ServerTimestamp,
    ) -> Result<Self, StateMachineError> {
        let next = coordinate_only_successor(&prior)?;
        let expires_at = recovery_expiry(received_at, package_not_after)?;
        let wrapper = vec![0xAA_u8; 32];
        let wrapper_sha256: [u8; 32] = Sha256::digest(&wrapper).into();
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::Acceptance {
            prior,
            next,
            recovery_request_id,
            invitation_provenance: InvitationBinding {
                transition_id: invitation_transition_id,
                inviter,
            },
            recovery: AcceptanceRecoveryBinding {
                request_id: recovery_request_id,
                conversation_id: *prior.conversation_id(),
                target: acceptor,
                kind: LeafRecoveryKind::Add,
                bound_coordinate: next,
                requester_key_id,
                requester_auth_generation,
                key_package_ref,
                key_package_wrapper: wrapper,
                key_package_wrapper_sha256: wrapper_sha256,
                requested_at: received_at,
                expires_at,
                canonical_digest: [0x5A_u8; 32],
            },
        });
        Ok(evidence)
    }

    /// A `signedLeafRecoveryFulfillment` `TransitionEvidence` carrying the exact
    /// `LeafRecoveryFulfillment` body a real signed fulfillment carries: the
    /// prior/next coordinates + recovery_request_id `require_commit_body` matches,
    /// and the Add manifest + welcome binding `require_commit_manifest` validates
    /// against the corpus ADD commit (single add of `target` with the reserved
    /// `key_package_ref`, the welcome bound to that target/request/ref), plus the
    /// mandatory metadata re-encryption snapshot the `leafRecovery` DDL arm demands.
    /// `authority` stays `None` (the test seam), which skips the crypto-digest
    /// cross-checks while still enforcing every coordinate/manifest/welcome field.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_leaf_recovery_fulfillment_with_metadata(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        recovery_request_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        target: DeviceIdentity,
        key_package_ref: [u8; 32],
        welcome_id: [u8; 16],
        welcome_wire_bytes: Vec<u8>,
        metadata: MetadataSnapshotBinding,
    ) -> Result<Self, StateMachineError> {
        let welcome_sha256: [u8; 32] = Sha256::digest(&welcome_wire_bytes).into();
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::LeafRecoveryFulfillment {
            recovery_request_id,
            prior,
            next,
            aad_digest: [0u8; 32],
            manifest: TransitionManifestBinding {
                participant_changes: Vec::new(),
                leaf_changes: vec![ManifestLeafChange::Add {
                    device: target.clone(),
                    recovery_request_id,
                    key_package_ref,
                }],
                leaf_recovery_request_id: Some(recovery_request_id),
                welcome: Some(ManifestWelcomeBinding {
                    welcome_id,
                    opaque_welcome: welcome_wire_bytes,
                    sha256: welcome_sha256,
                    recipient: target,
                    recovery_request_id,
                    key_package_ref,
                }),
            },
            commit_sha256: [0u8; 32],
            metadata,
        });
        Ok(evidence)
    }

    /// The `replace`-shaped leaf-recovery fulfillment `TransitionEvidence`: like
    /// `for_test_leaf_recovery_fulfillment_with_metadata`, but the manifest ALSO
    /// carries a `ManifestLeafChange::Remove(target)` for the rotated leaf, so
    /// `require_commit_manifest`'s `manifest_removed == commit.removes()` invariant
    /// (a `replace` commit removes the target's OLD leaf) holds. The `Recovery`
    /// form still requires exactly one Add for the target; the Remove is validated
    /// only against the commit's removes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_leaf_recovery_replace_fulfillment_with_metadata(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        recovery_request_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        target: DeviceIdentity,
        key_package_ref: [u8; 32],
        welcome_id: [u8; 16],
        welcome_wire_bytes: Vec<u8>,
        metadata: MetadataSnapshotBinding,
    ) -> Result<Self, StateMachineError> {
        let welcome_sha256: [u8; 32] = Sha256::digest(&welcome_wire_bytes).into();
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::LeafRecoveryFulfillment {
            recovery_request_id,
            prior,
            next,
            aad_digest: [0u8; 32],
            manifest: TransitionManifestBinding {
                participant_changes: Vec::new(),
                leaf_changes: vec![
                    ManifestLeafChange::Remove(target.clone()),
                    ManifestLeafChange::Add {
                        device: target.clone(),
                        recovery_request_id,
                        key_package_ref,
                    },
                ],
                leaf_recovery_request_id: Some(recovery_request_id),
                welcome: Some(ManifestWelcomeBinding {
                    welcome_id,
                    opaque_welcome: welcome_wire_bytes,
                    sha256: welcome_sha256,
                    recipient: target,
                    recovery_request_id,
                    key_package_ref,
                }),
            },
            commit_sha256: [0u8; 32],
            metadata,
        });
        Ok(evidence)
    }

    /// A generic `signedCommitTransition` `TransitionEvidence`: the exact `Commit`
    /// body a real zero-proposal epoch commit carries — prior/next coordinates
    /// (`require_commit_body`), an empty Generic manifest (no participant/leaf
    /// changes, no recovery id, no welcome — `require_commit_manifest` Generic
    /// arm), and the mandatory metadata re-encryption. `authority = None` skips
    /// only the crypto-digest cross-checks.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_commit_with_metadata(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        metadata: MetadataSnapshotBinding,
    ) -> Result<Self, StateMachineError> {
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::Commit {
            prior,
            next,
            aad_digest: [0u8; 32],
            manifest: TransitionManifestBinding {
                participant_changes: Vec::new(),
                leaf_changes: Vec::new(),
                leaf_recovery_request_id: None,
                welcome: None,
            },
            commit_sha256: [0u8; 32],
            metadata,
        });
        Ok(evidence)
    }

    /// A `leaveCommitFulfillment` `TransitionEvidence`: the exact body a real
    /// different-DID leave-fulfilling Commit carries — prior/next coordinates +
    /// `leave_request_id` (`require_commit_body`), and a Leave manifest
    /// (`require_commit_manifest` Leave arm: `participant_changes ==
    /// [Remove(requester)]`, NO Add leaf change, no recovery id, no welcome) plus
    /// the mandatory re-encryption metadata (`leaveCommit` ∈ requires_snapshot).
    /// `authority = None` skips only the crypto-digest cross-checks.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_leave_fulfillment_with_metadata(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        leave_request_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        requester: DeviceIdentity,
        metadata: MetadataSnapshotBinding,
    ) -> Result<Self, StateMachineError> {
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::LeaveCommitFulfillment {
            leave_request_id,
            prior,
            next,
            aad_digest: [0u8; 32],
            manifest: TransitionManifestBinding {
                participant_changes: vec![ManifestParticipantChange::Remove(
                    requester.principal().clone(),
                )],
                leaf_changes: vec![ManifestLeafChange::Remove(requester)],
                leaf_recovery_request_id: None,
                welcome: None,
            },
            commit_sha256: [0u8; 32],
            metadata,
        });
        Ok(evidence)
    }
}

#[cfg(test)]
impl ConversationHeadCasBinding {
    /// The head CAS a creation transaction's conversation-head lock would mint:
    /// true absence (`expected_prior == None`), genesis entry at seq 1, counter
    /// advanced to 2.
    pub(crate) fn for_test_creation(
        conversation_id: [u8; 16],
        entry_id: [u8; 16],
        locked_at: ServerTimestamp,
    ) -> Self {
        Self {
            transaction_id: "e2b3-executor-test".to_owned(),
            conversation_id,
            expected_prior: None,
            expected_next_entry_seq: 1,
            allocated_entry_id: Some(entry_id),
            allocated_seq: Some(1),
            successor_next_entry_seq: 2,
            locked_at,
            locked_head_digest: [1u8; 32],
        }
    }
}

/// Assemble a `ConversationPersistencePlan` from a pure-planner `PlannedTransition`
/// plus a synthesized head CAS, mirroring what `into_persistence_plan` produces in
/// production (which is `#[cfg(not(test))]` and unreachable from the test build).
///
/// For a `Creation`/`Policy` plan this ALSO synthesizes the
/// `InvitationQuotaCasBinding` that `into_persistence_plan` (state_machine.rs
/// `invitation_quota_valid`) requires every such plan to carry — modeled on
/// `bind_invitation_quota_cas`: the sorted newly-pending recipients, the inviter
/// (the sole/first active admin), the prior/successor live-pending counts, a
/// generous limit, and a non-zero locked-row digest bound to the head lock. Test
/// plans therefore mirror real plans, so the executor's invitation-quota consume
/// arm is exercised (removing it now fails the suite).
#[cfg(test)]
pub(crate) fn persistence_plan_for_test(
    transition: PlannedTransition,
    head_cas: ConversationHeadCasBinding,
) -> ConversationPersistencePlan {
    let mut effects = transition.effects;
    if matches!(effects.kind, PlanKind::Creation | PlanKind::Policy) {
        let mut new_recipients: Vec<PrincipalId> = effects
            .participant_changes
            .iter()
            .filter_map(|change| match (change.before(), change.after()) {
                (None, Some(after)) if after.status() == ParticipantStatus::Pending => {
                    Some(after.principal().clone())
                }
                _ => None,
            })
            .collect();
        new_recipients.sort();
        let successor_pending = transition
            .state
            .participants()
            .iter()
            .filter(|participant| participant.status() == ParticipantStatus::Pending)
            .count() as u64;
        let expected_pending = successor_pending.saturating_sub(new_recipients.len() as u64);
        let inviter = transition
            .state
            .participants()
            .iter()
            .find(|participant| {
                participant.status() == ParticipantStatus::Active
                    && participant.role() == ParticipantRole::Admin
            })
            .map(|participant| participant.principal().clone())
            .unwrap_or_else(|| {
                new_recipients
                    .first()
                    .cloned()
                    .unwrap_or_else(dummy_principal)
            });
        effects.invitation_quota_cas = Some(InvitationQuotaCasBinding {
            transaction_id: head_cas.transaction_id.clone(),
            inviter,
            new_recipients,
            expected_pending,
            successor_pending,
            quota_limit: 100,
            locked_at: head_cas.locked_at,
            locked_row_digest: [1u8; 32],
        });
    }
    // E2b-6b MINOR-1: synthesize the recovery-package CAS bijection production
    // requires for any plan carrying `package_transitions` (mirroring
    // `bind_recovery_package_cas`), so the executor's now-load-bearing bijection
    // assert is genuinely exercised. Only request_id / key_package_ref / from / to
    // are read by that assert (and by production's `package_cas_bijection_valid`);
    // the remaining authority columns are provenance placeholders here.
    if effects.recovery_package_cas.is_empty() && !effects.package_transitions.is_empty() {
        for edge in effects.package_transitions.clone() {
            if let Some(request) = effects
                .recovery_request_changes
                .iter()
                .filter_map(|change| change.after())
                .find(|request| request.request_id == edge.request_id)
            {
                effects
                    .recovery_package_cas
                    .push(RecoveryPackageCasBinding {
                        transaction_id: head_cas.transaction_id.clone(),
                        conversation_id: *request.bound_coordinate.conversation_id(),
                        request_id: edge.request_id,
                        target: request.target.clone(),
                        target_key_id: [0u8; 32],
                        target_auth_generation: 1,
                        bound_coordinate: request.bound_coordinate,
                        key_package_ref: edge.key_package_ref,
                        key_package_wrapper_sha256: [0u8; 32],
                        package_not_after: request.expires_at,
                        claimed_at: request.received_at,
                        expected_status: edge.from,
                        successor_status: edge.to,
                        locked_row_digest: [1u8; 32],
                    });
            }
        }
    }
    // Synthesize the welcome-disposition CAS binding production requires for a
    // welcome terminalization edge (expiry / acknowledge / reject), mirroring
    // `welcome_cas_from_guard`. The executor consumes it as a LOAD-BEARING witness
    // (it must match the welcome_change), and production carries it via
    // `bind_welcome_cas`, so synthesizing it here keeps the test plan
    // production-shaped. Only the identity/coordinate/status columns are read by the
    // executor; the locked-row digest is a provenance placeholder.
    if effects.welcome_cas.is_none() {
        if let Some((before, after)) = effects.welcome_changes.iter().find_map(|change| {
            match (change.before.as_ref(), change.after.as_ref()) {
                (Some(before), Some(after))
                    if before.status == WelcomeStatus::Pending
                        && matches!(
                            after.status,
                            WelcomeStatus::Expired
                                | WelcomeStatus::Acknowledged
                                | WelcomeStatus::Rejected
                        ) =>
                {
                    Some((before, after))
                }
                _ => None,
            }
        }) {
            effects.welcome_cas = Some(WelcomeCasBinding {
                transaction_id: head_cas.transaction_id.clone(),
                conversation_id: *after.coordinate.conversation_id(),
                welcome_id: after.welcome_id,
                recipient: after.recipient.clone(),
                transition_seq: after.transition_seq,
                coordinate: after.coordinate,
                recovery_request_id: after.recovery_request_id,
                key_package_ref: after.key_package_ref,
                opaque_welcome_sha256: after.sha256,
                expires_at: after.expires_at,
                expected_status: before.status,
                successor_status: after.status,
                locked_at: head_cas.locked_at,
                locked_row_digest: [1u8; 32],
            });
        }
    }
    effects.head_cas = Some(head_cas);
    ConversationPersistencePlan {
        expected_prior: transition.expected_prior,
        retired_coordinate: transition.retired_coordinate,
        successor_coordinate: transition.successor_coordinate,
        state: ConversationStateHydration::from_state(transition.state),
        effects,
    }
}

/// A syntactically-valid placeholder principal for the (unreachable) case where a
/// Creation/Policy plan has neither an active admin nor a pending recipient.
#[cfg(test)]
fn dummy_principal() -> PrincipalId {
    PrincipalId::new(b"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_vec()).expect("valid placeholder DID")
}

#[cfg(test)]
impl ConversationPersistencePlan {
    /// Drop the invitation-quota CAS binding, producing a plan production would
    /// reject as `InvalidHydrationAuthority` and the executor rejects as
    /// `InconsistentPlan`. Used to make the executor's invitation-quota consume
    /// arm an executable contract (removing the arm fails the negative test).
    pub(crate) fn with_invitation_quota_cleared_for_test(mut self) -> Self {
        self.effects.invitation_quota_cas = None;
        self
    }

    /// Drop the recovery-package CAS binding, desyncing it from
    /// `package_transitions` — production requires the two to be bijective
    /// (`package_cas_bijection_valid`) and the executor's
    /// `verify_recovery_package_consistency` rejects the desync as
    /// `InconsistentPlan`. Makes that (otherwise-always-bijective-by-construction)
    /// assert an executable contract: removing the assert fails the negative test.
    pub(crate) fn with_recovery_package_cas_cleared_for_test(mut self) -> Self {
        self.effects.recovery_package_cas.clear();
        self
    }

    /// Inject an EXTRA recovery-request delta that is neither the arm's own edge
    /// (`Open->Fulfilled`) nor a valid supersession (`Open->Superseded`): an
    /// `Open->Expired` change cloned from the plan's first request. A
    /// coordinate-changing arm must REJECT it (`reconcile_coordinate_change_families`),
    /// never silently drop it — removing that reconciliation fails the negative test.
    pub(crate) fn with_extra_untracked_recovery_request_for_test(mut self) -> Self {
        if let Some(open) = self
            .effects
            .recovery_request_changes
            .first()
            .and_then(|change| change.before.clone())
        {
            let mut expired = open.clone();
            expired.status = RecoveryRequestStatus::Expired;
            self.effects.recovery_request_changes.push(StateChange {
                before: Some(open),
                after: Some(expired),
            });
        }
        self
    }

    /// Corrupt the plan's first welcome supersession into a non-supersession shape
    /// (`Pending->Superseded` -> `Pending->Expired`). `write_welcome_supersessions`
    /// SKIPS it, so a coordinate-changing arm must catch it in the reconciliation
    /// rather than silently leave the durable Welcome delivery un-terminalized —
    /// removing the welcome reconciliation fails the negative test.
    pub(crate) fn with_welcome_supersession_corrupted_for_test(mut self) -> Self {
        if let Some(after) = self
            .effects
            .welcome_changes
            .first_mut()
            .and_then(|change| change.after.as_mut())
        {
            after.status = WelcomeStatus::Expired;
        }
        self
    }

    /// Corrupt the plan's first reset-request staling into a non-staling shape
    /// (`Pending->Stale` -> `Pending->Expired`). `write_prior_bound_staling` SKIPS
    /// it (it consumes only the exact `Pending->Stale` edge), so a coordinate-
    /// advancing arm must catch it in `reconcile_coordinate_change_families` rather
    /// than silently leave the durable reset request un-terminalized — removing the
    /// reset-family reconciliation fails the negative test.
    pub(crate) fn with_reset_staling_corrupted_for_test(mut self) -> Self {
        if let Some(after) = self
            .effects
            .reset_request_changes
            .first_mut()
            .and_then(|change| change.after.as_mut())
        {
            after.status = ResetRequestStatus::Expired;
        }
        self
    }

    /// Corrupt the plan's first leave-request staling into a non-staling shape
    /// (`Pending->Stale` -> `Pending->Expired`), exercising the leave-family half of
    /// the silent-drop guard exactly as `with_reset_staling_corrupted_for_test` does
    /// for the reset family.
    pub(crate) fn with_leave_staling_corrupted_for_test(mut self) -> Self {
        if let Some(after) = self
            .effects
            .leave_request_changes
            .first_mut()
            .and_then(|change| change.after.as_mut())
        {
            after.status = LeaveRequestStatus::Expired;
        }
        self
    }

    /// Corrupt the `welcome_cas` binding so it disagrees with the `welcome_changes`
    /// delta (flip a byte of its bound welcome id). The welcome-disposition arms
    /// validate the binding LOAD-BEARING against the delta (welcome id / recipient /
    /// coordinate / expiry / direction), so a corrupted binding must be a hard
    /// `InconsistentPlan` — removing that validation fails the negative test. Since
    /// `persistence_plan_for_test` always synthesizes a MATCHING binding, this is the
    /// only way to drive the validation red.
    pub(crate) fn with_welcome_cas_corrupted_for_test(mut self) -> Self {
        if let Some(binding) = self.effects.welcome_cas.as_mut() {
            binding.welcome_id[0] ^= 0xFF;
        }
        self
    }

    /// ADR-019 Erratum 01 desync (leave-fulfillment): append a second leave delta
    /// that STALES the very request the plan FULFILLS (same `request_id`), cloning
    /// its Pending predecessor and flipping the successor to `Stale`. `apply_leave_
    /// fulfillment`'s partition check must reject this as `InconsistentPlan` (ruling
    /// point 3 — the fulfilled request is `fulfilled`, never `stale`); the count-only
    /// reconciliation cannot catch it (staled+own would still equal total), so the
    /// explicit same-request guard is load-bearing.
    pub(crate) fn with_leave_fulfillment_own_staled_for_test(mut self) -> Self {
        if let Some(fulfilled_before) = self
            .effects
            .leave_request_changes
            .iter()
            .find(|change| {
                matches!(
                    (&change.before, &change.after),
                    (Some(b), Some(a))
                        if b.status == LeaveRequestStatus::Pending
                            && a.status == LeaveRequestStatus::Fulfilled
                )
            })
            .and_then(|change| change.before.clone())
        {
            let mut staled = fulfilled_before.clone();
            staled.status = LeaveRequestStatus::Stale;
            self.effects.leave_request_changes.push(StateChange {
                before: Some(fulfilled_before),
                after: Some(staled),
            });
        }
        self
    }

    /// ADR-019 Erratum 01 desync (zero-leaf-leave): flip the plan's first leave
    /// staling from `Pending->Stale` to `Pending->Fulfilled`. A zeroLeafLeave
    /// (leavePolicy) owns no leave request of its own, so ANY `Fulfilled` leave delta
    /// is illegal — `apply_zero_leaf_leave` must reject it as `InconsistentPlan`
    /// (shape guard: every leave delta must be `Pending->Stale`).
    pub(crate) fn with_leave_staling_flipped_to_fulfilled_for_test(mut self) -> Self {
        if let Some(after) = self
            .effects
            .leave_request_changes
            .first_mut()
            .and_then(|change| change.after.as_mut())
        {
            after.status = LeaveRequestStatus::Fulfilled;
        }
        self
    }
}

#[cfg(test)]
impl TransitionEvidence {
    /// A group `policy` addParticipant `TransitionEvidence`: authority-less test
    /// seam carrying the exact `Policy` body a real add produces (prior/next
    /// coordinate-only successor + `Add` changes).
    pub(crate) fn for_test_policy_add(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        prior: PublicGroupSnapshotCoordinate,
        added: Vec<PrincipalId>,
    ) -> Result<Self, StateMachineError> {
        let next = coordinate_only_successor(&prior)?;
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::Policy {
            prior,
            next,
            participant_changes: added
                .into_iter()
                .map(ManifestParticipantChange::Add)
                .collect(),
        });
        Ok(evidence)
    }
}

#[cfg(test)]
impl ConversationHeadCasBinding {
    /// The head CAS an INTERNAL (entry-less) op's head lock would mint: the prior
    /// coordinate verified, NO seq allocated, the counter UNCHANGED
    /// (`bind_non_control_request_authority` shape).
    pub(crate) fn for_test_internal(
        conversation_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        next_entry_seq: u64,
        locked_at: ServerTimestamp,
    ) -> Self {
        Self {
            transaction_id: "e2b6-executor-test".to_owned(),
            conversation_id,
            expected_prior: Some(prior),
            expected_next_entry_seq: next_entry_seq,
            allocated_entry_id: None,
            allocated_seq: None,
            successor_next_entry_seq: next_entry_seq,
            locked_at,
            locked_head_digest: [1u8; 32],
        }
    }

    /// The head CAS an existing-conversation edge's head lock would mint: the
    /// prior coordinate, the entry at `allocated_seq`, counter advanced by one.
    pub(crate) fn for_test_edge(
        conversation_id: [u8; 16],
        entry_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        allocated_seq: u64,
        locked_at: ServerTimestamp,
    ) -> Self {
        Self {
            transaction_id: "e2b3-executor-test".to_owned(),
            conversation_id,
            expected_prior: Some(prior),
            expected_next_entry_seq: allocated_seq,
            allocated_entry_id: Some(entry_id),
            allocated_seq: Some(allocated_seq),
            successor_next_entry_seq: allocated_seq + 1,
            locked_at,
            locked_head_digest: [1u8; 32],
        }
    }
}

#[cfg(test)]
pub(crate) fn plan_policy(
    prior: &ConversationState,
    actor: DeviceIdentity,
    transition: TransitionEvidence,
    relationship_evidence_digest: [u8; 32],
) -> Result<PlannedTransition, StateMachineError> {
    plan_policy_transition(
        prior,
        PolicyCommand {
            actor,
            transition,
            relationship_evidence_digest,
        },
    )
}

// The deterministic pure planners are intentionally reachable only from the
// test build. Production callers must enter through HydrationAuthority's
// route-specific methods, which consume repository lock/auth witnesses.
#[cfg(test)]
pub(crate) fn plan_creation(
    existing_direct: Option<&ConversationState>,
    command: CreationCommand,
) -> Result<CreationDecision, StateMachineError> {
    plan_creation_inner(existing_direct, command)
}

#[cfg(test)]
pub(crate) fn plan_accept_conversation(
    prior: &ConversationState,
    command: AcceptConversation,
) -> Result<PlannedTransition, StateMachineError> {
    plan_accept_conversation_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_metadata(
    prior: &ConversationState,
    command: MetadataCommand,
) -> Result<PlannedTransition, StateMachineError> {
    plan_metadata_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_leaf_recovery_request(
    prior: &ConversationState,
    command: LeafRecoveryRequestCommand,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leaf_recovery_request_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_leaf_recovery_cancellation(
    prior: &ConversationState,
    command: LeafRecoveryCancellation,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leaf_recovery_cancellation_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_device_revocation(
    prior: &ConversationState,
    evidence: DeviceRevocationEvidence,
) -> Result<PlannedTransition, StateMachineError> {
    plan_device_revocation_inner(prior, evidence)
}

/// The per-conversation revocation `ConversationPersistencePlan` a test drives
/// through the entry-less `apply_device_revocation` arm. Sets the entry-less
/// head CAS + `DeviceRevocation` authority and synthesizes the
/// `revocation_package_cas` bijection production requires (mirroring
/// `bind_device_revocation_authority` + `bind_revocation_package_cas`), so the
/// executor's load-bearing `revocation_package_cas_bijection_valid` check is
/// genuinely exercised. Only identity/coordinate/status columns are read by the
/// arm; the digest columns are provenance placeholders.
#[cfg(test)]
pub(crate) fn device_revocation_plan_for_test(
    transition: PlannedTransition,
    head_cas: ConversationHeadCasBinding,
    evidence: DeviceRevocationEvidence,
) -> ConversationPersistencePlan {
    let mut effects = transition.effects;
    debug_assert_eq!(effects.kind, PlanKind::DeviceRevocation);
    for edge in effects.package_transitions.clone() {
        debug_assert_eq!(edge.from, PackageStatus::Reserved);
        debug_assert_eq!(edge.to, PackageStatus::Revoked);
        effects
            .revocation_package_cas
            .push(RevocationPackageCasBinding {
                transaction_id: head_cas.transaction_id.clone(),
                target: evidence.target.clone(),
                target_key_id: [0u8; 32],
                target_auth_generation: evidence.expected_target_auth_generation,
                key_package_ref: edge.key_package_ref,
                wrapper_sha256: [0u8; 32],
                package_not_after: evidence.accepted_at,
                expected_status: PackageStatus::Reserved,
                successor_status: PackageStatus::Revoked,
                conversation_id: Some(head_cas.conversation_id),
                request_id: Some(edge.request_id),
                revocation_id: evidence.revocation_id,
                revoked_at: evidence.accepted_at,
                revocation_request_digest: evidence.request_digest,
                revocation_row_digest: evidence.durable_row_digest,
                locked_row_digest: [1u8; 32],
            });
    }
    effects.authority = Some(PlanAuthority::DeviceRevocation(evidence));
    effects.head_cas = Some(head_cas);
    ConversationPersistencePlan {
        expected_prior: transition.expected_prior,
        retired_coordinate: transition.retired_coordinate,
        successor_coordinate: transition.successor_coordinate,
        state: ConversationStateHydration::from_state(transition.state),
        effects,
    }
}

#[cfg(test)]
pub(crate) fn plan_leaf_recovery_fulfillment(
    prior: &ConversationState,
    command: LeafRecoveryFulfillment,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leaf_recovery_fulfillment_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_commit(
    prior: &ConversationState,
    command: CommitCommand,
) -> Result<PlannedTransition, StateMachineError> {
    plan_commit_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_reset_request(
    prior: &ConversationState,
    command: ResetRequestCommand,
) -> Result<PlannedTransition, StateMachineError> {
    plan_reset_request_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_welcome_expiry_for_test(
    prior: &ConversationState,
    welcome_id: [u8; 16],
) -> Result<PlannedTransition, StateMachineError> {
    plan_welcome_expiry(prior, welcome_id)
}

#[cfg(test)]
pub(crate) fn plan_welcome_response_for_test(
    prior: &ConversationState,
    evidence: RequestEvidence,
    successor_status: WelcomeStatus,
) -> Result<PlannedTransition, StateMachineError> {
    plan_welcome_response(prior, evidence, successor_status)
}

#[cfg(test)]
pub(crate) fn plan_reset_activation(
    prior: &ConversationState,
    command: ResetActivation,
) -> Result<PlannedTransition, StateMachineError> {
    plan_reset_activation_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_zero_leaf_leave(
    prior: &ConversationState,
    command: ZeroLeafLeave,
) -> Result<PlannedTransition, StateMachineError> {
    plan_zero_leaf_leave_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_leave_request(
    prior: &ConversationState,
    command: LeaveRequestCommand,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leave_request_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_leave_cancellation(
    prior: &ConversationState,
    command: LeaveCancellation,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leave_cancellation_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_leave_fulfillment(
    prior: &ConversationState,
    command: LeaveFulfillment,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leave_fulfillment_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_close(
    prior: &ConversationState,
    command: CloseConversation,
) -> Result<PlannedTransition, StateMachineError> {
    plan_close_inner(prior, command)
}

fn ensure_active(state: &ConversationState) -> Result<(), StateMachineError> {
    if state.coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
        || state.public_state.is_none()
    {
        return Err(StateMachineError::ConversationClosed);
    }
    if state.public_state().coordinate() != &state.coordinate {
        return Err(StateMachineError::InvalidPublicState);
    }
    Ok(())
}

fn resolve_prior_bound_work(
    state: &mut ConversationState,
    prior: &PublicGroupSnapshotCoordinate,
    evidence: &TransitionEvidence,
    fulfilled_recovery: Option<[u8; 16]>,
    consumed_reset: Option<[u8; 16]>,
    fulfilled_leave: Option<[u8; 16]>,
) {
    for request in &mut state.recovery_requests {
        if request.status != RecoveryRequestStatus::Open || &request.bound_coordinate != prior {
            continue;
        }
        if fulfilled_recovery == Some(request.request_id) {
            request.status = RecoveryRequestStatus::Fulfilled;
            request.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        } else if evidence.received_at >= request.expires_at {
            request.status = RecoveryRequestStatus::Expired;
            request.terminal = Some(WorkTerminalEvidence::Expiry(request.expires_at));
        } else {
            request.status = RecoveryRequestStatus::Superseded;
            request.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        }
    }
    for reservation in &mut state.recovery_reservations {
        if reservation.status != ReservationStatus::Active || &reservation.bound_coordinate != prior
        {
            continue;
        }
        if fulfilled_recovery == Some(reservation.request_id) {
            reservation.status = ReservationStatus::Consumed;
            reservation.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        } else if evidence.received_at >= reservation.expires_at {
            reservation.status = ReservationStatus::Expired;
            reservation.terminal = Some(WorkTerminalEvidence::Expiry(reservation.expires_at));
        } else {
            reservation.status = ReservationStatus::Released;
            reservation.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        }
    }
    for request in &mut state.reset_requests {
        if request.status != ResetRequestStatus::Pending || &request.bound_coordinate != prior {
            continue;
        }
        if consumed_reset == Some(request.request_id) {
            request.status = ResetRequestStatus::Consumed;
            request.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        } else if evidence.received_at >= request.expires_at {
            request.status = ResetRequestStatus::Expired;
            request.terminal = Some(WorkTerminalEvidence::Expiry(request.expires_at));
        } else {
            request.status = ResetRequestStatus::Stale;
            request.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        }
    }
    for request in &mut state.leave_requests {
        if request.status != LeaveRequestStatus::Pending || &request.bound_coordinate != prior {
            continue;
        }
        if fulfilled_leave == Some(request.request_id) {
            request.status = LeaveRequestStatus::Fulfilled;
            request.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        } else if evidence.received_at >= request.expires_at {
            request.status = LeaveRequestStatus::Expired;
            request.terminal = Some(WorkTerminalEvidence::Expiry(request.expires_at));
        } else {
            request.status = LeaveRequestStatus::Stale;
            request.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        }
    }
    for welcome in &mut state.welcomes {
        if welcome.status != WelcomeStatus::Pending || &welcome.coordinate != prior {
            continue;
        }
        if evidence.received_at >= welcome.expires_at {
            welcome.status = WelcomeStatus::Expired;
            welcome.terminal = Some(WorkTerminalEvidence::Expiry(welcome.expires_at));
        } else {
            welcome.status = WelcomeStatus::Superseded;
            welcome.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        }
    }
}

fn coordinate_only_successor(
    prior: &PublicGroupSnapshotCoordinate,
) -> Result<PublicGroupSnapshotCoordinate, StateMachineError> {
    let state_version = prior
        .state_version()
        .checked_add(1)
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(StateMachineError::CoordinateOverflow)?;
    Ok(PublicGroupSnapshotCoordinate::new(
        *prior.conversation_id(),
        prior.generation(),
        state_version,
        *prior.group_id(),
        prior.epoch(),
        *prior.group_context_hash(),
        *prior.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    ))
}

fn retired_coordinate(
    prior: &PublicGroupSnapshotCoordinate,
) -> Result<PublicGroupSnapshotCoordinate, StateMachineError> {
    let state_version = prior
        .state_version()
        .checked_add(1)
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(StateMachineError::CoordinateOverflow)?;
    Ok(PublicGroupSnapshotCoordinate::new(
        *prior.conversation_id(),
        prior.generation(),
        state_version,
        *prior.group_id(),
        prior.epoch(),
        *prior.group_context_hash(),
        *prior.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Superseded,
    ))
}

fn open_interval(
    intervals: &mut Vec<AccessInterval>,
    recipient: DeviceIdentity,
    opening: TransitionEvidence,
    opening_kind: OpeningKind,
    opening_context: PublicGroupSnapshotCoordinate,
) -> Result<(), StateMachineError> {
    if opening_context.lifecycle() != PublicGroupSnapshotLifecycle::Active
        || intervals
            .iter()
            .any(|interval| interval.recipient == recipient && interval.end.is_none())
    {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    if let Some(previous) = intervals
        .iter()
        .filter(|interval| interval.recipient == recipient)
        .max_by_key(|interval| interval.opening.seq)
    {
        let end = previous
            .end
            .as_ref()
            .ok_or(StateMachineError::InvalidIntervalBoundary)?;
        if end.evidence.seq > opening.seq {
            return Err(StateMachineError::InvalidIntervalBoundary);
        }
        if end.evidence.seq == opening.seq {
            let legal = matches!(
                (end.kind, opening_kind),
                (CloseKind::Replace, OpeningKind::Add) | (CloseKind::Reset, OpeningKind::Reset)
            ) && end.evidence.transition_id == opening.transition_id
                && end.evidence.outer_entry_fingerprint == opening.outer_entry_fingerprint;
            if !legal {
                return Err(StateMachineError::InvalidIntervalBoundary);
            }
        } else if end.kind == CloseKind::Terminal {
            return Err(StateMachineError::InvalidIntervalBoundary);
        }
    }
    intervals.push(AccessInterval {
        recipient,
        generation: opening_context.generation(),
        opening,
        opening_kind,
        opening_context,
        end: None,
    });
    Ok(())
}

fn close_open_interval(
    intervals: &mut [AccessInterval],
    recipient: &DeviceIdentity,
    evidence: &TransitionEvidence,
    kind: CloseKind,
) -> Result<(), StateMachineError> {
    let interval = intervals
        .iter_mut()
        .filter(|interval| &interval.recipient == recipient && interval.end.is_none())
        .max_by_key(|interval| interval.opening.seq)
        .ok_or(StateMachineError::InvalidIntervalBoundary)?;
    if evidence.seq <= interval.opening.seq {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    interval.end = Some(AccessIntervalEnd {
        evidence: evidence.clone(),
        kind,
    });
    Ok(())
}

fn sort_intervals(intervals: &mut [AccessInterval]) {
    intervals.sort_by(|left, right| {
        left.recipient
            .cmp(&right.recipient)
            .then_with(|| left.opening.seq.cmp(&right.opening.seq))
    });
}

fn validate_state(state: &ConversationState) -> Result<(), StateMachineError> {
    validate_participants(state)?;
    if !current_state_producer_matches(state)
        || !metadata_provenance_matches(state)
        || state.coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
        || state
            .public_state
            .as_ref()
            .map(ActivePublicState::coordinate)
            != Some(&state.coordinate)
        || state
            .metadata
            .as_ref()
            .is_some_and(|metadata| !metadata_coordinate_matches(metadata, &state.coordinate))
        || (state
            .intervals
            .iter()
            .any(|interval| interval.opening.authority.is_some())
            && state.metadata.is_none())
        || !(1..=MAX_LEAVES).contains(&state.leaves.len())
        || !state.terminal_proofs.is_empty()
        || state
            .leaves
            .windows(2)
            .any(|pair| pair[0].leaf_index >= pair[1].leaf_index)
        || state
            .leaves
            .iter()
            .map(|leaf| &leaf.device)
            .collect::<BTreeSet<_>>()
            .len()
            != state.leaves.len()
    {
        return Err(StateMachineError::InvariantViolation);
    }
    for participant in &state.participants {
        let leaf_count = state
            .leaves
            .iter()
            .filter(|leaf| leaf.device.principal() == &participant.principal)
            .count();
        if (participant.status == ParticipantStatus::Pending && leaf_count != 0)
            || leaf_count > MAX_LEAVES_PER_PRINCIPAL
        {
            return Err(StateMachineError::InvariantViolation);
        }
    }
    if state.leaves.iter().any(|leaf| {
        state
            .participant(leaf.device.principal())
            .is_none_or(|participant| !participant.is_active())
            || leaf.basic_credential != leaf.device.basic_credential()
            || leaf.signature_key.len() != 32
            || leaf.encryption_key.is_empty()
    }) {
        return Err(StateMachineError::InvariantViolation);
    }
    let public_leaves = state.public_state().binding().tree_summary().leaves();
    if public_leaves.len() != state.leaves.len()
        || state
            .leaves
            .iter()
            .zip(public_leaves)
            .any(|(leaf, public_leaf)| {
                leaf.leaf_index != public_leaf.leaf_index()
                    || leaf.basic_credential != public_leaf.basic_credential()
                    || leaf.signature_key != public_leaf.signature_key()
                    || leaf.encryption_key != public_leaf.encryption_key()
            })
    {
        return Err(StateMachineError::InvariantViolation);
    }
    validate_intervals(&state.intervals, &state.coordinate, state.kind)?;
    if state.intervals.iter().any(|interval| {
        interval
            .end
            .as_ref()
            .is_some_and(|end| end.kind == CloseKind::Terminal)
    }) {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    let leaf_devices = state
        .leaves
        .iter()
        .map(|leaf| &leaf.device)
        .collect::<BTreeSet<_>>();
    let open_devices = state
        .intervals
        .iter()
        .filter(|interval| interval.end.is_none())
        .map(|interval| &interval.recipient)
        .collect::<BTreeSet<_>>();
    if leaf_devices != open_devices {
        return Err(StateMachineError::InvariantViolation);
    }
    validate_work(state, false)
}

fn validate_participants(state: &ConversationState) -> Result<(), StateMachineError> {
    if !(1..=MAX_PARTICIPANTS).contains(&state.participants.len())
        || state
            .participants
            .windows(2)
            .any(|pair| pair[0].principal >= pair[1].principal)
        || state
            .participants
            .iter()
            .any(|participant| !participant_provenance_matches(state, participant))
        || !state.participants.iter().any(|participant| {
            participant.status == ParticipantStatus::Active
                && participant.role == ParticipantRole::Admin
        })
        || (state.kind == ConversationKind::Direct
            && (state.participants.len() != 2
                || state
                    .participants
                    .iter()
                    .any(|participant| participant.role != ParticipantRole::Admin)))
    {
        return Err(StateMachineError::InvariantViolation);
    }
    Ok(())
}

fn participant_provenance_matches(
    state: &ConversationState,
    participant: &ParticipantRecord,
) -> bool {
    if !participant_role_provenance_matches(state, participant) {
        return false;
    }
    match (
        participant.status,
        participant.invitation.as_ref(),
        participant.acceptance.as_ref(),
    ) {
        (ParticipantStatus::Pending, Some(invitation), None) => {
            invitation_matches_participant(state.kind, participant, invitation)
        }
        (ParticipantStatus::Active, None, None) => true,
        (ParticipantStatus::Active, Some(invitation), Some(acceptance)) => {
            invitation_matches_participant(state.kind, participant, invitation)
                && acceptance_matches_participant(state, participant, invitation, acceptance)
        }
        _ => false,
    }
}

fn participant_role_provenance_matches(
    state: &ConversationState,
    participant: &ParticipantRecord,
) -> bool {
    let initial_role = match participant.invitation.as_ref() {
        None => Some(ParticipantRole::Admin),
        Some(invitation) => match invitation.transition.body_binding.as_ref() {
            Some(TransitionBodyBinding::Creation { kind, .. }) if *kind == state.kind => {
                Some(if state.kind == ConversationKind::Direct {
                    ParticipantRole::Admin
                } else {
                    ParticipantRole::Member
                })
            }
            Some(TransitionBodyBinding::Policy {
                participant_changes,
                ..
            }) if participant_changes.iter().any(|change| {
                matches!(change, ManifestParticipantChange::Add(principal)
                    if principal == &participant.principal)
            }) =>
            {
                Some(ParticipantRole::Member)
            }
            // Pure planner tests intentionally omit sealed bodies. Production
            // hydration never admits this branch because it retains authority.
            None if invitation.transition.authority.is_none() => Some(participant.role),
            _ => None,
        },
    };

    match participant.role_producer.as_ref() {
        None => initial_role == Some(participant.role),
        Some(producer) => {
            if !validate_transition_evidence(producer) {
                return false;
            }
            let Some(authority) = producer.authority.as_ref() else {
                return true;
            };
            authority.kind == SignedMutationKind::PolicyTransition
                && authority.control_conversation_id.as_ref()
                    == Some(state.coordinate.conversation_id())
                && producer.seq <= state.producer.seq
                && producer.received_at <= state.producer.received_at
                && matches!(producer.body_binding.as_ref(),
                    Some(TransitionBodyBinding::Policy {
                        prior,
                        next,
                        participant_changes,
                    }) if coordinate_only_successor(prior).is_ok_and(|expected| &expected == next)
                        && coordinate_is_in_lineage(next, &state.coordinate)
                        && participant_changes.iter().filter(|change| {
                            matches!(change, ManifestParticipantChange::ChangeRole(principal, role)
                                if principal == &participant.principal && *role == participant.role)
                        }).count() == 1)
        }
    }
}

fn invitation_matches_participant(
    conversation_kind: ConversationKind,
    participant: &ParticipantRecord,
    invitation: &InvitationProvenance,
) -> bool {
    if !validate_transition_evidence(&invitation.transition)
        || invitation.inviter.basic_credential().is_empty()
    {
        return false;
    }
    let Some(authority) = invitation.transition.authority.as_ref() else {
        return true;
    };
    if authority.actor != invitation.inviter {
        return false;
    }
    match invitation.transition.body_binding.as_ref() {
        Some(TransitionBodyBinding::Creation { kind, manifest, .. }) => {
            let invitation_role = if *kind == ConversationKind::Direct {
                ParticipantRole::Admin
            } else {
                ParticipantRole::Member
            };
            authority.kind == SignedMutationKind::Creation
                && *kind == conversation_kind
                && manifest.actor_leaf == invitation.inviter
                && manifest
                    .participants
                    .iter()
                    .filter(|signed| {
                        signed.principal == participant.principal
                            && signed.status == ParticipantStatus::Pending
                            && signed.role == invitation_role
                            && signed.invitation.as_ref().is_some_and(|signed_invitation| {
                                signed_invitation.transition_id
                                    == invitation.transition.transition_id
                                    && signed_invitation.inviter == invitation.inviter
                            })
                    })
                    .count()
                    == 1
        }
        Some(TransitionBodyBinding::Policy {
            participant_changes,
            ..
        }) => {
            authority.kind == SignedMutationKind::PolicyTransition
                && participant_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestParticipantChange::Add(principal)
                        if principal == &participant.principal)
                    })
                    .count()
                    == 1
        }
        _ => false,
    }
}

fn acceptance_matches_participant(
    state: &ConversationState,
    participant: &ParticipantRecord,
    invitation: &InvitationProvenance,
    acceptance: &TransitionEvidence,
) -> bool {
    if !validate_transition_evidence(acceptance) {
        return false;
    }
    let Some(authority) = acceptance.authority.as_ref() else {
        return true;
    };
    if authority.kind != SignedMutationKind::ParticipantAcceptance
        || authority.actor.principal() != &participant.principal
    {
        return false;
    }
    let mut matching_requests = state.recovery_requests.iter().filter(|request| {
        request.source == RecoverySource::Acceptance
            && request.target == authority.actor
            && matches!(&request.origin, RecoveryOriginEvidence::Acceptance(origin)
                if origin == acceptance)
    });
    let Some(request) = matching_requests.next() else {
        return false;
    };
    if matching_requests.next().is_some() {
        return false;
    }
    let Some(reservation) = state
        .recovery_reservation(&request.request_id)
        .filter(|reservation| reservation.target == request.target)
    else {
        return false;
    };
    match acceptance.body_binding.as_ref() {
        Some(TransitionBodyBinding::Acceptance {
            next,
            recovery_request_id,
            invitation_provenance,
            recovery,
            ..
        }) => {
            *recovery_request_id == request.request_id
                && invitation_provenance.transition_id == invitation.transition.transition_id
                && invitation_provenance.inviter == invitation.inviter
                && recovery.request_id == request.request_id
                && recovery.conversation_id == *state.coordinate.conversation_id()
                && recovery.target == request.target
                && recovery.kind == LeafRecoveryKind::Add
                && recovery.bound_coordinate == request.bound_coordinate
                && *next == request.bound_coordinate
                && recovery.requester_key_id == authority.key_id
                && recovery.requester_auth_generation == authority.auth_generation
                && recovery.key_package_ref == request.key_package_ref
                && recovery.key_package_ref == reservation.key_package_ref
                && recovery.requested_at == request.received_at
                && recovery.requested_at == reservation.received_at
                && recovery.expires_at == request.expires_at
                && recovery.expires_at == reservation.expires_at
                && !recovery.key_package_wrapper.is_empty()
                && <[u8; 32]>::from(Sha256::digest(&recovery.key_package_wrapper))
                    == recovery.key_package_wrapper_sha256
                && recovery.canonical_digest != [0; 32]
        }
        _ => false,
    }
}

fn current_state_producer_matches(state: &ConversationState) -> bool {
    let evidence = &state.producer;
    if !validate_transition_evidence(evidence) {
        return false;
    }
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    if authority.control_conversation_id.as_ref() != Some(state.coordinate.conversation_id()) {
        return false;
    }
    match (authority.kind, evidence.body_binding.as_ref()) {
        (
            SignedMutationKind::Creation,
            Some(TransitionBodyBinding::Creation { kind, next, .. }),
        ) => *kind == state.kind && next == &state.coordinate,
        (
            SignedMutationKind::CommitTransition,
            Some(TransitionBodyBinding::Commit { next, .. }),
        )
        | (
            SignedMutationKind::PolicyTransition,
            Some(TransitionBodyBinding::Policy { next, .. }),
        )
        | (
            SignedMutationKind::ParticipantAcceptance,
            Some(TransitionBodyBinding::Acceptance { next, .. }),
        )
        | (
            SignedMutationKind::MetadataTransition,
            Some(TransitionBodyBinding::Metadata { next, .. }),
        )
        | (
            SignedMutationKind::LeafRecoveryFulfillment,
            Some(TransitionBodyBinding::LeafRecoveryFulfillment { next, .. }),
        )
        | (
            SignedMutationKind::ZeroLeafLeave,
            Some(TransitionBodyBinding::ZeroLeafLeave { next, .. }),
        )
        | (
            SignedMutationKind::LeaveCommitFulfillment,
            Some(TransitionBodyBinding::LeaveCommitFulfillment { next, .. }),
        ) => next == &state.coordinate,
        (
            SignedMutationKind::ResetActivation,
            Some(TransitionBodyBinding::ResetActivation {
                kind, successor, ..
            }),
        ) => *kind == state.kind && successor == &state.coordinate,
        (
            SignedMutationKind::ConversationClose,
            Some(TransitionBodyBinding::ConversationClose { kind, retired, .. }),
        ) => *kind == state.kind && retired == &state.coordinate,
        _ => false,
    }
}

fn metadata_provenance_matches(state: &ConversationState) -> bool {
    match (state.metadata.as_ref(), state.metadata_producer.as_ref()) {
        (None, None) => true,
        (Some(metadata), Some(producer)) => {
            if !validate_transition_evidence(producer)
                || transition_metadata(producer) != Some(metadata)
                || producer.seq > state.producer.seq
                || producer.received_at > state.producer.received_at
            {
                return false;
            }
            producer.authority.as_ref().is_none_or(|authority| {
                authority.control_conversation_id.as_ref()
                    == Some(state.coordinate.conversation_id())
                    && matches!(
                        authority.kind,
                        SignedMutationKind::Creation
                            | SignedMutationKind::CommitTransition
                            | SignedMutationKind::MetadataTransition
                            | SignedMutationKind::ResetActivation
                            | SignedMutationKind::LeafRecoveryFulfillment
                            | SignedMutationKind::LeaveCommitFulfillment
                    )
            })
        }
        _ => false,
    }
}

fn validate_terminal_state(state: &ConversationState) -> Result<(), StateMachineError> {
    validate_participants(state)?;
    if !current_state_producer_matches(state)
        || !metadata_provenance_matches(state)
        || state.coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Superseded
        || state.public_state.is_some()
        || !state.leaves.is_empty()
        || state
            .metadata
            .as_ref()
            .is_some_and(|metadata| !metadata_coordinate_matches(metadata, &state.coordinate))
    {
        return Err(StateMachineError::InvariantViolation);
    }
    validate_intervals(&state.intervals, &state.coordinate, state.kind)?;
    validate_terminal_proofs(state)?;
    validate_work(state, true)
}

fn validate_transition_evidence(evidence: &TransitionEvidence) -> bool {
    evidence.seq > 0
        && evidence.seq <= MAX_PROTOCOL_INTEGER
        && is_uuid_v4(&evidence.transition_id)
        && evidence.outer_entry_fingerprint != [0; 32]
        && evidence.authority.as_ref().is_none_or(|authority| {
            !evidence.outer_control_projection.is_empty()
                && !evidence.server_fields_dag_cbor.is_empty()
                && evidence.durable_row_digest != [0; 32]
                && durable_control_transition_row_digest(evidence)
                    .is_ok_and(|digest| digest == evidence.durable_row_digest)
                && authority.type_id == authority.kind.type_id()
                && authority.domain == authority.kind.domain()
                && authority
                    .control_entry_id
                    .is_some_and(|entry_id| is_uuid_v4(&entry_id))
                && authority
                    .control_conversation_id
                    .is_some_and(|conversation_id| is_uuid_v4(&conversation_id))
                && authority.auth_generation > 0
                && authority.auth_generation <= MAX_PROTOCOL_INTEGER
                && authority.key_id != [0; 32]
                && authority.request_digest != [0; 32]
                && authority.signature != [0; 64]
                && !authority.signed_request_bytes.is_empty()
                && !authority.canonical_projection.is_empty()
                && !authority.transcript_bytes.is_empty()
                && authority.signed_at <= evidence.received_at
        })
}

fn require_transition_kind(
    evidence: &TransitionEvidence,
    expected: SignedMutationKind,
) -> Result<(), StateMachineError> {
    if evidence
        .authority
        .as_ref()
        .is_some_and(|authority| authority.kind != expected)
    {
        return Err(StateMachineError::InvalidTransition);
    }
    Ok(())
}

fn require_transition_actor(
    evidence: &TransitionEvidence,
    expected: &DeviceIdentity,
) -> Result<(), StateMachineError> {
    if evidence
        .authority
        .as_ref()
        .is_some_and(|authority| &authority.actor != expected)
    {
        return Err(StateMachineError::InvalidTransition);
    }
    Ok(())
}

fn require_creation_body(
    evidence: &TransitionEvidence,
    kind: ConversationKind,
    creator: &DeviceIdentity,
    invitees: &[PrincipalId],
    public_state: &ActivePublicState,
) -> Result<(), StateMachineError> {
    match evidence.body_binding.as_ref() {
        Some(TransitionBodyBinding::Creation {
            kind: signed_kind,
            next: signed_next,
            manifest,
            group_info_sha256,
            metadata,
            ..
        }) if *signed_kind == kind
            && signed_next == public_state.coordinate()
            && (evidence.authority.is_none()
                || (public_state.verified_group_info_sha256() == Some(group_info_sha256)
                    && creation_manifest_matches(evidence, manifest, kind, creator, invitees)
                    && metadata_coordinate_matches(metadata, public_state.coordinate())
                    && metadata.metadata_version == 1
                    && metadata.origin_transition_id == evidence.transition_id
                    && metadata_author_matches_evidence(metadata, evidence))) =>
        {
            Ok(())
        }
        Some(_) => Err(StateMachineError::InvalidTransition),
        None => Ok(()),
    }
}

fn metadata_author_matches_evidence(
    metadata: &MetadataSnapshotBinding,
    evidence: &TransitionEvidence,
) -> bool {
    evidence.authority.as_ref().is_some_and(|authority| {
        metadata.author_proof.author == authority.actor
            && metadata.author_proof.author_key_id == authority.key_id
            && metadata.author_proof.auth_generation_at_origin == authority.auth_generation
            && metadata.author_proof.origin_transition_id == evidence.transition_id
            && metadata.author_proof.origin_seq == evidence.seq
    })
}

fn transition_metadata(evidence: &TransitionEvidence) -> Option<&MetadataSnapshotBinding> {
    match evidence.body_binding.as_ref()? {
        TransitionBodyBinding::Creation { metadata, .. }
        | TransitionBodyBinding::Commit { metadata, .. }
        | TransitionBodyBinding::Metadata { metadata, .. }
        | TransitionBodyBinding::ResetActivation { metadata, .. }
        | TransitionBodyBinding::LeafRecoveryFulfillment { metadata, .. }
        | TransitionBodyBinding::LeaveCommitFulfillment { metadata, .. } => Some(metadata),
        _ => None,
    }
}

/// Read-time accessor exposing the metadata snapshot binding a coordinate
/// transition's verified body carries, for the G1b-2 metadata hydration leg
/// (`repository::core::load_metadata_provenance`).
///
/// Thin `pub(crate)` wrapper over the module-private [`transition_metadata`]
/// classifier — forced in-module because both that fn and every field of
/// [`MetadataSnapshotBinding`] are private here, so `repository::core` cannot
/// introspect a re-minted transition's metadata directly. It lets the core leg
/// derive an existing conversation's `state.metadata` from its re-verified
/// producing transition EXACTLY as every production coordinate-advancing arm
/// does: `state.metadata = transition_metadata(&command.transition).cloned()`
/// (creation `commit_creation`, and the commit / policy / reset-activation /
/// leaf-recovery-fulfillment / leave-fulfillment arms all set it that way, e.g.
/// state_machine.rs:8813 and :9876). The binding is thus PROVENANCE-DERIVED from
/// its producer, never field-reconstructed from the durable `chat.metadata_snapshots`
/// columns (its `canonical_snapshot`/`digest` are not persisted at all, and the
/// only field-literal constructor, `for_test_creation`, is `#[cfg(test)]`).
///
/// DRIFT FENCE (unchanged, not edited): `validate_state`'s
/// [`metadata_provenance_matches`] re-checks
/// `state.metadata == transition_metadata(state.metadata_producer)` at hydration,
/// which this derivation satisfies by construction, so any residual disagreement
/// fails closed downstream (availability, not integrity — the OQ-G1-3 philosophy).
/// Returns `None` when the transition body carries no metadata; the core leg
/// treats that as a fail-closed linkage inconsistency when a durable metadata
/// snapshot row nonetheless names the transition as its producer.
#[allow(dead_code)] // wired by the G1b-2 aggregate.
pub(crate) fn metadata_binding_of_transition(
    evidence: &TransitionEvidence,
) -> Option<MetadataSnapshotBinding> {
    transition_metadata(evidence).cloned()
}

fn creation_manifest_matches(
    evidence: &TransitionEvidence,
    manifest: &RosterManifestBinding,
    kind: ConversationKind,
    creator: &DeviceIdentity,
    invitees: &[PrincipalId],
) -> bool {
    if manifest.actor_leaf != *creator || manifest.participants.len() != invitees.len() + 1 {
        return false;
    }
    let mut expected_principals = invitees.to_vec();
    expected_principals.push(creator.principal().clone());
    expected_principals.sort();
    if manifest
        .participants
        .iter()
        .map(|participant| &participant.principal)
        .ne(expected_principals.iter())
    {
        return false;
    }
    manifest.participants.iter().all(|participant| {
        if participant.principal == *creator.principal() {
            participant.status == ParticipantStatus::Active
                && participant.role == ParticipantRole::Admin
                && participant.invitation.is_none()
        } else {
            let expected_role = if kind == ConversationKind::Direct {
                ParticipantRole::Admin
            } else {
                ParticipantRole::Member
            };
            participant.status == ParticipantStatus::Pending
                && participant.role == expected_role
                && participant.invitation.as_ref().is_some_and(|invitation| {
                    invitation.transition_id == evidence.transition_id
                        && invitation.inviter == *creator
                })
        }
    })
}

fn require_commit_body(
    evidence: &TransitionEvidence,
    expected_kind: SignedMutationKind,
    prior_state: &ConversationState,
    commit: &VerifiedCommitPublicState,
    request_id: Option<&[u8; 16]>,
) -> Result<(), StateMachineError> {
    let prior = &prior_state.coordinate;
    let next = commit.next().coordinate();
    let valid = match (expected_kind, evidence.body_binding.as_ref()) {
        (
            SignedMutationKind::CommitTransition,
            Some(TransitionBodyBinding::Commit {
                prior: signed_prior,
                next: signed_next,
                aad_digest,
                commit_sha256,
                metadata,
                ..
            }),
        ) => {
            signed_prior == prior
                && signed_next == next
                && request_id.is_none()
                && (evidence.authority.is_none()
                    || (commit.verified_commit_sha256() == Some(commit_sha256)
                        && commit.verified_aad_sha256() == Some(aad_digest)
                        && commit_metadata_matches(prior_state, metadata, next)))
        }
        (
            SignedMutationKind::LeafRecoveryFulfillment,
            Some(TransitionBodyBinding::LeafRecoveryFulfillment {
                recovery_request_id,
                prior: signed_prior,
                next: signed_next,
                aad_digest,
                commit_sha256,
                metadata,
                ..
            }),
        ) => {
            signed_prior == prior
                && signed_next == next
                && request_id == Some(recovery_request_id)
                && (evidence.authority.is_none()
                    || (commit.verified_commit_sha256() == Some(commit_sha256)
                        && commit.verified_aad_sha256() == Some(aad_digest)
                        && commit_metadata_matches(prior_state, metadata, next)))
        }
        (
            SignedMutationKind::LeaveCommitFulfillment,
            Some(TransitionBodyBinding::LeaveCommitFulfillment {
                leave_request_id,
                prior: signed_prior,
                next: signed_next,
                aad_digest,
                commit_sha256,
                metadata,
                ..
            }),
        ) => {
            signed_prior == prior
                && signed_next == next
                && request_id == Some(leave_request_id)
                && (evidence.authority.is_none()
                    || (commit.verified_commit_sha256() == Some(commit_sha256)
                        && commit.verified_aad_sha256() == Some(aad_digest)
                        && commit_metadata_matches(prior_state, metadata, next)))
        }
        (_, None) => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(StateMachineError::InvalidTransition)
    }
}

fn commit_metadata_matches(
    prior: &ConversationState,
    next_metadata: &MetadataSnapshotBinding,
    next_coordinate: &PublicGroupSnapshotCoordinate,
) -> bool {
    let Some(prior_metadata) = prior.metadata.as_ref() else {
        return false;
    };
    metadata_coordinate_matches(next_metadata, next_coordinate)
        && next_metadata.metadata_version == prior_metadata.metadata_version
        && next_metadata.origin_transition_id == prior_metadata.origin_transition_id
        && next_metadata.author_proof == prior_metadata.author_proof
        && next_metadata.avatar_binding_digest == prior_metadata.avatar_binding_digest
        && next_metadata.nonce != prior_metadata.nonce
}

enum CommitManifestForm<'a> {
    Generic,
    Recovery {
        target: &'a DeviceIdentity,
        recovery_request_id: &'a [u8; 16],
        key_package_ref: &'a [u8; 32],
        welcome_id: &'a [u8; 16],
        welcome: &'a VerifiedRecoveryWelcome,
    },
    Leave {
        requester: &'a PrincipalId,
    },
}

fn require_commit_manifest(
    prior: &ConversationState,
    evidence: &TransitionEvidence,
    commit: &VerifiedCommitPublicState,
    form: CommitManifestForm<'_>,
) -> Result<(), StateMachineError> {
    let manifest = match evidence.body_binding.as_ref() {
        Some(TransitionBodyBinding::Commit { manifest, .. }) => manifest,
        Some(TransitionBodyBinding::LeafRecoveryFulfillment { manifest, .. }) => manifest,
        Some(TransitionBodyBinding::LeaveCommitFulfillment { manifest, .. }) => manifest,
        Some(_) => return Err(StateMachineError::InvalidTransition),
        None => return Ok(()),
    };
    let removed_devices = commit
        .removes()
        .iter()
        .map(|effect| {
            prior
                .leaves
                .iter()
                .find(|leaf| leaf.leaf_index == effect.leaf_index())
                .map(|leaf| leaf.device.clone())
                .ok_or(StateMachineError::InvalidCommitEffects)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let manifest_removed = manifest
        .leaf_changes
        .iter()
        .filter_map(|change| match change {
            ManifestLeafChange::Remove(device) => Some(device.clone()),
            ManifestLeafChange::Add { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    if manifest_removed != removed_devices {
        return Err(StateMachineError::InvalidCommitEffects);
    }

    match form {
        CommitManifestForm::Generic => {
            if !manifest.participant_changes.is_empty()
                || manifest
                    .leaf_changes
                    .iter()
                    .any(|change| matches!(change, ManifestLeafChange::Add { .. }))
                || manifest.leaf_recovery_request_id.is_some()
                || manifest.welcome.is_some()
            {
                return Err(StateMachineError::InvalidCommitEffects);
            }
        }
        CommitManifestForm::Recovery {
            target,
            recovery_request_id,
            key_package_ref,
            welcome_id,
            welcome,
        } => {
            let adds = manifest
                .leaf_changes
                .iter()
                .filter_map(|change| match change {
                    ManifestLeafChange::Add {
                        device,
                        recovery_request_id,
                        key_package_ref,
                    } => Some((device, recovery_request_id, key_package_ref)),
                    ManifestLeafChange::Remove(_) => None,
                })
                .collect::<Vec<_>>();
            let signed_welcome = manifest
                .welcome
                .as_ref()
                .ok_or(StateMachineError::InvalidWelcomeMapping)?;
            if !manifest.participant_changes.is_empty()
                || adds.len() != 1
                || adds[0].0 != target
                || adds[0].1 != recovery_request_id
                || adds[0].2 != key_package_ref
                || manifest.leaf_recovery_request_id.as_ref() != Some(recovery_request_id)
                || &signed_welcome.welcome_id != welcome_id
                || &signed_welcome.recipient != target
                || &signed_welcome.recovery_request_id != recovery_request_id
                || &signed_welcome.key_package_ref != key_package_ref
                || signed_welcome.opaque_welcome != welcome.wire_bytes()
                || signed_welcome.sha256 != <[u8; 32]>::from(Sha256::digest(welcome.wire_bytes()))
            {
                return Err(StateMachineError::InvalidWelcomeMapping);
            }
        }
        CommitManifestForm::Leave { requester } => {
            if manifest.participant_changes
                != vec![ManifestParticipantChange::Remove(requester.clone())]
                || manifest
                    .leaf_changes
                    .iter()
                    .any(|change| matches!(change, ManifestLeafChange::Add { .. }))
                || manifest.leaf_recovery_request_id.is_some()
                || manifest.welcome.is_some()
            {
                return Err(StateMachineError::InvalidCommitEffects);
            }
        }
    }
    Ok(())
}

fn require_acceptance_body(
    evidence: &TransitionEvidence,
    prior: &PublicGroupSnapshotCoordinate,
    next: &PublicGroupSnapshotCoordinate,
    recovery_request_id: &[u8; 16],
    actor: &DeviceIdentity,
    retained_invitation: Option<&InvitationProvenance>,
) -> Result<(), StateMachineError> {
    match evidence.body_binding.as_ref() {
        Some(TransitionBodyBinding::Acceptance {
            prior: signed_prior,
            next: signed_next,
            recovery_request_id: signed_request_id,
            invitation_provenance,
            recovery,
        }) if signed_prior == prior
            && signed_next == next
            && signed_request_id == recovery_request_id
            && recovery.request_id == *recovery_request_id
            && recovery.conversation_id == *prior.conversation_id()
            && recovery.target == *actor
            && recovery.kind == LeafRecoveryKind::Add
            && recovery.bound_coordinate == *next
            && retained_invitation.is_some_and(|retained| {
                invitation_provenance.transition_id == retained.transition.transition_id
                    && invitation_provenance.inviter == retained.inviter
            }) =>
        {
            Ok(())
        }
        Some(_) => Err(StateMachineError::InvalidTransition),
        None => Ok(()),
    }
}

fn require_metadata_body<'a>(
    prior: &ConversationState,
    evidence: &'a TransitionEvidence,
    next: &PublicGroupSnapshotCoordinate,
) -> Result<&'a MetadataSnapshotBinding, StateMachineError> {
    let previous = prior
        .metadata
        .as_ref()
        .ok_or(StateMachineError::InvalidMetadataAuthority)?;
    let Some(TransitionBodyBinding::Metadata {
        prior: signed_prior,
        next: signed_next,
        metadata,
    }) = evidence.body_binding.as_ref()
    else {
        return Err(StateMachineError::InvalidMetadataAuthority);
    };
    let expected_version = previous
        .metadata_version
        .checked_add(1)
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(StateMachineError::MetadataVersionOverflow)?;
    if signed_prior != &prior.coordinate
        || signed_next != next
        || !metadata_coordinate_matches(metadata, next)
        || metadata.metadata_version != expected_version
        || metadata.origin_transition_id != evidence.transition_id
        || metadata.nonce == previous.nonce
        || !metadata_author_matches_evidence(metadata, evidence)
    {
        return Err(StateMachineError::InvalidMetadataAuthority);
    }
    Ok(metadata)
}

fn require_reset_activation_body(
    evidence: &TransitionEvidence,
    reset_request_id: &[u8; 16],
    prior: &ConversationState,
    retired: &PublicGroupSnapshotCoordinate,
    actor: &DeviceIdentity,
    successor_public_state: &ActivePublicState,
) -> Result<(), StateMachineError> {
    let successor = successor_public_state.coordinate();
    match evidence.body_binding.as_ref() {
        Some(TransitionBodyBinding::ResetActivation {
            kind: signed_kind,
            reset_request_id: signed_request_id,
            prior: signed_prior,
            retired: signed_retired,
            successor: signed_successor,
            manifest,
            group_info_sha256,
            metadata,
            ..
        }) if *signed_kind == prior.kind
            && signed_request_id == reset_request_id
            && signed_prior == &prior.coordinate
            && signed_retired == retired
            && signed_successor == successor
            && (evidence.authority.is_none()
                || (successor_public_state.verified_group_info_sha256()
                    == Some(group_info_sha256)
                    && reset_manifest_matches(manifest, prior, actor)
                    && reset_metadata_matches(
                        evidence,
                        prior,
                        metadata,
                        successor_public_state.coordinate(),
                    ))) =>
        {
            Ok(())
        }
        Some(_) => Err(StateMachineError::InvalidTransition),
        None => Ok(()),
    }
}

fn reset_metadata_matches(
    evidence: &TransitionEvidence,
    prior: &ConversationState,
    next: &MetadataSnapshotBinding,
    successor: &PublicGroupSnapshotCoordinate,
) -> bool {
    let Some(previous) = prior.metadata.as_ref() else {
        return false;
    };
    if !metadata_coordinate_matches(next, successor) || next.nonce == previous.nonce {
        return false;
    }
    let reencrypted = next.metadata_version == previous.metadata_version
        && next.origin_transition_id == previous.origin_transition_id
        && next.author_proof == previous.author_proof
        && next.avatar_binding_digest == previous.avatar_binding_digest;
    let fresh_empty = previous
        .metadata_version
        .checked_add(1)
        .is_some_and(|version| version == next.metadata_version)
        && next.origin_transition_id == evidence.transition_id
        && metadata_author_matches_evidence(next, evidence);
    reencrypted || fresh_empty
}

fn reset_manifest_matches(
    manifest: &RosterManifestBinding,
    prior: &ConversationState,
    actor: &DeviceIdentity,
) -> bool {
    manifest.actor_leaf == *actor
        && manifest.participants.len() == prior.participants.len()
        && manifest
            .participants
            .iter()
            .zip(&prior.participants)
            .all(|(signed, retained)| {
                signed.principal == retained.principal
                    && signed.status == retained.status
                    && signed.role == retained.role
                    && match (&signed.invitation, &retained.invitation) {
                        (None, None) => true,
                        (Some(signed), Some(retained)) => {
                            signed.transition_id == retained.transition.transition_id
                                && signed.inviter == retained.inviter
                        }
                        _ => false,
                    }
            })
}

fn require_coordinate_only_body(
    evidence: &TransitionEvidence,
    expected_kind: SignedMutationKind,
    kind: ConversationKind,
    prior: &PublicGroupSnapshotCoordinate,
    next: &PublicGroupSnapshotCoordinate,
) -> Result<(), StateMachineError> {
    let valid = match (expected_kind, evidence.body_binding.as_ref()) {
        (
            SignedMutationKind::ZeroLeafLeave,
            Some(TransitionBodyBinding::ZeroLeafLeave {
                prior: signed_prior,
                next: signed_next,
            }),
        ) => signed_prior == prior && signed_next == next,
        (
            SignedMutationKind::ConversationClose,
            Some(TransitionBodyBinding::ConversationClose {
                kind: signed_kind,
                prior: signed_prior,
                retired: signed_retired,
            }),
        ) => *signed_kind == kind && signed_prior == prior && signed_retired == next,
        (_, None) => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(StateMachineError::InvalidTransition)
    }
}

fn transition_has_one_of_kinds(
    evidence: &TransitionEvidence,
    expected: &[SignedMutationKind],
) -> bool {
    evidence
        .authority
        .as_ref()
        .is_none_or(|authority| expected.contains(&authority.kind))
}

fn validate_intervals(
    intervals: &[AccessInterval],
    root: &PublicGroupSnapshotCoordinate,
    conversation_kind: ConversationKind,
) -> Result<(), StateMachineError> {
    if intervals.is_empty()
        || intervals.windows(2).any(|pair| {
            pair[0]
                .recipient
                .cmp(&pair[1].recipient)
                .then_with(|| pair[0].opening.seq.cmp(&pair[1].opening.seq))
                != Ordering::Less
        })
        || intervals.iter().enumerate().any(|(index, left)| {
            intervals[index + 1..].iter().any(|right| {
                left.generation == right.generation
                    && left.opening_context.group_id() != right.opening_context.group_id()
            })
        })
    {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    for interval in intervals {
        let opening_kind_valid = match interval.opening_kind {
            OpeningKind::Creation => {
                transition_has_one_of_kinds(&interval.opening, &[SignedMutationKind::Creation])
            }
            OpeningKind::Add => transition_has_one_of_kinds(
                &interval.opening,
                &[SignedMutationKind::LeafRecoveryFulfillment],
            ),
            OpeningKind::Reset => transition_has_one_of_kinds(
                &interval.opening,
                &[SignedMutationKind::ResetActivation],
            ),
        };
        let end_kind_valid = interval.end.as_ref().is_none_or(|end| match end.kind {
            CloseKind::Replace => transition_has_one_of_kinds(
                &end.evidence,
                &[SignedMutationKind::LeafRecoveryFulfillment],
            ),
            CloseKind::Reset => {
                transition_has_one_of_kinds(&end.evidence, &[SignedMutationKind::ResetActivation])
            }
            CloseKind::Terminal => {
                transition_has_one_of_kinds(&end.evidence, &[SignedMutationKind::ConversationClose])
            }
            CloseKind::Remove => transition_has_one_of_kinds(
                &end.evidence,
                &[
                    SignedMutationKind::CommitTransition,
                    SignedMutationKind::LeaveCommitFulfillment,
                ],
            ),
        });
        if !validate_transition_evidence(&interval.opening)
            || !opening_kind_valid
            || !opening_matches_interval(interval, conversation_kind, root)
            || !end_kind_valid
            || interval
                .opening
                .authority
                .as_ref()
                .is_some_and(|authority| {
                    authority.control_conversation_id.as_ref() != Some(root.conversation_id())
                })
            || interval.opening_context.lifecycle() != PublicGroupSnapshotLifecycle::Active
            || interval.opening_context.conversation_id() != root.conversation_id()
            || interval.opening_context.generation() != interval.generation
            || interval.generation > root.generation()
            || (interval.generation == root.generation()
                && interval.opening_context.group_id() != root.group_id())
            || interval.end.as_ref().is_some_and(|end| {
                !validate_transition_evidence(&end.evidence)
                    || !end_matches_interval(interval, end, conversation_kind, root)
                    || end.evidence.authority.as_ref().is_some_and(|authority| {
                        authority.control_conversation_id.as_ref() != Some(root.conversation_id())
                    })
                    || end.evidence.seq <= interval.opening.seq
            })
        {
            return Err(StateMachineError::InvalidIntervalBoundary);
        }
    }
    for window in intervals.windows(2) {
        if window[0].recipient != window[1].recipient {
            continue;
        }
        let end = window[0]
            .end
            .as_ref()
            .ok_or(StateMachineError::InvalidIntervalBoundary)?;
        let touching = end.evidence.seq == window[1].opening.seq;
        let valid_touch = match (end.kind, window[1].opening_kind) {
            (CloseKind::Replace, OpeningKind::Add) => {
                window[1].generation == window[0].generation
                    && window[1].opening_context.group_id() == window[0].opening_context.group_id()
            }
            (CloseKind::Reset, OpeningKind::Reset) => {
                window[0]
                    .generation
                    .checked_add(1)
                    .is_some_and(|generation| generation == window[1].generation)
                    && window[1].opening_context.state_version() == 0
                    && window[1].opening_context.epoch() == 0
                    && window[1].opening_context.group_id() != window[0].opening_context.group_id()
            }
            _ => false,
        };
        if end.evidence.seq > window[1].opening.seq
            || (touching && (!valid_touch || end.evidence != window[1].opening))
            || end.kind == CloseKind::Terminal
        {
            return Err(StateMachineError::InvalidIntervalBoundary);
        }
    }
    Ok(())
}

fn opening_matches_interval(
    interval: &AccessInterval,
    conversation_kind: ConversationKind,
    root: &PublicGroupSnapshotCoordinate,
) -> bool {
    let evidence = &interval.opening;
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    match (interval.opening_kind, evidence.body_binding.as_ref()) {
        (
            OpeningKind::Creation,
            Some(TransitionBodyBinding::Creation {
                kind,
                next,
                manifest,
                ..
            }),
        ) => {
            authority.kind == SignedMutationKind::Creation
                && authority.actor == interval.recipient
                && *kind == conversation_kind
                && next == &interval.opening_context
                && manifest.actor_leaf == interval.recipient
                && manifest
                    .participants
                    .iter()
                    .filter(|participant| {
                        participant.principal == *interval.recipient.principal()
                            && participant.status == ParticipantStatus::Active
                            && participant.role == ParticipantRole::Admin
                            && participant.invitation.is_none()
                    })
                    .count()
                    == 1
                && interval.opening_context.generation() == 0
                && interval.opening_context.state_version() == 0
                && interval.opening_context.epoch() == 0
        }
        (
            OpeningKind::Add,
            Some(TransitionBodyBinding::LeafRecoveryFulfillment {
                recovery_request_id,
                prior,
                next,
                manifest,
                ..
            }),
        ) => {
            authority.kind == SignedMutationKind::LeafRecoveryFulfillment
                && next == &interval.opening_context
                && commit_coordinate_edge(prior, next)
                && coordinate_is_in_lineage(next, root)
                && manifest.leaf_recovery_request_id.as_ref() == Some(recovery_request_id)
                && manifest
                    .leaf_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestLeafChange::Add {
                        device,
                        recovery_request_id: signed_request_id,
                        ..
                    } if device == &interval.recipient
                        && signed_request_id == recovery_request_id)
                    })
                    .count()
                    == 1
        }
        (
            OpeningKind::Reset,
            Some(TransitionBodyBinding::ResetActivation {
                kind,
                prior,
                retired,
                successor,
                manifest,
                ..
            }),
        ) => {
            authority.kind == SignedMutationKind::ResetActivation
                && authority.actor == interval.recipient
                && *kind == conversation_kind
                && successor == &interval.opening_context
                && manifest.actor_leaf == interval.recipient
                && retired_coordinate(prior).is_ok_and(|expected| &expected == retired)
                && reset_successor_edge(prior, successor)
                && coordinate_is_in_lineage(successor, root)
        }
        _ => false,
    }
}

fn end_matches_interval(
    interval: &AccessInterval,
    end: &AccessIntervalEnd,
    conversation_kind: ConversationKind,
    root: &PublicGroupSnapshotCoordinate,
) -> bool {
    let evidence = &end.evidence;
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    match (end.kind, authority.kind, evidence.body_binding.as_ref()) {
        (
            CloseKind::Replace,
            SignedMutationKind::LeafRecoveryFulfillment,
            Some(TransitionBodyBinding::LeafRecoveryFulfillment {
                recovery_request_id,
                prior,
                next,
                manifest,
                ..
            }),
        ) => {
            coordinate_after_opening(prior, &interval.opening_context)
                && commit_coordinate_edge(prior, next)
                && coordinate_is_in_lineage(next, root)
                && manifest.leaf_recovery_request_id.as_ref() == Some(recovery_request_id)
                && manifest
                    .leaf_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestLeafChange::Remove(device)
                        if device == &interval.recipient)
                    })
                    .count()
                    == 1
                && manifest
                    .leaf_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestLeafChange::Add {
                        device,
                        recovery_request_id: signed_request_id,
                        ..
                    } if device == &interval.recipient
                        && signed_request_id == recovery_request_id)
                    })
                    .count()
                    == 1
        }
        (
            CloseKind::Remove,
            SignedMutationKind::CommitTransition,
            Some(TransitionBodyBinding::Commit {
                prior,
                next,
                manifest,
                ..
            }),
        ) => {
            coordinate_after_opening(prior, &interval.opening_context)
                && commit_coordinate_edge(prior, next)
                && coordinate_is_in_lineage(next, root)
                && manifest
                    .leaf_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestLeafChange::Remove(device)
                        if device == &interval.recipient)
                    })
                    .count()
                    == 1
        }
        (
            CloseKind::Remove,
            SignedMutationKind::LeaveCommitFulfillment,
            Some(TransitionBodyBinding::LeaveCommitFulfillment {
                prior,
                next,
                manifest,
                ..
            }),
        ) => {
            coordinate_after_opening(prior, &interval.opening_context)
                && commit_coordinate_edge(prior, next)
                && coordinate_is_in_lineage(next, root)
                && manifest
                    .participant_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestParticipantChange::Remove(principal)
                        if principal == interval.recipient.principal())
                    })
                    .count()
                    == 1
                && manifest
                    .leaf_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestLeafChange::Remove(device)
                        if device == &interval.recipient)
                    })
                    .count()
                    == 1
        }
        (
            CloseKind::Reset,
            SignedMutationKind::ResetActivation,
            Some(TransitionBodyBinding::ResetActivation {
                kind,
                prior,
                retired,
                successor,
                ..
            }),
        ) => {
            *kind == conversation_kind
                && coordinate_after_opening(prior, &interval.opening_context)
                && retired_coordinate(prior).is_ok_and(|expected| &expected == retired)
                && reset_successor_edge(prior, successor)
                && coordinate_is_in_lineage(successor, root)
        }
        (
            CloseKind::Terminal,
            SignedMutationKind::ConversationClose,
            Some(TransitionBodyBinding::ConversationClose {
                kind,
                prior,
                retired,
            }),
        ) => {
            *kind == conversation_kind
                && coordinate_after_opening(prior, &interval.opening_context)
                && retired_coordinate(prior).is_ok_and(|expected| &expected == retired)
                && retired == root
        }
        _ => false,
    }
}

fn coordinate_after_opening(
    coordinate: &PublicGroupSnapshotCoordinate,
    opening: &PublicGroupSnapshotCoordinate,
) -> bool {
    coordinate.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && coordinate.conversation_id() == opening.conversation_id()
        && coordinate.generation() == opening.generation()
        && coordinate.group_id() == opening.group_id()
        && coordinate.state_version() >= opening.state_version()
}

fn commit_coordinate_edge(
    prior: &PublicGroupSnapshotCoordinate,
    next: &PublicGroupSnapshotCoordinate,
) -> bool {
    prior.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && next.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && prior.conversation_id() == next.conversation_id()
        && prior.generation() == next.generation()
        && prior.group_id() == next.group_id()
        && prior.state_version().checked_add(1) == Some(next.state_version())
        && prior.epoch().checked_add(1) == Some(next.epoch())
}

fn reset_successor_edge(
    prior: &PublicGroupSnapshotCoordinate,
    successor: &PublicGroupSnapshotCoordinate,
) -> bool {
    prior.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && successor.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && prior.conversation_id() == successor.conversation_id()
        && prior.generation().checked_add(1) == Some(successor.generation())
        && successor.state_version() == 0
        && successor.epoch() == 0
        && prior.group_id() != successor.group_id()
}

fn validate_terminal_proofs(state: &ConversationState) -> Result<(), StateMachineError> {
    if state
        .terminal_proofs
        .windows(2)
        .any(|pair| pair[0].recipient >= pair[1].recipient)
        || state
            .intervals
            .iter()
            .any(|interval| interval.end.is_none())
    {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    let recipients = state
        .intervals
        .iter()
        .map(|interval| &interval.recipient)
        .collect::<BTreeSet<_>>();
    let proof_recipients = state
        .terminal_proofs
        .iter()
        .map(|proof| &proof.recipient)
        .collect::<BTreeSet<_>>();
    if state.terminal_proofs.len() != recipients.len() || proof_recipients != recipients {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    let mut terminal_evidence: Option<&TransitionEvidence> = None;
    for interval in &state.intervals {
        let end = interval.end.as_ref().expect("checked above");
        if end.kind == CloseKind::Terminal {
            if terminal_evidence.is_some_and(|evidence| evidence != &end.evidence) {
                return Err(StateMachineError::InvalidIntervalBoundary);
            }
            terminal_evidence = Some(&end.evidence);
        }
    }
    let terminal_evidence = terminal_evidence.ok_or(StateMachineError::InvalidIntervalBoundary)?;
    if !validate_transition_evidence(terminal_evidence)
        || !transition_has_one_of_kinds(terminal_evidence, &[SignedMutationKind::ConversationClose])
        || state.terminal_proofs.iter().any(|proof| {
            &proof.conversation_id != state.coordinate.conversation_id()
                || proof.evidence != *terminal_evidence
        })
        || state.intervals.iter().any(|interval| {
            interval.opening.seq >= terminal_evidence.seq
                || interval.end.as_ref().is_some_and(|end| {
                    if end.kind == CloseKind::Terminal {
                        end.evidence != *terminal_evidence
                    } else {
                        end.evidence.seq >= terminal_evidence.seq
                    }
                })
        })
    {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    Ok(())
}

fn coordinate_is_in_lineage(
    coordinate: &PublicGroupSnapshotCoordinate,
    root: &PublicGroupSnapshotCoordinate,
) -> bool {
    coordinate.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && coordinate.conversation_id() == root.conversation_id()
        && coordinate.generation() <= root.generation()
        && (coordinate.generation() != root.generation()
            || (coordinate.group_id() == root.group_id()
                && coordinate.state_version() <= root.state_version()))
}

fn exact_expiry(
    received_at: ServerTimestamp,
    ttl_millis: i64,
    expires_at: ServerTimestamp,
) -> bool {
    received_at
        .checked_add_millis(ttl_millis)
        .is_ok_and(|expected| expected == expires_at)
}

fn transition_follows_origin(
    evidence: &TransitionEvidence,
    origin_seq: Option<u64>,
    received_at: ServerTimestamp,
    expires_at: ServerTimestamp,
) -> bool {
    validate_transition_evidence(evidence)
        && origin_seq.is_none_or(|origin_seq| evidence.seq > origin_seq)
        && evidence.received_at >= received_at
        && evidence.received_at < expires_at
}

/// A terminal transition may retire only work bound to the exact coordinate
/// consumed by its signed body. Sequence ordering alone is not authority: it
/// would allow a valid later transition from another branch to be spliced onto
/// the row during hydration.
fn transition_consumes_coordinate(
    evidence: &TransitionEvidence,
    bound: &PublicGroupSnapshotCoordinate,
) -> bool {
    if !validate_transition_evidence(evidence) {
        return false;
    }
    let Some(authority) = evidence.authority.as_ref() else {
        // Deterministic planner tests use unsealed evidence. Production rows
        // always carry an authority and a closed body binding.
        return true;
    };
    if authority.control_conversation_id.as_ref() != Some(bound.conversation_id()) {
        return false;
    }
    match evidence.body_binding.as_ref() {
        Some(TransitionBodyBinding::Commit { prior, .. })
        | Some(TransitionBodyBinding::Policy { prior, .. })
        | Some(TransitionBodyBinding::Acceptance { prior, .. })
        | Some(TransitionBodyBinding::Metadata { prior, .. })
        | Some(TransitionBodyBinding::ResetActivation { prior, .. })
        | Some(TransitionBodyBinding::LeafRecoveryFulfillment { prior, .. })
        | Some(TransitionBodyBinding::ConversationClose { prior, .. })
        | Some(TransitionBodyBinding::ZeroLeafLeave { prior, .. })
        | Some(TransitionBodyBinding::LeaveCommitFulfillment { prior, .. }) => prior == bound,
        _ => false,
    }
}

fn recovery_fulfillment_matches_request(
    evidence: &TransitionEvidence,
    request: &RecoveryRequest,
) -> bool {
    if !transition_consumes_coordinate(evidence, &request.bound_coordinate) {
        return false;
    }
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    if authority.kind != SignedMutationKind::LeafRecoveryFulfillment {
        return false;
    }
    matches!(
        evidence.body_binding.as_ref(),
        Some(TransitionBodyBinding::LeafRecoveryFulfillment {
            recovery_request_id,
            prior,
            next,
            manifest,
            ..
        }) if *recovery_request_id == request.request_id
            && prior == &request.bound_coordinate
            && commit_coordinate_edge(prior, next)
            && manifest.leaf_recovery_request_id == Some(request.request_id)
            && manifest.participant_changes.is_empty()
            && manifest.leaf_changes.iter().filter(|change| {
                matches!(change, ManifestLeafChange::Add {
                    device,
                    recovery_request_id,
                    key_package_ref,
                } if device == &request.target
                    && recovery_request_id == &request.request_id
                    && key_package_ref == &request.key_package_ref)
            }).count() == 1
            && match request.kind {
                LeafRecoveryKind::Add => manifest.leaf_changes.iter().all(|change| {
                    !matches!(change, ManifestLeafChange::Remove(device)
                        if device == &request.target)
                }),
                LeafRecoveryKind::Replace => manifest.leaf_changes.iter().filter(|change| {
                    matches!(change, ManifestLeafChange::Remove(device)
                        if device == &request.target)
                }).count() == 1,
            }
            && manifest.welcome.as_ref().is_some_and(|welcome| {
                welcome.recipient == request.target
                    && welcome.recovery_request_id == request.request_id
                    && welcome.key_package_ref == request.key_package_ref
            })
    )
}

fn acceptance_origin_matches_recovery(
    evidence: &TransitionEvidence,
    request: &RecoveryRequest,
    reservation: &RecoveryReservation,
    conversation_id: &[u8; 16],
) -> bool {
    if !validate_transition_evidence(evidence)
        || evidence.received_at != request.received_at
        || request.source != RecoverySource::Acceptance
        || request.kind != LeafRecoveryKind::Add
    {
        return false;
    }
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    if authority.kind != SignedMutationKind::ParticipantAcceptance
        || authority.control_conversation_id.as_ref() != Some(conversation_id)
        || authority.actor != request.target
    {
        return false;
    }
    matches!(
        evidence.body_binding.as_ref(),
        Some(TransitionBodyBinding::Acceptance {
            prior,
            next,
            recovery_request_id,
            invitation_provenance,
            recovery,
        }) if coordinate_only_successor(prior).is_ok_and(|expected| &expected == next)
            && next == &request.bound_coordinate
            && *recovery_request_id == request.request_id
            && is_uuid_v4(&invitation_provenance.transition_id)
            && invitation_provenance.inviter.principal() != request.target.principal()
            && recovery.request_id == request.request_id
            && recovery.conversation_id == *conversation_id
            && recovery.target == request.target
            && recovery.kind == request.kind
            && recovery.bound_coordinate == request.bound_coordinate
            && recovery.requester_key_id == authority.key_id
            && recovery.requester_auth_generation == authority.auth_generation
            && recovery.key_package_ref == request.key_package_ref
            && recovery.key_package_ref == reservation.key_package_ref
            && recovery.requested_at == request.received_at
            && recovery.requested_at == reservation.received_at
            && recovery.expires_at == request.expires_at
            && recovery.expires_at == reservation.expires_at
            && !recovery.key_package_wrapper.is_empty()
            && <[u8; 32]>::from(Sha256::digest(&recovery.key_package_wrapper))
                == recovery.key_package_wrapper_sha256
            && recovery.canonical_digest != [0; 32]
    )
}

fn reset_activation_matches_request(
    evidence: &TransitionEvidence,
    request: &ResetRequest,
    conversation_kind: ConversationKind,
) -> bool {
    if !transition_consumes_coordinate(evidence, &request.bound_coordinate) {
        return false;
    }
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    authority.kind == SignedMutationKind::ResetActivation
        && matches!(
            evidence.body_binding.as_ref(),
            Some(TransitionBodyBinding::ResetActivation {
                kind,
                reset_request_id,
                prior,
                retired,
                successor,
                ..
            }) if *kind == conversation_kind
                && *reset_request_id == request.request_id
                && prior == &request.bound_coordinate
                && retired_coordinate(prior).is_ok_and(|expected| &expected == retired)
                && reset_successor_edge(prior, successor)
        )
}

fn leave_fulfillment_matches_request(
    evidence: &TransitionEvidence,
    request: &LeaveRequest,
) -> bool {
    if !transition_consumes_coordinate(evidence, &request.bound_coordinate) {
        return false;
    }
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    authority.kind == SignedMutationKind::LeaveCommitFulfillment
        && matches!(
            evidence.body_binding.as_ref(),
            Some(TransitionBodyBinding::LeaveCommitFulfillment {
                leave_request_id,
                prior,
                next,
                manifest,
                ..
            }) if *leave_request_id == request.request_id
                && prior == &request.bound_coordinate
                && commit_coordinate_edge(prior, next)
                && manifest.leaf_recovery_request_id.is_none()
                && manifest.welcome.is_none()
                && manifest.participant_changes.iter().filter(|change| {
                    matches!(change, ManifestParticipantChange::Remove(principal)
                        if principal == request.requester.principal())
                }).count() == 1
                && manifest.leaf_changes.iter().any(|change| {
                    matches!(change, ManifestLeafChange::Remove(device)
                        if device.principal() == request.requester.principal())
                })
                && manifest.leaf_changes.iter().all(|change| {
                    matches!(change, ManifestLeafChange::Remove(device)
                        if device.principal() == request.requester.principal())
                })
        )
}

fn validate_work(state: &ConversationState, terminal_state: bool) -> Result<(), StateMachineError> {
    validate_recovery_work(state)?;
    validate_reset_work(state)?;
    validate_leave_work(state)?;
    validate_welcome_work(state)?;
    if terminal_state
        && (state
            .recovery_requests
            .iter()
            .any(|request| request.status == RecoveryRequestStatus::Open)
            || state
                .recovery_reservations
                .iter()
                .any(|reservation| reservation.status == ReservationStatus::Active)
            || state
                .reset_requests
                .iter()
                .any(|request| request.status == ResetRequestStatus::Pending)
            || state
                .leave_requests
                .iter()
                .any(|request| request.status == LeaveRequestStatus::Pending)
            || state
                .welcomes
                .iter()
                .any(|welcome| welcome.status == WelcomeStatus::Pending))
    {
        return Err(StateMachineError::InvariantViolation);
    }
    Ok(())
}

fn validate_recovery_work(state: &ConversationState) -> Result<(), StateMachineError> {
    if state.recovery_requests.len() != state.recovery_reservations.len()
        || state.recovery_requests.windows(2).any(|pair| {
            pair[0]
                .target
                .cmp(&pair[1].target)
                .then_with(|| pair[0].request_id.cmp(&pair[1].request_id))
                != Ordering::Less
        })
        || state.recovery_reservations.windows(2).any(|pair| {
            pair[0]
                .target
                .cmp(&pair[1].target)
                .then_with(|| pair[0].request_id.cmp(&pair[1].request_id))
                != Ordering::Less
        })
        || state
            .recovery_requests
            .iter()
            .map(|request| request.request_id)
            .collect::<BTreeSet<_>>()
            .len()
            != state.recovery_requests.len()
        || state
            .recovery_reservations
            .iter()
            .map(|reservation| reservation.request_id)
            .collect::<BTreeSet<_>>()
            .len()
            != state.recovery_reservations.len()
        || state
            .recovery_reservations
            .iter()
            .map(|reservation| reservation.key_package_ref)
            .collect::<BTreeSet<_>>()
            .len()
            != state.recovery_reservations.len()
    {
        return Err(StateMachineError::InvariantViolation);
    }
    let mut open_targets = BTreeSet::new();
    for request in &state.recovery_requests {
        if !is_uuid_v4(&request.request_id)
            || !coordinate_is_in_lineage(&request.bound_coordinate, &state.coordinate)
            || request.key_package_ref == [0; 32]
        {
            return Err(StateMachineError::InvariantViolation);
        }
        let reservation = state
            .recovery_reservations
            .iter()
            .find(|reservation| reservation.request_id == request.request_id)
            .ok_or(StateMachineError::InvariantViolation)?;
        let expected_expiry = recovery_expiry(request.received_at, reservation.package_not_after)
            .map_err(|_| StateMachineError::InvariantViolation)?;
        if reservation.target != request.target
            || reservation.bound_coordinate != request.bound_coordinate
            || reservation.key_package_ref != request.key_package_ref
            || reservation.received_at != request.received_at
            || reservation.expires_at != request.expires_at
            || request.expires_at != expected_expiry
            || (!matches!(
                reservation.terminal,
                Some(WorkTerminalEvidence::DeviceRevocation(_))
            ) && reservation.terminal != request.terminal)
        {
            return Err(StateMachineError::InvariantViolation);
        }
        let origin_seq = match (&request.source, &request.origin) {
            (RecoverySource::Acceptance, RecoveryOriginEvidence::Acceptance(evidence))
                if acceptance_origin_matches_recovery(
                    evidence,
                    request,
                    reservation,
                    state.coordinate.conversation_id(),
                ) =>
            {
                Some(evidence.seq)
            }
            (RecoverySource::Request, RecoveryOriginEvidence::Request(evidence)) => {
                validate_request_evidence(
                    evidence,
                    RequestEntryKind::LeafRecoveryRequest,
                    state.coordinate.conversation_id(),
                    &request.request_id,
                    &request.target,
                    request.received_at,
                )?;
                require_leaf_recovery_request_binding(
                    evidence,
                    &request.bound_coordinate,
                    request.kind,
                )?;
                None
            }
            _ => return Err(StateMachineError::InvariantViolation),
        };
        let status_matches = match request.status {
            RecoveryRequestStatus::Open => {
                request.terminal.is_none()
                    && reservation.status == ReservationStatus::Active
                    && request.bound_coordinate == state.coordinate
                    && state
                        .participant(request.target.principal())
                        .is_some_and(ParticipantRecord::is_active)
                    && match request.kind {
                        LeafRecoveryKind::Add => state.leaf(&request.target).is_none(),
                        LeafRecoveryKind::Replace => state.leaf(&request.target).is_some(),
                    }
                    && open_targets.insert(request.target.clone())
            }
            RecoveryRequestStatus::Fulfilled => {
                reservation.status == ReservationStatus::Consumed
                    && request.terminal.as_ref().is_some_and(|terminal| {
                        matches!(terminal, WorkTerminalEvidence::Transition(evidence)
                        if transition_follows_origin(
                            evidence,
                            origin_seq,
                            request.received_at,
                            request.expires_at,
                        ) && recovery_fulfillment_matches_request(evidence, request))
                    })
            }
            RecoveryRequestStatus::Cancelled => {
                reservation.status == ReservationStatus::Released
                    && request.terminal.as_ref().is_some_and(|terminal| {
                        let WorkTerminalEvidence::Request(evidence) = terminal else {
                            return false;
                        };
                        validate_request_evidence(
                            evidence,
                            RequestEntryKind::LeafRecoveryCancellation,
                            state.coordinate.conversation_id(),
                            &request.request_id,
                            &request.target,
                            evidence.received_at,
                        )
                        .is_ok()
                            && evidence.request_digest
                                != recovery_origin_request_digest(&request.origin)
                            && evidence.received_at >= request.received_at
                            && evidence.received_at < request.expires_at
                    })
            }
            RecoveryRequestStatus::Expired => {
                request.terminal == Some(WorkTerminalEvidence::Expiry(request.expires_at))
                    && (reservation.status == ReservationStatus::Expired
                        || (reservation.status == ReservationStatus::Released
                            && reservation.terminal.as_ref().is_some_and(|terminal| {
                                matches!(terminal, WorkTerminalEvidence::DeviceRevocation(evidence)
                                    if validate_device_revocation_evidence(evidence)
                                        && evidence.target == request.target
                                        && evidence.accepted_at >= request.expires_at)
                            })))
            }
            RecoveryRequestStatus::Superseded => {
                request
                    .terminal
                    .as_ref()
                    .is_some_and(|terminal| match terminal {
                        WorkTerminalEvidence::Transition(evidence) => {
                            reservation.status == ReservationStatus::Released
                                && transition_follows_origin(
                                    evidence,
                                    origin_seq,
                                    request.received_at,
                                    request.expires_at,
                                )
                                && transition_consumes_coordinate(
                                    evidence,
                                    &request.bound_coordinate,
                                )
                        }
                        WorkTerminalEvidence::DeviceRevocation(revocation) => {
                            reservation.status == ReservationStatus::Released
                                && reservation.terminal.as_ref() == Some(terminal)
                                && revocation_supersedes_request(revocation, request)
                        }
                        _ => false,
                    })
            }
        };
        if !status_matches {
            return Err(StateMachineError::InvariantViolation);
        }
    }
    Ok(())
}

fn revocation_supersedes_request(
    evidence: &DeviceRevocationEvidence,
    request: &RecoveryRequest,
) -> bool {
    let target_generation = match &request.origin {
        RecoveryOriginEvidence::Acceptance(origin) => origin
            .authority
            .as_ref()
            .map(|authority| authority.auth_generation),
        RecoveryOriginEvidence::Request(origin) => Some(origin.auth_generation),
    };
    validate_device_revocation_evidence(evidence)
        && evidence.target == request.target
        && target_generation == Some(evidence.expected_target_auth_generation)
        && evidence.accepted_at >= request.received_at
        && evidence.accepted_at < request.expires_at
}

fn recovery_origin_received_at(origin: &RecoveryOriginEvidence) -> ServerTimestamp {
    match origin {
        RecoveryOriginEvidence::Acceptance(evidence) => evidence.received_at,
        RecoveryOriginEvidence::Request(evidence) => evidence.received_at,
    }
}

fn recovery_origin_request_digest(origin: &RecoveryOriginEvidence) -> [u8; 32] {
    match origin {
        RecoveryOriginEvidence::Acceptance(evidence) => evidence
            .authority
            .as_ref()
            .map_or(evidence.outer_entry_fingerprint, |authority| {
                authority.request_digest
            }),
        RecoveryOriginEvidence::Request(evidence) => evidence.request_digest,
    }
}

fn validate_reset_work(state: &ConversationState) -> Result<(), StateMachineError> {
    if state
        .reset_requests
        .windows(2)
        .any(|pair| pair[0].request_id >= pair[1].request_id)
        || state
            .reset_requests
            .iter()
            .filter(|request| request.status == ResetRequestStatus::Pending)
            .count()
            > 1
    {
        return Err(StateMachineError::InvariantViolation);
    }
    for request in &state.reset_requests {
        if !is_uuid_v4(&request.request_id)
            || !coordinate_is_in_lineage(&request.bound_coordinate, &state.coordinate)
            || !exact_expiry(request.received_at, CONSENT_TTL_MILLIS, request.expires_at)
            || validate_request_evidence(
                &request.origin,
                RequestEntryKind::ResetRequest,
                state.coordinate.conversation_id(),
                &request.request_id,
                &request.requester,
                request.received_at,
            )
            .is_err()
            || require_request_prior(&request.origin, &request.bound_coordinate).is_err()
        {
            return Err(StateMachineError::InvariantViolation);
        }
        let valid = match request.status {
            ResetRequestStatus::Pending => {
                request.terminal.is_none()
                    && request.bound_coordinate == state.coordinate
                    && state
                        .participant(request.requester.principal())
                        .is_some_and(ParticipantRecord::is_active)
            }
            ResetRequestStatus::Consumed => request.terminal.as_ref().is_some_and(|terminal| {
                matches!(terminal, WorkTerminalEvidence::Transition(evidence)
                if transition_follows_origin(
                    evidence,
                    request.origin.control_seq,
                    request.received_at,
                    request.expires_at,
                ) && transition_has_one_of_kinds(
                    evidence,
                    &[SignedMutationKind::ResetActivation],
                ) && reset_activation_matches_request(evidence, request, state.kind))
            }),
            ResetRequestStatus::Stale => request.terminal.as_ref().is_some_and(|terminal| {
                matches!(terminal, WorkTerminalEvidence::Transition(evidence)
                if transition_follows_origin(
                    evidence,
                    request.origin.control_seq,
                    request.received_at,
                    request.expires_at,
                ) && transition_consumes_coordinate(evidence, &request.bound_coordinate))
            }),
            ResetRequestStatus::Expired => {
                request.terminal == Some(WorkTerminalEvidence::Expiry(request.expires_at))
            }
        };
        if !valid {
            return Err(StateMachineError::InvariantViolation);
        }
    }
    Ok(())
}

fn validate_leave_work(state: &ConversationState) -> Result<(), StateMachineError> {
    if state.leave_requests.windows(2).any(|pair| {
        pair[0]
            .requester
            .cmp(&pair[1].requester)
            .then_with(|| pair[0].request_id.cmp(&pair[1].request_id))
            != Ordering::Less
    }) || state
        .leave_requests
        .iter()
        .map(|request| request.request_id)
        .collect::<BTreeSet<_>>()
        .len()
        != state.leave_requests.len()
    {
        return Err(StateMachineError::InvariantViolation);
    }
    let mut pending_principals = BTreeSet::new();
    for request in &state.leave_requests {
        if !is_uuid_v4(&request.request_id)
            || !coordinate_is_in_lineage(&request.bound_coordinate, &state.coordinate)
            || !exact_expiry(request.received_at, CONSENT_TTL_MILLIS, request.expires_at)
            || validate_request_evidence(
                &request.origin,
                RequestEntryKind::LeaveRequest,
                state.coordinate.conversation_id(),
                &request.request_id,
                &request.requester,
                request.received_at,
            )
            .is_err()
            || require_request_prior(&request.origin, &request.bound_coordinate).is_err()
        {
            return Err(StateMachineError::InvariantViolation);
        }
        let valid = match request.status {
            LeaveRequestStatus::Pending => {
                request.terminal.is_none()
                    && request.bound_coordinate == state.coordinate
                    && state
                        .participant(request.requester.principal())
                        .is_some_and(ParticipantRecord::is_active)
                    && state
                        .leaves
                        .iter()
                        .any(|leaf| leaf.device.principal() == request.requester.principal())
                    && pending_principals.insert(request.requester.principal().clone())
            }
            LeaveRequestStatus::Fulfilled => request.terminal.as_ref().is_some_and(|terminal| {
                matches!(terminal, WorkTerminalEvidence::Transition(evidence)
                if transition_follows_origin(
                    evidence,
                    request.origin.control_seq,
                    request.received_at,
                    request.expires_at,
                ) && transition_has_one_of_kinds(
                    evidence,
                    &[SignedMutationKind::LeaveCommitFulfillment],
                ) && leave_fulfillment_matches_request(evidence, request))
            }),
            LeaveRequestStatus::Stale => request.terminal.as_ref().is_some_and(|terminal| {
                matches!(terminal, WorkTerminalEvidence::Transition(evidence)
                if transition_follows_origin(
                    evidence,
                    request.origin.control_seq,
                    request.received_at,
                    request.expires_at,
                ) && transition_consumes_coordinate(evidence, &request.bound_coordinate))
            }),
            LeaveRequestStatus::Cancelled => request.terminal.as_ref().is_some_and(|terminal| {
                let WorkTerminalEvidence::Request(evidence) = terminal else {
                    return false;
                };
                evidence.actor.principal() == request.requester.principal()
                    && validate_request_evidence(
                        evidence,
                        RequestEntryKind::LeaveCancellation,
                        state.coordinate.conversation_id(),
                        &request.request_id,
                        &evidence.actor,
                        evidence.received_at,
                    )
                    .is_ok()
                    && require_request_coordinate_binding(
                        evidence,
                        state.coordinate.conversation_id(),
                    )
                    .is_ok()
                    && evidence
                        .control_seq
                        .zip(request.origin.control_seq)
                        .is_some_and(|(terminal, origin)| terminal > origin)
                    && evidence.control_entry_id != request.origin.control_entry_id
                    && evidence.received_at >= request.received_at
                    && evidence.received_at < request.expires_at
            }),
            LeaveRequestStatus::Expired => {
                request.terminal == Some(WorkTerminalEvidence::Expiry(request.expires_at))
            }
        };
        if !valid {
            return Err(StateMachineError::InvariantViolation);
        }
    }
    Ok(())
}

fn validate_welcome_work(state: &ConversationState) -> Result<(), StateMachineError> {
    if state
        .welcomes
        .windows(2)
        .any(|pair| pair[0].welcome_id >= pair[1].welcome_id)
    {
        return Err(StateMachineError::InvariantViolation);
    }
    let mut fulfilled_requests = BTreeSet::new();
    for welcome in &state.welcomes {
        let request = state
            .recovery_request(&welcome.recovery_request_id)
            .ok_or(StateMachineError::InvariantViolation)?;
        let reservation = state
            .recovery_reservation(&welcome.recovery_request_id)
            .ok_or(StateMachineError::InvariantViolation)?;
        let fulfillment = match request.terminal.as_ref() {
            Some(WorkTerminalEvidence::Transition(evidence))
                if transition_has_one_of_kinds(
                    evidence,
                    &[SignedMutationKind::LeafRecoveryFulfillment],
                ) =>
            {
                evidence
            }
            _ => return Err(StateMachineError::InvariantViolation),
        };
        if !is_uuid_v4(&welcome.welcome_id)
            || !fulfilled_requests.insert(welcome.recovery_request_id)
            || !coordinate_is_in_lineage(&welcome.coordinate, &state.coordinate)
            || welcome.opaque_welcome.is_empty()
            || <[u8; 32]>::from(Sha256::digest(&welcome.opaque_welcome)) != welcome.sha256
            || request.status != RecoveryRequestStatus::Fulfilled
            || reservation.status != ReservationStatus::Consumed
            || welcome.recipient != request.target
            || welcome.key_package_ref != request.key_package_ref
            || welcome.expires_at != reservation.package_not_after
            || welcome.transition_seq != fulfillment.seq
            || (fulfillment.authority.is_some()
                && !fulfillment.body_binding.as_ref().is_some_and(|binding| {
                    matches!(
                        binding,
                        TransitionBodyBinding::LeafRecoveryFulfillment {
                            recovery_request_id,
                            next,
                            manifest,
                            ..
                        } if recovery_request_id == &welcome.recovery_request_id
                            && next == &welcome.coordinate
                            && manifest.welcome.as_ref().is_some_and(|signed| {
                                signed.welcome_id == welcome.welcome_id
                                    && signed.recipient == welcome.recipient
                                    && signed.recovery_request_id == welcome.recovery_request_id
                                    && signed.key_package_ref == welcome.key_package_ref
                                    && signed.opaque_welcome == welcome.opaque_welcome
                                    && signed.sha256 == welcome.sha256
                            })
                    )
                }))
        {
            return Err(StateMachineError::InvariantViolation);
        }
        let valid = match welcome.status {
            WelcomeStatus::Pending => {
                welcome.terminal.is_none() && welcome.coordinate == state.coordinate
            }
            WelcomeStatus::Expired => {
                welcome.terminal == Some(WorkTerminalEvidence::Expiry(welcome.expires_at))
            }
            WelcomeStatus::Superseded => {
                welcome
                    .terminal
                    .as_ref()
                    .is_some_and(|terminal| match terminal {
                        WorkTerminalEvidence::Transition(evidence) => {
                            validate_transition_evidence(evidence)
                                && evidence.seq > welcome.transition_seq
                                && evidence.received_at < welcome.expires_at
                                && transition_consumes_coordinate(evidence, &welcome.coordinate)
                        }
                        WorkTerminalEvidence::DeviceRevocation(evidence) => {
                            validate_device_revocation_evidence(evidence)
                                && evidence.target == welcome.recipient
                                && evidence.accepted_at < welcome.expires_at
                        }
                        _ => false,
                    })
            }
            WelcomeStatus::Acknowledged | WelcomeStatus::Rejected => welcome
                .terminal
                .as_ref()
                .is_some_and(|terminal| match terminal {
                    WorkTerminalEvidence::Request(evidence) => {
                        let expected_kind = if welcome.status == WelcomeStatus::Acknowledged {
                            RequestEntryKind::WelcomeAcknowledgement
                        } else {
                            RequestEntryKind::WelcomeRejection
                        };
                        validate_request_evidence(
                            evidence,
                            expected_kind,
                            state.coordinate.conversation_id(),
                            &welcome.welcome_id,
                            &welcome.recipient,
                            evidence.received_at,
                        )
                        .is_ok()
                            && evidence.received_at < welcome.expires_at
                            && matches!(
                                evidence.body_binding.as_ref(),
                                Some(RequestBodyBinding::WelcomeResponse {
                                    coordinates,
                                    transition_seq,
                                }) if coordinates == &welcome.coordinate
                                    && *transition_seq == welcome.transition_seq
                            )
                    }
                    _ => false,
                }),
        };
        if !valid {
            return Err(StateMachineError::InvariantViolation);
        }
    }
    if state
        .recovery_requests
        .iter()
        .filter(|request| request.status == RecoveryRequestStatus::Fulfilled)
        .any(|request| !fulfilled_requests.contains(&request.request_id))
    {
        return Err(StateMachineError::InvariantViolation);
    }
    Ok(())
}

fn would_remove_last_active_admin(state: &ConversationState, principal: &PrincipalId) -> bool {
    state.participant(principal).is_some_and(|participant| {
        participant.status == ParticipantStatus::Active
            && participant.role == ParticipantRole::Admin
    }) && state
        .participants
        .iter()
        .filter(|participant| {
            participant.status == ParticipantStatus::Active
                && participant.role == ParticipantRole::Admin
        })
        .count()
        == 1
}

// ===========================================================================
// Task E2b-2 — the transition executor: apply_conversation_persistence_plan.
//
// This is the composition seam. It lives inside `state_machine.rs` (the
// protocol's "only writer") because it reads the plan's PRIVATE evidence types
// without widening any type surface, then delegates the raw SQL to the E2a
// (`repository::transition`) and E1 + E2b-1 (`repository::delivery`) dumb-SQL
// writers. It is transaction-scoped: it never begins or commits the outer
// transaction, so failure paths stay testable (the caller owns commit/rollback).
//
// This module is compiled unconditionally (E2b-3). It resolves
// `super::repository::{transition,delivery}`, which `repository/mod.rs` now
// compiles unconditionally too. Under the production `cfg(not(test))` build this
// is byte-identical to the prior `#[cfg(not(test))]` gating (both were present);
// under `cfg(test)` it is additionally available so the integration harness can
// drive the executor end-to-end. The integration test include chain therefore
// provides a `chat_protocol::repository` module (matching the lib layout) so the
// `super::repository::*` paths resolve there as well. See the E2b-3 report.
// ===========================================================================

pub(crate) use executor::{
    apply_conversation_persistence_plan, apply_device_revocation_batch, AppliedTransition,
    ControlEntryContent, EventFanout, ExecutionActor, ExecutionContext, ExecutorError,
    LeafPersistenceColumns, MetadataAuthorColumns, RecoveryOpenContext, ResetRequestRow,
    SpineArtifacts, WelcomeDispositionInput, WelcomeExpiryContext, WelcomeRejectionWork,
    WelcomeResponseContext,
};

mod executor {
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    use std::collections::HashMap;

    use super::super::repository::delivery::{
        self as delivery, AppendEntry, ApplicationIntervalClose, DeliveryRepositoryError,
        EntryEntitlementKind, EntryRecipient, EventEntitlementKind, EventKind, EventRecipient,
        IntervalCloseKind, IntervalOpeningKind, NewApplicationInterval, NewEvent,
        NewScheduleTerminalProof, NewWelcomeBundle, NewWelcomeDelivery, OutboxWorkKind,
        WelcomeClientAuthorization, WelcomeDisposition, WelcomeRejectionReason,
    };
    use super::super::repository::transition::{
        self as transition, cas_registration_revoke, insert_device_revocation,
        ConversationHeadClose, ConversationHeadKind, GenerationStateKind, GenerationStateLifecycle,
        GenerationSupersede, LeafClose, LeafOrigin, LeafRecoveryKind as RepoLeafRecoveryKind,
        LeafRecoverySource, LeafRecoveryTermination, LeaveRequestTermination, NewDeviceRevocation,
        NewGeneration, NewGenerationState, NewLeafPeriod, NewLeafRecoveryRequest, NewLeaveRequest,
        NewMetadataSnapshot, NewParticipantPeriod, NewReservation, NewResetRequest, NewTransition,
        PackageStatus as RepoPackageStatus, PackageSuccessor, ParticipantAcceptance,
        ParticipantAcceptanceCas, ParticipantInvitation, ParticipantRole as RepoParticipantRole,
        ParticipantStatus as RepoParticipantStatus, RegistrationRevoke, ReservationTermination,
        ResetRequestTermination, TransitionActorRole, TransitionCoordinates, TransitionKind,
        TransitionRepositoryError,
    };
    use super::{
        revocation_package_cas_bijection_valid, CloseKind, ConversationKind, DeviceIdentity,
        DeviceRevocationBatchPersistencePlan, LeafHydrationRow, LeafRecord, LeafRecoveryKind,
        LeaveRequestStatus, MetadataSnapshotBinding, PackageStatus, ParticipantHydrationRow,
        ParticipantRole, ParticipantStatus, PlanAuthority, PlanKind, PrincipalId,
        PublicGroupSnapshotCoordinate, RecoveryRequestStatus, RecoverySource, ReservationStatus,
        ResetRequestStatus, ServerTimestamp, StateChange, TransitionEffects, WelcomeStatus,
    };
    use super::{ConversationPersistencePlan, ConversationStateHydration};
    use super::{Engine, URL_SAFE_NO_PAD};

    /// Failures the executor surfaces. Repository errors propagate typed; the
    /// executor's own contract violations (an effect family the current
    /// composition does not persist, a missing context input, a coordinate that
    /// overflows `i64`) are distinct so a caller can tell a CAS conflict from a
    /// programming/plan-shape error.
    #[derive(Debug)]
    pub(crate) enum ExecutorError {
        /// A `repository::transition` writer failed (including its typed
        /// `CompareAndSetConflict` — the head/spine CAS lost a race or drifted).
        Transition(TransitionRepositoryError),
        /// A `repository::delivery` writer failed (append/audience/event, or its
        /// typed `CompareAndSetConflict`).
        Delivery(DeliveryRepositoryError),
        /// The plan carried a non-empty effect family this executor does not yet
        /// persist. Emitted as a HARD error rather than silently dropped, so a
        /// future planner change cannot lose writes. Carries the family name.
        UnsupportedEffect(&'static str),
        /// The plan was internally inconsistent for the executor's contract
        /// (e.g. a creation plan without a head CAS binding or without the
        /// required metadata snapshot). Never a silent skip.
        InconsistentPlan(&'static str),
        /// An `ExecutionContext` input required for a row was absent (e.g. no
        /// leaf-auth-generation for an opened leaf).
        MissingContext(&'static str),
        /// A protocol integer or timestamp fell outside the safe `i64` range.
        ValueOutOfRange,
    }

    impl From<TransitionRepositoryError> for ExecutorError {
        fn from(error: TransitionRepositoryError) -> Self {
            Self::Transition(error)
        }
    }

    impl From<DeliveryRepositoryError> for ExecutorError {
        fn from(error: DeliveryRepositoryError) -> Self {
            Self::Delivery(error)
        }
    }

    /// The actor's identity + auth-sourced columns the plan does NOT carry. The
    /// facade sources these from the locked registration / participant / device
    /// context; the integration tests supply them explicitly from their fixtures.
    #[derive(Clone, Debug)]
    pub(crate) struct ExecutionActor {
        pub(crate) user_did: String,
        pub(crate) device_id: Uuid,
        pub(crate) key_id: String,
        pub(crate) auth_generation: i64,
        /// `transitions.actor_role` — the actor's locked participant role.
        pub(crate) role: TransitionActorRole,
        /// `transitions.actor_device_status` — the actor's locked device status.
        pub(crate) device_status: String,
    }

    /// The exact control-entry row content + the transition's signed material.
    /// Every field is the verified signed artifact or its digest; none is
    /// re-derived by the executor.
    #[derive(Clone, Debug)]
    pub(crate) struct ControlEntryContent {
        pub(crate) entry_id: Uuid,
        pub(crate) entry_kind: String,
        pub(crate) accepted_payload_bytes: Vec<u8>,
        pub(crate) accepted_payload_sha256: Vec<u8>,
        pub(crate) signed_request_bytes: Vec<u8>,
        pub(crate) unsigned_projection_bytes: Vec<u8>,
        pub(crate) signing_transcript_bytes: Vec<u8>,
        pub(crate) request_digest: Vec<u8>,
        pub(crate) signature: Vec<u8>,
        pub(crate) server_fields_bytes: Vec<u8>,
        pub(crate) outer_entry_fingerprint: Vec<u8>,
    }

    /// The public-state serialization artifacts the coordinate spine stores. The
    /// facade produces these from the validated merged public state; they are
    /// input, never re-serialized by the executor.
    #[derive(Clone, Debug)]
    pub(crate) struct SpineArtifacts {
        pub(crate) public_snapshot_bytes: Vec<u8>,
        pub(crate) public_snapshot_sha256: Vec<u8>,
        pub(crate) tree_summary_bytes: Vec<u8>,
        pub(crate) tree_summary_sha256: Vec<u8>,
        pub(crate) leaf_count: i64,
        /// Genesis GroupInfo for the activated generation (creation / reset).
        pub(crate) genesis_group_info_bytes: Vec<u8>,
        pub(crate) genesis_group_info_sha256: Vec<u8>,
    }

    /// Per-opened-leaf columns absent from `LeafHydrationRow`: the leaf's key id
    /// and `member_devices.leaf_auth_generation` (sourced from
    /// `chat.device_keys.enrollment_auth_generation`).
    #[derive(Clone, Debug)]
    pub(crate) struct LeafPersistenceColumns {
        pub(crate) device: DeviceIdentity,
        pub(crate) leaf_key_id: String,
        pub(crate) leaf_auth_generation: i64,
    }

    /// Metadata author columns the `MetadataSnapshotBinding` does not carry as DB
    /// strings: `author_role` / `author_device_status` (DDL-forced `admin` /
    /// `active`) and the 32-byte Ed25519 signature public key stored verbatim.
    #[derive(Clone, Debug)]
    pub(crate) struct MetadataAuthorColumns {
        pub(crate) author_role: String,
        pub(crate) author_device_status: String,
        pub(crate) author_public_key: Vec<u8>,
        /// The author's `chat.device_keys.key_id` (base64url) — the DB string the
        /// `MetadataSnapshotBinding` author-proof carries only as a raw 32-byte id.
        /// For a creation/reset self-origin snapshot this equals the actor's key id;
        /// for a commit/leafRecovery re-encryption it is the ORIGINAL author's key
        /// id (carried forward, may differ from the fulfiller).
        pub(crate) author_key_id: String,
        /// Fresh `chat.metadata_snapshots` primary key for this snapshot.
        pub(crate) metadata_snapshot_id: Uuid,
    }

    /// One event to append with its frozen audience and outbox work.
    #[derive(Clone, Debug)]
    pub(crate) struct EventFanout {
        pub(crate) event_id: Uuid,
        pub(crate) event_kind: EventKind,
        pub(crate) payload_bytes: Vec<u8>,
        /// `(device, entitlement, predecessor_position)` in canonical order.
        pub(crate) recipients: Vec<(DeviceIdentity, EventEntitlementKind, Option<i64>)>,
        /// `(outbox_id, work_kind)` rows to enqueue for this event.
        pub(crate) outbox: Vec<(Uuid, OutboxWorkKind)>,
    }

    /// For a `welcomeExpiry` edge: the DB-side facts the plan does not carry — the
    /// fresh `recovery_work_items` primary key and the `welcomeDisposition` event
    /// whose position binds the disposition row. The welcome id / recipient /
    /// bound coordinate / `expires_at` come from the plan's `welcome_changes`.
    /// `None` for every other edge.
    #[derive(Clone, Debug)]
    pub(crate) struct WelcomeExpiryContext {
        pub(crate) recovery_work_id: Uuid,
        pub(crate) event: EventFanout,
    }

    /// For a `welcomeAcknowledgement` / `welcomeRejection` edge: the
    /// `welcomeDisposition` event (its position binds the disposition row) plus, for
    /// a REJECTION only, the `welcomeRejected` recovery work. The client-authored
    /// signed authorization the disposition row binds comes from `ctx.entry` (the
    /// signed request's bytes/digest/signature); the welcome id / recipient / bound
    /// coordinate come from the plan's `welcome_changes`. `None` otherwise.
    #[derive(Clone, Debug)]
    pub(crate) struct WelcomeResponseContext {
        pub(crate) event: EventFanout,
        /// `Some` for a rejection (adds a `welcomeRejected` recovery work item with
        /// the closed reason); `None` for an acknowledgement (no recovery work).
        pub(crate) rejection: Option<WelcomeRejectionWork>,
    }

    /// The `welcomeRejected` recovery work a rejection creates.
    #[derive(Clone, Debug)]
    pub(crate) struct WelcomeRejectionWork {
        pub(crate) recovery_work_id: Uuid,
        pub(crate) reason: WelcomeRejectionReason,
    }

    /// Everything the plan does NOT carry. AUDIENCE IS INPUT, NOT DERIVED: the
    /// executor never queries `chat.devices` to invent an audience.
    #[derive(Clone, Debug)]
    pub(crate) struct ExecutionContext {
        pub(crate) protocol_instance_id: Uuid,
        /// The trusted request instant `T` — every `*_at` the executor writes.
        pub(crate) applied_at: DateTime<Utc>,
        pub(crate) actor: ExecutionActor,
        pub(crate) entry: ControlEntryContent,
        pub(crate) spine: SpineArtifacts,
        pub(crate) opened_leaves: Vec<LeafPersistenceColumns>,
        pub(crate) metadata_author: Option<MetadataAuthorColumns>,
        /// Fresh participant-period ids in the plan's canonical participant order.
        pub(crate) participant_period_ids: Vec<Uuid>,
        /// Fresh leaf-period ids in the plan's opened-leaf order.
        pub(crate) leaf_period_ids: Vec<Uuid>,
        /// The exact control-entry audience, canonical `(DID, device)` order.
        pub(crate) entry_recipients: Vec<(DeviceIdentity, EntryEntitlementKind)>,
        pub(crate) events: Vec<EventFanout>,
        /// For a `close`/`reset` edge that closes existing intervals: the exact
        /// active leaf-period id to record as each interval's
        /// `closing_leaf_period_id`. The facade queries `chat.member_devices` for
        /// the recipient's active leaf under lock; the plan's `interval_changes`
        /// supply everything else (terminal seq, closing transition + fingerprint).
        /// Empty for edges that close no interval (creation / policy / reset req).
        pub(crate) closing_leaf_periods: Vec<(DeviceIdentity, Uuid)>,
        /// For an edge that TERMINALIZES an existing participant period (a
        /// `zeroLeafLeave` self-removal of a leafless/pending participant): the
        /// exact active `chat.participants.participant_period_id` to close. The
        /// removed participant is NOT in the successor hydration, so its period id
        /// cannot come from `participant_period_ids`; the facade queries
        /// `chat.participants` for it under lock. Empty for every other edge.
        pub(crate) closing_participant_periods: Vec<(DeviceIdentity, Uuid)>,
        /// For a `reset request` edge: the exact `chat.reset_requests` row content
        /// the signed request carries (reason + signed material + expiry). `None`
        /// for every other edge.
        pub(crate) reset_request_row: Option<ResetRequestRow>,
        /// For an edge that OPENS a leaf-recovery request + reservation and
        /// reserves a key package (acceptance / leaf-recovery request): the DB-side
        /// facts the plan does not carry. `None` for every other edge. The
        /// requester/recipient identity is the transition/request actor
        /// (`ctx.actor`); the request id, kind, bound coordinate, and key-package
        /// ref come from the plan's `recovery_request_changes`.
        pub(crate) recovery_open: Option<RecoveryOpenContext>,
        /// For a `welcomeExpiry` edge (see `WelcomeExpiryContext`). `None` otherwise.
        pub(crate) welcome_expiry: Option<WelcomeExpiryContext>,
        /// For a `welcomeAcknowledgement`/`welcomeRejection` edge (see
        /// `WelcomeResponseContext`). `None` otherwise.
        pub(crate) welcome_response: Option<WelcomeResponseContext>,
        /// For a coordinate-changing commit that SUPERSEDES a prior-coordinate
        /// pending Welcome: the `welcomeDisposition` event the executor appends and
        /// binds the disposition row to (one per superseded welcome). Empty for
        /// edges that supersede no welcome.
        pub(crate) welcome_dispositions: Vec<WelcomeDispositionInput>,
    }

    /// The `welcomeDisposition` event + outbox the executor appends when a
    /// coordinate change supersedes a prior-coordinate pending Welcome. The
    /// disposition row (`terminalize_welcome_delivery`) is bound to this event's
    /// position.
    #[derive(Clone, Debug)]
    pub(crate) struct WelcomeDispositionInput {
        pub(crate) welcome_id: Uuid,
        pub(crate) event: EventFanout,
    }

    /// DB-side facts a recovery-opening edge needs that the plan does not carry.
    /// The `expires_at` the mapping trigger checks is
    /// `LEAST(created_at + 5 min, package.not_after)`, so the executor writes
    /// DB-clock timestamps (`created_at = requested_at = applied_at`) and needs the
    /// reserved package's `not_after` to compute that bound exactly.
    #[derive(Clone, Debug)]
    pub(crate) struct RecoveryOpenContext {
        /// The acceptor's current participant period — the acceptance CAS target.
        /// `Some` only for the acceptance edge (a leaf-recovery request touches no
        /// participant row).
        pub(crate) participant_period_id: Option<Uuid>,
        /// `chat.key_packages.not_after` of the reserved package.
        pub(crate) package_not_after: DateTime<Utc>,
        /// For a `replace` leaf-recovery request: the leaf period being replaced.
        /// `None` for an `add`.
        pub(crate) replaced_leaf_period_id: Option<Uuid>,
    }

    /// The exact `chat.reset_requests` row a reset-request edge persists. Sourced
    /// from the verified signed `requestReset` body; the executor writes it
    /// verbatim (the DB re-verifies `request_digest`/`expires_at`).
    #[derive(Clone, Debug)]
    pub(crate) struct ResetRequestRow {
        pub(crate) reset_request_id: Uuid,
        pub(crate) reason: transition::ResetReason,
        pub(crate) signed_request_bytes: Vec<u8>,
        pub(crate) signing_transcript_bytes: Vec<u8>,
        pub(crate) request_digest: Vec<u8>,
        pub(crate) signature: Vec<u8>,
        pub(crate) expires_at: DateTime<Utc>,
    }

    /// What the executor allocated/produced, echoed for the caller's response.
    #[derive(Clone, Debug)]
    pub(crate) struct AppliedTransition {
        pub(crate) allocated_seq: u64,
        pub(crate) entry_id: Uuid,
        pub(crate) event_positions: Vec<i64>,
        pub(crate) successor_coordinate: Option<PublicGroupSnapshotCoordinate>,
    }

    fn principal_did(principal: &PrincipalId) -> Result<String, ExecutorError> {
        String::from_utf8(principal.as_bytes().to_vec()).map_err(|_| ExecutorError::ValueOutOfRange)
    }

    fn device_did(device: &DeviceIdentity) -> Result<String, ExecutorError> {
        principal_did(device.principal())
    }

    fn device_uuid(device: &DeviceIdentity) -> Uuid {
        Uuid::from_bytes(*device.device_id())
    }

    fn checked_i64(value: u64) -> Result<i64, ExecutorError> {
        i64::try_from(value).map_err(|_| ExecutorError::ValueOutOfRange)
    }

    fn server_instant(value: ServerTimestamp) -> Result<DateTime<Utc>, ExecutorError> {
        DateTime::<Utc>::from_timestamp_millis(value.unix_millis())
            .ok_or(ExecutorError::ValueOutOfRange)
    }

    fn repo_participant_status(status: ParticipantStatus) -> RepoParticipantStatus {
        match status {
            ParticipantStatus::Pending => RepoParticipantStatus::Pending,
            ParticipantStatus::Active => RepoParticipantStatus::Active,
        }
    }

    fn repo_participant_role(role: ParticipantRole) -> RepoParticipantRole {
        match role {
            ParticipantRole::Member => RepoParticipantRole::Member,
            ParticipantRole::Admin => RepoParticipantRole::Admin,
        }
    }

    /// Reject any non-empty effect family the executor does not (yet) persist,
    /// so nothing is ever silently dropped. Called for every family this
    /// composition path does not translate.
    fn reject_if_present<T>(family: &'static str, changes: &[T]) -> Result<(), ExecutorError> {
        if changes.is_empty() {
            Ok(())
        } else {
            Err(ExecutorError::UnsupportedEffect(family))
        }
    }

    /// Make the `recovery_package_cas` binding load-bearing (E2b-6b review MINOR-1),
    /// mirroring the invitation-quota discipline: production requires it to be
    /// BIJECTIVE with `package_transitions` (`package_cas_bijection_valid`), and
    /// `persistence_plan_for_test` now synthesizes it, so this asserts the
    /// bijection rather than silently reading the witness. Additionally
    /// cross-validates (MINOR-4) that the exact key-package ref the executor drives
    /// through `cas_key_package_status` equals every semantic package edge's own
    /// ref — a planner that disagreed would be a hard error, never a silent skip.
    /// The `recovery_package_cas` <-> `package_transitions` bijection production
    /// requires (`package_cas_bijection_valid`), made load-bearing (E2b-6b MINOR-1).
    fn verify_recovery_package_bijection(effects: &TransitionEffects) -> Result<(), ExecutorError> {
        let edges = effects.package_transitions();
        let cas = effects.recovery_package_cas();
        if edges.len() != cas.len() {
            return Err(ExecutorError::InconsistentPlan(
                "recovery package CAS is not bijective with package_transitions",
            ));
        }
        for edge in edges {
            let unique = cas
                .iter()
                .filter(|binding| {
                    binding.request_id == edge.request_id
                        && binding.key_package_ref == edge.key_package_ref
                        && binding.expected_status == edge.from
                        && binding.successor_status == edge.to
                })
                .count();
            if unique != 1 {
                return Err(ExecutorError::InconsistentPlan(
                    "recovery package CAS binding missing/duplicated for a package edge",
                ));
            }
        }
        Ok(())
    }

    /// Bijection + the OWN package edge's driven-ref (MINOR-4) and direction
    /// (MINOR-2) — for an arm that drives exactly ONE own package edge. Any OTHER
    /// edges (prior-bound `Reserved->Available` supersessions) are validated by
    /// `write_prior_bound_supersessions`; here only the own edge is direction-checked.
    fn verify_recovery_package_consistency(
        effects: &TransitionEffects,
        driven_key_package_ref: &[u8; 32],
        expected_from: PackageStatus,
        expected_to: PackageStatus,
    ) -> Result<(), ExecutorError> {
        verify_recovery_package_bijection(effects)?;
        let own = effects
            .package_transitions()
            .iter()
            .filter(|edge| edge.key_package_ref == *driven_key_package_ref)
            .count();
        if own != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "exactly one package edge must match the executor's driven ref",
            ));
        }
        let own_edge = effects
            .package_transitions()
            .iter()
            .find(|edge| edge.key_package_ref == *driven_key_package_ref)
            .expect("own edge exists");
        if own_edge.from != expected_from || own_edge.to != expected_to {
            return Err(ExecutorError::InconsistentPlan(
                "the driven package edge's direction disagrees with the executor's CAS",
            ));
        }
        Ok(())
    }

    /// Apply one `ConversationPersistencePlan` inside the caller's transaction.
    ///
    /// Transaction-scoped: never begins or commits. Ordered per the E2b-2 design
    /// (head → generation → generation_state → entry → transition → metadata →
    /// families → audience → events). Every effect family is consumed
    /// exhaustively; a non-empty family this path does not handle is a hard
    /// `UnsupportedEffect`, never a silent skip.
    pub(crate) async fn apply_conversation_persistence_plan(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let hydration = plan.state();
        let coordinate = &hydration.coordinate;
        let conversation_id = Uuid::from_bytes(*coordinate.conversation_id());
        let transition_id = Uuid::from_bytes(*hydration.producer.transition_id());
        let generation = checked_i64(coordinate.generation())?;
        let state_version = checked_i64(coordinate.state_version())?;
        let epoch = checked_i64(coordinate.epoch())?;

        // Dispatch split: entry-less internal ops vs entry-bearing edges.
        //
        // `leafRecoveryRequest` / `leafRecoveryCancellation` are INTERNAL — there
        // is no control-entry kind for them (`bind_non_control_request_authority`:
        // `allocated_seq == None`, `successor_next_entry_seq == expected`), so they
        // append NO entry and allocate NO seq, and their head CAS is a
        // prior-coordinate VERIFY that advances neither the coordinate nor the
        // counter. Branch on these BEFORE the entry-bearing `allocated_seq`
        // extraction (which would otherwise `InconsistentPlan` on their `None`
        // seq). Every OTHER plan kind is entry-bearing (creation / policy / accept
        // / commit / close / reset-activation / fulfillment) and allocates a seq.
        match effects.kind() {
            PlanKind::RecoveryRequest => {
                return apply_leaf_recovery_request(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    generation,
                    state_version,
                    epoch,
                )
                .await;
            }
            PlanKind::RecoveryCancellation => {
                return apply_leaf_recovery_cancellation(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    generation,
                    state_version,
                    epoch,
                )
                .await;
            }
            // `welcomeExpiry` is ALSO entry-less (server-observed pending-only CAS,
            // `bind_welcome_expiry_authority`: `allocated_seq == None`, coordinate +
            // seq counter UNCHANGED) — dispatch it here before the `allocated_seq`
            // extraction would `InconsistentPlan` on its `None` seq.
            PlanKind::WelcomeExpiry => {
                return apply_welcome_expiry(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    generation,
                    state_version,
                    epoch,
                )
                .await;
            }
            // `welcomeAcknowledgement` / `welcomeRejection` are entry-less signed
            // non-control responses (`bind_non_control_request_authority`:
            // `allocated_seq == None`, coordinate + seq UNCHANGED) — dispatch here.
            PlanKind::WelcomeAcknowledgement | PlanKind::WelcomeRejection => {
                return apply_welcome_response(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    generation,
                    state_version,
                    epoch,
                )
                .await;
            }
            // `deviceRevocation` is entry-less and coordinate-UNCHANGED (a global
            // signed authority op; `bind_device_revocation_authority`:
            // `allocated_seq == None`, successor coordinate == prior). It closes
            // NO leaf / interval — it only supersedes the target's own recovery
            // requests / reservations / welcomes and revokes their packages, all
            // bound to the revocation id. Dispatch here before the entry-bearing
            // `allocated_seq` extraction would `InconsistentPlan` on its `None` seq.
            PlanKind::DeviceRevocation => {
                return apply_device_revocation(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    generation,
                    state_version,
                    epoch,
                )
                .await;
            }
            _ => {}
        }

        let allocated_seq = head.allocated_seq().ok_or(ExecutorError::InconsistentPlan(
            "head CAS has no allocated seq",
        ))?;
        let seq_i64 = checked_i64(allocated_seq)?;
        let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

        match effects.kind() {
            PlanKind::Creation => {
                apply_creation(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    transition_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            }
            PlanKind::Policy => {
                apply_policy(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    transition_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            }
            // Every other plan kind is a real, planned edge this executor slice
            // does not yet compose. It is a HARD error (never a silent skip), so a
            // caller cannot mistake "not implemented" for "applied". The
            // remaining kinds (acceptConversation, metadata, commit, reset
            // request/activation, leave family, welcome dispositions, device
            // revocation, close) are the E2b-3 remainder — see the report.
            PlanKind::Acceptance => {
                apply_acceptance(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    transition_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            }
            PlanKind::Metadata => Err(ExecutorError::UnsupportedEffect("metadata")),
            PlanKind::Commit => {
                // Three `PlanKind::Commit` shapes, partitioned by their own edges.
                //
                // PARTITION PROOF (exhaustive + mutually exclusive by construction —
                // the planners are the authority):
                //   * A LEAVE fulfillment is the ONLY `Commit` whose planner
                //     (`plan_leave_fulfillment_inner`) terminalizes a leave request as
                //     FULFILLED (`Pending->Fulfilled`); it removes members and emits NO
                //     new Welcome. The discriminator matches that exact edge — NOT any
                //     leave-request delta: EVERY coordinate-advancing commit (generic /
                //     recovery / leave) may ALSO carry a prior-bound `Pending->Stale`
                //     leave staling (a co-pending leave request the coordinate change
                //     retired), which must NOT be read as a fulfillment.
                //   * A leaf-recovery fulfillment (`plan_leaf_recovery_fulfillment_inner`)
                //     ALWAYS emits exactly one NEW Welcome (`None->Some`, how the
                //     recovered target joins) and NEVER FULFILLS a leave request (though
                //     it may stale one).
                //   * A generic zero-proposal commit (`plan_commit_inner`) does
                //     NEITHER — no leave FULFILLMENT, no `None->Some` welcome (its only
                //     welcome delta is a prior-bound `Pending->Superseded`).
                // The two predicates are therefore disjoint (a Pending->Fulfilled leave
                // edge vs. a None->Some welcome are never both set) and exhaustive
                // (their negation is exactly the generic commit). Each branch's own
                // exact-shape guards (leave requires exactly one leave-request +
                // participant close; recovery requires exactly one own request/
                // reservation/package/new welcome; generic rejects every membership
                // delta) HARD-error a mis-partitioned plan rather than mis-applying it —
                // the discriminator is backstopped, never load-bearing alone.
                let is_leave_fulfillment = effects.leave_request_changes().iter().any(|change| {
                    matches!(
                        (change.before(), change.after()),
                        (Some(before), Some(after))
                            if before.status() == LeaveRequestStatus::Pending
                                && after.status() == LeaveRequestStatus::Fulfilled
                    )
                });
                let is_recovery_fulfillment = effects
                    .welcome_changes()
                    .iter()
                    .any(|change| matches!((change.before(), change.after()), (None, Some(_))));
                if is_leave_fulfillment {
                    apply_leave_fulfillment(
                        transaction,
                        plan,
                        ctx,
                        conversation_id,
                        transition_id,
                        seq_i64,
                        successor_next_entry_seq,
                        generation,
                        state_version,
                        epoch,
                    )
                    .await
                } else if is_recovery_fulfillment {
                    apply_leaf_recovery_fulfillment(
                        transaction,
                        plan,
                        ctx,
                        conversation_id,
                        transition_id,
                        seq_i64,
                        successor_next_entry_seq,
                        generation,
                        state_version,
                        epoch,
                    )
                    .await
                } else {
                    apply_generic_commit(
                        transaction,
                        plan,
                        ctx,
                        conversation_id,
                        transition_id,
                        seq_i64,
                        successor_next_entry_seq,
                        generation,
                        state_version,
                        epoch,
                    )
                    .await
                }
            }
            // Entry-less internal ops are dispatched (and returned) above, before
            // the entry-bearing `allocated_seq` extraction.
            PlanKind::RecoveryRequest | PlanKind::RecoveryCancellation => {
                unreachable!("entry-less recovery ops are dispatched before this match")
            }
            // Entry-less; dispatched (and returned) above.
            PlanKind::DeviceRevocation => {
                unreachable!("entry-less device revocation is dispatched before this match")
            }
            PlanKind::ResetRequest => {
                apply_reset_request(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            }
            PlanKind::ResetActivation => {
                apply_reset_activation(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    transition_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            }
            PlanKind::LeaveRequest => {
                apply_leave_request(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            }
            PlanKind::LeaveCancellation => {
                apply_leave_cancellation(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            }
            PlanKind::ZeroLeafLeave => {
                apply_zero_leaf_leave(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    transition_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            }
            // Entry-less; dispatched (and returned) above.
            PlanKind::WelcomeAcknowledgement
            | PlanKind::WelcomeRejection
            | PlanKind::WelcomeExpiry => {
                unreachable!("entry-less welcome disposition ops are dispatched before this match")
            }
            PlanKind::Close => {
                apply_close(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    transition_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            }
        }
    }

    /// Apply an entry-less `leafRecoveryRequest` internal op. The coordinate and
    /// seq counter are UNCHANGED (the head CAS is a prior-coordinate verify); it
    /// opens the `add`/`replace` recovery request + reservation and reserves the
    /// requester's key package, all bound to the CURRENT coordinate. No entry, no
    /// transition, no generation state, no participant change.
    #[allow(clippy::too_many_arguments)]
    async fn apply_leaf_recovery_request(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        generation: i64,
        state_version: i64,
        _epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "leaf recovery request needs a prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
        let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

        // Internal op: only a new open recovery request + its reservation + the
        // Available->Reserved package edge. Everything else must be empty.
        reject_if_present("participant_changes", effects.participant_changes())?;
        reject_if_present("leaf_changes", effects.leaf_changes())?;
        reject_if_present("interval_changes", effects.interval_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present("reset_request_changes", effects.reset_request_changes())?;
        reject_if_present("leave_request_changes", effects.leave_request_changes())?;
        reject_if_present("welcome_changes", effects.welcome_changes())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        if effects.metadata_change().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "leaf recovery request metadata change",
            ));
        }
        if effects.revocation_target_cas().is_some()
            || effects.welcome_cas().is_some()
            || effects.invitation_quota_cas().is_some()
        {
            return Err(ExecutorError::UnsupportedEffect(
                "leaf recovery request revocation/welcome/quota CAS",
            ));
        }
        // Internal op MUST NOT change the coordinate or advance the seq counter
        // (E2b-6b review MINOR-2: the head CAS is a pure prior-coordinate verify).
        if successor_next_entry_seq != expected_next_entry_seq {
            return Err(ExecutorError::InconsistentPlan(
                "leaf recovery request must not advance the seq counter",
            ));
        }
        if generation != expected_generation || state_version != expected_state_version {
            return Err(ExecutorError::InconsistentPlan(
                "leaf recovery request must not change the coordinate",
            ));
        }

        let recovery = effects
            .recovery_request_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (None, Some(after)) => Some(after),
                _ => None,
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "leaf recovery request adds no open recovery request",
            ))?;
        if effects.recovery_request_changes().len() != 1
            || effects.reservation_changes().len() != 1
            || effects.package_transitions().len() != 1
        {
            return Err(ExecutorError::InconsistentPlan(
                "leaf recovery request must add exactly one request + reservation + package edge",
            ));
        }
        verify_recovery_package_consistency(
            effects,
            recovery.key_package_ref(),
            PackageStatus::Available,
            PackageStatus::Reserved,
        )?;

        // 1. Head CAS VERIFY — coordinate and seq counter both UNCHANGED
        //    (successor == expected on every column). A drifted head is a typed
        //    conflict; a matched head is a no-op update that pins the read.
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. The atomic recovery open (request + reservation + package reserve).
        write_recovery_open(transaction, ctx, recovery, conversation_id, applied_at).await?;

        // 3. No control entry (internal op) -> no entry recipients; only events.
        let event_positions = write_events(transaction, ctx).await?;

        Ok(AppliedTransition {
            // No control entry / seq was allocated; echo the unchanged counter.
            allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply an entry-less `welcomeExpiry` op: a server-observed pending Welcome
    /// past its `expires_at` is terminalized `expired` and a `welcomeExpired`
    /// `recovery_work_items` row is created so the recipient can be re-added later.
    /// Coordinate + seq counter UNCHANGED (a pure prior-coordinate verify). NO
    /// entry, transition, or membership change. Both the disposition `terminal_at`
    /// and the recovery-work `created_at` are the welcome's OWN `expires_at` (the DB
    /// `welcome_deliveries.terminal_at = expires_at` and `recovery_work_items.created_at
    /// = disposition_terminal_at` cross-checks), NOT `applied_at`; the recovery-work
    /// coordinate is the welcome's OWN bound coordinate.
    async fn apply_welcome_expiry(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        generation: i64,
        state_version: i64,
        _epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "welcome expiry needs an expected prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
        let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

        // Only a welcome delivery CAS (Pending -> Expired). Reject every other family.
        reject_if_present("participant_changes", effects.participant_changes())?;
        reject_if_present("leaf_changes", effects.leaf_changes())?;
        reject_if_present("interval_changes", effects.interval_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present(
            "recovery_request_changes",
            effects.recovery_request_changes(),
        )?;
        reject_if_present("reservation_changes", effects.reservation_changes())?;
        reject_if_present("reset_request_changes", effects.reset_request_changes())?;
        reject_if_present("leave_request_changes", effects.leave_request_changes())?;
        reject_if_present("package_transitions", effects.package_transitions())?;
        reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        if effects.metadata_change().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "welcome expiry metadata change",
            ));
        }
        if effects.revocation_target_cas().is_some() || effects.invitation_quota_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "welcome expiry revocation/quota CAS",
            ));
        }
        // A `welcomeExpiry` is the ONE kind that carries `welcome_cas` (the
        // authoritative pending-only CAS binding). The `welcome_changes` delta drives
        // the write; the CAS binding is a LOAD-BEARING witness validated against that
        // delta below (welcome id, recipient, bound coordinate, expiry instant, and
        // the Pending->Expired direction must all agree).
        let welcome_cas = effects
            .welcome_cas()
            .ok_or(ExecutorError::InconsistentPlan(
                "welcome expiry plan missing welcome CAS binding",
            ))?;

        // Pure prior-coordinate verify: coordinate + seq counter UNCHANGED.
        if successor_next_entry_seq != expected_next_entry_seq {
            return Err(ExecutorError::InconsistentPlan(
                "welcome expiry must not advance the seq counter",
            ));
        }
        if generation != expected_generation || state_version != expected_state_version {
            return Err(ExecutorError::InconsistentPlan(
                "welcome expiry must not change the coordinate",
            ));
        }

        // Exactly one Pending -> Expired welcome change.
        if effects.welcome_changes().len() != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "welcome expiry must change exactly one welcome",
            ));
        }
        let expired = effects
            .welcome_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (Some(before), Some(after))
                    if before.status() == WelcomeStatus::Pending
                        && after.status() == WelcomeStatus::Expired =>
                {
                    Some(after)
                }
                _ => None,
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "welcome expiry must expire a pending welcome",
            ))?;
        let welcome_id = Uuid::from_bytes(*expired.welcome_id());
        let terminal_at = server_instant(expired.expires_at())?;
        let recipient = expired.recipient().clone();
        let welcome_coordinate = expired.coordinate();
        // Consume the CAS binding as load-bearing: it must bind exactly the pending
        // welcome the delta expires. A planner that disagreed is a hard
        // `InconsistentPlan`, never a silently-unread witness.
        if welcome_cas.welcome_id() != expired.welcome_id()
            || welcome_cas.recipient() != &recipient
            || welcome_cas.coordinate() != welcome_coordinate
            || welcome_cas.expires_at() != expired.expires_at()
            || welcome_cas.expected_status() != WelcomeStatus::Pending
            || welcome_cas.successor_status() != WelcomeStatus::Expired
        {
            return Err(ExecutorError::InconsistentPlan(
                "welcome expiry CAS binding disagrees with the welcome change",
            ));
        }
        let expiry = ctx
            .welcome_expiry
            .as_ref()
            .ok_or(ExecutorError::MissingContext("welcome expiry context"))?;

        // 1. Head CAS VERIFY (coordinate + seq counter both UNCHANGED).
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. Append the `welcomeDisposition` event. Its `created_at` MUST equal the
        //    welcome's `expires_at` (`assert_welcome_disposition_cas`:
        //    `event.created_at = delivery.terminal_at`), NOT `applied_at` — a welcome
        //    expiry is stamped at the deterministic `expires_at`, so this arm uses
        //    `terminal_at` throughout and never `applied_at`.
        let position = delivery::append_event(
            transaction,
            &NewEvent {
                event_id: expiry.event.event_id,
                event_kind: expiry.event.event_kind,
                payload_bytes: expiry.event.payload_bytes.clone(),
                created_at: terminal_at,
                protocol_instance_id: ctx.protocol_instance_id,
            },
        )
        .await?;
        let event_recipients = expiry
            .event
            .recipients
            .iter()
            .map(|(device, kind, predecessor)| {
                Ok(EventRecipient {
                    user_did: device_did(device)?,
                    device_id: device_uuid(device),
                    entitlement_kind: *kind,
                    audience_predecessor_position: *predecessor,
                })
            })
            .collect::<Result<Vec<_>, ExecutorError>>()?;
        delivery::insert_event_recipients(transaction, position, &event_recipients).await?;
        for (outbox_id, work_kind) in &expiry.event.outbox {
            delivery::enqueue_outbox(transaction, *outbox_id, position, *work_kind, terminal_at)
                .await?;
        }

        // 3. Terminalize the pending delivery `expired` at its `expires_at`.
        delivery::terminalize_welcome_delivery(
            transaction,
            welcome_id,
            &WelcomeDisposition::Expired,
            terminal_at,
            position,
        )
        .await?;

        // 4. The `welcomeExpired` recovery work item (created_at == the disposition
        //    terminal_at; coordinate == the welcome's own bound coordinate).
        delivery::insert_recovery_work_item(
            transaction,
            &delivery::NewRecoveryWorkItem {
                recovery_work_id: expiry.recovery_work_id,
                conversation_id,
                recipient_did: device_did(&recipient)?,
                recipient_device_id: device_uuid(&recipient),
                source_kind: delivery::RecoveryWorkSourceKind::WelcomeExpired,
                source_id: welcome_id,
                generation: checked_i64(welcome_coordinate.generation())?,
                state_version: checked_i64(welcome_coordinate.state_version())?,
                created_at: terminal_at,
            },
        )
        .await?;

        Ok(AppliedTransition {
            // No control entry / seq was allocated; echo the unchanged counter.
            allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions: vec![position],
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply an entry-less `deviceRevocation` op for ONE conversation. The
    /// coordinate + seq counter are UNCHANGED (a pure prior-coordinate verify);
    /// there is NO MLS Remove and NO interval close. It supersedes the TARGET's
    /// own open recovery requests (Open->Superseded), releases their reservations
    /// (Active->Released), revokes their reserved packages (Reserved->Revoked),
    /// and supersedes their pending welcomes (Pending->Superseded) — ALL bound to
    /// the revocation id at `terminal_at == accepted_at`. The immutable
    /// `device_revocations` row + the registration revoke are batch-level
    /// (`apply_device_revocation_batch`); this arm owns only the per-conversation
    /// work terminalizations. Modeled on `apply_leaf_recovery_request`.
    #[allow(clippy::too_many_arguments)]
    async fn apply_device_revocation(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        generation: i64,
        state_version: i64,
        _epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "device revocation needs a prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
        let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

        // The revocation identity comes from the plan authority — the revocation
        // id + accepted_at every terminalization binds (all `terminal_at`).
        let evidence = match effects.authority() {
            Some(PlanAuthority::DeviceRevocation(evidence)) => evidence,
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "device revocation plan missing revocation authority",
                ))
            }
        };
        let revocation_id = Uuid::from_bytes(*evidence.revocation_id());
        let accepted_at = server_instant(evidence.accepted_at())?;

        // Only the target's own work is terminalized; every other family empty.
        // recovery_request / reservation / package / welcome deltas are the
        // revocation-bound supersessions (handled below); everything else is a
        // hard error, never a silent drop.
        reject_if_present("participant_changes", effects.participant_changes())?;
        reject_if_present("leaf_changes", effects.leaf_changes())?;
        reject_if_present("interval_changes", effects.interval_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present("reset_request_changes", effects.reset_request_changes())?;
        reject_if_present("leave_request_changes", effects.leave_request_changes())?;
        reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
        if effects.metadata_change().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "device revocation metadata change",
            ));
        }
        if effects.welcome_cas().is_some()
            || effects.revocation_target_cas().is_some()
            || effects.invitation_quota_cas().is_some()
        {
            return Err(ExecutorError::UnsupportedEffect(
                "device revocation welcome/target/quota CAS",
            ));
        }
        // Internal op MUST NOT change the coordinate or advance the seq counter.
        if successor_next_entry_seq != expected_next_entry_seq {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation must not advance the seq counter",
            ));
        }
        if generation != expected_generation || state_version != expected_state_version {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation must not change the coordinate",
            ));
        }
        // The package edges are Reserved->Revoked, load-bearing-bound to the
        // `revocation_package_cas` witnesses (bijective per the plan seam). An
        // empty package set (a target with only welcomes) is legal.
        if !effects.package_transitions().is_empty()
            && !revocation_package_cas_bijection_valid(effects)
        {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation package CAS is not bijective with the Reserved->Revoked edges",
            ));
        }

        // 1. Head CAS VERIFY (coordinate + seq counter both UNCHANGED).
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. Revocation-bound terminalizations of the target's OWN work.
        let mut superseded =
            write_revocation_bound_supersessions(transaction, effects, revocation_id, accepted_at)
                .await?;
        // 3. The target's pending welcomes (Pending->Superseded), each bound to a
        //    `welcomeDisposition` event (stamped at ctx.applied_at == accepted_at).
        superseded.welcomes = write_welcome_supersessions(transaction, ctx, effects).await?;
        // 4. Silent-drop guard: a device revocation FULFILLS nothing (own == 0),
        //    so every delta MUST be a revocation-bound supersession.
        reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

        // 5. No control entry (internal op) -> no entry recipients; only events.
        let event_positions = write_events(transaction, ctx).await?;

        Ok(AppliedTransition {
            // No control entry / seq was allocated; echo the unchanged counter.
            allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Terminalize the target's OWN open recovery requests / active reservations /
    /// reserved packages, all bound to `revocation_id` at `terminal_at`. Mirrors
    /// `write_prior_bound_supersessions` but binds a REVOCATION (not a transition)
    /// and drives packages Reserved->**Revoked** (not Reserved->Available). Returns
    /// the per-family counts (welcomes left 0 — the caller adds them) so the caller
    /// reconciles `own + superseded == total`. A delta that is NOT one of these
    /// exact shapes is skipped here and caught by that reconciliation, never
    /// silently dropped.
    async fn write_revocation_bound_supersessions(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        effects: &TransitionEffects,
        revocation_id: Uuid,
        terminal_at: DateTime<Utc>,
    ) -> Result<FamilyCounts, ExecutorError> {
        let mut counts = FamilyCounts::default();
        for change in effects.recovery_request_changes() {
            if let (Some(before), Some(after)) = (change.before(), change.after()) {
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Superseded
                {
                    transition::terminalize_leaf_recovery_request(
                        transaction,
                        Uuid::from_bytes(*after.request_id()),
                        &LeafRecoveryTermination::SupersededByRevocation {
                            terminal_revocation_id: revocation_id,
                            terminal_at,
                        },
                    )
                    .await?;
                    counts.requests += 1;
                }
            }
        }
        for change in effects.reservation_changes() {
            if let (Some(before), Some(after)) = (change.before(), change.after()) {
                if before.status() == ReservationStatus::Active
                    && after.status() == ReservationStatus::Released
                {
                    transition::terminalize_reservation(
                        transaction,
                        Uuid::from_bytes(after.request_id),
                        &ReservationTermination::ReleasedByRevocation {
                            terminal_revocation_id: revocation_id,
                            terminal_at,
                        },
                    )
                    .await?;
                    counts.reservations += 1;
                }
            }
        }
        for edge in effects.package_transitions() {
            if edge.from == PackageStatus::Reserved && edge.to == PackageStatus::Revoked {
                transition::cas_key_package_status(
                    transaction,
                    &edge.key_package_ref,
                    RepoPackageStatus::Reserved,
                    &PackageSuccessor::Revoke {
                        terminal_revocation_id: revocation_id,
                        terminal_at,
                    },
                )
                .await?;
                counts.packages += 1;
            }
        }
        Ok(counts)
    }

    /// Apply a device-revocation BATCH: insert the immutable `device_revocations`
    /// row + revoke the target registration ONCE, revoke every AVAILABLE target
    /// package (the reserved ones are revoked per-conversation by
    /// `apply_device_revocation`), then drive each conversation's entry-less
    /// revocation plan. Bounded integration: the loop over `plan.conversations()`
    /// is exactly the fanout the production `plan_device_revocation_batch`
    /// assembles; a single-conversation caller passes one context. The
    /// `revokeDevice` idempotency receipt the DEFERRED
    /// `enforce_device_revocation_mapping` COMMIT trigger requires is written by
    /// the request handler (the test seeds it), not here.
    pub(crate) async fn apply_device_revocation_batch(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &DeviceRevocationBatchPersistencePlan,
        conversation_ctxs: &[ExecutionContext],
    ) -> Result<Vec<AppliedTransition>, ExecutorError> {
        let evidence = plan.authority();
        let revocation_id = Uuid::from_bytes(*evidence.revocation_id());
        let accepted_at = server_instant(evidence.accepted_at())?;

        // 1. The immutable device_revocations row (the terminal_revocation_id FK
        //    target for every work-row terminalization below).
        insert_device_revocation(
            transaction,
            &NewDeviceRevocation {
                revocation_id,
                actor_did: device_did(evidence.actor())?,
                actor_device_id: device_uuid(evidence.actor()),
                actor_key_id: URL_SAFE_NO_PAD.encode(evidence.actor_key_id()),
                actor_auth_generation: checked_i64(evidence.actor_auth_generation())?,
                target_did: device_did(evidence.target())?,
                target_device_id: device_uuid(evidence.target()),
                target_auth_generation: checked_i64(evidence.expected_target_auth_generation())?,
                accepted_request_bytes: evidence.signed_request_bytes().to_vec(),
                signing_transcript_bytes: evidence.signing_transcript_bytes().to_vec(),
                request_digest: evidence.request_digest().to_vec(),
                signature: evidence.signature().to_vec(),
                signed_at: server_instant(evidence.signed_at())?,
                accepted_at,
            },
        )
        .await?;

        // 2. The target registration revoke (devices active -> revoked + its key).
        let target_cas = plan.target_cas();
        cas_registration_revoke(
            transaction,
            &RegistrationRevoke {
                target_did: device_did(target_cas.target())?,
                target_device_id: device_uuid(target_cas.target()),
                expected_auth_generation: checked_i64(target_cas.expected_auth_generation())?,
                revocation_id,
                revoked_at: accepted_at,
            },
        )
        .await?;

        // 3. Revoke the AVAILABLE target packages (conversation_id == None); the
        //    Reserved ones (conversation_id == Some) are revoked by the
        //    per-conversation arm, so revoking them here too would double-CAS.
        for binding in plan.revoked_packages() {
            if binding.conversation_id().is_none() {
                transition::cas_key_package_status(
                    transaction,
                    binding.key_package_ref(),
                    RepoPackageStatus::Available,
                    &PackageSuccessor::Revoke {
                        terminal_revocation_id: revocation_id,
                        terminal_at: accepted_at,
                    },
                )
                .await?;
            }
        }

        // 4. Drive each conversation's entry-less revocation plan.
        if plan.conversations().len() != conversation_ctxs.len() {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation batch needs one execution context per conversation",
            ));
        }
        let mut applied = Vec::with_capacity(plan.conversations().len());
        for (conversation, ctx) in plan.conversations().iter().zip(conversation_ctxs) {
            applied
                .push(apply_conversation_persistence_plan(transaction, conversation, ctx).await?);
        }
        Ok(applied)
    }

    /// Apply an entry-less `welcomeAcknowledgement` / `welcomeRejection`: a
    /// client-authored signed disposition of a pending Welcome. Coordinate + seq
    /// counter UNCHANGED (a pure prior-coordinate verify); NO entry / transition /
    /// membership change. Terminalizes the delivery `acknowledged` (recipient
    /// joined — NO recovery work) or `rejected` (adds a `welcomeRejected`
    /// recovery-work item with the closed reason). The disposition row binds the
    /// client's signed authorization (from `ctx.entry`). Unlike expiry, every
    /// timestamp is the request instant `applied_at` (the client's action time,
    /// which the DB requires `< expires_at`), so the disposition event uses
    /// `applied_at` (`= terminal_at`). `welcome_cas` is validated load-bearing.
    async fn apply_welcome_response(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        generation: i64,
        state_version: i64,
        _epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "welcome response needs an expected prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
        let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

        // Only a welcome delivery CAS. Reject every other family.
        reject_if_present("participant_changes", effects.participant_changes())?;
        reject_if_present("leaf_changes", effects.leaf_changes())?;
        reject_if_present("interval_changes", effects.interval_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present(
            "recovery_request_changes",
            effects.recovery_request_changes(),
        )?;
        reject_if_present("reservation_changes", effects.reservation_changes())?;
        reject_if_present("reset_request_changes", effects.reset_request_changes())?;
        reject_if_present("leave_request_changes", effects.leave_request_changes())?;
        reject_if_present("package_transitions", effects.package_transitions())?;
        reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        if effects.metadata_change().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "welcome response metadata change",
            ));
        }
        if effects.revocation_target_cas().is_some() || effects.invitation_quota_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "welcome response revocation/quota CAS",
            ));
        }
        let welcome_cas = effects
            .welcome_cas()
            .ok_or(ExecutorError::InconsistentPlan(
                "welcome response plan missing welcome CAS binding",
            ))?;

        // Pure prior-coordinate verify: coordinate + seq counter UNCHANGED.
        if successor_next_entry_seq != expected_next_entry_seq {
            return Err(ExecutorError::InconsistentPlan(
                "welcome response must not advance the seq counter",
            ));
        }
        if generation != expected_generation || state_version != expected_state_version {
            return Err(ExecutorError::InconsistentPlan(
                "welcome response must not change the coordinate",
            ));
        }

        // Exactly one Pending -> {Acknowledged,Rejected} welcome change.
        if effects.welcome_changes().len() != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "welcome response must change exactly one welcome",
            ));
        }
        let responded = effects
            .welcome_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (Some(before), Some(after))
                    if before.status() == WelcomeStatus::Pending
                        && matches!(
                            after.status(),
                            WelcomeStatus::Acknowledged | WelcomeStatus::Rejected
                        ) =>
                {
                    Some(after)
                }
                _ => None,
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "welcome response must acknowledge or reject a pending welcome",
            ))?;
        let successor_status = responded.status();
        let welcome_id = Uuid::from_bytes(*responded.welcome_id());
        let recipient = responded.recipient().clone();
        let welcome_coordinate = responded.coordinate();
        // Load-bearing welcome CAS validation (mirrors the expiry arm).
        if welcome_cas.welcome_id() != responded.welcome_id()
            || welcome_cas.recipient() != &recipient
            || welcome_cas.coordinate() != welcome_coordinate
            || welcome_cas.expires_at() != responded.expires_at()
            || welcome_cas.expected_status() != WelcomeStatus::Pending
            || welcome_cas.successor_status() != successor_status
        {
            return Err(ExecutorError::InconsistentPlan(
                "welcome response CAS binding disagrees with the welcome change",
            ));
        }
        let response = ctx
            .welcome_response
            .as_ref()
            .ok_or(ExecutorError::MissingContext("welcome response context"))?;
        // The client-authored signed authorization the disposition row binds — the
        // signed request's bytes/digest/signature (the signature-shape trigger
        // requires them non-NULL for acknowledged/rejected).
        let authorization = WelcomeClientAuthorization {
            signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
            signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
            request_digest: ctx.entry.request_digest.clone(),
            signature: ctx.entry.signature.clone(),
        };
        // The disposition shape must match the successor status; a rejection carries
        // the recovery work, an acknowledgement must not.
        let (disposition, rejection_work): (WelcomeDisposition, Option<&WelcomeRejectionWork>) =
            match successor_status {
                WelcomeStatus::Acknowledged => {
                    if response.rejection.is_some() {
                        return Err(ExecutorError::InconsistentPlan(
                            "welcome acknowledgement must not carry rejection recovery work",
                        ));
                    }
                    (WelcomeDisposition::Acknowledged { authorization }, None)
                }
                WelcomeStatus::Rejected => {
                    let rejection =
                        response
                            .rejection
                            .as_ref()
                            .ok_or(ExecutorError::MissingContext(
                                "welcome rejection recovery work",
                            ))?;
                    (
                        WelcomeDisposition::Rejected {
                            authorization,
                            reason: rejection.reason,
                        },
                        Some(rejection),
                    )
                }
                _ => {
                    return Err(ExecutorError::InconsistentPlan(
                        "welcome response status must be acknowledged or rejected",
                    ))
                }
            };

        // 1. Head CAS VERIFY (coordinate + seq counter both UNCHANGED).
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. Append the `welcomeDisposition` event. Its `created_at` (= applied_at)
        //    must equal the delivery terminal_at (= applied_at), so append_one_event
        //    (which stamps applied_at) is correct here.
        let position = append_one_event(transaction, ctx, &response.event).await?;

        // 3. Terminalize the pending delivery at the request instant, binding the
        //    client authorization (+ reason for a rejection).
        delivery::terminalize_welcome_delivery(
            transaction,
            welcome_id,
            &disposition,
            applied_at,
            position,
        )
        .await?;

        // 4. A rejection additionally creates the `welcomeRejected` recovery work.
        if let Some(rejection) = rejection_work {
            delivery::insert_recovery_work_item(
                transaction,
                &delivery::NewRecoveryWorkItem {
                    recovery_work_id: rejection.recovery_work_id,
                    conversation_id,
                    recipient_did: device_did(&recipient)?,
                    recipient_device_id: device_uuid(&recipient),
                    source_kind: delivery::RecoveryWorkSourceKind::WelcomeRejected,
                    source_id: welcome_id,
                    generation: checked_i64(welcome_coordinate.generation())?,
                    state_version: checked_i64(welcome_coordinate.state_version())?,
                    created_at: applied_at,
                },
            )
            .await?;
        }

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions: vec![position],
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply an entry-less `leafRecoveryCancellation` internal op: terminalize one
    /// open recovery request as `cancelled` with its signed cancellation
    /// provenance, release its reservation, and RE-ACTIVATE the reserved key
    /// package back to `available` (the E2b-6b `PackageSuccessor::Reactivate`
    /// writer). The coordinate and seq counter are byte-untouched (head CAS
    /// verify). The `assert_recovery_fulfillment_mapping` cancelled-status arm
    /// requires the released reservation and request to carry the SAME
    /// `terminal_request_digest` + `terminal_at`, and the package to be
    /// `available` with all terminal columns NULL — all satisfied here.
    #[allow(clippy::too_many_arguments)]
    async fn apply_leaf_recovery_cancellation(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        generation: i64,
        state_version: i64,
        _epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "leaf recovery cancellation needs a prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
        let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

        // Only a request terminalization + reservation release + package
        // re-activation. Everything else must be empty.
        reject_if_present("participant_changes", effects.participant_changes())?;
        reject_if_present("leaf_changes", effects.leaf_changes())?;
        reject_if_present("interval_changes", effects.interval_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present("reset_request_changes", effects.reset_request_changes())?;
        reject_if_present("leave_request_changes", effects.leave_request_changes())?;
        reject_if_present("welcome_changes", effects.welcome_changes())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        if effects.metadata_change().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "leaf recovery cancellation metadata change",
            ));
        }
        if effects.revocation_target_cas().is_some()
            || effects.welcome_cas().is_some()
            || effects.invitation_quota_cas().is_some()
        {
            return Err(ExecutorError::UnsupportedEffect(
                "leaf recovery cancellation revocation/welcome/quota CAS",
            ));
        }
        // Internal op MUST NOT change the coordinate or advance the seq counter
        // (E2b-6b review MINOR-2).
        if successor_next_entry_seq != expected_next_entry_seq {
            return Err(ExecutorError::InconsistentPlan(
                "leaf recovery cancellation must not advance the seq counter",
            ));
        }
        if generation != expected_generation || state_version != expected_state_version {
            return Err(ExecutorError::InconsistentPlan(
                "leaf recovery cancellation must not change the coordinate",
            ));
        }

        // Exactly one Open->Cancelled recovery request + one released reservation +
        // one package edge.
        let recovery = effects
            .recovery_request_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (Some(before), Some(after))
                    if before.status() == RecoveryRequestStatus::Open
                        && after.status() == RecoveryRequestStatus::Cancelled =>
                {
                    Some(after)
                }
                _ => None,
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "cancellation does not cancel an open recovery request",
            ))?;
        if effects.recovery_request_changes().len() != 1
            || effects.reservation_changes().len() != 1
            || effects.package_transitions().len() != 1
        {
            return Err(ExecutorError::InconsistentPlan(
                "cancellation must terminalize exactly one request + reservation + package edge",
            ));
        }
        verify_recovery_package_consistency(
            effects,
            recovery.key_package_ref(),
            PackageStatus::Reserved,
            PackageStatus::Available,
        )?;
        let recovery_request_id = Uuid::from_bytes(*recovery.request_id());
        let key_package_ref = recovery.key_package_ref().to_vec();
        // The signed cancellation request's digest — the SAME value the released
        // reservation records, per the cancelled-status mapping cross-check.
        let terminal_request_digest = ctx.entry.request_digest.clone();

        // 1. Head CAS VERIFY (coordinate + seq counter unchanged).
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. Terminalize the request as cancelled with its signed provenance.
        transition::terminalize_leaf_recovery_request(
            transaction,
            recovery_request_id,
            &LeafRecoveryTermination::Cancelled {
                terminal_signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
                terminal_signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
                terminal_request_digest: terminal_request_digest.clone(),
                terminal_signature: ctx.entry.signature.clone(),
                terminal_at: applied_at,
            },
        )
        .await?;

        // 3. Release the reservation by the same signed cancellation request digest.
        transition::terminalize_reservation(
            transaction,
            recovery_request_id,
            &ReservationTermination::ReleasedByRequestDigest {
                terminal_request_digest,
                terminal_at: applied_at,
            },
        )
        .await?;

        // 4. Re-activate the reserved package back to the available pool.
        transition::cas_key_package_status(
            transaction,
            &key_package_ref,
            RepoPackageStatus::Reserved,
            &PackageSuccessor::Reactivate,
        )
        .await?;

        // 5. No control entry (internal op); only events.
        let event_positions = write_events(transaction, ctx).await?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply a `signedLeafRecoveryFulfillment` edge (kind `leafRecovery`): the
    /// epoch-changing commit that adds the recovered target by KeyPackage and emits
    /// its Welcome. sv+1, epoch+1 (new hash/tag), same generation. Composes: head
    /// CAS + gen-state-version CAS + `commit`/active gen_state (epoch+1) +
    /// leafRecoveryFulfillmentEntry + transition (`leafRecovery`) + metadata
    /// RE-ENCRYPTION snapshot + exactly one `addLeafByRecovery` (the target's leaf
    /// period, `keyPackage` origin with join provenance, + its `add`-opened interval
    /// at the fulfillment seq) + request `fulfilled` / reservation `consumed` /
    /// package `consumed` + Welcome bundle + delivery (`expires_at` == consumed
    /// package `not_after`) + audience + `welcomeAvailable` event.
    ///
    /// SCOPE: the single-request Add fulfillment (what the frozen corpus commit
    /// exercises). Prior-coordinate open-request supersession (multiple
    /// recovery/reservation/package changes) and a `replace` close are NOT composed
    /// here — the exact-count guards below turn either into a hard `InconsistentPlan`
    /// rather than a silent drop; they are a bounded follow-on once a corpus with a
    /// second open request / a Remove-capable commit exists.
    #[allow(clippy::too_many_arguments)]
    async fn apply_leaf_recovery_fulfillment(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        transition_id: Uuid,
        seq_i64: i64,
        successor_next_entry_seq: i64,
        generation: i64,
        state_version: i64,
        epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let hydration = plan.state();
        let coordinate = &hydration.coordinate; // successor (sv+1, epoch+1).
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan("fulfillment needs a prior"))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

        // Guards: fulfillment carries leaf / interval / welcome / recovery-request /
        // reservation / package / metadata changes + (a legal interleaving)
        // prior-bound reset/leave STALING; reject the families it never has.
        reject_if_present("participant_changes", effects.participant_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        if effects.revocation_target_cas().is_some()
            || effects.welcome_cas().is_some()
            || effects.invitation_quota_cas().is_some()
        {
            return Err(ExecutorError::UnsupportedEffect(
                "fulfillment revocation/welcome/quota CAS",
            ));
        }
        // Metadata re-encryption is MANDATORY (DDL requires_snapshot ∋ leafRecovery).
        let metadata = effects
            .metadata_change()
            .and_then(StateChange::after)
            .ok_or(ExecutorError::InconsistentPlan(
                "fulfillment carries no metadata re-encryption",
            ))?;
        let author_cols = ctx
            .metadata_author
            .as_ref()
            .ok_or(ExecutorError::MissingContext(
                "fulfillment commit metadata author",
            ))?;

        // Exact-SHAPE: exactly ONE own Open->Fulfilled recovery request +
        // Active->Consumed reservation + Reserved->Consumed package edge + one new
        // pending welcome. Any OTHER recovery/reservation/package delta must be a
        // prior-bound supersession (Open->Superseded / Active->Released /
        // Reserved->Available), consumed by write_prior_bound_supersessions.
        let own_fulfilled = effects
            .recovery_request_changes()
            .iter()
            .filter(|change| {
                matches!((change.before(), change.after()), (Some(b), Some(a))
                    if b.status() == RecoveryRequestStatus::Open
                        && a.status() == RecoveryRequestStatus::Fulfilled)
            })
            .count();
        let own_consumed = effects
            .reservation_changes()
            .iter()
            .filter(|change| {
                matches!((change.before(), change.after()), (Some(b), Some(a))
                    if b.status() == ReservationStatus::Active
                        && a.status() == ReservationStatus::Consumed)
            })
            .count();
        // Exactly ONE own NEW pending welcome. A `replace` fulfillment ALSO
        // supersedes the target's prior-bound pending welcome (a (Some,Some)
        // Pending->Superseded change consumed by write_welcome_supersessions +
        // reconcile), so the total welcome-change count is NOT constrained here —
        // only the own new-pending count is.
        let own_new_welcomes = effects
            .welcome_changes()
            .iter()
            .filter(|change| {
                matches!((change.before(), change.after()), (None, Some(a))
                    if a.status() == WelcomeStatus::Pending)
            })
            .count();
        if own_fulfilled != 1 || own_consumed != 1 || own_new_welcomes != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment must carry exactly one own fulfilled request + consumed reservation + welcome",
            ));
        }
        let fulfilled = effects
            .recovery_request_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (Some(before), Some(after))
                    if before.status() == RecoveryRequestStatus::Open
                        && after.status() == RecoveryRequestStatus::Fulfilled =>
                {
                    Some(after)
                }
                _ => None,
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "fulfillment fulfills no open recovery request",
            ))?;
        let recovery_request_id = Uuid::from_bytes(*fulfilled.request_id());
        let reserved_ref = *fulfilled.key_package_ref();
        // The OWN Reserved -> Consumed package edge (bijection + driven-ref +
        // direction); any other edges are Reserved->Available supersessions.
        verify_recovery_package_consistency(
            effects,
            &reserved_ref,
            PackageStatus::Reserved,
            PackageStatus::Consumed,
        )?;
        // Exactly one new pending welcome.
        let welcome = effects
            .welcome_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (None, Some(after)) if after.status() == WelcomeStatus::Pending => Some(after),
                _ => None,
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "fulfillment adds no pending welcome",
            ))?;

        // 1. Head CAS sv+1.
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. Generation state-version pointer CAS (same generation).
        transition::cas_generation_state_version(
            transaction,
            &transition::GenerationStateVersionCas {
                conversation_id,
                generation,
                expected_state_version,
                successor_state_version: state_version,
            },
        )
        .await?;

        // 3. `commit`/active gen_state at the NEW epoch (fresh hash/tag).
        transition::insert_generation_state_row(
            transaction,
            &NewGenerationState {
                conversation_id,
                generation,
                state_version,
                group_id: coordinate.group_id().to_vec(),
                epoch,
                group_context_hash: coordinate.group_context_hash().to_vec(),
                confirmation_tag: coordinate.confirmation_tag().to_vec(),
                lifecycle: GenerationStateLifecycle::Active,
                state_kind: GenerationStateKind::Commit,
                producing_transition_id: transition_id,
                public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
                snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
                tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
                tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
                leaf_count: ctx.spine.leaf_count,
                created_at: applied_at,
            },
        )
        .await?;

        // 4. Entry (leafRecoveryFulfillmentEntry).
        let append = build_append_entry(
            ctx,
            conversation_id,
            generation,
            state_version,
            transition_id,
        );
        delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

        // 5. Transition (kind leafRecovery, prior -> next, carries the request).
        transition::insert_transition_row(
            transaction,
            &NewTransition {
                transition_id,
                conversation_id,
                kind: TransitionKind::LeafRecovery,
                actor_did: ctx.actor.user_did.clone(),
                actor_device_id: ctx.actor.device_id,
                actor_key_id: ctx.actor.key_id.clone(),
                actor_auth_generation: ctx.actor.auth_generation,
                actor_role: ctx.actor.role,
                actor_device_status: ctx.actor.device_status.clone(),
                signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
                unsigned_projection_bytes: ctx.entry.unsigned_projection_bytes.clone(),
                signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
                request_digest: ctx.entry.request_digest.clone(),
                signature: ctx.entry.signature.clone(),
                coordinates: TransitionCoordinates {
                    prior: Some((expected_generation, expected_state_version)),
                    next: Some((generation, state_version)),
                    retired: None,
                    successor: None,
                },
                reset_request_id: None,
                close_transition_id: None,
                metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
                entry_seq: seq_i64,
                accepted_at: applied_at,
            },
        )
        .await?;

        // 6. Metadata re-encryption snapshot (carry-forward author/origin/version).
        write_commit_metadata_snapshot(
            transaction,
            metadata,
            author_cols,
            conversation_id,
            generation,
            state_version,
            epoch,
            &coordinate.group_id().to_vec(),
            &coordinate.group_context_hash().to_vec(),
            &coordinate.confirmation_tag().to_vec(),
            transition_id,
            applied_at,
        )
        .await?;

        // 7. The target's recovered leaf. An `add` fulfillment opens a fresh
        //    (None,Some) leaf for a target that had none; a `replace` fulfillment
        //    ROTATES an existing target leaf — because the diff is keyed by DEVICE
        //    (not leaf index), the rotation surfaces as ONE (Some,Some) change for
        //    the target (the whole `LeafRecord` differs: new signature/encryption
        //    key + key-package origin), which must close the OLD leaf period and
        //    open a fresh one. A NON-target (Some,Some) is the committer's own
        //    tolerated key rotation — the DS `member_devices` row stores no
        //    ephemeral encryption key, so it needs no write. Any other leaf delta
        //    (a non-target add, or a full removal) is a hard error.
        let target = fulfilled.target().clone();
        let mut target_leaf: Option<(bool, &LeafRecord)> = None;
        for change in effects.leaf_changes() {
            match (change.before(), change.after()) {
                (None, Some(after)) if after.device() == &target => {
                    if target_leaf.replace((false, after)).is_some() {
                        return Err(ExecutorError::InconsistentPlan(
                            "fulfillment carries more than one target leaf change",
                        ));
                    }
                }
                (Some(_), Some(after)) if after.device() == &target => {
                    if target_leaf.replace((true, after)).is_some() {
                        return Err(ExecutorError::InconsistentPlan(
                            "fulfillment carries more than one target leaf change",
                        ));
                    }
                }
                (Some(_), Some(_)) => {}
                (None, Some(_)) | (Some(_), None) | (None, None) => {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment carries an unexpected leaf change",
                    ))
                }
            }
        }
        let (is_replace, new_leaf_change) = target_leaf.ok_or(ExecutorError::InconsistentPlan(
            "fulfillment carries no target leaf change",
        ))?;
        debug_assert_eq!(new_leaf_change.device(), &target);
        let leaf_row = hydration
            .leaves
            .iter()
            .find(|row| row.device == target)
            .ok_or(ExecutorError::InconsistentPlan(
                "recovered leaf not in hydration",
            ))?;
        let leaf_cols = ctx
            .opened_leaves
            .iter()
            .find(|cols| cols.device == target)
            .ok_or(ExecutorError::MissingContext("recovered leaf columns"))?;
        let leaf_period_id = *ctx
            .leaf_period_ids
            .first()
            .ok_or(ExecutorError::MissingContext("recovered leaf period id"))?;
        let participant_period_id = participant_period_for(ctx, hydration, target.principal())?;
        // A `replace` closes the target's OLD leaf period FIRST (a single active
        // leaf per device), sourcing the period id from ctx.closing_leaf_periods,
        // before the fresh period below reuses the vacated slot.
        if is_replace {
            let old_leaf_period = closing_leaf_period(ctx, &target)?;
            transition::close_leaf_period(
                transaction,
                &LeafClose {
                    leaf_period_id: old_leaf_period,
                    removed_state_version: state_version,
                    removed_transition_id: transition_id,
                    removed_seq: seq_i64,
                    removed_at: applied_at,
                },
            )
            .await?;
        }
        transition::insert_leaf_period(
            transaction,
            &NewLeafPeriod {
                leaf_period_id,
                participant_period_id,
                conversation_id,
                generation,
                user_did: device_did(&target)?,
                device_id: device_uuid(&target),
                leaf_index: checked_i64(u64::from(leaf_row.leaf_index))?,
                basic_credential: leaf_row.basic_credential.clone(),
                leaf_signature_key: leaf_row.signature_key.clone(),
                leaf_key_id: leaf_cols.leaf_key_id.clone(),
                leaf_auth_generation: leaf_cols.leaf_auth_generation,
                origin: LeafOrigin::KeyPackage {
                    key_package_ref: reserved_ref.to_vec(),
                },
                joined_state_version: state_version,
                joined_transition_id: transition_id,
                joined_seq: seq_i64,
                created_at: applied_at,
            },
        )
        .await?;

        // 8. Intervals. The target's fresh `add` interval opens at the fulfillment
        //    seq (keyed on the new opening seq). A `replace` ADDITIONALLY carries
        //    the target's PRIOR interval as a (Some,Some) close (keyed on the old
        //    opening seq), `Replace`-closed inclusively at the fulfillment seq —
        //    the removed old leaf period sources the close. Every interval change
        //    must be consumed; the counts are asserted against the request kind.
        let mut opened_intervals = 0usize;
        let mut closed_intervals = 0usize;
        for change in effects.interval_changes() {
            match (change.before(), change.after()) {
                (None, Some(after)) => {
                    if after.recipient() != &target
                        || after.opening_kind() != super::OpeningKind::Add
                        || after.end().is_some()
                    {
                        return Err(ExecutorError::InconsistentPlan(
                            "fulfillment opens an unexpected interval",
                        ));
                    }
                    let opening_context = after.opening_context();
                    delivery::insert_application_interval(
                        transaction,
                        &NewApplicationInterval {
                            membership_interval_id: Uuid::from_bytes(
                                *after.opening_transition_id(),
                            ),
                            conversation_id,
                            generation: checked_i64(opening_context.generation())?,
                            recipient_did: device_did(after.recipient())?,
                            recipient_device_id: device_uuid(after.recipient()),
                            start_seq: checked_i64(after.opening_seq())?,
                            opening_kind: IntervalOpeningKind::Add,
                            opening_transition_id: Uuid::from_bytes(*after.opening_transition_id()),
                            opening_outer_entry_fingerprint: after
                                .opening_outer_entry_fingerprint()
                                .to_vec(),
                            opening_state_version: checked_i64(opening_context.state_version())?,
                            opening_group_id: opening_context.group_id().to_vec(),
                            opening_epoch: checked_i64(opening_context.epoch())?,
                            opening_group_context_hash: opening_context
                                .group_context_hash()
                                .to_vec(),
                            opening_confirmation_tag: opening_context.confirmation_tag().to_vec(),
                            opening_leaf_period_id: leaf_period_id,
                            created_at: applied_at,
                        },
                    )
                    .await?;
                    opened_intervals += 1;
                }
                (Some(_), Some(after)) => {
                    let end = after.end().ok_or(ExecutorError::InconsistentPlan(
                        "fulfillment replace-close carries no interval end",
                    ))?;
                    if after.recipient() != &target || end.kind() != CloseKind::Replace {
                        return Err(ExecutorError::InconsistentPlan(
                            "fulfillment closes an unexpected interval",
                        ));
                    }
                    let old_leaf_period = closing_leaf_period(ctx, after.recipient())?;
                    delivery::close_application_interval(
                        transaction,
                        &ApplicationIntervalClose {
                            membership_interval_id: Uuid::from_bytes(
                                *after.opening_transition_id(),
                            ),
                            terminal_seq: checked_i64(end.seq())?,
                            closing_state_version: state_version,
                            closing_transition_id: Uuid::from_bytes(*end.transition_id()),
                            closing_outer_entry_fingerprint: end.outer_entry_fingerprint().to_vec(),
                            closing_kind: repo_interval_close_kind(end.kind()),
                            closing_leaf_period_id: old_leaf_period,
                            removed_at: applied_at,
                        },
                    )
                    .await?;
                    closed_intervals += 1;
                }
                (Some(_), None) | (None, None) => {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment carries an unexpected interval change",
                    ))
                }
            }
        }
        let expected_closed = usize::from(is_replace);
        if opened_intervals != 1 || closed_intervals != expected_closed {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment interval changes do not match the request kind",
            ));
        }

        // 9. Terminalize: request fulfilled, reservation consumed, package consumed.
        transition::terminalize_leaf_recovery_request(
            transaction,
            recovery_request_id,
            &LeafRecoveryTermination::Fulfilled {
                fulfilling_transition_id: transition_id,
                terminal_at: applied_at,
            },
        )
        .await?;
        transition::terminalize_reservation(
            transaction,
            recovery_request_id,
            &ReservationTermination::Consumed {
                consumed_transition_id: transition_id,
                terminal_at: applied_at,
            },
        )
        .await?;
        transition::cas_key_package_status(
            transaction,
            &reserved_ref,
            RepoPackageStatus::Reserved,
            &PackageSuccessor::Consume {
                terminal_transition_id: transition_id,
                terminal_at: applied_at,
            },
        )
        .await?;

        // 10. Welcome bundle + delivery (expires_at == consumed package not_after).
        let welcome_id = Uuid::from_bytes(*welcome.welcome_id());
        delivery::insert_welcome_bundle(
            transaction,
            &NewWelcomeBundle {
                welcome_id,
                conversation_id,
                transition_id,
                entry_seq: seq_i64,
                generation,
                state_version,
                group_id: coordinate.group_id().to_vec(),
                epoch,
                group_context_hash: coordinate.group_context_hash().to_vec(),
                confirmation_tag: coordinate.confirmation_tag().to_vec(),
                wrapper_bytes: welcome.opaque_welcome().to_vec(),
                wrapper_sha256: welcome.sha256().to_vec(),
                created_at: applied_at,
            },
        )
        .await?;
        delivery::insert_welcome_delivery(
            transaction,
            &NewWelcomeDelivery {
                welcome_id,
                recipient_did: device_did(welcome.recipient())?,
                recipient_device_id: device_uuid(welcome.recipient()),
                recovery_request_id,
                key_package_ref: welcome.key_package_ref().to_vec(),
                expires_at: server_instant(welcome.expires_at())?,
            },
        )
        .await?;

        // 11. Audience + events.
        let recipients = build_entry_recipients(&ctx.entry_recipients)?;
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
        let event_positions = write_events(transaction, ctx).await?;
        // Prior-coordinate open-work supersession (a legal interleaving): the corpus
        // fulfillment carries none, but the path composes it for the general case.
        let mut superseded =
            write_prior_bound_supersessions(transaction, effects, transition_id, applied_at)
                .await?;
        superseded.welcomes = write_welcome_supersessions(transaction, ctx, effects).await?;
        // Durably stale any prior-bound pending reset/leave request the coordinate
        // change retired (this arm owns none — kind is `leafRecovery`, DB-legal for
        // the leave `stale` edge).
        let staled = write_prior_bound_staling(
            transaction,
            effects,
            transition_id,
            &ctx.entry.request_digest,
            applied_at,
        )
        .await?;
        superseded.reset_requests = staled.reset_requests;
        superseded.leave_requests = staled.leave_requests;
        // Silent-drop guard: this arm's OWN edges are exactly one fulfilled request +
        // consumed reservation + Reserved->Consumed package + new pending welcome; every
        // OTHER delta MUST be a supersession/staling the calls above applied. Reject any
        // delta that is neither (e.g. an Open->Expired request) rather than dropping it.
        reconcile_coordinate_change_families(
            effects,
            &FamilyCounts {
                requests: 1,
                reservations: 1,
                packages: 1,
                welcomes: 1,
                reset_requests: 0,
                leave_requests: 0,
            },
            &superseded,
        )?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(seq_i64).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply a generic `signedCommitTransition` (zero adds / no membership change):
    /// an epoch-only crypto commit. sv+1 AND epoch+1 with a fresh hash/tag, the
    /// metadata re-encrypted (carry-forward), and NO leaf/interval/participant/
    /// welcome/recovery change beyond the sender's own key rotation (which the DS
    /// `member_devices` row does not store, so it is a no-op here). Distinguished
    /// from a fulfillment purely by the ABSENCE of a Welcome (a fulfillment always
    /// emits exactly one; a generic commit never does), backstopped by the
    /// exact-empty guards below.
    #[allow(clippy::too_many_arguments)]
    async fn apply_generic_commit(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        transition_id: Uuid,
        seq_i64: i64,
        successor_next_entry_seq: i64,
        generation: i64,
        state_version: i64,
        epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let hydration = plan.state();
        let coordinate = &hydration.coordinate; // successor (sv+1, epoch+1).
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "generic commit needs a prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

        // A generic (zero-proposal) commit changes ONLY the crypto coordinate + the
        // re-encrypted metadata + (a legal interleaving) prior-coordinate open-work
        // SUPERSESSION + prior-bound reset/leave STALING. It has no membership change
        // and no OWN recovery/reset/leave work: every recovery/reservation/package
        // delta must be a supersession and every reset/leave delta a Pending->Stale
        // staling (verified by exact-shape below).
        reject_if_present("participant_changes", effects.participant_changes())?;
        reject_if_present("interval_changes", effects.interval_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        // recovery_request_changes / reservation_changes / package_transitions /
        // welcome_changes: NOT rejected — a coordinate-changing commit supersedes
        // prior-coordinate open work (request->Superseded, reservation->Released,
        // package Reserved->Available) and a prior pending Welcome. Handled by
        // write_prior_bound_supersessions + write_welcome_supersessions; every such
        // delta MUST be a supersession shape (exact-shape checks below).
        for change in effects.recovery_request_changes() {
            if !matches!((change.before(), change.after()), (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Superseded)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "generic commit recovery request change is not a supersession",
                ));
            }
        }
        for change in effects.reservation_changes() {
            if !matches!((change.before(), change.after()), (Some(before), Some(after))
                if before.status() == ReservationStatus::Active
                    && after.status() == ReservationStatus::Released)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "generic commit reservation change is not a release",
                ));
            }
        }
        for edge in effects.package_transitions() {
            if edge.from != PackageStatus::Reserved || edge.to != PackageStatus::Available {
                return Err(ExecutorError::InconsistentPlan(
                    "generic commit package edge is not a Reserved->Available release",
                ));
            }
        }
        verify_recovery_package_bijection(effects)?;
        if effects.revocation_target_cas().is_some()
            || effects.welcome_cas().is_some()
            || effects.invitation_quota_cas().is_some()
        {
            return Err(ExecutorError::UnsupportedEffect(
                "generic commit revocation/welcome/quota CAS",
            ));
        }
        // Only the sender's own key rotation may appear as a leaf change — a
        // (Some,Some) with NO DS row impact. Any add (None,Some) or remove
        // (Some,None) is NOT a zero-proposal commit and is a hard error.
        for change in effects.leaf_changes() {
            if !matches!((change.before(), change.after()), (Some(_), Some(_))) {
                return Err(ExecutorError::InconsistentPlan(
                    "generic commit carries a membership leaf change (not zero-proposal)",
                ));
            }
        }
        // Metadata re-encryption is MANDATORY (DDL requires_snapshot ∋ commit).
        let metadata = effects
            .metadata_change()
            .and_then(StateChange::after)
            .ok_or(ExecutorError::InconsistentPlan(
                "generic commit carries no metadata re-encryption",
            ))?;
        let author_cols = ctx
            .metadata_author
            .as_ref()
            .ok_or(ExecutorError::MissingContext(
                "generic commit metadata author",
            ))?;

        // 1. Head CAS sv+1 (the epoch bump lives in the gen_state).
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. Generation state-version pointer CAS (same generation).
        transition::cas_generation_state_version(
            transaction,
            &transition::GenerationStateVersionCas {
                conversation_id,
                generation,
                expected_state_version,
                successor_state_version: state_version,
            },
        )
        .await?;

        // 3. `commit`/active gen_state at the NEW epoch (fresh hash/tag).
        transition::insert_generation_state_row(
            transaction,
            &NewGenerationState {
                conversation_id,
                generation,
                state_version,
                group_id: coordinate.group_id().to_vec(),
                epoch,
                group_context_hash: coordinate.group_context_hash().to_vec(),
                confirmation_tag: coordinate.confirmation_tag().to_vec(),
                lifecycle: GenerationStateLifecycle::Active,
                state_kind: GenerationStateKind::Commit,
                producing_transition_id: transition_id,
                public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
                snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
                tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
                tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
                leaf_count: ctx.spine.leaf_count,
                created_at: applied_at,
            },
        )
        .await?;

        // 4. Entry (commitEntry).
        let append = build_append_entry(
            ctx,
            conversation_id,
            generation,
            state_version,
            transition_id,
        );
        delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

        // 5. Transition (kind commit, prior -> next).
        transition::insert_transition_row(
            transaction,
            &NewTransition {
                transition_id,
                conversation_id,
                kind: TransitionKind::Commit,
                actor_did: ctx.actor.user_did.clone(),
                actor_device_id: ctx.actor.device_id,
                actor_key_id: ctx.actor.key_id.clone(),
                actor_auth_generation: ctx.actor.auth_generation,
                actor_role: ctx.actor.role,
                actor_device_status: ctx.actor.device_status.clone(),
                signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
                unsigned_projection_bytes: ctx.entry.unsigned_projection_bytes.clone(),
                signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
                request_digest: ctx.entry.request_digest.clone(),
                signature: ctx.entry.signature.clone(),
                coordinates: TransitionCoordinates {
                    prior: Some((expected_generation, expected_state_version)),
                    next: Some((generation, state_version)),
                    retired: None,
                    successor: None,
                },
                reset_request_id: None,
                close_transition_id: None,
                metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
                entry_seq: seq_i64,
                accepted_at: applied_at,
            },
        )
        .await?;

        // 6. Metadata re-encryption snapshot (carry-forward author/origin/version).
        write_commit_metadata_snapshot(
            transaction,
            metadata,
            author_cols,
            conversation_id,
            generation,
            state_version,
            epoch,
            &coordinate.group_id().to_vec(),
            &coordinate.group_context_hash().to_vec(),
            &coordinate.confirmation_tag().to_vec(),
            transition_id,
            applied_at,
        )
        .await?;

        // 7. Audience + events.
        let recipients = build_entry_recipients(&ctx.entry_recipients)?;
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
        let event_positions = write_events(transaction, ctx).await?;
        // Supersede prior-coordinate open work (requests/reservations/packages) +
        // any prior pending Welcome the epoch change retired.
        let mut superseded =
            write_prior_bound_supersessions(transaction, effects, transition_id, applied_at)
                .await?;
        superseded.welcomes = write_welcome_supersessions(transaction, ctx, effects).await?;
        // Durably stale any prior-bound pending reset/leave request the epoch change
        // retired (kind is `commit`, DB-legal for the leave `stale` edge).
        let staled = write_prior_bound_staling(
            transaction,
            effects,
            transition_id,
            &ctx.entry.request_digest,
            applied_at,
        )
        .await?;
        superseded.reset_requests = staled.reset_requests;
        superseded.leave_requests = staled.leave_requests;
        // Silent-drop guard: a generic commit has NO own recovery/reservation/package/
        // welcome/reset/leave edge — every such delta MUST be a supersession/staling the
        // calls above applied. The per-delta shape loops above already reject a malformed
        // recovery/reservation/package delta; this additionally catches a malformed
        // welcome delta (e.g. Pending->Expired) or a non-Pending->Stale reset/leave delta
        // that the writers skip, closing the last silent-drop path.
        reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(seq_i64).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply a `leaveCommitFulfillment` (`PlanKind::Commit`): a DIFFERENT-DID
    /// current member commits a Remove of every requester leaf, fulfilling the
    /// requester's retained group-leave consent. `sv+1` AND `epoch+1` (fresh
    /// hash/tag), metadata re-encryption carry-forward (`leaveCommit` ∈
    /// requires_snapshot), every requester leaf closed + its interval closed
    /// (`Remove`, inclusive at the fulfillment seq), the requester participant
    /// terminalized, and the pending leave request marked `fulfilled` (bound to
    /// this `leaveCommit` transition). Coordinate-changing, so it runs the SHARED
    /// prior-bound supersession path WITH the reconciliation from the start — the
    /// fulfillment-scenario prior carries a pending Welcome the epoch change
    /// supersedes (own welcome 0 + superseded 1). The committer's own key rotation
    /// surfaces as a `(Some,Some)` leaf change with no DS row impact (tolerated).
    #[allow(clippy::too_many_arguments)]
    async fn apply_leave_fulfillment(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        transition_id: Uuid,
        seq_i64: i64,
        successor_next_entry_seq: i64,
        generation: i64,
        state_version: i64,
        epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let hydration = plan.state();
        let coordinate = &hydration.coordinate; // successor (sv+1, epoch+1).
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "leave fulfillment needs a prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

        // Guards. Leave fulfillment carries participant/leaf/interval/leave-request/
        // metadata changes + (a legal interleaving) prior-bound recovery/welcome
        // SUPERSESSIONS + prior-bound reset/leave STALING. It has NO own recovery/
        // reservation/package edge and no terminal-proof/revocation change; those
        // recovery families flow ONLY through the shared supersession path (own
        // counts 0, verified by the reconciliation). Its OWN leave-request edge is the
        // single Pending->Fulfilled fulfilled below; per ADR-019 Erratum 01 the same
        // leaveCommit MAY additionally stale OTHER members' predecessor-bound pending
        // leaves (the partition check below enforces exactly-one-fulfilled + others-
        // only Pending->Stale). Reject the families it never carries.
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        if effects.revocation_target_cas().is_some()
            || effects.welcome_cas().is_some()
            || effects.invitation_quota_cas().is_some()
        {
            return Err(ExecutorError::UnsupportedEffect(
                "leave fulfillment revocation/welcome/quota CAS",
            ));
        }

        // Metadata re-encryption is MANDATORY (DDL requires_snapshot ∋ leaveCommit).
        let metadata = effects
            .metadata_change()
            .and_then(StateChange::after)
            .ok_or(ExecutorError::InconsistentPlan(
                "leave fulfillment carries no metadata re-encryption",
            ))?;
        let author_cols = ctx
            .metadata_author
            .as_ref()
            .ok_or(ExecutorError::MissingContext(
                "leave fulfillment commit metadata author",
            ))?;

        // Partition the leave-request deltas (ADR-019 Erratum 01). A leaveCommit
        // fulfills EXACTLY ONE requester's leave (its own Pending->Fulfilled edge) and
        // MAY additionally stale any number of OTHER members' predecessor-bound pending
        // leaves (Pending->Stale). Reject every other shape: a non-transition delta, a
        // request that did not start Pending, a re-binding (ruling point 4), a second
        // Fulfilled, or a Stale that targets the fulfilled request itself (ruling point
        // 3 — the fulfilled request is `fulfilled`, never `stale`). The Pending->Stale
        // others flow through `write_prior_bound_staling` at the tail; reconcile
        // own(1) + staled == total.
        let mut fulfilled_request_id: Option<[u8; 16]> = None;
        for change in effects.leave_request_changes() {
            let (before, after) = match (change.before(), change.after()) {
                (Some(before), Some(after)) => (before, after),
                _ => {
                    return Err(ExecutorError::InconsistentPlan(
                        "leave fulfillment leave-request delta must be a status transition",
                    ))
                }
            };
            if before.status() != LeaveRequestStatus::Pending {
                return Err(ExecutorError::InconsistentPlan(
                    "leave fulfillment leave-request delta must start Pending",
                ));
            }
            if before.bound_coordinate != after.bound_coordinate {
                return Err(ExecutorError::InconsistentPlan(
                    "leave fulfillment must not re-bind a leave request",
                ));
            }
            match after.status() {
                LeaveRequestStatus::Fulfilled => {
                    if fulfilled_request_id.is_some() {
                        return Err(ExecutorError::InconsistentPlan(
                            "leave fulfillment must fulfill exactly one leave request",
                        ));
                    }
                    fulfilled_request_id = Some(after.request_id);
                }
                LeaveRequestStatus::Stale => {}
                _ => {
                    return Err(ExecutorError::InconsistentPlan(
                        "leave fulfillment leave-request delta must be Fulfilled or Stale",
                    ))
                }
            }
        }
        let fulfilled_request_id = fulfilled_request_id.ok_or(ExecutorError::InconsistentPlan(
            "leave fulfillment must fulfill a pending leave request",
        ))?;
        // Ruling point 3: no Stale delta may target the request being fulfilled.
        for change in effects.leave_request_changes() {
            if let Some(after) = change.after() {
                if after.status() == LeaveRequestStatus::Stale
                    && after.request_id == fulfilled_request_id
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "leave fulfillment must not stale the request it fulfills",
                    ));
                }
            }
        }
        let leave_request_id = Uuid::from_bytes(fulfilled_request_id);

        // Exactly one participant is removed (the requester).
        if effects.participant_changes().len() != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "leave fulfillment must remove exactly one participant",
            ));
        }
        let removed = effects
            .participant_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (Some(before), None) => Some(before),
                _ => None,
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "leave fulfillment must close the requester participant",
            ))?;
        let participant_period_id = ctx
            .closing_participant_periods
            .iter()
            .find(|(device, _)| device.principal() == removed.principal())
            .map(|(_, id)| *id)
            .ok_or(ExecutorError::MissingContext(
                "closing participant period id for the leave requester",
            ))?;

        // 1. Head CAS sv+1.
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. Generation state-version pointer CAS (same generation).
        transition::cas_generation_state_version(
            transaction,
            &transition::GenerationStateVersionCas {
                conversation_id,
                generation,
                expected_state_version,
                successor_state_version: state_version,
            },
        )
        .await?;

        // 3. `commit`/active gen_state at the NEW epoch (fresh hash/tag).
        transition::insert_generation_state_row(
            transaction,
            &NewGenerationState {
                conversation_id,
                generation,
                state_version,
                group_id: coordinate.group_id().to_vec(),
                epoch,
                group_context_hash: coordinate.group_context_hash().to_vec(),
                confirmation_tag: coordinate.confirmation_tag().to_vec(),
                lifecycle: GenerationStateLifecycle::Active,
                state_kind: GenerationStateKind::Commit,
                producing_transition_id: transition_id,
                public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
                snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
                tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
                tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
                leaf_count: ctx.spine.leaf_count,
                created_at: applied_at,
            },
        )
        .await?;

        // 4. Entry (leaveCommitFulfillmentEntry).
        let append = build_append_entry(
            ctx,
            conversation_id,
            generation,
            state_version,
            transition_id,
        );
        delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

        // 5. Transition (kind leaveCommit, prior -> next).
        transition::insert_transition_row(
            transaction,
            &NewTransition {
                transition_id,
                conversation_id,
                kind: TransitionKind::LeaveCommit,
                actor_did: ctx.actor.user_did.clone(),
                actor_device_id: ctx.actor.device_id,
                actor_key_id: ctx.actor.key_id.clone(),
                actor_auth_generation: ctx.actor.auth_generation,
                actor_role: ctx.actor.role,
                actor_device_status: ctx.actor.device_status.clone(),
                signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
                unsigned_projection_bytes: ctx.entry.unsigned_projection_bytes.clone(),
                signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
                request_digest: ctx.entry.request_digest.clone(),
                signature: ctx.entry.signature.clone(),
                coordinates: TransitionCoordinates {
                    prior: Some((expected_generation, expected_state_version)),
                    next: Some((generation, state_version)),
                    retired: None,
                    successor: None,
                },
                reset_request_id: None,
                close_transition_id: None,
                metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
                entry_seq: seq_i64,
                accepted_at: applied_at,
            },
        )
        .await?;

        // 6. Metadata re-encryption snapshot (carry-forward author/origin/version).
        write_commit_metadata_snapshot(
            transaction,
            metadata,
            author_cols,
            conversation_id,
            generation,
            state_version,
            epoch,
            &coordinate.group_id().to_vec(),
            &coordinate.group_context_hash().to_vec(),
            &coordinate.confirmation_tag().to_vec(),
            transition_id,
            applied_at,
        )
        .await?;

        // 7. Close every requester leaf. A `(Some,None)` is a real removal; the
        //    committer's own key rotation is a tolerated `(Some,Some)` (no DS row);
        //    an add `(None,Some)` is not a leave and is a hard error.
        let mut removed_leaves = 0usize;
        for change in effects.leaf_changes() {
            match (change.before(), change.after()) {
                (Some(before), None) => {
                    let leaf = closing_leaf_period(ctx, before.device())?;
                    transition::close_leaf_period(
                        transaction,
                        &LeafClose {
                            leaf_period_id: leaf,
                            removed_state_version: state_version,
                            removed_transition_id: transition_id,
                            removed_seq: seq_i64,
                            removed_at: applied_at,
                        },
                    )
                    .await?;
                    removed_leaves += 1;
                }
                (Some(_), Some(_)) => {}
                (None, Some(_)) => {
                    return Err(ExecutorError::InconsistentPlan(
                        "leave fulfillment must not add a leaf",
                    ))
                }
                (None, None) => {}
            }
        }
        if removed_leaves == 0 {
            return Err(ExecutorError::InconsistentPlan(
                "leave fulfillment removed no leaf",
            ));
        }

        // 8. Close every removed device's interval inclusively at the fulfillment
        //    seq (`Remove`), sourcing the closing leaf period from ctx.
        for change in effects.interval_changes() {
            match (change.before(), change.after()) {
                (Some(_), Some(after)) => {
                    let end = after.end().ok_or(ExecutorError::InconsistentPlan(
                        "leave-closed interval has no end",
                    ))?;
                    let leaf = closing_leaf_period(ctx, after.recipient())?;
                    delivery::close_application_interval(
                        transaction,
                        &ApplicationIntervalClose {
                            membership_interval_id: Uuid::from_bytes(
                                *after.opening_transition_id(),
                            ),
                            terminal_seq: checked_i64(end.seq())?,
                            closing_state_version: state_version,
                            closing_transition_id: Uuid::from_bytes(*end.transition_id()),
                            closing_outer_entry_fingerprint: end.outer_entry_fingerprint().to_vec(),
                            closing_kind: repo_interval_close_kind(end.kind()),
                            closing_leaf_period_id: leaf,
                            removed_at: applied_at,
                        },
                    )
                    .await?;
                }
                _ => {
                    return Err(ExecutorError::InconsistentPlan(
                        "leave fulfillment interval change must close an open interval",
                    ))
                }
            }
        }

        // 9. Terminalize the requester's participant period.
        transition::terminalize_participant_period(
            transaction,
            &transition::ParticipantTerminalization {
                participant_period_id,
                removing_transition_id: transition_id,
                removing_seq: seq_i64,
                removed_at: applied_at,
            },
        )
        .await?;

        // 10. Mark the leave request `fulfilled`, bound to this leaveCommit
        //     transition (the assert_leave_request_mapping fulfilled arm cross-checks
        //     kind ∈ leaveCommit/leavePolicy + prior coordinate + digest + instant).
        transition::terminalize_leave_request(
            transaction,
            leave_request_id,
            &LeaveRequestTermination::Fulfilled {
                terminal_request_digest: ctx.entry.request_digest.clone(),
                terminal_transition_id: transition_id,
                terminal_at: applied_at,
            },
        )
        .await?;

        // 11. Audience + events.
        let recipients = build_entry_recipients(&ctx.entry_recipients)?;
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
        let event_positions = write_events(transaction, ctx).await?;

        // 12. Shared prior-bound supersession + welcome supersession + reset/leave
        //     STALING + the silent-drop reconciliation (own recovery/reservation/
        //     package/welcome edges are ALL zero for a leave fulfillment; its ONE own
        //     leave edge is the Pending->Fulfilled handled above — every OTHER delta
        //     must be a supersession/staling the calls below applied). Per ADR-019
        //     Erratum 01 `write_prior_bound_staling` now also terminalizes any
        //     Pending->Stale leaves of OTHER members the leaveCommit retired (bound to
        //     this transition + the commit's request digest); reconcile own(1) +
        //     staled == total.
        let mut superseded =
            write_prior_bound_supersessions(transaction, effects, transition_id, applied_at)
                .await?;
        superseded.welcomes = write_welcome_supersessions(transaction, ctx, effects).await?;
        let staled = write_prior_bound_staling(
            transaction,
            effects,
            transition_id,
            &ctx.entry.request_digest,
            applied_at,
        )
        .await?;
        superseded.reset_requests = staled.reset_requests;
        superseded.leave_requests = staled.leave_requests;
        reconcile_coordinate_change_families(
            effects,
            &FamilyCounts {
                leave_requests: 1,
                ..FamilyCounts::default()
            },
            &superseded,
        )?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(seq_i64).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_creation(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        transition_id: Uuid,
        seq_i64: i64,
        successor_next_entry_seq: i64,
        generation: i64,
        state_version: i64,
        epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let hydration = plan.state();
        let coordinate = &hydration.coordinate;
        let applied_at = ctx.applied_at;
        let group_id = coordinate.group_id().to_vec();
        let group_context_hash = coordinate.group_context_hash().to_vec();
        let confirmation_tag = coordinate.confirmation_tag().to_vec();

        // Creation carries no prior; every side family is a pure insert. Reject
        // any family this path does not translate so nothing is silently dropped.
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present(
            "recovery_request_changes",
            effects.recovery_request_changes(),
        )?;
        reject_if_present("reservation_changes", effects.reservation_changes())?;
        reject_if_present("reset_request_changes", effects.reset_request_changes())?;
        reject_if_present("leave_request_changes", effects.leave_request_changes())?;
        reject_if_present("welcome_changes", effects.welcome_changes())?;
        reject_if_present("package_transitions", effects.package_transitions())?;
        reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        if effects.revocation_target_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect("revocation_target_cas"));
        }
        if effects.welcome_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect("welcome_cas"));
        }
        // invitation_quota_cas: EXPLICITLY consumed, not written. It is the
        // WITNESS of the planner's locked live-pending-invitation counts for the
        // newly pending recipients; there is no row for the executor to persist.
        // The invitation quota is enforced by the `enforce_invitation_quota`
        // DEFERRED trigger, which independently re-counts live pending
        // invitations under `FOR UPDATE` at COMMIT. Production
        // `into_persistence_plan` requires EVERY Creation/Policy plan to carry
        // this binding (else `InvalidHydrationAuthority`); a missing binding here
        // is an `InconsistentPlan`, so this family is consumed — never silently
        // dropped — exactly as the exhaustive-dispatch contract demands.
        let _invitation_quota_witness =
            effects
                .invitation_quota_cas()
                .ok_or(ExecutorError::InconsistentPlan(
                    "creation plan missing invitation quota CAS binding",
                ))?;
        // effects.authority() is likewise deliberately unread: it is the sealed
        // control/request/revocation authority that JUSTIFIED the plan
        // (provenance/witness), not a persistable row family. The signed bytes it
        // attests to reach the durable rows through `ExecutionContext` (the entry
        // + transition signed material), which is caller-supplied input.

        // 1. Head (INSERT — true absence; the seq counter starts already advanced
        //    past the genesis entry).
        let head_kind = match hydration.kind {
            ConversationKind::Group => ConversationHeadKind::Group,
            ConversationKind::Direct => {
                let (low, high) = direct_pair(&hydration.participants)?;
                ConversationHeadKind::Direct {
                    direct_did_low: low,
                    direct_did_high: high,
                }
            }
        };
        transition::insert_conversation_head(
            transaction,
            &transition::NewConversationHead {
                conversation_id,
                kind: head_kind,
                current_generation: generation,
                current_state_version: state_version,
                next_entry_seq: successor_next_entry_seq,
                created_at: applied_at,
            },
        )
        .await?;

        // 2. Generation (activated at the genesis seq/instant).
        transition::insert_generation(
            transaction,
            &NewGeneration {
                conversation_id,
                generation,
                group_id: group_id.clone(),
                genesis_group_info_bytes: ctx.spine.genesis_group_info_bytes.clone(),
                genesis_group_info_sha256: ctx.spine.genesis_group_info_sha256.clone(),
                current_state_version: state_version,
                activated_seq: seq_i64,
                activated_at: applied_at,
            },
        )
        .await?;

        // 3. Generation state (the produced `creation` public coordinate).
        transition::insert_generation_state_row(
            transaction,
            &NewGenerationState {
                conversation_id,
                generation,
                state_version,
                group_id: group_id.clone(),
                epoch,
                group_context_hash: group_context_hash.clone(),
                confirmation_tag: confirmation_tag.clone(),
                lifecycle: GenerationStateLifecycle::Active,
                state_kind: GenerationStateKind::Creation,
                producing_transition_id: transition_id,
                public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
                snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
                tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
                tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
                leaf_count: ctx.spine.leaf_count,
                created_at: applied_at,
            },
        )
        .await?;

        // 4. Entry at the exact allocated seq (the head already advanced the
        //    counter). Immediate FK targets for the transition's `entry_seq`.
        let append = build_append_entry(
            ctx,
            conversation_id,
            generation,
            state_version,
            transition_id,
        );
        delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

        // 5. Metadata snapshot — REQUIRED for creation by the deferred mapping.
        let metadata = effects
            .metadata_change()
            .and_then(StateChange::after)
            .ok_or(ExecutorError::InconsistentPlan(
                "creation plan carries no metadata snapshot",
            ))?;
        let author_cols = ctx
            .metadata_author
            .as_ref()
            .ok_or(ExecutorError::MissingContext("metadata author columns"))?;
        write_creation_metadata_snapshot(
            transaction,
            metadata,
            author_cols,
            &ctx.actor,
            conversation_id,
            generation,
            state_version,
            epoch,
            &group_id,
            &group_context_hash,
            &confirmation_tag,
            transition_id,
            seq_i64,
            applied_at,
        )
        .await?;

        // 6. Transition row (needs entry_seq; entry written above).
        transition::insert_transition_row(
            transaction,
            &NewTransition {
                transition_id,
                conversation_id,
                kind: TransitionKind::Creation,
                actor_did: ctx.actor.user_did.clone(),
                actor_device_id: ctx.actor.device_id,
                actor_key_id: ctx.actor.key_id.clone(),
                actor_auth_generation: ctx.actor.auth_generation,
                actor_role: ctx.actor.role,
                actor_device_status: ctx.actor.device_status.clone(),
                signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
                unsigned_projection_bytes: ctx.entry.unsigned_projection_bytes.clone(),
                signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
                request_digest: ctx.entry.request_digest.clone(),
                signature: ctx.entry.signature.clone(),
                coordinates: TransitionCoordinates {
                    prior: None,
                    next: Some((generation, state_version)),
                    retired: None,
                    successor: None,
                },
                reset_request_id: None,
                close_transition_id: None,
                metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
                entry_seq: seq_i64,
                accepted_at: applied_at,
            },
        )
        .await?;

        // 7. Participant periods, then leaves, then intervals — every change is a
        //    pure insert for creation; a non-insert shape is a hard error.
        write_creation_participants(
            transaction,
            ctx,
            hydration,
            effects,
            transition_id,
            applied_at,
        )
        .await?;
        let leaf_ids = write_creation_leaves(
            transaction,
            ctx,
            hydration,
            effects,
            conversation_id,
            generation,
            transition_id,
            state_version,
            seq_i64,
            applied_at,
        )
        .await?;
        write_creation_intervals(transaction, effects, &leaf_ids, conversation_id, applied_at)
            .await?;

        // 8. Frozen control-entry audience.
        let recipients = build_entry_recipients(&ctx.entry_recipients)?;
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;

        // 9. Events + audience + outbox.
        let event_positions = write_events(transaction, ctx).await?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(seq_i64).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply a group `policy` addParticipant edge: same crypto coordinate,
    /// `stateVersion+1`, no metadata / leaf / interval change. Reuses the head
    /// CAS (existing conversation), the generation-pointer CAS, and the
    /// participant-insert path that creation uses; the only new participant is
    /// the added `pending/member` (the `StateChange` diff).
    #[allow(clippy::too_many_arguments)]
    async fn apply_policy(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        transition_id: Uuid,
        seq_i64: i64,
        successor_next_entry_seq: i64,
        generation: i64,
        state_version: i64,
        epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let hydration = plan.state();
        let coordinate = &hydration.coordinate;
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "policy needs an expected prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

        // Policy is a coordinate-only, participant-add edge. It carries NO leaf /
        // interval / terminal-proof change, but `plan_policy_transition` calls
        // `resolve_prior_bound_work` unconditionally, so it CAN carry (a legal
        // interleaving) prior-coordinate open-work SUPERSESSIONS — a co-open
        // leaf-recovery request (Open->Superseded) + its reservation (Active->Released)
        // + reserved package (Reserved->Available), a prior pending Welcome
        // (Pending->Superseded), and prior-bound reset/leave STALING (Pending->Stale).
        // Policy owns NONE of those (own counts 0); every such delta MUST be a
        // supersession/staling the shared writers apply at the tail, exact-shape
        // checked here (mirroring the close/commit arms). `recovery_package_cas` is the
        // production-shape package witness the bijection validates, NOT a rejected
        // family. (kind is `policy`, DB-legal for the recovery/welcome/leave edges.)
        reject_if_present("leaf_changes", effects.leaf_changes())?;
        reject_if_present("interval_changes", effects.interval_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        for change in effects.recovery_request_changes() {
            if !matches!((change.before(), change.after()), (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Superseded)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "policy recovery request change is not a supersession",
                ));
            }
        }
        for change in effects.reservation_changes() {
            if !matches!((change.before(), change.after()), (Some(before), Some(after))
                if before.status() == ReservationStatus::Active
                    && after.status() == ReservationStatus::Released)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "policy reservation change is not a release",
                ));
            }
        }
        for edge in effects.package_transitions() {
            if edge.from != PackageStatus::Reserved || edge.to != PackageStatus::Available {
                return Err(ExecutorError::InconsistentPlan(
                    "policy package edge is not a Reserved->Available release",
                ));
            }
        }
        verify_recovery_package_bijection(effects)?;
        if effects.metadata_change().is_some() {
            return Err(ExecutorError::UnsupportedEffect("policy metadata change"));
        }
        if effects.revocation_target_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect("revocation_target_cas"));
        }
        if effects.welcome_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect("welcome_cas"));
        }
        // invitation_quota_cas: consumed as witness (see apply_creation) — a
        // group policy addParticipant edge is the other kind production requires
        // to carry it. The quota itself is enforced by the deferred
        // `enforce_invitation_quota` trigger; a missing binding is InconsistentPlan.
        let _invitation_quota_witness =
            effects
                .invitation_quota_cas()
                .ok_or(ExecutorError::InconsistentPlan(
                    "policy plan missing invitation quota CAS binding",
                ))?;

        // 1. Head CAS advances the coordinate + counter (single seq authority).
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. Advance the generation's state-version pointer (same generation).
        transition::cas_generation_state_version(
            transaction,
            &transition::GenerationStateVersionCas {
                conversation_id,
                generation,
                expected_state_version,
                successor_state_version: state_version,
            },
        )
        .await?;

        // 3. Successor generation state (policy kind, identical crypto edge).
        transition::insert_generation_state_row(
            transaction,
            &NewGenerationState {
                conversation_id,
                generation,
                state_version,
                group_id: coordinate.group_id().to_vec(),
                epoch,
                group_context_hash: coordinate.group_context_hash().to_vec(),
                confirmation_tag: coordinate.confirmation_tag().to_vec(),
                lifecycle: GenerationStateLifecycle::Active,
                state_kind: GenerationStateKind::Policy,
                producing_transition_id: transition_id,
                public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
                snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
                tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
                tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
                leaf_count: ctx.spine.leaf_count,
                created_at: applied_at,
            },
        )
        .await?;

        // 4. Entry at the allocated seq.
        let append = build_append_entry(
            ctx,
            conversation_id,
            generation,
            state_version,
            transition_id,
        );
        delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

        // 5. Transition (prior -> next).
        transition::insert_transition_row(
            transaction,
            &NewTransition {
                transition_id,
                conversation_id,
                kind: TransitionKind::Policy,
                actor_did: ctx.actor.user_did.clone(),
                actor_device_id: ctx.actor.device_id,
                actor_key_id: ctx.actor.key_id.clone(),
                actor_auth_generation: ctx.actor.auth_generation,
                actor_role: ctx.actor.role,
                actor_device_status: ctx.actor.device_status.clone(),
                signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
                unsigned_projection_bytes: ctx.entry.unsigned_projection_bytes.clone(),
                signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
                request_digest: ctx.entry.request_digest.clone(),
                signature: ctx.entry.signature.clone(),
                coordinates: TransitionCoordinates {
                    prior: Some((expected_generation, expected_state_version)),
                    next: Some((generation, state_version)),
                    retired: None,
                    successor: None,
                },
                reset_request_id: None,
                close_transition_id: None,
                metadata_snapshot_id: None,
                entry_seq: seq_i64,
                accepted_at: applied_at,
            },
        )
        .await?;

        // 6. The added pending participant(s) — the participant-change diff.
        write_creation_participants(
            transaction,
            ctx,
            hydration,
            effects,
            transition_id,
            applied_at,
        )
        .await?;

        // 7. Audience + events.
        let recipients = build_entry_recipients(&ctx.entry_recipients)?;
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
        let event_positions = write_events(transaction, ctx).await?;

        // 8. Supersede prior-coordinate open work the policy edge retired (an open
        //    recovery request / active reservation / reserved package + a prior pending
        //    Welcome) AND stale any prior-bound pending reset/leave request. Policy owns
        //    NONE of these families (own == default), so every such delta MUST be a
        //    supersession/staling the shared writers below applied — reconcile rejects
        //    any that is neither (silent-drop guard).
        let mut superseded =
            write_prior_bound_supersessions(transaction, effects, transition_id, applied_at)
                .await?;
        superseded.welcomes = write_welcome_supersessions(transaction, ctx, effects).await?;
        let staled = write_prior_bound_staling(
            transaction,
            effects,
            transition_id,
            &ctx.entry.request_digest,
            applied_at,
        )
        .await?;
        superseded.reset_requests = staled.reset_requests;
        superseded.leave_requests = staled.leave_requests;
        reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(seq_i64).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply a `zeroLeafLeave` edge: an active but LEAFLESS participant (a pending
    /// invitee who never joined) self-removes immediately. `stateVersion+1`, same
    /// generation/epoch (a coordinate-only rebind, NO crypto commit and NO metadata
    /// snapshot — `leavePolicy` is not in the metadata-required set). It closes the
    /// participant period (releasing its invitation-quota slot, which the deferred
    /// `enforce_invitation_quota` trigger recomputes), with no leaf/interval change
    /// (the leaver had neither). Mirrors `apply_policy`'s coordinate/gen-state CAS
    /// spine, but terminalizes the participant instead of adding one.
    #[allow(clippy::too_many_arguments)]
    async fn apply_zero_leaf_leave(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        transition_id: Uuid,
        seq_i64: i64,
        successor_next_entry_seq: i64,
        generation: i64,
        state_version: i64,
        epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let hydration = plan.state();
        let coordinate = &hydration.coordinate;
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "zero-leaf leave needs an expected prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

        // Coordinate-only self-removal: the leaver's OWN delta is one participant
        // close (leafless, so no leaf/interval/proof change). But
        // `plan_zero_leaf_leave_inner` calls `resolve_prior_bound_work`
        // unconditionally, so it CAN carry prior-coordinate open-work SUPERSESSIONS —
        // a co-open recovery request / reservation / reserved package + a prior
        // pending Welcome — which are consumed via the shared writers at the tail
        // (own counts 0), exact-shape checked here (mirroring close/policy).
        reject_if_present("leaf_changes", effects.leaf_changes())?;
        reject_if_present("interval_changes", effects.interval_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        // reset_request_changes: KEPT fail-closed. A leavePolicy transition staling a
        // prior-bound reset request is DB-legal (reset `stale` accepts any kind), but
        // ADR-019 Erratum 01 rules only on LEAVE staling; reset staling on this arm is
        // out of scope and stays rejected pending its own ruling (the planner does not
        // emit it in the reachable zero-leaf-leave flows).
        reject_if_present("reset_request_changes", effects.reset_request_changes())?;
        // leave_request_changes (ADR-019 Erratum 01): a zeroLeafLeave (leavePolicy)
        // owns NO leave request of its own — it removes a leafless invitee via a
        // zeroLeafLeaveEntry, never a leave request. Every leave delta must therefore
        // be a Pending->Stale staling of a DIFFERENT member's predecessor-bound pending
        // leave (own leave count 0). Validate the shape here; the own-DID exclusion is
        // checked below once the leaver is resolved. The stale rows flow through
        // `write_prior_bound_staling` at the tail (own 0 + staled == total).
        for change in effects.leave_request_changes() {
            let (before, after) = match (change.before(), change.after()) {
                (Some(before), Some(after)) => (before, after),
                _ => {
                    return Err(ExecutorError::InconsistentPlan(
                        "zero-leaf leave leave-request delta must be a status transition",
                    ))
                }
            };
            if before.status() != LeaveRequestStatus::Pending
                || after.status() != LeaveRequestStatus::Stale
            {
                return Err(ExecutorError::InconsistentPlan(
                    "zero-leaf leave leave-request delta must be Pending->Stale",
                ));
            }
            // No re-binding (ruling point 4): staling never moves a request's binding.
            if before.bound_coordinate != after.bound_coordinate {
                return Err(ExecutorError::InconsistentPlan(
                    "zero-leaf leave must not re-bind a leave request",
                ));
            }
        }
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        for change in effects.recovery_request_changes() {
            if !matches!((change.before(), change.after()), (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Superseded)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "zero-leaf leave recovery request change is not a supersession",
                ));
            }
        }
        for change in effects.reservation_changes() {
            if !matches!((change.before(), change.after()), (Some(before), Some(after))
                if before.status() == ReservationStatus::Active
                    && after.status() == ReservationStatus::Released)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "zero-leaf leave reservation change is not a release",
                ));
            }
        }
        for edge in effects.package_transitions() {
            if edge.from != PackageStatus::Reserved || edge.to != PackageStatus::Available {
                return Err(ExecutorError::InconsistentPlan(
                    "zero-leaf leave package edge is not a Reserved->Available release",
                ));
            }
        }
        verify_recovery_package_bijection(effects)?;
        if effects.metadata_change().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "zero-leaf leave metadata change",
            ));
        }
        if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "zero-leaf leave revocation/welcome CAS",
            ));
        }
        // A zero-leaf leave releases (never consumes) an invitation slot, so the
        // plan carries NO invitation-quota CAS (only Creation/Policy do); the
        // deferred quota trigger recomputes from the closed participant row.
        if effects.invitation_quota_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "zero-leaf leave invitation quota CAS",
            ));
        }
        // Exactly one participant is closed (Some -> None); records are never
        // deleted, only terminalized.
        if effects.participant_changes().len() != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "zero-leaf leave must change exactly one participant",
            ));
        }
        let removed = effects
            .participant_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (Some(before), None) => Some(before),
                _ => None,
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "zero-leaf leave must close exactly one participant",
            ))?;
        // ADR-019 Erratum 01: a zeroLeafLeave stales only OTHER members' leaves. Any
        // leave delta targeting the leaver's own DID is a hard InconsistentPlan (a
        // zero-leaf leaver holds no leave request of its own).
        for change in effects.leave_request_changes() {
            if let Some(after) = change.after() {
                if after.requester().principal() == removed.principal() {
                    return Err(ExecutorError::InconsistentPlan(
                        "zero-leaf leave must not stale its own leave request",
                    ));
                }
            }
        }
        let participant_period_id = ctx
            .closing_participant_periods
            .iter()
            .find(|(device, _)| device.principal() == removed.principal())
            .map(|(_, id)| *id)
            .ok_or(ExecutorError::MissingContext(
                "closing participant period id for the zero-leaf leaver",
            ))?;

        // 1. Head CAS advances the coordinate + counter (single seq authority).
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. Advance the generation's state-version pointer (same generation).
        transition::cas_generation_state_version(
            transaction,
            &transition::GenerationStateVersionCas {
                conversation_id,
                generation,
                expected_state_version,
                successor_state_version: state_version,
            },
        )
        .await?;

        // 3. Successor generation state (leavePolicy kind, coordinate-only rebind).
        transition::insert_generation_state_row(
            transaction,
            &NewGenerationState {
                conversation_id,
                generation,
                state_version,
                group_id: coordinate.group_id().to_vec(),
                epoch,
                group_context_hash: coordinate.group_context_hash().to_vec(),
                confirmation_tag: coordinate.confirmation_tag().to_vec(),
                lifecycle: GenerationStateLifecycle::Active,
                state_kind: GenerationStateKind::LeavePolicy,
                producing_transition_id: transition_id,
                public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
                snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
                tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
                tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
                leaf_count: ctx.spine.leaf_count,
                created_at: applied_at,
            },
        )
        .await?;

        // 4. Entry (zeroLeafLeaveEntry) at the allocated seq.
        let append = build_append_entry(
            ctx,
            conversation_id,
            generation,
            state_version,
            transition_id,
        );
        delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

        // 5. Transition (leavePolicy, prior -> next, no metadata snapshot).
        transition::insert_transition_row(
            transaction,
            &NewTransition {
                transition_id,
                conversation_id,
                kind: TransitionKind::LeavePolicy,
                actor_did: ctx.actor.user_did.clone(),
                actor_device_id: ctx.actor.device_id,
                actor_key_id: ctx.actor.key_id.clone(),
                actor_auth_generation: ctx.actor.auth_generation,
                actor_role: ctx.actor.role,
                actor_device_status: ctx.actor.device_status.clone(),
                signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
                unsigned_projection_bytes: ctx.entry.unsigned_projection_bytes.clone(),
                signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
                request_digest: ctx.entry.request_digest.clone(),
                signature: ctx.entry.signature.clone(),
                coordinates: TransitionCoordinates {
                    prior: Some((expected_generation, expected_state_version)),
                    next: Some((generation, state_version)),
                    retired: None,
                    successor: None,
                },
                reset_request_id: None,
                close_transition_id: None,
                metadata_snapshot_id: None,
                entry_seq: seq_i64,
                accepted_at: applied_at,
            },
        )
        .await?;

        // 6. Close the leaver's participant period (invitation-slot release).
        transition::terminalize_participant_period(
            transaction,
            &transition::ParticipantTerminalization {
                participant_period_id,
                removing_transition_id: transition_id,
                removing_seq: seq_i64,
                removed_at: applied_at,
            },
        )
        .await?;

        // 7. Audience + events.
        let recipients = build_entry_recipients(&ctx.entry_recipients)?;
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
        let event_positions = write_events(transaction, ctx).await?;

        // Supersede prior-coordinate open work the leave retired (an open recovery
        // request / active reservation / reserved package + a prior pending Welcome)
        // AND stale any prior-bound pending LEAVE request of OTHER members (ADR-019
        // Erratum 01). A zero-leaf leave owns NONE of these families (own == default),
        // so every such delta MUST be a supersession/staling the shared writers
        // applied — reconcile rejects any that is neither. reset was rejected above
        // (count 0), so its family trivially reconciles.
        let mut superseded =
            write_prior_bound_supersessions(transaction, effects, transition_id, applied_at)
                .await?;
        superseded.welcomes = write_welcome_supersessions(transaction, ctx, effects).await?;
        let staled = write_prior_bound_staling(
            transaction,
            effects,
            transition_id,
            &ctx.entry.request_digest,
            applied_at,
        )
        .await?;
        superseded.leave_requests = staled.leave_requests;
        reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(seq_i64).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply a `closeConversation` edge: `stateVersion+1`, `lifecycle=superseded`,
    /// no successor. Closes every still-open interval with a `Terminal` proof,
    /// inserts one schedule terminal proof per historical device schedule, closes
    /// the genesis leaf, and emits the single conversation-close tombstone event.
    #[allow(clippy::too_many_arguments)]
    async fn apply_close(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        transition_id: Uuid,
        seq_i64: i64,
        successor_next_entry_seq: i64,
        generation: i64,
        state_version: i64,
        epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let hydration = plan.state();
        let coordinate = &hydration.coordinate; // retired coordinate (same crypto).
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "close needs an expected prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

        // Close is coordinate-retire + interval/leaf teardown. It carries NO own
        // recovery/welcome edge, but it DOES supersede prior-coordinate open work:
        // `plan_close_inner` calls `resolve_prior_bound_work` unconditionally, and a
        // close IS reachable while the actor's own (group-of-1 admin) or the other
        // party's (direct 1:1) leaf-recovery request is open — superseding it +
        // releasing the reservation + reactivating the package. Those deltas are
        // consumed below via the shared write_prior_bound_supersessions +
        // write_welcome_supersessions + write_prior_bound_staling + reconcile (own
        // counts 0). A close is likewise reachable while a pending reset/leave request
        // is bound to the prior coordinate — staled below (kind is `closeConversation`,
        // DB-legal for the leave `stale` edge). Families the close genuinely never
        // carries stay fail-closed.
        reject_if_present("participant_changes", effects.participant_changes())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        // Every recovery/reservation/package delta a close carries MUST be a
        // prior-bound supersession (request Open->Superseded, reservation
        // Active->Released, package Reserved->Available) — exact-shape checked here
        // (mirroring the generic-commit arm) and consumed below. `recovery_package_cas`
        // is the production-shape package witness the bijection validates, NOT a
        // rejected family.
        for change in effects.recovery_request_changes() {
            if !matches!((change.before(), change.after()), (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Superseded)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "close recovery request change is not a supersession",
                ));
            }
        }
        for change in effects.reservation_changes() {
            if !matches!((change.before(), change.after()), (Some(before), Some(after))
                if before.status() == ReservationStatus::Active
                    && after.status() == ReservationStatus::Released)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "close reservation change is not a release",
                ));
            }
        }
        for edge in effects.package_transitions() {
            if edge.from != PackageStatus::Reserved || edge.to != PackageStatus::Available {
                return Err(ExecutorError::InconsistentPlan(
                    "close package edge is not a Reserved->Available release",
                ));
            }
        }
        verify_recovery_package_bijection(effects)?;
        if effects.metadata_change().is_some() {
            return Err(ExecutorError::UnsupportedEffect("close metadata change"));
        }
        if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "close revocation/welcome CAS",
            ));
        }
        if effects.invitation_quota_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "close invitation quota CAS",
            ));
        }

        // 1. Head CAS to superseded with the exact close coordinate.
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: Some(ConversationHeadClose {
                    close_transition_id: transition_id,
                    close_generation: generation,
                    close_state_version: state_version,
                    close_seq: seq_i64,
                    closed_at: applied_at,
                }),
            },
        )
        .await?;

        // 2. Supersede the generation (points at the superseded state).
        transition::supersede_generation(
            transaction,
            &GenerationSupersede {
                conversation_id,
                generation,
                expected_state_version,
                successor_state_version: state_version,
                superseded_seq: seq_i64,
                superseded_at: applied_at,
            },
        )
        .await?;

        // 3. Superseded closeConversation generation state (same crypto edge).
        transition::insert_generation_state_row(
            transaction,
            &NewGenerationState {
                conversation_id,
                generation,
                state_version,
                group_id: coordinate.group_id().to_vec(),
                epoch,
                group_context_hash: coordinate.group_context_hash().to_vec(),
                confirmation_tag: coordinate.confirmation_tag().to_vec(),
                lifecycle: GenerationStateLifecycle::Superseded,
                state_kind: GenerationStateKind::CloseConversation,
                producing_transition_id: transition_id,
                public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
                snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
                tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
                tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
                leaf_count: ctx.spine.leaf_count,
                created_at: applied_at,
            },
        )
        .await?;

        // 4. Entry (conversationCloseEntry) at the close seq.
        let append = build_append_entry(
            ctx,
            conversation_id,
            generation,
            state_version,
            transition_id,
        );
        delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

        // 5. Transition (prior -> retired; a close transition references itself).
        transition::insert_transition_row(
            transaction,
            &NewTransition {
                transition_id,
                conversation_id,
                kind: TransitionKind::CloseConversation,
                actor_did: ctx.actor.user_did.clone(),
                actor_device_id: ctx.actor.device_id,
                actor_key_id: ctx.actor.key_id.clone(),
                actor_auth_generation: ctx.actor.auth_generation,
                actor_role: ctx.actor.role,
                actor_device_status: ctx.actor.device_status.clone(),
                signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
                unsigned_projection_bytes: ctx.entry.unsigned_projection_bytes.clone(),
                signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
                request_digest: ctx.entry.request_digest.clone(),
                signature: ctx.entry.signature.clone(),
                coordinates: TransitionCoordinates {
                    prior: Some((expected_generation, expected_state_version)),
                    next: Some((generation, state_version)),
                    retired: None,
                    successor: None,
                },
                reset_request_id: None,
                close_transition_id: Some(transition_id),
                metadata_snapshot_id: None,
                entry_seq: seq_i64,
                accepted_at: applied_at,
            },
        )
        .await?;

        // 6. Close the genesis leaf (leaf_change = Some -> None).
        for change in effects.leaf_changes() {
            let before = match (change.before(), change.after()) {
                (Some(before), None) => before,
                _ => {
                    return Err(ExecutorError::UnsupportedEffect(
                        "close leaf change is not a removal",
                    ))
                }
            };
            let leaf_period_id = closing_leaf_period(ctx, before.device())?;
            transition::close_leaf_period(
                transaction,
                &LeafClose {
                    leaf_period_id,
                    removed_state_version: state_version,
                    removed_transition_id: transition_id,
                    removed_seq: seq_i64,
                    removed_at: applied_at,
                },
            )
            .await?;
        }

        // 7. Close every still-open interval with the Terminal proof (from the plan).
        for change in effects.interval_changes() {
            let after = match (change.before(), change.after()) {
                (Some(_), Some(after)) => after,
                _ => {
                    return Err(ExecutorError::UnsupportedEffect(
                        "close interval change is not a finite close",
                    ))
                }
            };
            let end = after.end().ok_or(ExecutorError::InconsistentPlan(
                "close interval carries no end",
            ))?;
            let leaf_period_id = closing_leaf_period(ctx, after.recipient())?;
            delivery::close_application_interval(
                transaction,
                &ApplicationIntervalClose {
                    membership_interval_id: Uuid::from_bytes(*after.opening_transition_id()),
                    terminal_seq: checked_i64(end.seq())?,
                    closing_state_version: state_version,
                    closing_transition_id: Uuid::from_bytes(*end.transition_id()),
                    closing_outer_entry_fingerprint: end.outer_entry_fingerprint().to_vec(),
                    closing_kind: repo_interval_close_kind(end.kind()),
                    closing_leaf_period_id: leaf_period_id,
                    removed_at: applied_at,
                },
            )
            .await?;
        }

        // 8. One schedule terminal proof per historical device schedule.
        for change in effects.terminal_proof_changes() {
            let proof = match (change.before(), change.after()) {
                (None, Some(proof)) => proof,
                _ => {
                    return Err(ExecutorError::UnsupportedEffect(
                        "schedule proof change is not an insert",
                    ))
                }
            };
            delivery::insert_schedule_terminal_proof(
                transaction,
                &NewScheduleTerminalProof {
                    conversation_id,
                    recipient_did: device_did(proof.recipient())?,
                    recipient_device_id: device_uuid(proof.recipient()),
                    terminal_seq: seq_i64,
                    transition_id,
                    outer_entry_fingerprint: ctx.entry.outer_entry_fingerprint.clone(),
                    received_at: applied_at,
                },
            )
            .await?;
        }

        // 9. Retained scheduleTerminal audience + the conversation-close event.
        let recipients = build_entry_recipients(&ctx.entry_recipients)?;
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
        let event_positions = write_events(transaction, ctx).await?;

        // 10. Supersede prior-coordinate open work the close retired: an open
        //     leaf-recovery request (Open->Superseded) + its reservation
        //     (Active->Released) + reserved package (Reserved->Available), any prior
        //     pending welcome, and any prior-bound pending reset/leave request
        //     (Pending->Stale). The close has ZERO own recovery/welcome/reset/leave
        //     edges, so own == default and every such delta MUST be a supersession/
        //     staling the calls below applied — reconcile rejects any that is neither.
        let mut superseded =
            write_prior_bound_supersessions(transaction, effects, transition_id, applied_at)
                .await?;
        superseded.welcomes = write_welcome_supersessions(transaction, ctx, effects).await?;
        let staled = write_prior_bound_staling(
            transaction,
            effects,
            transition_id,
            &ctx.entry.request_digest,
            applied_at,
        )
        .await?;
        superseded.reset_requests = staled.reset_requests;
        superseded.leave_requests = staled.leave_requests;
        reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(seq_i64).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply a `reset request` edge: a non-mutating signed intent. It appends the
    /// request entry + the `chat.reset_requests` row + the event, and advances the
    /// seq counter — but the crypto coordinate is UNCHANGED (no generation state,
    /// no transition row, no stateVersion bump).
    #[allow(clippy::too_many_arguments)]
    async fn apply_reset_request(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        seq_i64: i64,
        successor_next_entry_seq: i64,
        generation: i64,
        state_version: i64,
        epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let hydration = plan.state();
        let coordinate = &hydration.coordinate; // unchanged coordinate.
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "reset request needs an expected prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

        // Non-mutating: only a reset-request row changes. Everything else empty.
        reject_if_present("participant_changes", effects.participant_changes())?;
        reject_if_present("leaf_changes", effects.leaf_changes())?;
        reject_if_present("interval_changes", effects.interval_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present(
            "recovery_request_changes",
            effects.recovery_request_changes(),
        )?;
        reject_if_present("reservation_changes", effects.reservation_changes())?;
        reject_if_present("leave_request_changes", effects.leave_request_changes())?;
        reject_if_present("welcome_changes", effects.welcome_changes())?;
        reject_if_present("package_transitions", effects.package_transitions())?;
        reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        if effects.metadata_change().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "reset request metadata change",
            ));
        }
        // Complete defensive dispatch (E2b-4 review): a resetRequest plan carries
        // none of these; production `into_persistence_plan` forces them empty/None.
        // Guarding them keeps this path in the same no-silent-skip class as the rest.
        if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "reset request revocation/welcome CAS",
            ));
        }
        if effects.invitation_quota_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "reset request invitation quota CAS",
            ));
        }
        let row = ctx
            .reset_request_row
            .as_ref()
            .ok_or(ExecutorError::MissingContext("reset request row content"))?;
        // Exactly one new pending reset request in the delta.
        if effects.reset_request_changes().len() != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "reset request must add exactly one pending request",
            ));
        }

        // 1. Head CAS: advance the seq counter, coordinate UNCHANGED.
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. The request entry (resetRequestEntry carries no transition_id).
        let mut append =
            build_append_entry(ctx, conversation_id, generation, state_version, Uuid::nil());
        append.generation = None;
        append.state_version = None;
        append.transition_id = None;
        delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

        // 3. The pending reset_requests row (signed content from ctx; bound
        //    coordinate from the unchanged current coordinate).
        transition::insert_reset_request(
            transaction,
            &transition::NewResetRequest {
                reset_request_id: row.reset_request_id,
                conversation_id,
                requester_did: ctx.actor.user_did.clone(),
                requester_device_id: ctx.actor.device_id,
                requester_key_id: ctx.actor.key_id.clone(),
                requester_auth_generation: ctx.actor.auth_generation,
                prior_generation: generation,
                prior_state_version: state_version,
                prior_group_id: coordinate.group_id().to_vec(),
                prior_epoch: epoch,
                prior_group_context_hash: coordinate.group_context_hash().to_vec(),
                prior_confirmation_tag: coordinate.confirmation_tag().to_vec(),
                reason: row.reason.clone(),
                signed_request_bytes: row.signed_request_bytes.clone(),
                signing_transcript_bytes: row.signing_transcript_bytes.clone(),
                request_digest: row.request_digest.clone(),
                signature: row.signature.clone(),
                received_at: applied_at,
                expires_at: row.expires_at,
            },
        )
        .await?;

        // 4. Audience + event.
        let recipients = build_entry_recipients(&ctx.entry_recipients)?;
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
        let event_positions = write_events(transaction, ctx).await?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(seq_i64).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply an entry-bearing `leaveRequest` control op. Non-mutating: the head
    /// CAS advances ONLY the seq counter (the `(generation,state_version)`
    /// coordinate is untouched), it appends the `leaveRequestEntry`, and it inserts
    /// a pending 24h-consent `leave_requests` row bound to the current coordinate.
    /// The row's signed material is the entry's — `assert_leave_request_mapping`
    /// requires the row and its `leaveRequestEntry` to carry byte-equal
    /// `signed_request_bytes`/`request_digest`/`signature`/`received_at` — so no
    /// side ctx row is needed; the DB `expires_at = received_at + 24h`. Mirrors
    /// `apply_reset_request`.
    #[allow(clippy::too_many_arguments)]
    async fn apply_leave_request(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        seq_i64: i64,
        successor_next_entry_seq: i64,
        generation: i64,
        state_version: i64,
        epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let hydration = plan.state();
        let coordinate = &hydration.coordinate; // unchanged coordinate.
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "leave request needs an expected prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

        // Non-mutating: only a leave-request row changes. Everything else empty.
        reject_if_present("participant_changes", effects.participant_changes())?;
        reject_if_present("leaf_changes", effects.leaf_changes())?;
        reject_if_present("interval_changes", effects.interval_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present(
            "recovery_request_changes",
            effects.recovery_request_changes(),
        )?;
        reject_if_present("reservation_changes", effects.reservation_changes())?;
        reject_if_present("reset_request_changes", effects.reset_request_changes())?;
        reject_if_present("welcome_changes", effects.welcome_changes())?;
        reject_if_present("package_transitions", effects.package_transitions())?;
        reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        if effects.metadata_change().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "leave request metadata change",
            ));
        }
        if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "leave request revocation/welcome CAS",
            ));
        }
        if effects.invitation_quota_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "leave request invitation quota CAS",
            ));
        }
        // Exactly one new pending leave request in the delta.
        if effects.leave_request_changes().len() != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "leave request must change exactly one request",
            ));
        }
        let request = effects
            .leave_request_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (None, Some(after)) if after.status() == LeaveRequestStatus::Pending => Some(after),
                _ => None,
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "leave request must open exactly one pending request",
            ))?;
        let leave_request_id = Uuid::from_bytes(request.request_id);

        // 1. Head CAS: advance the seq counter, coordinate UNCHANGED.
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. The request entry (leaveRequestEntry carries no transition_id).
        let mut append =
            build_append_entry(ctx, conversation_id, generation, state_version, Uuid::nil());
        append.generation = None;
        append.state_version = None;
        append.transition_id = None;
        delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

        // 3. The pending leave_requests row. Signed material is the entry's (the
        //    entry<->row mapping trigger requires byte-equality); the bound
        //    coordinate is the unchanged current coordinate; `expires_at` is the
        //    DB-required `received_at + 24h`.
        transition::insert_leave_request(
            transaction,
            &NewLeaveRequest {
                leave_request_id,
                conversation_id,
                requester_did: ctx.actor.user_did.clone(),
                requester_device_id: ctx.actor.device_id,
                requester_key_id: ctx.actor.key_id.clone(),
                requester_auth_generation: ctx.actor.auth_generation,
                prior_generation: generation,
                prior_state_version: state_version,
                prior_group_id: coordinate.group_id().to_vec(),
                prior_epoch: epoch,
                prior_group_context_hash: coordinate.group_context_hash().to_vec(),
                prior_confirmation_tag: coordinate.confirmation_tag().to_vec(),
                signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
                signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
                request_digest: ctx.entry.request_digest.clone(),
                signature: ctx.entry.signature.clone(),
                received_at: applied_at,
                expires_at: applied_at + chrono::Duration::hours(24),
            },
        )
        .await?;

        // 4. Audience + event.
        let recipients = build_entry_recipients(&ctx.entry_recipients)?;
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
        let event_positions = write_events(transaction, ctx).await?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(seq_i64).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply an entry-bearing `leaveCancellation` control op. Non-mutating (the
    /// requester withdraws their own pending leave consent): the head CAS advances
    /// only the seq counter, it appends the `leaveCancellationEntry`, and it
    /// terminalizes the pending `leave_requests` row as `cancelled`. The cancelled
    /// row's `terminal_request_digest` == the cancellation entry's `request_digest`
    /// and `terminal_at` == its `received_at` (`= applied_at`), exactly as the
    /// cancelled-status arms of `assert_leave_request_mapping` /
    /// `assert_control_request_entry` cross-check. No transition (non-mutating).
    #[allow(clippy::too_many_arguments)]
    async fn apply_leave_cancellation(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        seq_i64: i64,
        successor_next_entry_seq: i64,
        generation: i64,
        state_version: i64,
        _epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "leave cancellation needs an expected prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

        // Non-mutating: only a leave-request row is terminalized. Everything else empty.
        reject_if_present("participant_changes", effects.participant_changes())?;
        reject_if_present("leaf_changes", effects.leaf_changes())?;
        reject_if_present("interval_changes", effects.interval_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present(
            "recovery_request_changes",
            effects.recovery_request_changes(),
        )?;
        reject_if_present("reservation_changes", effects.reservation_changes())?;
        reject_if_present("reset_request_changes", effects.reset_request_changes())?;
        reject_if_present("welcome_changes", effects.welcome_changes())?;
        reject_if_present("package_transitions", effects.package_transitions())?;
        reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        if effects.metadata_change().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "leave cancellation metadata change",
            ));
        }
        if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "leave cancellation revocation/welcome CAS",
            ));
        }
        if effects.invitation_quota_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "leave cancellation invitation quota CAS",
            ));
        }
        // Exactly one pending -> cancelled leave request in the delta.
        if effects.leave_request_changes().len() != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "leave cancellation must change exactly one request",
            ));
        }
        let cancelled = effects
            .leave_request_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (Some(before), Some(after))
                    if before.status() == LeaveRequestStatus::Pending
                        && after.status() == LeaveRequestStatus::Cancelled =>
                {
                    Some(after)
                }
                _ => None,
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "leave cancellation must cancel exactly one pending request",
            ))?;
        let leave_request_id = Uuid::from_bytes(cancelled.request_id);

        // 1. Head CAS: advance the seq counter, coordinate UNCHANGED.
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. The cancellation entry (leaveCancellationEntry carries no transition_id).
        let mut append =
            build_append_entry(ctx, conversation_id, generation, state_version, Uuid::nil());
        append.generation = None;
        append.state_version = None;
        append.transition_id = None;
        delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

        // 3. Terminalize the pending request as `cancelled`, bound to the
        //    cancellation entry's digest + instant (the mapping cross-check).
        transition::terminalize_leave_request(
            transaction,
            leave_request_id,
            &LeaveRequestTermination::Cancelled {
                terminal_request_digest: ctx.entry.request_digest.clone(),
                terminal_at: applied_at,
            },
        )
        .await?;

        // 4. Audience + event.
        let recipients = build_entry_recipients(&ctx.entry_recipients)?;
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
        let event_positions = write_events(transaction, ctx).await?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(seq_i64).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply a `resetActivation` edge: retire the old generation and activate a
    /// fresh one. Retired gen_state (`stateVersion+1`, superseded) + a new
    /// generation at `generation+1` (epoch 0, fresh group/hash/tag) + successor
    /// gen_state (sv 0, active) + head CAS to the successor pointer; close every
    /// still-open old interval at the reset seq and open ONLY the activator's
    /// successor interval at the same seq (touching `Reset -> Reset`); close every
    /// old-generation leaf and install the activator's new genesis leaf;
    /// terminalize the pending reset request as consumed.
    #[allow(clippy::too_many_arguments)]
    async fn apply_reset_activation(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        transition_id: Uuid,
        seq_i64: i64,
        successor_next_entry_seq: i64,
        generation: i64,
        state_version: i64,
        epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let hydration = plan.state();
        let coordinate = &hydration.coordinate; // successor coordinate.
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "reset activation needs a prior",
            ))?;
        let retired = plan
            .retired_coordinate()
            .ok_or(ExecutorError::InconsistentPlan(
                "reset activation needs a retired coordinate",
            ))?;
        let prior_generation = checked_i64(prior.generation())?;
        let prior_state_version = checked_i64(prior.state_version())?;
        let retired_generation = checked_i64(retired.generation())?;
        let retired_state_version = checked_i64(retired.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

        // Reset activation carries no participant change and no OWN recovery edge.
        // Its ONE own request edge is the named reset request it CONSUMES
        // (Pending->Consumed, step 11 below). It DOES supersede prior-coordinate open
        // work: a retired generation's pending welcome / open recovery request /
        // active reservation / reserved package are all resolved to superseded/
        // released by the plan and consumed below via write_prior_bound_supersessions
        // + write_welcome_supersessions + reconcile (own counts 0 for those). It also
        // stales a prior-bound pending LEAVE request the retirement retired
        // (Pending->Stale; kind is `resetActivation`, DB-legal for the leave `stale`
        // edge — the one-pending index means no SECOND reset request can be staled).
        // Families the reset genuinely never carries stay fail-closed.
        reject_if_present("participant_changes", effects.participant_changes())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        // Every recovery/reservation/package delta a reset carries MUST be a
        // prior-bound supersession (mirroring the generic-commit / close arms):
        // request Open->Superseded, reservation Active->Released, package
        // Reserved->Available. `recovery_package_cas` is the production-shape witness
        // the bijection validates, NOT a rejected family — so a reset that retires a
        // generation with an OPEN recovery request (reserved package) is composed,
        // not hard-errored.
        for change in effects.recovery_request_changes() {
            if !matches!((change.before(), change.after()), (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Superseded)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "reset recovery request change is not a supersession",
                ));
            }
        }
        for change in effects.reservation_changes() {
            if !matches!((change.before(), change.after()), (Some(before), Some(after))
                if before.status() == ReservationStatus::Active
                    && after.status() == ReservationStatus::Released)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "reset reservation change is not a release",
                ));
            }
        }
        for edge in effects.package_transitions() {
            if edge.from != PackageStatus::Reserved || edge.to != PackageStatus::Available {
                return Err(ExecutorError::InconsistentPlan(
                    "reset package edge is not a Reserved->Available release",
                ));
            }
        }
        verify_recovery_package_bijection(effects)?;
        if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "reset revocation/welcome CAS",
            ));
        }
        if effects.metadata_change().is_none() {
            return Err(ExecutorError::InconsistentPlan(
                "reset activation carries no metadata",
            ));
        }
        if effects.invitation_quota_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "reset invitation quota CAS",
            ));
        }
        // Exactly one pending reset request is consumed.
        let consumed_request = effects
            .reset_request_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (Some(_), Some(after)) => Some(after),
                _ => None,
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "reset activation consumes no pending reset request",
            ))?;
        let reset_request_id = Uuid::from_bytes(consumed_request.request_id);
        let metadata = effects
            .metadata_change()
            .and_then(StateChange::after)
            .ok_or(ExecutorError::InconsistentPlan(
                "reset activation carries no metadata",
            ))?;
        let author_cols = ctx
            .metadata_author
            .as_ref()
            .ok_or(ExecutorError::MissingContext(
                "reset metadata author columns",
            ))?;

        // 1. Head CAS to the successor pointer (generation+1, stateVersion 0).
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation: prior_generation,
                expected_state_version: prior_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. Supersede the old generation (points at the retired state).
        transition::supersede_generation(
            transaction,
            &GenerationSupersede {
                conversation_id,
                generation: prior_generation,
                expected_state_version: prior_state_version,
                successor_state_version: retired_state_version,
                superseded_seq: seq_i64,
                superseded_at: applied_at,
            },
        )
        .await?;

        // 3. Retired generation state (old crypto, superseded, resetRetirement).
        transition::insert_generation_state_row(
            transaction,
            &NewGenerationState {
                conversation_id,
                generation: retired_generation,
                state_version: retired_state_version,
                group_id: prior.group_id().to_vec(),
                epoch: checked_i64(prior.epoch())?,
                group_context_hash: prior.group_context_hash().to_vec(),
                confirmation_tag: prior.confirmation_tag().to_vec(),
                lifecycle: GenerationStateLifecycle::Superseded,
                state_kind: GenerationStateKind::ResetRetirement,
                producing_transition_id: transition_id,
                public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
                snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
                tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
                tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
                leaf_count: ctx.spine.leaf_count,
                created_at: applied_at,
            },
        )
        .await?;

        // 4. Fresh successor generation (epoch 0, fresh group id).
        transition::insert_generation(
            transaction,
            &NewGeneration {
                conversation_id,
                generation,
                group_id: coordinate.group_id().to_vec(),
                genesis_group_info_bytes: ctx.spine.genesis_group_info_bytes.clone(),
                genesis_group_info_sha256: ctx.spine.genesis_group_info_sha256.clone(),
                current_state_version: state_version,
                activated_seq: seq_i64,
                activated_at: applied_at,
            },
        )
        .await?;

        // 5. Successor generation state (fresh crypto, active, resetSuccessor).
        transition::insert_generation_state_row(
            transaction,
            &NewGenerationState {
                conversation_id,
                generation,
                state_version,
                group_id: coordinate.group_id().to_vec(),
                epoch,
                group_context_hash: coordinate.group_context_hash().to_vec(),
                confirmation_tag: coordinate.confirmation_tag().to_vec(),
                lifecycle: GenerationStateLifecycle::Active,
                state_kind: GenerationStateKind::ResetSuccessor,
                producing_transition_id: transition_id,
                public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
                snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
                tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
                tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
                leaf_count: ctx.spine.leaf_count,
                created_at: applied_at,
            },
        )
        .await?;

        // 6. Entry (resetActivationEntry).
        let append = build_append_entry(
            ctx,
            conversation_id,
            generation,
            state_version,
            transition_id,
        );
        delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

        // 7. Transition (prior -> retired + successor; carries the reset request).
        transition::insert_transition_row(
            transaction,
            &NewTransition {
                transition_id,
                conversation_id,
                kind: TransitionKind::ResetActivation,
                actor_did: ctx.actor.user_did.clone(),
                actor_device_id: ctx.actor.device_id,
                actor_key_id: ctx.actor.key_id.clone(),
                actor_auth_generation: ctx.actor.auth_generation,
                actor_role: ctx.actor.role,
                actor_device_status: ctx.actor.device_status.clone(),
                signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
                unsigned_projection_bytes: ctx.entry.unsigned_projection_bytes.clone(),
                signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
                request_digest: ctx.entry.request_digest.clone(),
                signature: ctx.entry.signature.clone(),
                coordinates: TransitionCoordinates {
                    // resetActivation: next == successor (both point at the fresh
                    // generation), retired == (prior_gen, prior_sv + 1).
                    prior: Some((prior_generation, prior_state_version)),
                    next: Some((generation, state_version)),
                    retired: Some((retired_generation, retired_state_version)),
                    successor: Some((generation, state_version)),
                },
                reset_request_id: Some(reset_request_id),
                close_transition_id: None,
                metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
                entry_seq: seq_i64,
                accepted_at: applied_at,
            },
        )
        .await?;

        // 8. Successor metadata snapshot (self-origin, version from the binding).
        write_creation_metadata_snapshot(
            transaction,
            metadata,
            author_cols,
            &ctx.actor,
            conversation_id,
            generation,
            state_version,
            epoch,
            &coordinate.group_id().to_vec(),
            &coordinate.group_context_hash().to_vec(),
            &coordinate.confirmation_tag().to_vec(),
            transition_id,
            seq_i64,
            applied_at,
        )
        .await?;

        // 9. Close every old-generation leaf (facade-supplied) and install the
        //    successor genesis leaf(s). `leaf_changes` is a same-content diff that
        //    under-reports the generation change (the activator's new leaf has the
        //    same credential/index/keys as its old leaf), so the reset leaf ops are
        //    driven authoritatively by ctx.closing_leaf_periods + the successor
        //    hydration leaves rather than by the delta.
        for (device, old_leaf) in &ctx.closing_leaf_periods {
            let _ = device;
            transition::close_leaf_period(
                transaction,
                &LeafClose {
                    leaf_period_id: *old_leaf,
                    removed_state_version: retired_state_version,
                    removed_transition_id: transition_id,
                    removed_seq: seq_i64,
                    removed_at: applied_at,
                },
            )
            .await?;
        }
        for (index, row) in hydration.leaves.iter().enumerate() {
            let leaf_period_id = *ctx
                .leaf_period_ids
                .get(index)
                .ok_or(ExecutorError::MissingContext("successor leaf period id"))?;
            write_successor_leaf(
                transaction,
                ctx,
                hydration,
                row,
                leaf_period_id,
                conversation_id,
                generation,
                transition_id,
                state_version,
                seq_i64,
                applied_at,
            )
            .await?;
        }

        // 10. Close old open intervals (Reset), open the activator's new one (Reset).
        for change in effects.interval_changes() {
            match (change.before(), change.after()) {
                (Some(_), Some(after)) => {
                    let end = after.end().ok_or(ExecutorError::InconsistentPlan(
                        "reset closed interval has no end",
                    ))?;
                    let leaf = closing_leaf_period(ctx, after.recipient())?;
                    delivery::close_application_interval(
                        transaction,
                        &ApplicationIntervalClose {
                            membership_interval_id: Uuid::from_bytes(
                                *after.opening_transition_id(),
                            ),
                            terminal_seq: checked_i64(end.seq())?,
                            closing_state_version: retired_state_version,
                            closing_transition_id: Uuid::from_bytes(*end.transition_id()),
                            closing_outer_entry_fingerprint: end.outer_entry_fingerprint().to_vec(),
                            closing_kind: repo_interval_close_kind(end.kind()),
                            closing_leaf_period_id: leaf,
                            removed_at: applied_at,
                        },
                    )
                    .await?;
                }
                (None, Some(after)) => {
                    let opening_context = after.opening_context();
                    let opening_leaf_period_id =
                        *ctx.leaf_period_ids
                            .first()
                            .ok_or(ExecutorError::MissingContext(
                                "successor interval leaf period",
                            ))?;
                    delivery::insert_application_interval(
                        transaction,
                        &NewApplicationInterval {
                            membership_interval_id: Uuid::from_bytes(
                                *after.opening_transition_id(),
                            ),
                            conversation_id,
                            generation: checked_i64(opening_context.generation())?,
                            recipient_did: device_did(after.recipient())?,
                            recipient_device_id: device_uuid(after.recipient()),
                            start_seq: checked_i64(after.opening_seq())?,
                            opening_kind: IntervalOpeningKind::Reset,
                            opening_transition_id: Uuid::from_bytes(*after.opening_transition_id()),
                            opening_outer_entry_fingerprint: after
                                .opening_outer_entry_fingerprint()
                                .to_vec(),
                            opening_state_version: checked_i64(opening_context.state_version())?,
                            opening_group_id: opening_context.group_id().to_vec(),
                            opening_epoch: checked_i64(opening_context.epoch())?,
                            opening_group_context_hash: opening_context
                                .group_context_hash()
                                .to_vec(),
                            opening_confirmation_tag: opening_context.confirmation_tag().to_vec(),
                            opening_leaf_period_id,
                            created_at: applied_at,
                        },
                    )
                    .await?;
                }
                _ => {
                    return Err(ExecutorError::UnsupportedEffect(
                        "reset interval change shape",
                    ))
                }
            }
        }

        // 11. Terminalize the pending reset request as consumed.
        transition::terminalize_reset_request(
            transaction,
            reset_request_id,
            &ResetRequestTermination::Consumed {
                terminal_transition_id: transition_id,
                terminal_at: applied_at,
            },
        )
        .await?;

        // 12. Audience + event.
        let recipients = build_entry_recipients(&ctx.entry_recipients)?;
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
        let event_positions = write_events(transaction, ctx).await?;

        // 13. Supersede prior-coordinate open work the reset retired: the retired
        //     generation's pending welcome(s) + any open recovery request / active
        //     reservation / reserved package bound to the prior coordinate, and stale
        //     any prior-bound pending LEAVE request. The reset has ZERO own recovery/
        //     welcome/leave edges (its ONE own request edge is the reset request
        //     CONSUMED in step 11, counted as own below), so every recovery/welcome/
        //     leave delta MUST be a supersession/staling the calls below applied —
        //     reconcile rejects any that is neither (silent-drop guard). The reset
        //     loop in write_prior_bound_staling skips the own Pending->Consumed edge.
        let mut superseded =
            write_prior_bound_supersessions(transaction, effects, transition_id, applied_at)
                .await?;
        superseded.welcomes = write_welcome_supersessions(transaction, ctx, effects).await?;
        let staled = write_prior_bound_staling(
            transaction,
            effects,
            transition_id,
            &ctx.entry.request_digest,
            applied_at,
        )
        .await?;
        superseded.reset_requests = staled.reset_requests;
        superseded.leave_requests = staled.leave_requests;
        reconcile_coordinate_change_families(
            effects,
            &FamilyCounts {
                reset_requests: 1,
                ..FamilyCounts::default()
            },
            &superseded,
        )?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(seq_i64).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Apply an `acceptConversation` edge: promote a pending invitee to active and
    /// atomically open the `add` leaf-recovery request + reservation bound to the
    /// NEXT coordinate, reserving the acceptor's key package. `stateVersion+1`,
    /// same crypto edge, no metadata / leaf / interval change.
    #[allow(clippy::too_many_arguments)]
    async fn apply_acceptance(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        transition_id: Uuid,
        seq_i64: i64,
        successor_next_entry_seq: i64,
        generation: i64,
        state_version: i64,
        epoch: i64,
    ) -> Result<AppliedTransition, ExecutorError> {
        let effects = plan.effects();
        let hydration = plan.state();
        let coordinate = &hydration.coordinate; // next coordinate (same crypto, sv+1).
        let applied_at = ctx.applied_at;
        let head = effects
            .head_cas()
            .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
        let expected_prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "acceptance needs an expected prior",
            ))?;
        let expected_generation = checked_i64(expected_prior.generation())?;
        let expected_state_version = checked_i64(expected_prior.state_version())?;
        let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

        // Acceptance OWNS: one pending->active participant, one new open recovery
        // request (None->Open), one new active reservation (None->Active), one
        // Available->Reserved package transition. It ALSO calls
        // `resolve_prior_bound_work` (via `plan_accept_conversation_inner`), so it CAN
        // carry (a legal interleaving) prior-coordinate open-work SUPERSESSIONS — a
        // DIFFERENT member's open recovery request (Open->Superseded) + reservation
        // (Active->Released) + reserved package (Reserved->Available), a prior pending
        // Welcome (Pending->Superseded), AND a prior-bound pending reset/leave request
        // (Pending->Stale). The own vs superseded partition is proven by the own-counts
        // below + the reconciliation; acceptance owns NO reset/leave edge (own 0 for
        // both). The `acceptConversation` kind is DB-LEGAL as the terminal authority
        // for both stale edges — reset staling has no kind restriction, and
        // `assert_leave_request_mapping` forbids only `leaveCommit`/`leavePolicy` (the
        // deferred Concerns 1/3 wall applies to zero-leaf-leave + leave-fulfillment
        // ONLY, not acceptance). So reset/leave staling is wired here exactly like
        // apply_policy. Every family the acceptance never carries is a hard error.
        reject_if_present("leaf_changes", effects.leaf_changes())?;
        reject_if_present("interval_changes", effects.interval_changes())?;
        reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
        reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
        if effects.metadata_change().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "acceptance metadata change",
            ));
        }
        if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "acceptance revocation/welcome CAS",
            ));
        }
        if effects.invitation_quota_cas().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "acceptance invitation quota CAS",
            ));
        }
        // Exactly one pending->active participant.
        let participant_change = {
            let changes = effects.participant_changes();
            if changes.len() != 1 {
                return Err(ExecutorError::InconsistentPlan(
                    "acceptance must change exactly one participant",
                ));
            }
            match (changes[0].before(), changes[0].after()) {
                (Some(before), Some(after))
                    if before.status() == ParticipantStatus::Pending
                        && after.status() == ParticipantStatus::Active =>
                {
                    after
                }
                _ => {
                    return Err(ExecutorError::UnsupportedEffect(
                        "acceptance participant change is not pending->active",
                    ))
                }
            }
        };
        // Exactly one new open recovery request + one new active reservation +
        // one package transition (Available->Reserved).
        let recovery = effects
            .recovery_request_changes()
            .iter()
            .find_map(|change| match (change.before(), change.after()) {
                (None, Some(after)) => Some(after),
                _ => None,
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "acceptance adds no open recovery request",
            ))?;
        // Exactly ONE own edge per family (None->Open recovery, None->Active
        // reservation, Available->Reserved package). Any OTHER recovery/reservation/
        // package delta must be a prior-bound supersession (Open->Superseded /
        // Active->Released / Reserved->Available), consumed by
        // write_prior_bound_supersessions and proven by the tail reconciliation.
        let own_open = effects
            .recovery_request_changes()
            .iter()
            .filter(|change| matches!((change.before(), change.after()), (None, Some(_))))
            .count();
        let own_reserved = effects
            .reservation_changes()
            .iter()
            .filter(|change| {
                matches!((change.before(), change.after()), (None, Some(a))
                    if a.status() == ReservationStatus::Active)
            })
            .count();
        let own_package = effects
            .package_transitions()
            .iter()
            .filter(|edge| {
                edge.from == PackageStatus::Available && edge.to == PackageStatus::Reserved
            })
            .count();
        if own_open != 1 || own_reserved != 1 || own_package != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "acceptance must add exactly one own recovery request + reservation + package edge",
            ));
        }
        // Load-bearing recovery-package CAS bijection (over ALL edges) + the OWN
        // package edge's driven-ref + direction; any prior-bound Reserved->Available
        // supersession edges are validated by write_prior_bound_supersessions.
        verify_recovery_package_consistency(
            effects,
            recovery.key_package_ref(),
            PackageStatus::Available,
            PackageStatus::Reserved,
        )?;

        // 1. Head CAS advances the coordinate + counter (sv+1, same generation).
        transition::cas_conversation_head(
            transaction,
            &transition::ConversationHeadCas {
                conversation_id,
                expected_generation,
                expected_state_version,
                expected_next_entry_seq,
                successor_generation: generation,
                successor_state_version: state_version,
                successor_next_entry_seq,
                close: None,
            },
        )
        .await?;

        // 2. Advance the generation's state-version pointer (same generation).
        transition::cas_generation_state_version(
            transaction,
            &transition::GenerationStateVersionCas {
                conversation_id,
                generation,
                expected_state_version,
                successor_state_version: state_version,
            },
        )
        .await?;

        // 3. Successor generation state (acceptConversation, identical crypto edge).
        transition::insert_generation_state_row(
            transaction,
            &NewGenerationState {
                conversation_id,
                generation,
                state_version,
                group_id: coordinate.group_id().to_vec(),
                epoch,
                group_context_hash: coordinate.group_context_hash().to_vec(),
                confirmation_tag: coordinate.confirmation_tag().to_vec(),
                lifecycle: GenerationStateLifecycle::Active,
                state_kind: GenerationStateKind::AcceptConversation,
                producing_transition_id: transition_id,
                public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
                snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
                tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
                tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
                leaf_count: ctx.spine.leaf_count,
                created_at: applied_at,
            },
        )
        .await?;

        // 4. Entry (participantAcceptanceEntry) at the allocated seq.
        let append = build_append_entry(
            ctx,
            conversation_id,
            generation,
            state_version,
            transition_id,
        );
        delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

        // 5. Transition (prior -> next).
        transition::insert_transition_row(
            transaction,
            &NewTransition {
                transition_id,
                conversation_id,
                kind: TransitionKind::AcceptConversation,
                actor_did: ctx.actor.user_did.clone(),
                actor_device_id: ctx.actor.device_id,
                actor_key_id: ctx.actor.key_id.clone(),
                actor_auth_generation: ctx.actor.auth_generation,
                actor_role: ctx.actor.role,
                actor_device_status: ctx.actor.device_status.clone(),
                signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
                unsigned_projection_bytes: ctx.entry.unsigned_projection_bytes.clone(),
                signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
                request_digest: ctx.entry.request_digest.clone(),
                signature: ctx.entry.signature.clone(),
                coordinates: TransitionCoordinates {
                    prior: Some((expected_generation, expected_state_version)),
                    next: Some((generation, state_version)),
                    retired: None,
                    successor: None,
                },
                reset_request_id: None,
                close_transition_id: None,
                metadata_snapshot_id: None,
                entry_seq: seq_i64,
                accepted_at: applied_at,
            },
        )
        .await?;

        // 6. Promote the pending participant to active with acceptance provenance.
        let open = ctx
            .recovery_open
            .as_ref()
            .ok_or(ExecutorError::MissingContext("recovery open context"))?;
        let participant_period_id =
            open.participant_period_id
                .ok_or(ExecutorError::MissingContext(
                    "acceptance participant period id",
                ))?;
        transition::cas_participant_pending_to_active(
            transaction,
            &ParticipantAcceptanceCas {
                participant_period_id,
                conversation_id,
                user_did: principal_did(participant_change.principal())?,
                acceptance: ParticipantAcceptance {
                    acceptance_transition_id: transition_id,
                    acceptance_entry_id: ctx.entry.entry_id,
                    accepted_at: applied_at,
                },
            },
        )
        .await?;

        // 7-9. The atomic recovery open (request + reservation + package reserve),
        //      bound to the NEXT coordinate; requester = recipient = the acceptor.
        write_recovery_open(transaction, ctx, recovery, conversation_id, applied_at).await?;

        // 10. Audience + events.
        let recipients = build_entry_recipients(&ctx.entry_recipients)?;
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
        let event_positions = write_events(transaction, ctx).await?;

        // 11. Supersede any prior-coordinate open work a DIFFERENT member left bound
        //     to the retired coordinate (Open->Superseded recovery / Active->Released
        //     reservation / Reserved->Available package + Pending->Superseded welcome).
        //     Acceptance's OWN edges are the None->Open recovery / None->Active
        //     reservation / Available->Reserved package applied by write_recovery_open
        //     above (own counts {1,1,1}); write_prior_bound_supersessions SKIPS those
        //     (they are not the supersession shape), so it consumes ONLY the other
        //     member's work, and reconcile proves own + superseded == total.
        let mut superseded =
            write_prior_bound_supersessions(transaction, effects, transition_id, applied_at)
                .await?;
        superseded.welcomes = write_welcome_supersessions(transaction, ctx, effects).await?;
        // Stale any prior-bound pending reset/leave request the acceptance retired
        // (own 0 — acceptance creates/consumes neither; kind `acceptConversation` is
        // DB-legal for both stale edges), exactly like apply_policy.
        let staled = write_prior_bound_staling(
            transaction,
            effects,
            transition_id,
            &ctx.entry.request_digest,
            applied_at,
        )
        .await?;
        superseded.reset_requests = staled.reset_requests;
        superseded.leave_requests = staled.leave_requests;
        reconcile_coordinate_change_families(
            effects,
            &FamilyCounts {
                requests: 1,
                reservations: 1,
                packages: 1,
                welcomes: 0,
                reset_requests: 0,
                leave_requests: 0,
            },
            &superseded,
        )?;

        Ok(AppliedTransition {
            allocated_seq: u64::try_from(seq_i64).unwrap(),
            entry_id: ctx.entry.entry_id,
            event_positions,
            successor_coordinate: plan.successor_coordinate().copied(),
        })
    }

    /// Open a leaf-recovery request + its paired reservation and reserve the
    /// requester's key package (Available -> Reserved), all bound to
    /// `recovery.bound_coordinate()`. Shared by the acceptance edge (source
    /// `acceptConversation`, kind `add`, bound to the successor) and the
    /// leaf-recovery request edge (source `requestLeafRecovery`, `add`/`replace`,
    /// bound to the current coordinate). The requester and recipient are the same
    /// device — the transition/request actor (`ctx.actor`). Timestamps are DB-clock:
    /// `created_at == requested_at == applied_at` and
    /// `expires_at == LEAST(applied_at + 5 min, package.not_after)`, exactly what
    /// `assert_recovery_fulfillment_mapping` cross-checks.
    async fn write_recovery_open(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &ExecutionContext,
        recovery: &super::RecoveryRequest,
        conversation_id: Uuid,
        applied_at: DateTime<Utc>,
    ) -> Result<(), ExecutorError> {
        let open = ctx
            .recovery_open
            .as_ref()
            .ok_or(ExecutorError::MissingContext("recovery open context"))?;
        let bound = recovery.bound_coordinate();
        let generation = checked_i64(bound.generation())?;
        let bound_state_version = checked_i64(bound.state_version())?;
        let bound_epoch = checked_i64(bound.epoch())?;
        let requested_at = applied_at;
        let expires_at = (applied_at + chrono::Duration::minutes(5)).min(open.package_not_after);
        let recovery_request_id = Uuid::from_bytes(*recovery.request_id());
        let key_package_ref = recovery.key_package_ref().to_vec();
        let recovery_kind = match recovery.kind() {
            LeafRecoveryKind::Add => RepoLeafRecoveryKind::Add,
            LeafRecoveryKind::Replace => RepoLeafRecoveryKind::Replace {
                replaced_leaf_period_id: open.replaced_leaf_period_id.ok_or(
                    ExecutorError::MissingContext("replace request replaced leaf period id"),
                )?,
            },
        };
        let source = match recovery.source() {
            RecoverySource::Acceptance => LeafRecoverySource::AcceptConversation,
            RecoverySource::Request => LeafRecoverySource::RequestLeafRecovery,
        };
        transition::insert_leaf_recovery_request(
            transaction,
            &NewLeafRecoveryRequest {
                recovery_request_id,
                conversation_id,
                generation,
                requester_did: ctx.actor.user_did.clone(),
                requester_device_id: ctx.actor.device_id,
                requester_key_id: ctx.actor.key_id.clone(),
                requester_auth_generation: ctx.actor.auth_generation,
                recovery_kind,
                source,
                bound_state_version,
                bound_group_id: bound.group_id().to_vec(),
                bound_epoch,
                bound_group_context_hash: bound.group_context_hash().to_vec(),
                bound_confirmation_tag: bound.confirmation_tag().to_vec(),
                reservation_request_id: recovery_request_id,
                signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
                signing_transcript_bytes: ctx.entry.signing_transcript_bytes.clone(),
                request_digest: ctx.entry.request_digest.clone(),
                signature: ctx.entry.signature.clone(),
                requested_at,
                expires_at,
            },
        )
        .await?;
        transition::insert_reservation(
            transaction,
            &NewReservation {
                recovery_request_id,
                key_package_ref: key_package_ref.clone(),
                conversation_id,
                generation,
                requester_did: ctx.actor.user_did.clone(),
                requester_device_id: ctx.actor.device_id,
                requester_key_id: ctx.actor.key_id.clone(),
                requester_auth_generation: ctx.actor.auth_generation,
                recipient_did: ctx.actor.user_did.clone(),
                recipient_device_id: ctx.actor.device_id,
                bound_state_version,
                bound_group_id: bound.group_id().to_vec(),
                bound_epoch,
                bound_group_context_hash: bound.group_context_hash().to_vec(),
                bound_confirmation_tag: bound.confirmation_tag().to_vec(),
                expires_at,
                created_at: requested_at,
            },
        )
        .await?;
        transition::cas_key_package_status(
            transaction,
            &key_package_ref,
            RepoPackageStatus::Available,
            &PackageSuccessor::Reserve,
        )
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_successor_leaf(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &ExecutionContext,
        hydration: &ConversationStateHydration,
        row: &LeafHydrationRow,
        leaf_period_id: Uuid,
        conversation_id: Uuid,
        generation: i64,
        transition_id: Uuid,
        state_version: i64,
        seq_i64: i64,
        applied_at: DateTime<Utc>,
    ) -> Result<(), ExecutorError> {
        let cols = ctx
            .opened_leaves
            .iter()
            .find(|cols| cols.device == row.device)
            .ok_or(ExecutorError::MissingContext("successor leaf columns"))?;
        let participant_period_id = participant_period_for(ctx, hydration, row.device.principal())?;
        transition::insert_leaf_period(
            transaction,
            &NewLeafPeriod {
                leaf_period_id,
                participant_period_id,
                conversation_id,
                generation,
                user_did: device_did(&row.device)?,
                device_id: device_uuid(&row.device),
                leaf_index: checked_i64(u64::from(row.leaf_index))?,
                basic_credential: row.basic_credential.clone(),
                leaf_signature_key: row.signature_key.clone(),
                leaf_key_id: cols.leaf_key_id.clone(),
                leaf_auth_generation: cols.leaf_auth_generation,
                origin: LeafOrigin::Genesis,
                joined_state_version: state_version,
                joined_transition_id: transition_id,
                joined_seq: seq_i64,
                created_at: applied_at,
            },
        )
        .await?;
        Ok(())
    }

    fn closing_leaf_period(
        ctx: &ExecutionContext,
        device: &DeviceIdentity,
    ) -> Result<Uuid, ExecutorError> {
        ctx.closing_leaf_periods
            .iter()
            .find(|(candidate, _)| candidate == device)
            .map(|(_, id)| *id)
            .ok_or(ExecutorError::MissingContext("closing leaf period id"))
    }

    fn repo_interval_close_kind(kind: CloseKind) -> IntervalCloseKind {
        match kind {
            CloseKind::Remove => IntervalCloseKind::Remove,
            CloseKind::Replace => IntervalCloseKind::Replace,
            CloseKind::Reset => IntervalCloseKind::Reset,
            CloseKind::Terminal => IntervalCloseKind::Terminal,
        }
    }

    fn direct_pair(
        participants: &[ParticipantHydrationRow],
    ) -> Result<(String, String), ExecutorError> {
        if participants.len() != 2 {
            return Err(ExecutorError::InconsistentPlan(
                "direct conversation is not a pair",
            ));
        }
        let mut dids = participants
            .iter()
            .map(|row| principal_did(&row.principal))
            .collect::<Result<Vec<_>, _>>()?;
        dids.sort();
        Ok((dids[0].clone(), dids[1].clone()))
    }

    fn build_append_entry(
        ctx: &ExecutionContext,
        conversation_id: Uuid,
        generation: i64,
        state_version: i64,
        transition_id: Uuid,
    ) -> AppendEntry {
        AppendEntry {
            conversation_id,
            entry_id: ctx.entry.entry_id,
            entry_kind: ctx.entry.entry_kind.clone(),
            accepted_payload_bytes: ctx.entry.accepted_payload_bytes.clone(),
            accepted_payload_sha256: ctx.entry.accepted_payload_sha256.clone(),
            signed_request_bytes: ctx.entry.signed_request_bytes.clone(),
            request_digest: ctx.entry.request_digest.clone(),
            signature: ctx.entry.signature.clone(),
            server_fields_bytes: ctx.entry.server_fields_bytes.clone(),
            outer_entry_fingerprint: ctx.entry.outer_entry_fingerprint.clone(),
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            generation: Some(generation),
            state_version: Some(state_version),
            transition_id: Some(transition_id),
            message_id: None,
            received_at: ctx.applied_at,
        }
    }

    /// Persist the creation metadata snapshot. The author identity is sourced
    /// from the **actor** (not the binding): for creation the metadata author is
    /// definitionally the creation actor, and the deferred author-proof trigger
    /// joins the snapshot's author columns back to the creation transition's
    /// actor columns, so they must byte-equal. The encrypted CONTENT (nonce,
    /// ciphertext, its digest) is sourced from the plan's `MetadataSnapshotBinding`;
    /// `origin_transition_id`/`metadata_version`/`author_origin_seq` are the
    /// creation transition itself / 1 / the genesis seq.
    #[allow(clippy::too_many_arguments)]
    async fn write_creation_metadata_snapshot(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        metadata: &MetadataSnapshotBinding,
        author_cols: &MetadataAuthorColumns,
        actor: &ExecutionActor,
        conversation_id: Uuid,
        generation: i64,
        state_version: i64,
        epoch: i64,
        group_id: &[u8],
        group_context_hash: &[u8],
        confirmation_tag: &[u8],
        transition_id: Uuid,
        seq_i64: i64,
        applied_at: DateTime<Utc>,
    ) -> Result<(), ExecutorError> {
        let ciphertext = metadata.ciphertext().to_vec();
        let ciphertext_size = checked_i64(ciphertext.len() as u64)?;
        transition::insert_metadata_snapshot(
            transaction,
            &NewMetadataSnapshot {
                metadata_snapshot_id: author_cols.metadata_snapshot_id,
                conversation_id,
                generation,
                state_version,
                group_id: group_id.to_vec(),
                epoch,
                group_context_hash: group_context_hash.to_vec(),
                confirmation_tag: confirmation_tag.to_vec(),
                producing_transition_id: transition_id,
                // Self-origin snapshot: creation (version 1) and reset activation
                // (fresh, version prior+1) both set origin_transition_id to the
                // producing transition and author = the actor; the version comes
                // from the plan's binding so this serves both edges.
                origin_transition_id: transition_id,
                metadata_version: checked_i64(metadata.metadata_version())?,
                nonce: metadata.nonce().to_vec(),
                ciphertext_sha256: metadata.ciphertext_sha256().to_vec(),
                ciphertext,
                ciphertext_size,
                avatar: None,
                author_did: actor.user_did.clone(),
                author_device_id: actor.device_id,
                author_key_id: actor.key_id.clone(),
                author_public_key: author_cols.author_public_key.clone(),
                author_auth_generation: actor.auth_generation,
                author_origin_seq: seq_i64,
                author_role: author_cols.author_role.clone(),
                author_device_status: author_cols.author_device_status.clone(),
                created_at: applied_at,
            },
        )
        .await?;
        Ok(())
    }

    /// Persist a commit/leafRecovery metadata RE-ENCRYPTION snapshot. Per the DDL
    /// `assert_metadata_snapshot_mapping` `commit/leafRecovery/leaveCommit` arm the
    /// new snapshot's author / origin / metadata_version / ciphertext_size / avatar
    /// columns must byte-equal the PRIOR snapshot's — only nonce / ciphertext /
    /// ciphertext_sha256 are fresh (the metadata content re-encrypted for the new
    /// epoch). So author identity is CARRIED FORWARD from the re-encryption
    /// binding's author-proof (the ORIGINAL author — creation/metadata author, NOT
    /// the fulfiller `ctx.actor`), with the DB `author_key_id` / `author_role` /
    /// `author_device_status` / snapshot PK supplied by `MetadataAuthorColumns`;
    /// `producing_transition_id` and the coordinate are this transition's successor.
    #[allow(clippy::too_many_arguments)]
    async fn write_commit_metadata_snapshot(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        metadata: &MetadataSnapshotBinding,
        author_cols: &MetadataAuthorColumns,
        conversation_id: Uuid,
        generation: i64,
        state_version: i64,
        epoch: i64,
        group_id: &[u8],
        group_context_hash: &[u8],
        confirmation_tag: &[u8],
        producing_transition_id: Uuid,
        applied_at: DateTime<Utc>,
    ) -> Result<(), ExecutorError> {
        let proof = &metadata.author_proof;
        let ciphertext = metadata.ciphertext().to_vec();
        let ciphertext_size = checked_i64(ciphertext.len() as u64)?;
        transition::insert_metadata_snapshot(
            transaction,
            &NewMetadataSnapshot {
                metadata_snapshot_id: author_cols.metadata_snapshot_id,
                conversation_id,
                generation,
                state_version,
                group_id: group_id.to_vec(),
                epoch,
                group_context_hash: group_context_hash.to_vec(),
                confirmation_tag: confirmation_tag.to_vec(),
                producing_transition_id,
                // Carry-forward origin + version from the prior snapshot.
                origin_transition_id: Uuid::from_bytes(*metadata.origin_transition_id()),
                metadata_version: checked_i64(metadata.metadata_version())?,
                // Fresh re-encryption (same ciphertext size as the prior snapshot).
                nonce: metadata.nonce().to_vec(),
                ciphertext_sha256: metadata.ciphertext_sha256().to_vec(),
                ciphertext,
                ciphertext_size,
                avatar: None,
                // Carry-forward author identity from the binding's author-proof.
                author_did: principal_did(proof.author.principal())?,
                author_device_id: device_uuid(&proof.author),
                author_key_id: author_cols.author_key_id.clone(),
                author_public_key: proof.signature_public_key.to_vec(),
                author_auth_generation: checked_i64(proof.auth_generation_at_origin)?,
                author_origin_seq: checked_i64(proof.origin_seq)?,
                author_role: author_cols.author_role.clone(),
                author_device_status: author_cols.author_device_status.clone(),
                created_at: applied_at,
            },
        )
        .await?;
        Ok(())
    }

    async fn write_creation_participants(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &ExecutionContext,
        hydration: &ConversationStateHydration,
        effects: &TransitionEffects,
        transition_id: Uuid,
        applied_at: DateTime<Utc>,
    ) -> Result<(), ExecutorError> {
        let creator = &ctx.actor;
        let mut period_ids = ctx.participant_period_ids.iter();
        for change in effects.participant_changes() {
            let (before, after) = (change.before(), change.after());
            let after = match (before, after) {
                (None, Some(after)) => after,
                _ => {
                    return Err(ExecutorError::UnsupportedEffect(
                        "participant change is not a creation insert",
                    ))
                }
            };
            let row = hydration
                .participants
                .iter()
                .find(|row| &row.principal == after.principal())
                .ok_or(ExecutorError::InconsistentPlan(
                    "participant not in hydration",
                ))?;
            let period_id = *period_ids
                .next()
                .ok_or(ExecutorError::MissingContext("participant period id"))?;
            let invitation = match &row.invitation {
                Some(_) => Some(ParticipantInvitation {
                    invitation_transition_id: transition_id,
                    invitation_entry_id: ctx.entry.entry_id,
                    invited_at: applied_at,
                }),
                None => None,
            };
            transition::insert_participant_period(
                transaction,
                &NewParticipantPeriod {
                    participant_period_id: period_id,
                    conversation_id: Uuid::from_bytes(*hydration.coordinate.conversation_id()),
                    user_did: principal_did(&row.principal)?,
                    status: repo_participant_status(row.status),
                    role: repo_participant_role(row.role),
                    role_transition_id: transition_id,
                    role_changed_at: applied_at,
                    created_by_did: creator.user_did.clone(),
                    created_by_device_id: creator.device_id,
                    invitation,
                    acceptance: None,
                    created_at: applied_at,
                },
            )
            .await?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_creation_leaves(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &ExecutionContext,
        hydration: &ConversationStateHydration,
        effects: &TransitionEffects,
        conversation_id: Uuid,
        generation: i64,
        transition_id: Uuid,
        state_version: i64,
        seq_i64: i64,
        applied_at: DateTime<Utc>,
    ) -> Result<HashMap<DeviceIdentity, Uuid>, ExecutorError> {
        let mut opened: HashMap<DeviceIdentity, Uuid> = HashMap::new();
        let mut leaf_ids = ctx.leaf_period_ids.iter();
        for change in effects.leaf_changes() {
            let after = match (change.before(), change.after()) {
                (None, Some(after)) => after,
                _ => {
                    return Err(ExecutorError::UnsupportedEffect(
                        "leaf change is not a creation insert",
                    ))
                }
            };
            let row: &LeafHydrationRow = hydration
                .leaves
                .iter()
                .find(|row| &row.device == after.device())
                .ok_or(ExecutorError::InconsistentPlan("leaf not in hydration"))?;
            let cols = ctx
                .opened_leaves
                .iter()
                .find(|cols| &cols.device == after.device())
                .ok_or(ExecutorError::MissingContext("leaf persistence columns"))?;
            // The owning participant period must already be inserted; its id is
            // matched by DID (one current period per DID at creation).
            let participant_period_id =
                participant_period_for(ctx, hydration, after.device().principal())?;
            let leaf_id = *leaf_ids
                .next()
                .ok_or(ExecutorError::MissingContext("leaf period id"))?;
            transition::insert_leaf_period(
                transaction,
                &NewLeafPeriod {
                    leaf_period_id: leaf_id,
                    participant_period_id,
                    conversation_id,
                    generation,
                    user_did: device_did(after.device())?,
                    device_id: device_uuid(after.device()),
                    leaf_index: checked_i64(u64::from(row.leaf_index))?,
                    basic_credential: row.basic_credential.clone(),
                    leaf_signature_key: row.signature_key.clone(),
                    leaf_key_id: cols.leaf_key_id.clone(),
                    leaf_auth_generation: cols.leaf_auth_generation,
                    origin: LeafOrigin::Genesis,
                    joined_state_version: state_version,
                    joined_transition_id: transition_id,
                    joined_seq: seq_i64,
                    created_at: applied_at,
                },
            )
            .await?;
            opened.insert(after.device().clone(), leaf_id);
        }
        Ok(opened)
    }

    /// Resolve the participant-period id the executor minted for `principal`.
    /// Creation inserts periods in the plan's canonical participant order, so the
    /// id is the ctx `participant_period_ids` entry at that principal's index.
    fn participant_period_for(
        ctx: &ExecutionContext,
        hydration: &ConversationStateHydration,
        principal: &PrincipalId,
    ) -> Result<Uuid, ExecutorError> {
        let index = hydration
            .participants
            .iter()
            .position(|row| &row.principal == principal)
            .ok_or(ExecutorError::InconsistentPlan(
                "leaf owner not a participant",
            ))?;
        ctx.participant_period_ids
            .get(index)
            .copied()
            .ok_or(ExecutorError::MissingContext(
                "participant period id for leaf owner",
            ))
    }

    async fn write_creation_intervals(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        effects: &TransitionEffects,
        leaf_ids: &HashMap<DeviceIdentity, Uuid>,
        conversation_id: Uuid,
        applied_at: DateTime<Utc>,
    ) -> Result<(), ExecutorError> {
        for change in effects.interval_changes() {
            let after = match (change.before(), change.after()) {
                (None, Some(after)) => after,
                _ => {
                    return Err(ExecutorError::UnsupportedEffect(
                        "interval change is not a creation open",
                    ))
                }
            };
            if after.end().is_some() {
                return Err(ExecutorError::UnsupportedEffect(
                    "creation interval is born closed",
                ));
            }
            if after.opening_kind() != super::OpeningKind::Creation {
                return Err(ExecutorError::UnsupportedEffect(
                    "non-creation interval opening in a creation plan",
                ));
            }
            let opening_transition_id = Uuid::from_bytes(*after.opening_transition_id());
            let opening_leaf_period_id =
                *leaf_ids
                    .get(after.recipient())
                    .ok_or(ExecutorError::InconsistentPlan(
                        "interval recipient has no opened leaf",
                    ))?;
            let opening_context = after.opening_context();
            delivery::insert_application_interval(
                transaction,
                &NewApplicationInterval {
                    membership_interval_id: opening_transition_id,
                    conversation_id,
                    generation: checked_i64(opening_context.generation())?,
                    recipient_did: device_did(after.recipient())?,
                    recipient_device_id: device_uuid(after.recipient()),
                    start_seq: checked_i64(after.opening_seq())?,
                    opening_kind: IntervalOpeningKind::Creation,
                    opening_transition_id,
                    opening_outer_entry_fingerprint: after
                        .opening_outer_entry_fingerprint()
                        .to_vec(),
                    opening_state_version: checked_i64(opening_context.state_version())?,
                    opening_group_id: opening_context.group_id().to_vec(),
                    opening_epoch: checked_i64(opening_context.epoch())?,
                    opening_group_context_hash: opening_context.group_context_hash().to_vec(),
                    opening_confirmation_tag: opening_context.confirmation_tag().to_vec(),
                    opening_leaf_period_id,
                    created_at: applied_at,
                },
            )
            .await?;
        }
        Ok(())
    }

    fn build_entry_recipients(
        recipients: &[(DeviceIdentity, EntryEntitlementKind)],
    ) -> Result<Vec<EntryRecipient>, ExecutorError> {
        recipients
            .iter()
            .map(|(device, kind)| {
                Ok(EntryRecipient {
                    user_did: device_did(device)?,
                    device_id: device_uuid(device),
                    entitlement_kind: *kind,
                })
            })
            .collect()
    }

    /// Consume the prior-coordinate open-work SUPERSESSION deltas a
    /// coordinate-changing commit carries (the planner's `resolve_prior_bound_work`
    /// emits them; E2b-7 arm 1). For each `(Open -> Superseded)` recovery request:
    /// terminalize `SupersededByTransition`. For each `(Active -> Released)`
    /// reservation: terminalize `ReleasedByTransition`. For each
    /// `Reserved -> Available` package edge: re-activate. The OWN delta of an
    /// edge (a fulfillment's `Fulfilled`/`Consumed`/`Consumed`) has a DIFFERENT
    /// shape and is SKIPPED here (the arm handles it), so this is safely callable
    /// from every coordinate-changing arm. Returns the number of each family
    /// superseded so the caller can enforce exact-shape (own + supersessions ==
    /// total). All three are bound to the same producing transition.
    async fn write_prior_bound_supersessions(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        effects: &TransitionEffects,
        transition_id: Uuid,
        applied_at: DateTime<Utc>,
    ) -> Result<FamilyCounts, ExecutorError> {
        let mut counts = FamilyCounts::default();
        for change in effects.recovery_request_changes() {
            if let (Some(before), Some(after)) = (change.before(), change.after()) {
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Superseded
                {
                    transition::terminalize_leaf_recovery_request(
                        transaction,
                        Uuid::from_bytes(*after.request_id()),
                        &LeafRecoveryTermination::SupersededByTransition {
                            terminal_transition_id: transition_id,
                            terminal_at: applied_at,
                        },
                    )
                    .await?;
                    counts.requests += 1;
                }
            }
        }
        for change in effects.reservation_changes() {
            if let (Some(before), Some(after)) = (change.before(), change.after()) {
                if before.status() == ReservationStatus::Active
                    && after.status() == ReservationStatus::Released
                {
                    transition::terminalize_reservation(
                        transaction,
                        Uuid::from_bytes(after.request_id),
                        &ReservationTermination::ReleasedByTransition {
                            terminal_transition_id: transition_id,
                            terminal_at: applied_at,
                        },
                    )
                    .await?;
                    counts.reservations += 1;
                }
            }
        }
        for edge in effects.package_transitions() {
            if edge.from == PackageStatus::Reserved && edge.to == PackageStatus::Available {
                transition::cas_key_package_status(
                    transaction,
                    &edge.key_package_ref,
                    RepoPackageStatus::Reserved,
                    &PackageSuccessor::Reactivate,
                )
                .await?;
                counts.packages += 1;
            }
        }
        Ok(counts)
    }

    /// Durably stale each prior-coordinate PENDING reset/leave request the plan
    /// retired. `resolve_prior_bound_work` marks a `Pending` reset request `Stale`
    /// and a `Pending` leave request `Stale` when a coordinate-advancing transition
    /// supersedes the coordinate they were bound to; this consumes exactly those
    /// `(Pending -> Stale)` deltas. A reset/leave delta of any OTHER shape (the
    /// arm's OWN `Pending -> Consumed` reset-activation edge, or `Pending ->
    /// Fulfilled` leave-fulfillment edge) is SKIPPED here and handled by the arm,
    /// with `reconcile_coordinate_change_families` proving `own + staled == total`
    /// per family so nothing is silently dropped.
    ///
    /// The leave-request `stale` terminal edge binds the STALING transition's own
    /// request digest (`assert_leave_request_mapping` requires
    /// `terminal_request_digest == transition.request_digest`). Per ADR-019
    /// Erratum 01 the terminal transition may be of ANY kind, INCLUDING
    /// `leaveCommit`/`leavePolicy`: the coordinate-binding invariant governs, so a
    /// coordinate-advancing leave-kind transition stales OTHER members'
    /// predecessor-bound pending leave requests (the `fulfilled`-not-`stale`
    /// distinction for the request the transition fulfills is enforced here in the
    /// executor, not the DDL). The reset-request `stale` edge needs only the
    /// transition id + instant. Returns the per-family staled counts for the
    /// caller's reconciliation.
    async fn write_prior_bound_staling(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        effects: &TransitionEffects,
        transition_id: Uuid,
        staling_request_digest: &[u8],
        applied_at: DateTime<Utc>,
    ) -> Result<FamilyCounts, ExecutorError> {
        let mut counts = FamilyCounts::default();
        for change in effects.reset_request_changes() {
            if let (Some(before), Some(after)) = (change.before(), change.after()) {
                if before.status() == ResetRequestStatus::Pending
                    && after.status() == ResetRequestStatus::Stale
                {
                    transition::terminalize_reset_request(
                        transaction,
                        Uuid::from_bytes(after.request_id),
                        &ResetRequestTermination::Stale {
                            terminal_transition_id: transition_id,
                            terminal_at: applied_at,
                        },
                    )
                    .await?;
                    counts.reset_requests += 1;
                }
            }
        }
        for change in effects.leave_request_changes() {
            if let (Some(before), Some(after)) = (change.before(), change.after()) {
                if before.status() == LeaveRequestStatus::Pending
                    && after.status() == LeaveRequestStatus::Stale
                {
                    transition::terminalize_leave_request(
                        transaction,
                        Uuid::from_bytes(after.request_id),
                        &LeaveRequestTermination::Stale {
                            terminal_request_digest: staling_request_digest.to_vec(),
                            terminal_transition_id: transition_id,
                            terminal_at: applied_at,
                        },
                    )
                    .await?;
                    counts.leave_requests += 1;
                }
            }
        }
        Ok(counts)
    }

    /// The per-family count of deltas a coordinate-changing arm actually
    /// consumed. Used for both the applied SUPERSESSIONS (what
    /// `write_prior_bound_supersessions` / `write_welcome_supersessions` wrote) and
    /// the arm's OWN edges, so the reconciliation `own + superseded == total` holds
    /// per family (see `reconcile_coordinate_change_families`).
    #[derive(Default)]
    struct FamilyCounts {
        requests: usize,
        reservations: usize,
        packages: usize,
        welcomes: usize,
        reset_requests: usize,
        leave_requests: usize,
    }

    /// The silent-drop guard for every coordinate-changing arm (fulfillment,
    /// generic commit, leave fulfillment). `write_prior_bound_supersessions` and
    /// `write_welcome_supersessions` SKIP any delta that is not their exact
    /// supersession shape; an arm's own-edge handling consumes exactly its own
    /// deltas. So a delta that is NEITHER the arm's own shape NOR a valid
    /// supersession (e.g. an `Open->Expired` request, a wrong-direction package
    /// edge, a `Pending->Expired` welcome) would be neither applied nor rejected —
    /// a silent drop. This reconciliation makes that impossible: for EVERY family,
    /// `own + superseded` MUST equal the plan's total delta count, else the whole
    /// transaction is a hard `InconsistentPlan` (rolled back by the caller). A
    /// future planner that emits a shape neither path handles surfaces here, never
    /// as a lost write.
    fn reconcile_coordinate_change_families(
        effects: &TransitionEffects,
        own: &FamilyCounts,
        superseded: &FamilyCounts,
    ) -> Result<(), ExecutorError> {
        if own.requests + superseded.requests != effects.recovery_request_changes().len() {
            return Err(ExecutorError::InconsistentPlan(
                "recovery request delta neither applied as own nor superseded (silent-drop guard)",
            ));
        }
        if own.reservations + superseded.reservations != effects.reservation_changes().len() {
            return Err(ExecutorError::InconsistentPlan(
                "reservation delta neither applied as own nor released (silent-drop guard)",
            ));
        }
        if own.packages + superseded.packages != effects.package_transitions().len() {
            return Err(ExecutorError::InconsistentPlan(
                "package edge neither applied as own nor reactivated (silent-drop guard)",
            ));
        }
        if own.welcomes + superseded.welcomes != effects.welcome_changes().len() {
            return Err(ExecutorError::InconsistentPlan(
                "welcome delta neither applied as own nor superseded (silent-drop guard)",
            ));
        }
        if own.reset_requests + superseded.reset_requests != effects.reset_request_changes().len() {
            return Err(ExecutorError::InconsistentPlan(
                "reset request delta neither applied as own nor staled (silent-drop guard)",
            ));
        }
        if own.leave_requests + superseded.leave_requests != effects.leave_request_changes().len() {
            return Err(ExecutorError::InconsistentPlan(
                "leave request delta neither applied as own nor staled (silent-drop guard)",
            ));
        }
        Ok(())
    }

    /// Supersede each prior-coordinate pending Welcome the plan retired: append its
    /// `welcomeDisposition` event and terminalize the delivery as `superseded`,
    /// bound to that event. A coordinate-changing commit whose prior carried a
    /// pending Welcome (e.g. an epoch commit after a leaf-recovery fulfillment)
    /// carries these `welcome_changes` `(Pending -> Superseded)`; consuming them
    /// keeps the durable delivery in sync with the state machine.
    ///
    /// Returns the COUNT of welcomes actually superseded so the caller can
    /// reconcile `own + superseded == total` (`reconcile_coordinate_change_families`)
    /// — a `Pending->Expired` or other non-supersession welcome delta is skipped
    /// here and must be caught by that reconciliation, never silently dropped.
    async fn write_welcome_supersessions(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &ExecutionContext,
        effects: &TransitionEffects,
    ) -> Result<usize, ExecutorError> {
        let mut superseded = 0usize;
        for change in effects.welcome_changes() {
            // Only prior-bound supersessions here; a fulfillment's OWN new welcome
            // (None->Some Pending) is handled by its arm and skipped.
            let after = match (change.before(), change.after()) {
                (Some(before), Some(after))
                    if before.status() == WelcomeStatus::Pending
                        && after.status() == WelcomeStatus::Superseded =>
                {
                    after
                }
                _ => continue,
            };
            let welcome_id = Uuid::from_bytes(*after.welcome_id());
            let disposition = ctx
                .welcome_dispositions
                .iter()
                .find(|input| input.welcome_id == welcome_id)
                .ok_or(ExecutorError::MissingContext(
                    "welcome disposition event for a superseded welcome",
                ))?;
            let position = append_one_event(transaction, ctx, &disposition.event).await?;
            delivery::terminalize_welcome_delivery(
                transaction,
                welcome_id,
                &WelcomeDisposition::Superseded,
                ctx.applied_at,
                position,
            )
            .await?;
            superseded += 1;
        }
        Ok(superseded)
    }

    /// Append one event with its audience + outbox, returning its position.
    async fn append_one_event(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &ExecutionContext,
        event: &EventFanout,
    ) -> Result<i64, ExecutorError> {
        let position = delivery::append_event(
            transaction,
            &NewEvent {
                event_id: event.event_id,
                event_kind: event.event_kind,
                payload_bytes: event.payload_bytes.clone(),
                created_at: ctx.applied_at,
                protocol_instance_id: ctx.protocol_instance_id,
            },
        )
        .await?;
        let recipients = event
            .recipients
            .iter()
            .map(|(device, kind, predecessor)| {
                Ok(EventRecipient {
                    user_did: device_did(device)?,
                    device_id: device_uuid(device),
                    entitlement_kind: *kind,
                    audience_predecessor_position: *predecessor,
                })
            })
            .collect::<Result<Vec<_>, ExecutorError>>()?;
        delivery::insert_event_recipients(transaction, position, &recipients).await?;
        for (outbox_id, work_kind) in &event.outbox {
            delivery::enqueue_outbox(
                transaction,
                *outbox_id,
                position,
                *work_kind,
                ctx.applied_at,
            )
            .await?;
        }
        Ok(position)
    }

    async fn write_events(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &ExecutionContext,
    ) -> Result<Vec<i64>, ExecutorError> {
        let mut positions = Vec::with_capacity(ctx.events.len());
        for event in &ctx.events {
            let position = delivery::append_event(
                transaction,
                &NewEvent {
                    event_id: event.event_id,
                    event_kind: event.event_kind,
                    payload_bytes: event.payload_bytes.clone(),
                    created_at: ctx.applied_at,
                    protocol_instance_id: ctx.protocol_instance_id,
                },
            )
            .await?;
            let recipients = event
                .recipients
                .iter()
                .map(|(device, kind, predecessor)| {
                    Ok(EventRecipient {
                        user_did: device_did(device)?,
                        device_id: device_uuid(device),
                        entitlement_kind: *kind,
                        audience_predecessor_position: *predecessor,
                    })
                })
                .collect::<Result<Vec<_>, ExecutorError>>()?;
            delivery::insert_event_recipients(transaction, position, &recipients).await?;
            for (outbox_id, work_kind) in &event.outbox {
                delivery::enqueue_outbox(
                    transaction,
                    *outbox_id,
                    position,
                    *work_kind,
                    ctx.applied_at,
                )
                .await?;
            }
            positions.push(position);
        }
        Ok(positions)
    }
}
