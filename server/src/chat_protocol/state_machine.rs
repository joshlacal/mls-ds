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
        conversation_id: closed_uuid(&coordinate, "conversationId")?,
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
        && evidence.actor.device_id() != evidence.target.device_id()
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
