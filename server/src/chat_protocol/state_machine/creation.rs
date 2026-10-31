#![allow(unused_imports)]
use super::*;


pub(in crate::chat_protocol::state_machine) const MAX_PARTICIPANTS: usize = 100;
pub(in crate::chat_protocol::state_machine) const MAX_LEAVES: usize = 100;
pub(in crate::chat_protocol::state_machine) const MAX_LEAVES_PER_PRINCIPAL: usize = 20;
pub(in crate::chat_protocol::state_machine) const RECOVERY_RESERVATION_TTL_MILLIS: i64 = 300_000;
pub(in crate::chat_protocol::state_machine) const CONSENT_TTL_MILLIS: i64 = 86_400_000;
pub(in crate::chat_protocol::state_machine) const COMMIT_AAD_DOMAIN: &[u8] = b"CATBIRD-CHAT-MLS-AAD-COMMIT\0";

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

pub(in crate::chat_protocol::state_machine) fn relationship_consumption_error(error: RelationshipConsumptionError) -> StateMachineError {
    match error {
        RelationshipConsumptionError::InvalidWitness => {
            StateMachineError::InvalidHydrationAuthority
        }
        RelationshipConsumptionError::PolicyDenied => StateMachineError::InvalidPolicyAuthority,
    }
}

/// One captured trusted server instant represented at canonical millisecond
/// precision. Request admission constructs this once and every planner derives
/// expiry from this same value rather than from client `signedAt`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ServerTimestamp(pub(in crate::chat_protocol::state_machine) i64);

impl ServerTimestamp {
    pub(in crate::chat_protocol::state_machine) fn from_unix_millis(value: i64) -> Result<Self, StateMachineError> {
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

    pub(in crate::chat_protocol::state_machine) fn checked_add_millis(self, millis: i64) -> Result<Self, StateMachineError> {
        self.0
            .checked_add(millis)
            .and_then(|value| (value >= 0).then_some(Self(value)))
            .ok_or(StateMachineError::InvalidServerTime)
    }
}
impl From<PublicStateError> for StateMachineError {
    fn from(value: PublicStateError) -> Self {
        tracing::error!("PublicStateError -> InvalidPublicState: {:?}", value);
        Self::InvalidPublicState
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PrincipalId(pub(in crate::chat_protocol::state_machine) Vec<u8>);

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
    pub(in crate::chat_protocol::state_machine) principal: PrincipalId,
    pub(in crate::chat_protocol::state_machine) device_id: [u8; 16],
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

pub(in crate::chat_protocol::state_machine) fn is_uuid_v4(value: &[u8; 16]) -> bool {
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
    pub(in crate::chat_protocol::state_machine) transition: TransitionEvidence,
    pub(in crate::chat_protocol::state_machine) inviter: DeviceIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParticipantRecord {
    pub(in crate::chat_protocol::state_machine) principal: PrincipalId,
    pub(in crate::chat_protocol::state_machine) status: ParticipantStatus,
    pub(in crate::chat_protocol::state_machine) role: ParticipantRole,
    /// The latest sealed policy transition that established `role`.  `None`
    /// means the role is still the one established by creation/invitation.
    pub(in crate::chat_protocol::state_machine) role_producer: Option<TransitionEvidence>,
    pub(in crate::chat_protocol::state_machine) invitation: Option<InvitationProvenance>,
    pub(in crate::chat_protocol::state_machine) acceptance: Option<TransitionEvidence>,
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

    /// The sealed invitation transition's sequence: the ordinal that orders an
    /// invitation consent period against an access-interval close.
    pub(crate) fn invitation_transition_seq(&self) -> Option<u64> {
        self.invitation
            .as_ref()
            .map(|invitation| invitation.transition.seq())
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
    pub(in crate::chat_protocol::state_machine) device: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) leaf_index: u32,
    pub(in crate::chat_protocol::state_machine) basic_credential: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) signature_key: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) encryption_key: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) key_package_ref: Option<[u8; 32]>,
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
    DirectRequest,
    Creation,
    Add,
    Reset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseKind {
    DirectRequest,
    Remove,
    Replace,
    Reset,
    Terminal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedEntryEvidence {
    pub(in crate::chat_protocol::state_machine) kind: SignedMutationKind,
    pub(in crate::chat_protocol::state_machine) type_id: &'static str,
    pub(in crate::chat_protocol::state_machine) domain: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) control_entry_id: Option<[u8; 16]>,
    pub(in crate::chat_protocol::state_machine) control_conversation_id: Option<[u8; 16]>,
    pub(in crate::chat_protocol::state_machine) actor: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) key_id: [u8; 32],
    pub(in crate::chat_protocol::state_machine) auth_generation: u64,
    pub(in crate::chat_protocol::state_machine) signed_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) request_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) signature: [u8; 64],
    pub(in crate::chat_protocol::state_machine) signed_request_bytes: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) canonical_projection: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) transcript_bytes: Vec<u8>,
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
pub(in crate::chat_protocol::state_machine) enum TransitionBodyBinding {
    DirectRequestPublication {
        prior: Option<PublicGroupSnapshotCoordinate>,
        next: PublicGroupSnapshotCoordinate,
        recipient: PrincipalId,
        devices: Vec<DeviceIdentity>,
        metadata: MetadataSnapshotBinding,
    },
    DirectRequestAcceptance {
        request_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        invitation: InvitationBinding,
    },
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
    pub(in crate::chat_protocol::state_machine) coordinate: MetadataCryptoCoordinate,
    pub(in crate::chat_protocol::state_machine) origin_transition_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) metadata_version: u64,
    pub(in crate::chat_protocol::state_machine) nonce: [u8; 12],
    pub(in crate::chat_protocol::state_machine) ciphertext: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) ciphertext_sha256: [u8; 32],
    pub(in crate::chat_protocol::state_machine) avatar_binding: Option<MetadataAvatarDescriptorBinding>,
    pub(in crate::chat_protocol::state_machine) author_proof: MetadataAuthorProofBinding,
    pub(in crate::chat_protocol::state_machine) canonical_snapshot: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) digest: [u8; 32],
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

    pub(crate) fn avatar_binding(&self) -> Option<&MetadataAvatarDescriptorBinding> {
        self.avatar_binding.as_ref()
    }

    pub(crate) fn avatar_binding_digest(&self) -> Option<&[u8; 32]> {
        self.avatar_binding.as_ref().map(|binding| &binding.digest)
    }

    pub(crate) fn coordinate_conversation_id(&self) -> &[u8; 16] {
        &self.coordinate.conversation_id
    }

    pub(crate) fn coordinate_generation(&self) -> u64 {
        self.coordinate.generation
    }

    pub(crate) fn coordinate_group_id(&self) -> &[u8; 32] {
        &self.coordinate.group_id
    }

    pub(crate) fn coordinate_epoch(&self) -> u64 {
        self.coordinate.epoch
    }

    pub(crate) fn coordinate_group_context_hash(&self) -> &[u8; 32] {
        &self.coordinate.group_context_hash
    }

    pub(crate) fn coordinate_confirmation_tag(&self) -> &[u8; 32] {
        &self.coordinate.confirmation_tag
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

/// Exact signed `#metadataAvatarBinding`. Purpose is closed to `metadata` by
/// the lexicon projector, so the sealed value carries the three variable
/// columns plus its canonical descriptor and digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MetadataAvatarDescriptorBinding {
    pub(in crate::chat_protocol::state_machine) blob_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) ciphertext_sha256: [u8; 32],
    pub(in crate::chat_protocol::state_machine) ciphertext_size: u64,
    pub(in crate::chat_protocol::state_machine) canonical_descriptor: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) digest: [u8; 32],
}

impl MetadataAvatarDescriptorBinding {
    pub(crate) fn blob_id(&self) -> &[u8; 16] {
        &self.blob_id
    }

    pub(crate) fn ciphertext_sha256(&self) -> &[u8; 32] {
        &self.ciphertext_sha256
    }

    pub(crate) fn ciphertext_size(&self) -> u64 {
        self.ciphertext_size
    }

    pub(crate) fn canonical_descriptor(&self) -> &[u8] {
        &self.canonical_descriptor
    }

    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine) struct MetadataCryptoCoordinate {
    pub(in crate::chat_protocol::state_machine) conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) generation: u64,
    pub(in crate::chat_protocol::state_machine) group_id: [u8; 32],
    pub(in crate::chat_protocol::state_machine) epoch: u64,
    pub(in crate::chat_protocol::state_machine) group_context_hash: [u8; 32],
    pub(in crate::chat_protocol::state_machine) confirmation_tag: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine) struct MetadataAuthorProofBinding {
    pub(in crate::chat_protocol::state_machine) author: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) author_key_id: [u8; 32],
    pub(in crate::chat_protocol::state_machine) signature_public_key: [u8; 32],
    pub(in crate::chat_protocol::state_machine) auth_generation_at_origin: u64,
    pub(in crate::chat_protocol::state_machine) origin_transition_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) origin_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine) struct RosterManifestBinding {
    pub(in crate::chat_protocol::state_machine) participants: Vec<RosterParticipantBinding>,
    pub(in crate::chat_protocol::state_machine) actor_leaf: DeviceIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine) struct RosterParticipantBinding {
    pub(in crate::chat_protocol::state_machine) principal: PrincipalId,
    pub(in crate::chat_protocol::state_machine) status: ParticipantStatus,
    pub(in crate::chat_protocol::state_machine) role: ParticipantRole,
    pub(in crate::chat_protocol::state_machine) invitation: Option<InvitationBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine) struct InvitationBinding {
    pub(in crate::chat_protocol::state_machine) transition_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) inviter: DeviceIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine) struct AcceptanceRecoveryBinding {
    pub(in crate::chat_protocol::state_machine) request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) target: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) kind: LeafRecoveryKind,
    pub(in crate::chat_protocol::state_machine) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) requester_key_id: [u8; 32],
    pub(in crate::chat_protocol::state_machine) requester_auth_generation: u64,
    pub(in crate::chat_protocol::state_machine) key_package_ref: [u8; 32],
    pub(in crate::chat_protocol::state_machine) key_package_wrapper: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) key_package_wrapper_sha256: [u8; 32],
    pub(in crate::chat_protocol::state_machine) requested_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) expires_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) canonical_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine) struct TransitionManifestBinding {
    pub(in crate::chat_protocol::state_machine) participant_changes: Vec<ManifestParticipantChange>,
    pub(in crate::chat_protocol::state_machine) leaf_changes: Vec<ManifestLeafChange>,
    pub(in crate::chat_protocol::state_machine) leaf_recovery_request_id: Option<[u8; 16]>,
    pub(in crate::chat_protocol::state_machine) welcome: Option<ManifestWelcomeBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine) enum ManifestParticipantChange {
    Add(PrincipalId),
    Remove(PrincipalId),
    ChangeRole(PrincipalId, ParticipantRole),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine) enum ManifestLeafChange {
    Add {
        device: DeviceIdentity,
        recovery_request_id: [u8; 16],
        key_package_ref: [u8; 32],
    },
    Remove(DeviceIdentity),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine) struct ManifestWelcomeBinding {
    pub(in crate::chat_protocol::state_machine) welcome_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) opaque_welcome: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) sha256: [u8; 32],
    pub(in crate::chat_protocol::state_machine) recipient: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) recovery_request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) key_package_ref: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransitionEvidence {
    pub(in crate::chat_protocol::state_machine) seq: u64,
    pub(in crate::chat_protocol::state_machine) transition_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) outer_entry_fingerprint: [u8; 32],
    pub(in crate::chat_protocol::state_machine) outer_control_projection: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) server_fields_dag_cbor: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) durable_row_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) received_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) authority: Option<AuthenticatedEntryEvidence>,
    pub(in crate::chat_protocol::state_machine) body_binding: Option<TransitionBodyBinding>,
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

    #[cfg(any(
        test,
        all(
            feature = "chat-protocol-production-proof",
            not(feature = "server-bin")
        )
    ))]
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
pub(in crate::chat_protocol::state_machine) enum RequestBodyBinding {
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
        /// Present only for `welcomeRejection`. Retained from the verified
        /// closed request body so the executor can bind recovery work to the
        /// signed reason without trusting a separately hydrated value.
        rejection_reason: Option<String>,
    },
}

/// Authenticated immutable outer evidence for a non-coordinate signed request.
/// Production construction is intentionally absent until transcript.rs has
/// verified the closed body, historical key, row/body bindings, and signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestEvidence {
    pub(in crate::chat_protocol::state_machine) kind: RequestEntryKind,
    pub(in crate::chat_protocol::state_machine) control_entry_id: Option<[u8; 16]>,
    pub(in crate::chat_protocol::state_machine) conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) control_seq: Option<u64>,
    pub(in crate::chat_protocol::state_machine) control_outer_entry_fingerprint: Option<[u8; 32]>,
    pub(in crate::chat_protocol::state_machine) control_outer_projection: Option<Vec<u8>>,
    pub(in crate::chat_protocol::state_machine) control_server_fields_dag_cbor: Option<Vec<u8>>,
    pub(in crate::chat_protocol::state_machine) request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) actor: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) key_id: [u8; 32],
    pub(in crate::chat_protocol::state_machine) auth_generation: u64,
    pub(in crate::chat_protocol::state_machine) request_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) signature: [u8; 64],
    /// Exact accepted signed wrapper. Non-control requests have no synthetic
    /// control-entry identity or sequence; this immutable byte string and its
    /// signature/digest are their durable identity.
    pub(in crate::chat_protocol::state_machine) signed_request_bytes: Vec<u8>,
    /// Internal digest of the complete durable request row. This is not the
    /// fingerprint of a protocol control entry.
    pub(in crate::chat_protocol::state_machine) durable_row_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) received_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) authority: Option<AuthenticatedEntryEvidence>,
    pub(in crate::chat_protocol::state_machine) body_binding: Option<RequestBodyBinding>,
}

/// Exact same-DID signed device-revocation authority. It is deliberately
/// independent of conversation entry sequencing: one global revocation can
/// release request/package work in several conversations while leaving their
/// signed MLS leaves untouched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeviceRevocationEvidence {
    pub(in crate::chat_protocol::state_machine) revocation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) actor: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) target: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) actor_key_id: [u8; 32],
    pub(in crate::chat_protocol::state_machine) actor_auth_generation: u64,
    pub(in crate::chat_protocol::state_machine) expected_target_auth_generation: u64,
    pub(in crate::chat_protocol::state_machine) signed_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) accepted_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) request_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) signature: [u8; 64],
    pub(in crate::chat_protocol::state_machine) signed_request_bytes: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) signing_transcript_bytes: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) durable_row_digest: [u8; 32],
}
