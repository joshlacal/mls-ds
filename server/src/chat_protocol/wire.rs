// Bounded, exact MLS wire validation for the clean chat protocol.
//
// All functions in this module accept a complete RFC 9420 `MLSMessage`, not
// a raw inner object. The clean protocol is deliberately closed to MLS 1.0
// and the XWing ciphersuite.

use std::{
    collections::{HashMap, HashSet},
    panic::AssertUnwindSafe,
};

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use openmls::{
    ciphersuite::{
        hash_ref::make_key_package_ref, signable::Verifiable, signature::SignaturePublicKey,
    },
    group::{ProposalStore, PublicGroup},
    prelude::{
        Ciphersuite, ContentType, CredentialType, ExternalPubExtension, MlsMessageBodyIn,
        MlsMessageIn, ProcessedMessageContent, Proposal, ProposalOrRefType, ProtocolMessage,
        RatchetTreeExtension, Sender, WireFormat,
    },
};
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tls_codec::{
    Deserialize as TlsDeserialize, Serialize as TlsSerialize, Size as TlsSizeTrait, TlsDeserialize,
    TlsSerialize, TlsSize, VLBytes,
};

use super::snapshot::{
    decode_public_group_snapshot, encode_public_group_snapshot,
    expected_update_path_ciphertext_counts, public_group_snapshot_binding,
    PublicGroupSnapshotBinding, PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle,
    PublicGroupState,
};
use super::{xwing_kem_output_is_valid, xwing_public_key_is_valid};

/// The only ciphersuite accepted by the clean chat protocol (`0x004D`).
pub const XWING_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const MLS_1_0_WIRE_VALUE: u16 = 1;
const CLEAN_GROUP_ID_BYTES: usize = 32;
const XWING_HASH_BYTES: usize = 32;

/// KeyPackages are bounded before any TLS decoder can allocate.
pub const MAX_KEY_PACKAGE_WIRE_BYTES: usize = 64 * 1024;
pub const MAX_PUBLIC_MESSAGE_WIRE_BYTES: usize = 1_048_576;
pub const MAX_PRIVATE_MESSAGE_WIRE_BYTES: usize = 1_048_576;
pub const MAX_GROUP_INFO_WIRE_BYTES: usize = 1_048_576;
pub const MAX_WELCOME_WIRE_BYTES: usize = 1_048_576;
pub const MAX_WELCOME_RECIPIENTS: usize = 100;
/// Clean-protocol packages must remain usable for at least ten minutes.
pub const MIN_KEY_PACKAGE_REMAINING_SECONDS: u64 = 10 * 60;
/// Clean-protocol package validity spans at most 30 days plus one hour of
/// allowed clock skew.
pub const MAX_KEY_PACKAGE_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60 + 60 * 60;

/// Convert one sealed trusted server timestamp from canonical milliseconds to
/// the Unix-second instant used for MLS lifetime validation.
///
/// This is deliberately total over `i64`: pre-epoch values are rejected, and
/// nonnegative subsecond values are floored rather than rounded.
#[doc(hidden)]
pub fn trusted_unix_millis_to_seconds(unix_millis: i64) -> Option<u64> {
    u64::try_from(unix_millis.div_euclid(1_000)).ok()
}

const BASIC_CREDENTIAL_TYPE: u16 = 1;

// Local wire mirrors are intentionally made only of TLS primitives. They let
// the server apply a caller-frozen lifetime decision while still verifying
// both RFC signatures, without calling OpenMLS' wall-clock-based
// `KeyPackageIn::validate`.
#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireKeyPackage {
    payload: WireKeyPackageTbs,
    signature: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireKeyPackageTbs {
    protocol_version: u16,
    ciphersuite: u16,
    init_key: VLBytes,
    leaf_node: WireLeafNode,
    extensions: Vec<WireExtension>,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireLeafNode {
    payload: WireLeafNodeTbs,
    signature: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireLeafNodeTbs {
    encryption_key: VLBytes,
    signature_key: VLBytes,
    credential: WireCredential,
    capabilities: WireCapabilities,
    source: WireLeafNodeSource,
    extensions: Vec<WireExtension>,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireCredential {
    credential_type: u16,
    serialized_content: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireCapabilities {
    versions: Vec<u16>,
    ciphersuites: Vec<u16>,
    extensions: Vec<u16>,
    proposals: Vec<u16>,
    credentials: Vec<u16>,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
enum WireLeafNodeSource {
    #[tls_codec(discriminant = 1)]
    KeyPackage(WireLifetime),
    #[tls_codec(discriminant = 2)]
    Update,
    #[tls_codec(discriminant = 3)]
    Commit(VLBytes),
}

#[derive(Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireLifetime {
    not_before: u64,
    not_after: u64,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[allow(dead_code)]
struct WireExtension {
    extension_type: u16,
    extension_data: VLBytes,
}

#[derive(TlsSerialize, TlsSize)]
struct MlsSignContent {
    label: VLBytes,
    content: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireGroupInfoEnvelope {
    version: u16,
    wire_format: u16,
    group_info: WireGroupInfo,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireGroupInfo {
    context: WireGroupContext,
    extensions: Vec<WireExtension>,
    confirmation_tag: VLBytes,
    signer: u32,
    signature: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireGroupContext {
    protocol_version: u16,
    ciphersuite: u16,
    group_id: VLBytes,
    epoch: u64,
    tree_hash: VLBytes,
    confirmed_transcript_hash: VLBytes,
    extensions: Vec<WireExtension>,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireHpkeCiphertext {
    kem_output: VLBytes,
    ciphertext: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireUpdatePathNode {
    public_key: VLBytes,
    encrypted_path_secrets: Vec<WireHpkeCiphertext>,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireUpdatePath {
    leaf_node: WireLeafNode,
    nodes: Vec<WireUpdatePathNode>,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireWelcomeEnvelope {
    version: u16,
    wire_format: u16,
    welcome: WireWelcome,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireWelcome {
    ciphersuite: u16,
    secrets: Vec<WireEncryptedGroupSecrets>,
    encrypted_group_info: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireEncryptedGroupSecrets {
    new_member: VLBytes,
    encrypted_group_secrets: WireHpkeCiphertext,
}

/// Caller-owned expectations for one uploaded clean-protocol KeyPackage.
#[derive(Clone, Copy, Debug)]
pub struct KeyPackageValidationPolicy<'a> {
    pub expected_basic_credential: &'a [u8],
    pub expected_signature_key: &'a [u8],
    /// Frozen Unix time used for the protocol lifetime decision.
    pub now_unix_seconds: u64,
    pub max_bytes: usize,
}

/// Evidence returned only after exact wire, profile, and signature validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedKeyPackage {
    inner_bytes: Vec<u8>,
    key_package_ref: [u8; 32],
    init_key: Vec<u8>,
    leaf_encryption_key: Vec<u8>,
    not_before: u64,
    not_after: u64,
}

impl ValidatedKeyPackage {
    /// Exact serialized `KeyPackage` bytes, excluding the four-byte
    /// `MLSMessage` version/wire-format prefix.
    pub fn inner_bytes(&self) -> &[u8] {
        &self.inner_bytes
    }

    /// Raw RFC 9420 KeyPackageRef bytes (never hex/base64 and never a TLS
    /// vector containing the reference).
    pub fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }

    /// Validated XWing init key. The inventory transaction must enforce that
    /// this exact key has never appeared in another package.
    pub fn init_key(&self) -> &[u8] {
        &self.init_key
    }

    pub fn leaf_encryption_key(&self) -> &[u8] {
        &self.leaf_encryption_key
    }

    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    pub fn not_after(&self) -> u64 {
        self.not_after
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GroupInfoValidationPolicy<'a> {
    pub expected_basic_credential: &'a [u8],
    pub expected_signature_key: &'a [u8],
    /// Frozen Unix time shared with the enclosing creation/reset validation.
    pub now_unix_seconds: u64,
    pub max_bytes: usize,
    pub max_ratchet_tree_bytes: usize,
    pub max_members: usize,
}

/// Signature-authenticated actor-only epoch-0 public state for conversation
/// creation or reset bootstrap.
///
/// The public service has no epoch secrets, so the carried confirmation tag is
/// opaque evidence for clients to verify. It is not a server-verified MAC.
pub struct ValidatedGroupInfo {
    canonical_bytes: Vec<u8>,
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
    public_state: PublicGroupState,
}

impl std::fmt::Debug for ValidatedGroupInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedGroupInfo")
            .field("encoded_len", &self.canonical_bytes.len())
            .field("group_id_len", &self.group_id().len())
            .field("epoch", &self.epoch())
            .finish_non_exhaustive()
    }
}

impl ValidatedGroupInfo {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn group_id(&self) -> &[u8] {
        self.public_state.public_group().group_id().as_slice()
    }

    pub fn epoch(&self) -> u64 {
        self.public_state
            .public_group()
            .group_context()
            .epoch()
            .as_u64()
    }

    /// SHA-256 of the exact canonical TLS serialization of `GroupContext`.
    pub fn group_context_hash(&self) -> &[u8; 32] {
        &self.group_context_hash
    }

    /// Raw suite-sized confirmation tag from the signature-authenticated
    /// GroupInfo. Clients with the epoch secrets must verify its MAC before
    /// accepting the group; the public service only binds these exact bytes.
    pub fn confirmation_tag(&self) -> &[u8; 32] {
        &self.confirmation_tag
    }

    pub fn public_group(&self) -> &PublicGroup {
        self.public_state.public_group()
    }

    pub fn public_state(&self) -> &PublicGroupState {
        &self.public_state
    }

    pub fn into_public_state(self) -> PublicGroupState {
        self.public_state
    }
}

/// Structurally validated public Commit. Cryptographic commit processing is
/// intentionally deferred to the caller's authoritative `PublicGroup`.
#[derive(Debug)]
pub struct ValidatedPublicCommit {
    group_id: Vec<u8>,
    epoch: u64,
    aad: Vec<u8>,
    sender: Sender,
    raw_proposals: Vec<RawCommitProposalKind>,
    path_ciphertext_counts: Vec<usize>,
    message: openmls::prelude::PublicMessageIn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawCommitProposalKind {
    Add,
    Remove,
}

#[derive(Clone, Copy, Debug)]
pub struct PublicCommitValidationPolicy<'a> {
    /// Exact protocol-defined MLS AAD derived from the signed transition.
    pub expected_aad: &'a [u8],
    /// Exact snapshot binding loaded from the separately locked current
    /// conversation head. It must never be derived from `prior_state`.
    pub trusted_prior_binding: &'a PublicGroupSnapshotBinding,
    /// Exact outer-declared successor coordinate. MLS-derived fields are
    /// checked only after the Commit has been processed in disposable state.
    /// Equality with the received confirmation tag does not prove its MAC;
    /// clients with epoch secrets own that verification and recovery boundary.
    pub expected_next_coordinate: &'a PublicGroupSnapshotCoordinate,
    /// Frozen Unix time shared with reservation/package consumption checks.
    pub now_unix_seconds: u64,
    pub max_members: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCommitAdd {
    leaf_index: u32,
    basic_credential: Vec<u8>,
    signature_key: Vec<u8>,
    key_package: ValidatedKeyPackage,
}

impl ValidatedCommitAdd {
    pub fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    pub fn basic_credential(&self) -> &[u8] {
        &self.basic_credential
    }

    pub fn signature_key(&self) -> &[u8] {
        &self.signature_key
    }

    pub fn key_package(&self) -> &ValidatedKeyPackage {
        &self.key_package
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCommitRemove {
    leaf_index: u32,
    basic_credential: Vec<u8>,
    signature_key: Vec<u8>,
}

impl ValidatedCommitRemove {
    pub fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    pub fn basic_credential(&self) -> &[u8] {
        &self.basic_credential
    }

    pub fn signature_key(&self) -> &[u8] {
        &self.signature_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCommitSenderUpdate {
    leaf_index: u32,
    basic_credential: Vec<u8>,
    signature_key: Vec<u8>,
    prior_encryption_key: Vec<u8>,
    next_encryption_key: Vec<u8>,
}

impl ValidatedCommitSenderUpdate {
    pub fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    pub fn basic_credential(&self) -> &[u8] {
        &self.basic_credential
    }

    pub fn signature_key(&self) -> &[u8] {
        &self.signature_key
    }

    pub fn prior_encryption_key(&self) -> &[u8] {
        &self.prior_encryption_key
    }

    pub fn next_encryption_key(&self) -> &[u8] {
        &self.next_encryption_key
    }
}

/// A Commit processed and merged in disposable storage. The caller can compare
/// the exact effects with the signed manifest before atomically replacing the
/// authoritative state with `into_next_state` and `next_snapshot`.
pub struct ProcessedPublicCommit {
    next_state: PublicGroupState,
    next_snapshot: Vec<u8>,
    next_binding: PublicGroupSnapshotBinding,
    adds: Vec<ValidatedCommitAdd>,
    removes: Vec<ValidatedCommitRemove>,
    sender_update: ValidatedCommitSenderUpdate,
}

impl std::fmt::Debug for ProcessedPublicCommit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessedPublicCommit")
            .field("next_epoch", &self.next_binding.epoch())
            .field("add_count", &self.adds.len())
            .field("remove_count", &self.removes.len())
            .finish_non_exhaustive()
    }
}

impl ProcessedPublicCommit {
    pub fn next_state(&self) -> &PublicGroupState {
        &self.next_state
    }

    pub fn next_snapshot(&self) -> &[u8] {
        &self.next_snapshot
    }

    pub fn next_binding(&self) -> &PublicGroupSnapshotBinding {
        &self.next_binding
    }

    pub fn adds(&self) -> &[ValidatedCommitAdd] {
        &self.adds
    }

    pub fn removes(&self) -> &[ValidatedCommitRemove] {
        &self.removes
    }

    pub fn sender_update(&self) -> &ValidatedCommitSenderUpdate {
        &self.sender_update
    }

    pub fn into_next_state(self) -> PublicGroupState {
        self.next_state
    }
}

impl ValidatedPublicCommit {
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    pub fn sender(&self) -> &Sender {
        &self.sender
    }

    /// Stateful signature/proposal/extension checks happen when this message
    /// is processed against the exact authoritative public group.
    pub fn into_protocol_message(self) -> ProtocolMessage {
        self.message.into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedWelcome {
    inner_bytes: Vec<u8>,
    key_package_refs: Vec<[u8; 32]>,
}

impl ValidatedWelcome {
    pub fn inner_bytes(&self) -> &[u8] {
        &self.inner_bytes
    }

    /// Ordered raw `EncryptedGroupSecrets.new_member` KeyPackageRefs. These
    /// are visible routing identifiers, not decrypted Welcome contents.
    pub fn key_package_refs(&self) -> &[[u8; 32]] {
        &self.key_package_refs
    }
}

/// Visible, unverified routing metadata from a private Application message.
/// No method on this type can decrypt the ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPrivateApplication {
    group_id: Vec<u8>,
    epoch: u64,
    aad: Vec<u8>,
    inner_bytes: Vec<u8>,
}

impl ValidatedPrivateApplication {
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    pub fn inner_bytes(&self) -> &[u8] {
        &self.inner_bytes
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireValidationError {
    #[error("wire input limit must be non-zero")]
    InvalidLimit,
    #[error("MLS wire input is too large: {actual} bytes exceeds {maximum}")]
    InputTooLarge { actual: usize, maximum: usize },
    #[error("MLS wire input is truncated")]
    Truncated,
    #[error("MLS wire input is malformed")]
    Malformed,
    #[error("MLS wire input contains trailing bytes")]
    TrailingData,
    #[error("MLS wire input is not canonically encoded")]
    NonCanonicalEncoding,
    #[error("unsupported MLS protocol version 0x{actual:04X}")]
    UnsupportedProtocolVersion { actual: u16 },
    #[error("wrong MLS wire format: expected {expected:?}, got 0x{actual:04X}")]
    WrongWireFormat { expected: WireFormat, actual: u16 },
    #[error("wrong MLS content type: expected {expected:?}, got {actual:?}")]
    WrongContentType {
        expected: ContentType,
        actual: ContentType,
    },
    #[error("clean-protocol Commit sender must be an existing group member")]
    NonMemberCommitSender,
    #[error("public Commit does not match the authoritative prior MLS coordinate")]
    CommitCoordinateMismatch,
    #[error("public Commit AAD does not match the signed transition")]
    CommitAadMismatch,
    #[error("public Commit failed OpenMLS signature or semantic processing")]
    InvalidPublicCommit,
    #[error("public Commit contains too many proposals")]
    TooManyCommitProposals,
    #[error("public Commit contains a proposal by reference")]
    ReferencedCommitProposal,
    #[error("public Commit contains a duplicate by-value proposal")]
    DuplicateCommitProposal,
    #[error("public Commit contains a proposal outside the closed Add/Remove profile")]
    UnsupportedCommitProposal,
    #[error("public Commit sender cannot remove its own leaf")]
    CommitSenderSelfRemove,
    #[error("public Commit must contain an ordinary sender update path")]
    MissingCommitUpdatePath,
    #[error("public Commit update-path leaf is outside the clean profile")]
    InvalidCommitUpdatePath,
    #[error("public Commit Add KeyPackage is outside the clean profile")]
    InvalidCommitAdd,
    #[error("public Commit produced effects inconsistent with its proposals")]
    InconsistentCommitEffects,
    #[error("authoritative public state snapshot is invalid or internally inconsistent")]
    InvalidPublicState,
    #[error("unsupported MLS ciphersuite 0x{actual:04X}")]
    UnsupportedCiphersuite { actual: u16 },
    #[error("MLS group ID has wrong length: expected 32 bytes, got {actual}")]
    WrongGroupIdLength { actual: usize },
    #[error("GroupInfo tree hash has wrong length: expected 32 bytes, got {actual}")]
    WrongTreeHashLength { actual: usize },
    #[error("MLS confirmation tag has wrong length: expected 32 bytes, got {actual}")]
    WrongConfirmationTagLength { actual: usize },
    #[error("KeyPackage leaf-node signature is invalid")]
    InvalidLeafNodeSignature,
    #[error("KeyPackage signature is invalid")]
    InvalidKeyPackageSignature,
    #[error("KeyPackage BasicCredential does not match the expected identity")]
    WrongBasicCredential,
    #[error("KeyPackage signature key does not match the enrolled device key")]
    WrongSignatureKey,
    #[error("KeyPackage lifetime is invalid at Unix time {now}")]
    InvalidLifetime {
        now: u64,
        not_before: u64,
        not_after: u64,
    },
    #[error("KeyPackage has less than the required ten minutes of remaining lifetime")]
    InsufficientRemainingLifetime,
    #[error("KeyPackage lifetime span exceeds the clean protocol maximum")]
    LifetimeTooLong,
    #[error("clean-protocol leaf must use the KeyPackage source")]
    UnsupportedLeafSource,
    #[error("KeyPackage advertises capabilities outside the clean protocol profile")]
    UnsupportedCapabilities,
    #[error("KeyPackage contains unsupported extensions")]
    UnsupportedExtensions,
    #[error("KeyPackage init key and leaf encryption key are not distinct")]
    ReusedEncryptionKey,
    #[error("XWing HPKE public key is malformed, noncanonical, or unusable")]
    InvalidXwingPublicKey,
    #[error("XWing HPKE KEM output is malformed, noncanonical, or unusable")]
    InvalidXwingKemOutput,
    #[error("HPKE ciphertext length is invalid for the protocol context")]
    InvalidHpkeCiphertext,
    #[error("MLS cryptographic provider initialization failed")]
    ProviderInitialization,
    #[error("GroupInfo extensions do not match the closed RatchetTree + ExternalPub profile")]
    UnsupportedGroupInfoExtensions,
    #[error("GroupInfo public state or signature is invalid")]
    InvalidGroupInfo,
    #[error("GroupInfo ratchet tree is missing")]
    MissingRatchetTree,
    #[error("GroupInfo ratchet tree is too large: {actual} bytes exceeds {maximum}")]
    RatchetTreeTooLarge { actual: usize, maximum: usize },
    #[error("GroupInfo has too many members: {actual} exceeds {maximum}")]
    TooManyMembers { actual: usize, maximum: usize },
    #[error("clean bootstrap GroupInfo must be actor-only at epoch zero")]
    GroupInfoNotSingletonGenesis,
    #[error("epoch-zero confirmed transcript hash must be empty")]
    NonemptyGenesisConfirmedTranscriptHash,
    #[error("GroupInfo signer key does not identify its singleton member")]
    WrongGroupInfoSigner,
    #[error("GroupInfo singleton BasicCredential does not match the expected identity")]
    WrongGroupInfoCredential,
    #[error("Welcome contains no encrypted group secrets")]
    EmptyWelcome,
    #[error("Welcome KeyPackageRef has wrong length: expected 32 bytes, got {actual}")]
    WrongWelcomeKeyPackageRefLength { actual: usize },
    #[error("Welcome contains a duplicate KeyPackageRef")]
    DuplicateWelcomeKeyPackageRef,
    #[error("Welcome contains too many recipients: {actual} exceeds {maximum}")]
    TooManyWelcomeRecipients { actual: usize, maximum: usize },
}

fn verify_ed25519_mls_signature(
    signature_key: &[u8],
    label: &[u8],
    unsigned_payload: &[u8],
    signature: &[u8],
) -> Result<(), ()> {
    let signature_key: [u8; 32] = signature_key.try_into().map_err(|_| ())?;
    let signature_key = VerifyingKey::from_bytes(&signature_key).map_err(|_| ())?;
    let signature = Ed25519Signature::from_slice(signature).map_err(|_| ())?;
    let mut prefixed_label = b"MLS 1.0 ".to_vec();
    prefixed_label.extend_from_slice(label);
    let sign_content = MlsSignContent {
        label: prefixed_label.into(),
        content: unsigned_payload.to_vec().into(),
    }
    .tls_serialize_detached()
    .map_err(|_| ())?;
    signature_key
        .verify_strict(&sign_content, &signature)
        .map_err(|_| ())
}

fn validate_xwing_public_key(bytes: &[u8]) -> Result<(), WireValidationError> {
    xwing_public_key_is_valid(bytes)
        .then_some(())
        .ok_or(WireValidationError::InvalidXwingPublicKey)
}

fn validate_xwing_kem_output(bytes: &[u8]) -> Result<(), WireValidationError> {
    xwing_kem_output_is_valid(bytes)
        .then_some(())
        .ok_or(WireValidationError::InvalidXwingKemOutput)
}

fn tls_deserialize_exact_no_panic<T: TlsDeserialize>(bytes: &[u8]) -> Result<T, ()> {
    std::panic::catch_unwind(AssertUnwindSafe(|| T::tls_deserialize_exact(bytes)))
        .map_err(|_| ())?
        .map_err(|_| ())
}

fn validate_clean_lifetime(
    lifetime: WireLifetime,
    now_unix_seconds: u64,
) -> Result<(), WireValidationError> {
    if !(lifetime.not_before < now_unix_seconds && now_unix_seconds < lifetime.not_after) {
        return Err(WireValidationError::InvalidLifetime {
            now: now_unix_seconds,
            not_before: lifetime.not_before,
            not_after: lifetime.not_after,
        });
    }
    if lifetime.not_after - now_unix_seconds < MIN_KEY_PACKAGE_REMAINING_SECONDS {
        return Err(WireValidationError::InsufficientRemainingLifetime);
    }
    if lifetime.not_after.saturating_sub(lifetime.not_before) > MAX_KEY_PACKAGE_LIFETIME_SECONDS {
        return Err(WireValidationError::LifetimeTooLong);
    }
    Ok(())
}

fn validate_clean_leaf_profile(
    leaf: &WireLeafNode,
    now_unix_seconds: u64,
) -> Result<WireLifetime, WireValidationError> {
    let lifetime = match &leaf.payload.source {
        WireLeafNodeSource::KeyPackage(lifetime) => *lifetime,
        _ => return Err(WireValidationError::UnsupportedLeafSource),
    };
    validate_clean_lifetime(lifetime, now_unix_seconds)?;

    validate_clean_leaf_shape(leaf)?;
    Ok(lifetime)
}

fn validate_clean_leaf_shape(leaf: &WireLeafNode) -> Result<(), WireValidationError> {
    let capabilities = &leaf.payload.capabilities;
    if capabilities.versions != [MLS_1_0_WIRE_VALUE]
        || capabilities.ciphersuites != [XWING_CIPHERSUITE as u16]
        || !capabilities.extensions.is_empty()
        || !capabilities.proposals.is_empty()
        || capabilities.credentials != [BASIC_CREDENTIAL_TYPE]
    {
        return Err(WireValidationError::UnsupportedCapabilities);
    }
    if !leaf.payload.extensions.is_empty() {
        return Err(WireValidationError::UnsupportedExtensions);
    }
    validate_xwing_public_key(leaf.payload.encryption_key.as_slice())?;
    Ok(())
}

fn exact_singleton_ratchet_tree_leaf(
    extension_data: &[u8],
) -> Result<WireLeafNode, WireValidationError> {
    let encoded_nodes = tls_deserialize_exact_no_panic::<VLBytes>(extension_data)
        .map_err(|_| WireValidationError::NonCanonicalEncoding)?;
    let mut nodes = encoded_nodes.as_slice();
    let present = u8::tls_deserialize(&mut nodes).map_err(|_| WireValidationError::Malformed)?;
    if present != 1 {
        return Err(WireValidationError::GroupInfoNotSingletonGenesis);
    }
    let node_type = u8::tls_deserialize(&mut nodes).map_err(|_| WireValidationError::Malformed)?;
    if node_type != 1 {
        return Err(WireValidationError::GroupInfoNotSingletonGenesis);
    }
    tls_deserialize_exact_no_panic::<WireLeafNode>(nodes)
        .map_err(|_| WireValidationError::GroupInfoNotSingletonGenesis)
}

fn preflight_exact_message(
    bytes: &[u8],
    expected_wire_format: WireFormat,
    requested_maximum: usize,
    protocol_maximum: usize,
) -> Result<MlsMessageIn, WireValidationError> {
    if requested_maximum == 0 {
        return Err(WireValidationError::InvalidLimit);
    }
    let maximum = requested_maximum.min(protocol_maximum);
    if bytes.len() > maximum {
        return Err(WireValidationError::InputTooLarge {
            actual: bytes.len(),
            maximum,
        });
    }
    if bytes.len() < 4 {
        return Err(WireValidationError::Truncated);
    }

    let version = u16::from_be_bytes([bytes[0], bytes[1]]);
    if version != MLS_1_0_WIRE_VALUE {
        return Err(WireValidationError::UnsupportedProtocolVersion { actual: version });
    }
    let wire_format = u16::from_be_bytes([bytes[2], bytes[3]]);
    if wire_format != expected_wire_format as u16 {
        return Err(WireValidationError::WrongWireFormat {
            expected: expected_wire_format,
            actual: wire_format,
        });
    }

    let decoded = std::panic::catch_unwind(AssertUnwindSafe(|| {
        MlsMessageIn::tls_deserialize_exact(bytes)
    }))
    .map_err(|_| WireValidationError::Malformed)?;
    decoded.map_err(|error| match error {
        tls_codec::Error::TrailingData => WireValidationError::TrailingData,
        tls_codec::Error::EndOfStream => WireValidationError::Truncated,
        tls_codec::Error::InvalidVectorLength => WireValidationError::NonCanonicalEncoding,
        _ => WireValidationError::Malformed,
    })
}

fn canonical_wrapped<T: TlsSerialize>(
    wire_format: WireFormat,
    inner: &T,
) -> Result<Vec<u8>, WireValidationError> {
    let inner = inner
        .tls_serialize_detached()
        .map_err(|_| WireValidationError::Malformed)?;
    let mut canonical = Vec::with_capacity(4 + inner.len());
    canonical.extend_from_slice(&MLS_1_0_WIRE_VALUE.to_be_bytes());
    canonical.extend_from_slice(&(wire_format as u16).to_be_bytes());
    canonical.extend_from_slice(&inner);
    Ok(canonical)
}

fn serialized_vl_bytes_len(value: &impl TlsSerialize) -> Result<usize, WireValidationError> {
    let encoded = value
        .tls_serialize_detached()
        .map_err(|_| WireValidationError::Malformed)?;
    let opaque =
        VLBytes::tls_deserialize_exact(&encoded).map_err(|_| WireValidationError::Malformed)?;
    Ok(opaque.as_slice().len())
}

/// Validate one exact wire-format-5 `MLSMessage` carrying a KeyPackage.
pub fn validate_key_package(
    bytes: &[u8],
    policy: KeyPackageValidationPolicy<'_>,
) -> Result<ValidatedKeyPackage, WireValidationError> {
    let message = preflight_exact_message(
        bytes,
        WireFormat::KeyPackage,
        policy.max_bytes,
        MAX_KEY_PACKAGE_WIRE_BYTES,
    )?;
    let key_package_in = match message.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => key_package,
        _ => {
            return Err(WireValidationError::WrongWireFormat {
                expected: WireFormat::KeyPackage,
                actual: u16::from_be_bytes([bytes[2], bytes[3]]),
            })
        }
    };

    let canonical_wrapped_key_package = canonical_wrapped(WireFormat::KeyPackage, &key_package_in)?;
    if canonical_wrapped_key_package != bytes {
        return Err(WireValidationError::NonCanonicalEncoding);
    }
    let canonical_inner = canonical_wrapped_key_package[4..].to_vec();
    let key_package = tls_deserialize_exact_no_panic::<WireKeyPackage>(&canonical_inner)
        .map_err(|_| WireValidationError::Malformed)?;

    if key_package.payload.protocol_version != MLS_1_0_WIRE_VALUE {
        return Err(WireValidationError::UnsupportedProtocolVersion {
            actual: key_package.payload.protocol_version,
        });
    }
    let actual_ciphersuite = key_package.payload.ciphersuite;
    if actual_ciphersuite != XWING_CIPHERSUITE as u16 {
        return Err(WireValidationError::UnsupportedCiphersuite {
            actual: actual_ciphersuite,
        });
    }

    let leaf = &key_package.payload.leaf_node;
    if leaf.payload.credential.credential_type != BASIC_CREDENTIAL_TYPE
        || leaf.payload.credential.serialized_content.as_slice() != policy.expected_basic_credential
    {
        return Err(WireValidationError::WrongBasicCredential);
    }
    if leaf.payload.signature_key.as_slice() != policy.expected_signature_key {
        return Err(WireValidationError::WrongSignatureKey);
    }

    let lifetime = validate_clean_leaf_profile(leaf, policy.now_unix_seconds)?;
    if !key_package.payload.extensions.is_empty() {
        return Err(WireValidationError::UnsupportedExtensions);
    }
    validate_xwing_public_key(key_package.payload.init_key.as_slice())?;
    if key_package.payload.init_key.as_slice() == leaf.payload.encryption_key.as_slice() {
        return Err(WireValidationError::ReusedEncryptionKey);
    }

    let leaf_payload = leaf
        .payload
        .tls_serialize_detached()
        .map_err(|_| WireValidationError::Malformed)?;
    verify_ed25519_mls_signature(
        leaf.payload.signature_key.as_slice(),
        b"LeafNodeTBS",
        &leaf_payload,
        leaf.signature.as_slice(),
    )
    .map_err(|_| WireValidationError::InvalidLeafNodeSignature)?;
    let key_package_payload = key_package
        .payload
        .tls_serialize_detached()
        .map_err(|_| WireValidationError::Malformed)?;
    verify_ed25519_mls_signature(
        leaf.payload.signature_key.as_slice(),
        b"KeyPackageTBS",
        &key_package_payload,
        key_package.signature.as_slice(),
    )
    .map_err(|_| WireValidationError::InvalidKeyPackageSignature)?;

    let provider = openmls_libcrux_crypto::Provider::new()
        .map_err(|_| WireValidationError::ProviderInitialization)?;
    let key_package_ref = std::panic::catch_unwind(AssertUnwindSafe(|| {
        make_key_package_ref(&canonical_inner, XWING_CIPHERSUITE, provider.crypto())
    }))
    .map_err(|_| WireValidationError::InvalidKeyPackageSignature)?
    .map_err(|_| WireValidationError::InvalidKeyPackageSignature)?;
    let key_package_ref: [u8; 32] = key_package_ref
        .as_slice()
        .try_into()
        .map_err(|_| WireValidationError::InvalidKeyPackageSignature)?;

    Ok(ValidatedKeyPackage {
        inner_bytes: canonical_inner,
        key_package_ref,
        init_key: key_package.payload.init_key.as_slice().to_vec(),
        leaf_encryption_key: leaf.payload.encryption_key.as_slice().to_vec(),
        not_before: lifetime.not_before,
        not_after: lifetime.not_after,
    })
}

fn public_message_aad(bytes: &[u8]) -> Result<Vec<u8>, WireValidationError> {
    let mut inner = bytes.get(4..).ok_or(WireValidationError::Truncated)?;
    let _group_id =
        VLBytes::tls_deserialize(&mut inner).map_err(|_| WireValidationError::Malformed)?;
    let _epoch = u64::tls_deserialize(&mut inner).map_err(|_| WireValidationError::Malformed)?;
    let _sender =
        Sender::tls_deserialize(&mut inner).map_err(|_| WireValidationError::Malformed)?;
    let aad = VLBytes::tls_deserialize(&mut inner).map_err(|_| WireValidationError::Malformed)?;
    Ok(aad.as_slice().to_vec())
}

fn validate_wire_commit_update_path(inner: &mut &[u8]) -> Result<Vec<usize>, WireValidationError> {
    let present = u8::tls_deserialize(inner).map_err(|_| WireValidationError::Malformed)?;
    match present {
        0 => Ok(Vec::new()),
        1 => {
            let path = WireUpdatePath::tls_deserialize(inner)
                .map_err(|_| WireValidationError::Malformed)?;
            validate_xwing_public_key(path.leaf_node.payload.encryption_key.as_slice())?;
            let mut ciphertext_counts = Vec::with_capacity(path.nodes.len());
            for node in path.nodes {
                validate_xwing_public_key(node.public_key.as_slice())?;
                ciphertext_counts.push(node.encrypted_path_secrets.len());
                for encrypted_path_secret in node.encrypted_path_secrets {
                    validate_xwing_kem_output(encrypted_path_secret.kem_output.as_slice())?;
                    if encrypted_path_secret.ciphertext.as_slice().len() != 48 {
                        return Err(WireValidationError::InvalidHpkeCiphertext);
                    }
                }
            }
            Ok(ciphertext_counts)
        }
        _ => Err(WireValidationError::Malformed),
    }
}

fn raw_commit_profile(
    bytes: &[u8],
) -> Result<(Vec<RawCommitProposalKind>, Vec<usize>), WireValidationError> {
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut inner = bytes.get(4..).ok_or(WireValidationError::Truncated)?;
        let _group_id =
            VLBytes::tls_deserialize(&mut inner).map_err(|_| WireValidationError::Malformed)?;
        let _epoch =
            u64::tls_deserialize(&mut inner).map_err(|_| WireValidationError::Malformed)?;
        let _sender =
            Sender::tls_deserialize(&mut inner).map_err(|_| WireValidationError::Malformed)?;
        let _aad =
            VLBytes::tls_deserialize(&mut inner).map_err(|_| WireValidationError::Malformed)?;
        let content_type =
            u8::tls_deserialize(&mut inner).map_err(|_| WireValidationError::Malformed)?;
        if content_type != ContentType::Commit as u8 {
            return Err(WireValidationError::WrongContentType {
                expected: ContentType::Commit,
                actual: ContentType::try_from(content_type)
                    .map_err(|_| WireValidationError::Malformed)?,
            });
        }

        // `ProposalOrRef proposals<V>` is one TLS variable-length vector. By
        // isolating that vector first, every supported element can be split
        // into its exact canonical bytes without parsing the following path.
        let proposal_vector =
            VLBytes::tls_deserialize(&mut inner).map_err(|_| WireValidationError::Malformed)?;
        let mut proposals = proposal_vector.as_slice();
        let mut kinds = Vec::new();
        let mut exact_encodings = HashSet::new();
        while !proposals.is_empty() {
            let before = proposals;
            let proposal_or_ref_type =
                u8::tls_deserialize(&mut proposals).map_err(|_| WireValidationError::Malformed)?;
            if proposal_or_ref_type == ProposalOrRefType::Reference as u8 {
                return Err(WireValidationError::ReferencedCommitProposal);
            }
            if proposal_or_ref_type != ProposalOrRefType::Proposal as u8 {
                return Err(WireValidationError::Malformed);
            }
            let proposal_type =
                u16::tls_deserialize(&mut proposals).map_err(|_| WireValidationError::Malformed)?;
            let kind = match proposal_type {
                1 => {
                    WireKeyPackage::tls_deserialize(&mut proposals)
                        .map_err(|_| WireValidationError::Malformed)?;
                    RawCommitProposalKind::Add
                }
                3 => {
                    u32::tls_deserialize(&mut proposals)
                        .map_err(|_| WireValidationError::Malformed)?;
                    RawCommitProposalKind::Remove
                }
                _ => return Err(WireValidationError::UnsupportedCommitProposal),
            };
            let consumed = before.len() - proposals.len();
            if !exact_encodings.insert(before[..consumed].to_vec()) {
                return Err(WireValidationError::DuplicateCommitProposal);
            }
            kinds.push(kind);
            if kinds.len() > MAX_WELCOME_RECIPIENTS {
                return Err(WireValidationError::TooManyCommitProposals);
            }
        }
        let path_ciphertext_counts = validate_wire_commit_update_path(&mut inner)?;
        Ok((kinds, path_ciphertext_counts))
    }))
    .map_err(|_| WireValidationError::Malformed)?
}

/// Parse one exact wire-format-1 Commit and expose only routing metadata plus
/// the stateful `ProtocolMessage` seam. Proposal/extension/signature semantics
/// require the exact authoritative public state and are therefore enforced by
/// the later `PublicGroup` processing step, not guessed by this parser.
pub fn validate_public_commit(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<ValidatedPublicCommit, WireValidationError> {
    let message = preflight_exact_message(
        bytes,
        WireFormat::PublicMessage,
        max_bytes,
        MAX_PUBLIC_MESSAGE_WIRE_BYTES,
    )?;
    let public_message = match message.extract() {
        MlsMessageBodyIn::PublicMessage(message) => message,
        _ => {
            return Err(WireValidationError::WrongWireFormat {
                expected: WireFormat::PublicMessage,
                actual: u16::from_be_bytes([bytes[2], bytes[3]]),
            })
        }
    };
    if public_message.content_type() != ContentType::Commit {
        return Err(WireValidationError::WrongContentType {
            expected: ContentType::Commit,
            actual: public_message.content_type(),
        });
    }
    if !matches!(public_message.sender(), Sender::Member(_)) {
        return Err(WireValidationError::NonMemberCommitSender);
    }
    let group_id_length = public_message.group_id().as_slice().len();
    if group_id_length != CLEAN_GROUP_ID_BYTES {
        return Err(WireValidationError::WrongGroupIdLength {
            actual: group_id_length,
        });
    }
    let confirmation_tag_length = public_message
        .confirmation_tag()
        .ok_or(WireValidationError::Malformed)
        .and_then(serialized_vl_bytes_len)?;
    if confirmation_tag_length != XWING_HASH_BYTES {
        return Err(WireValidationError::WrongConfirmationTagLength {
            actual: confirmation_tag_length,
        });
    }
    if canonical_wrapped(WireFormat::PublicMessage, &public_message)? != bytes {
        return Err(WireValidationError::NonCanonicalEncoding);
    }
    let aad = public_message_aad(bytes)?;
    let (raw_proposals, path_ciphertext_counts) = raw_commit_profile(bytes)?;
    Ok(ValidatedPublicCommit {
        group_id: public_message.group_id().as_slice().to_vec(),
        epoch: public_message.epoch().as_u64(),
        aad,
        sender: public_message.sender().clone(),
        raw_proposals,
        path_ciphertext_counts,
        message: public_message,
    })
}

fn decode_openmls_leaf(
    leaf: &openmls::prelude::LeafNode,
) -> Result<WireLeafNode, WireValidationError> {
    let encoded = leaf
        .tls_serialize_detached()
        .map_err(|_| WireValidationError::InvalidCommitUpdatePath)?;
    tls_deserialize_exact_no_panic(&encoded)
        .map_err(|_| WireValidationError::InvalidCommitUpdatePath)
}

fn validate_commit_path_leaf(
    leaf: &openmls::prelude::LeafNode,
    prior_credential: &[u8],
    prior_signature_key: &[u8],
    prior_encryption_key: &[u8],
) -> Result<Vec<u8>, WireValidationError> {
    let wire_leaf = decode_openmls_leaf(leaf)?;
    if wire_leaf.payload.credential.credential_type != BASIC_CREDENTIAL_TYPE
        || wire_leaf.payload.credential.serialized_content.as_slice() != prior_credential
        || wire_leaf.payload.signature_key.as_slice() != prior_signature_key
    {
        return Err(WireValidationError::InvalidCommitUpdatePath);
    }
    match &wire_leaf.payload.source {
        WireLeafNodeSource::Commit(parent_hash)
            if matches!(parent_hash.as_slice().len(), 0 | XWING_HASH_BYTES) => {}
        _ => return Err(WireValidationError::InvalidCommitUpdatePath),
    }
    validate_clean_leaf_shape(&wire_leaf)
        .map_err(|_| WireValidationError::InvalidCommitUpdatePath)?;
    if wire_leaf.payload.encryption_key.as_slice() == prior_encryption_key {
        return Err(WireValidationError::InvalidCommitUpdatePath);
    }
    Ok(wire_leaf.payload.encryption_key.as_slice().to_vec())
}

fn validate_persisted_leaf(leaf: &openmls::prelude::LeafNode) -> Result<(), WireValidationError> {
    let wire_leaf = decode_openmls_leaf(leaf)?;
    if wire_leaf.payload.credential.credential_type != BASIC_CREDENTIAL_TYPE {
        return Err(WireValidationError::InconsistentCommitEffects);
    }
    match &wire_leaf.payload.source {
        WireLeafNodeSource::KeyPackage(_) => {}
        WireLeafNodeSource::Commit(parent_hash)
            if matches!(parent_hash.as_slice().len(), 0 | XWING_HASH_BYTES) => {}
        _ => return Err(WireValidationError::InconsistentCommitEffects),
    }
    validate_clean_leaf_shape(&wire_leaf)
        .map_err(|_| WireValidationError::InconsistentCommitEffects)
}

struct PendingCommitAdd {
    basic_credential: Vec<u8>,
    signature_key: Vec<u8>,
    key_package: ValidatedKeyPackage,
}

/// Verify the member signature and closed public MLS profile, then merge a
/// public Commit into a disposable clone of `prior_state`.
///
/// The authoritative state is never mutated. Higher-level transaction code
/// must compare the returned Add/Remove effects with the signed manifest and
/// only then persist `next_snapshot` and replace its state row atomically.
///
/// `PublicGroup` deliberately has no epoch secrets. OpenMLS therefore carries
/// the received confirmation tag into the public transcript state but cannot
/// verify its MAC here. This function checks that the tag is present, exactly
/// 32 bytes, differs from the prior tag, and matches both the outer-declared
/// successor coordinate and the returned snapshot. Clients must verify the MAC
/// and enter recovery instead of accepting the transition when that check
/// fails.
pub fn process_public_commit(
    prior_state: &PublicGroupState,
    commit: ValidatedPublicCommit,
    policy: PublicCommitValidationPolicy<'_>,
) -> Result<ProcessedPublicCommit, WireValidationError> {
    if policy.max_members == 0 {
        return Err(WireValidationError::InvalidLimit);
    }
    let maximum_members = policy.max_members.min(MAX_WELCOME_RECIPIENTS);
    let prior_snapshot = encode_public_group_snapshot(prior_state)
        .map_err(|_| WireValidationError::InvalidPublicState)?;
    let prior_binding = policy.trusted_prior_binding;
    let mut next_state = decode_public_group_snapshot(&prior_snapshot, prior_binding)
        .map_err(|_| WireValidationError::InvalidPublicState)?;

    if commit.group_id() != prior_binding.group_id() || commit.epoch() != prior_binding.epoch() {
        return Err(WireValidationError::CommitCoordinateMismatch);
    }
    if commit.aad() != policy.expected_aad {
        tracing::error!(
            "CommitAadMismatch: commit.aad (len={})={:02x?}, expected.aad (len={})={:02x?}",
            commit.aad().len(),
            commit.aad(),
            policy.expected_aad.len(),
            policy.expected_aad
        );
        return Err(WireValidationError::CommitAadMismatch);
    }
    let sender_index = match commit.sender() {
        Sender::Member(index) => index.u32(),
        _ => return Err(WireValidationError::NonMemberCommitSender),
    };

    let prior_members = prior_state
        .public_group()
        .members()
        .map(|member| (member.index.u32(), member))
        .collect::<HashMap<_, _>>();
    if prior_members.is_empty() || prior_members.len() > maximum_members {
        return Err(WireValidationError::TooManyMembers {
            actual: prior_members.len(),
            maximum: maximum_members,
        });
    }
    let sender_member = prior_members
        .get(&sender_index)
        .ok_or(WireValidationError::NonMemberCommitSender)?;

    let raw_proposals = commit.raw_proposals.clone();
    let path_ciphertext_counts = commit.path_ciphertext_counts.clone();
    let protocol_message = commit.into_protocol_message();
    let processed = std::panic::catch_unwind(AssertUnwindSafe(|| {
        next_state
            .public_group()
            .process_message(next_state.provider().crypto(), protocol_message)
    }))
    .map_err(|_| WireValidationError::InvalidPublicCommit)?
    .map_err(|_| WireValidationError::InvalidPublicCommit)?;
    if processed.group_id().as_slice() != prior_binding.group_id()
        || processed.epoch().as_u64() != prior_binding.epoch()
        || processed.sender() != &Sender::Member(sender_member.index)
        || processed.aad() != policy.expected_aad
        || processed.credential() != &sender_member.credential
    {
        return Err(WireValidationError::CommitCoordinateMismatch);
    }
    let staged_commit = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        _ => return Err(WireValidationError::InvalidPublicCommit),
    };

    let proposal_count = staged_commit.queued_proposals().count();
    if proposal_count != raw_proposals.len() {
        // OpenMLS' ProposalQueue deduplicates by ProposalRef. Comparing with
        // the retained exact wire cardinality prevents duplicate proposals
        // from collapsing into a smaller, apparently valid effect set.
        return Err(WireValidationError::DuplicateCommitProposal);
    }
    if proposal_count > MAX_WELCOME_RECIPIENTS {
        return Err(WireValidationError::TooManyCommitProposals);
    }

    let mut pending_adds = Vec::new();
    let mut removes = Vec::new();
    let mut removed_indices = HashSet::new();
    for (queued, raw_kind) in staged_commit.queued_proposals().zip(raw_proposals) {
        if queued.proposal_or_ref_type() != ProposalOrRefType::Proposal {
            return Err(WireValidationError::ReferencedCommitProposal);
        }
        if queued.sender() != &Sender::Member(sender_member.index) {
            return Err(WireValidationError::UnsupportedCommitProposal);
        }
        match (queued.proposal(), raw_kind) {
            (Proposal::Add(add), RawCommitProposalKind::Add) => {
                let key_package = add.key_package();
                let leaf = key_package.leaf_node();
                if leaf.credential().credential_type() != CredentialType::Basic {
                    return Err(WireValidationError::InvalidCommitAdd);
                }
                let basic_credential = leaf.credential().serialized_content().to_vec();
                let signature_key = leaf.signature_key().as_slice().to_vec();
                let wrapped = canonical_wrapped(WireFormat::KeyPackage, key_package)
                    .map_err(|_| WireValidationError::InvalidCommitAdd)?;
                let validated = validate_key_package(
                    &wrapped,
                    KeyPackageValidationPolicy {
                        expected_basic_credential: &basic_credential,
                        expected_signature_key: &signature_key,
                        now_unix_seconds: policy.now_unix_seconds,
                        max_bytes: MAX_KEY_PACKAGE_WIRE_BYTES,
                    },
                )
                .map_err(|_| WireValidationError::InvalidCommitAdd)?;
                pending_adds.push(PendingCommitAdd {
                    basic_credential,
                    signature_key,
                    key_package: validated,
                });
            }
            (Proposal::Remove(remove), RawCommitProposalKind::Remove) => {
                let removed = remove.removed().u32();
                if removed == sender_index {
                    return Err(WireValidationError::CommitSenderSelfRemove);
                }
                let member = prior_members
                    .get(&removed)
                    .ok_or(WireValidationError::InconsistentCommitEffects)?;
                if !removed_indices.insert(removed) {
                    return Err(WireValidationError::InconsistentCommitEffects);
                }
                removes.push(ValidatedCommitRemove {
                    leaf_index: removed,
                    basic_credential: member.credential.serialized_content().to_vec(),
                    signature_key: member.signature_key.clone(),
                });
            }
            (Proposal::Update(_), _)
            | (Proposal::PreSharedKey(_), _)
            | (Proposal::ReInit(_), _)
            | (Proposal::ExternalInit(_), _)
            | (Proposal::GroupContextExtensions(_), _)
            | (Proposal::SelfRemove, _)
            | (Proposal::Custom(_), _)
            | (Proposal::Add(_), RawCommitProposalKind::Remove)
            | (Proposal::Remove(_), RawCommitProposalKind::Add) => {
                return Err(WireValidationError::UnsupportedCommitProposal)
            }
        }
    }

    let path_leaf = staged_commit
        .update_path_leaf_node()
        .ok_or(WireValidationError::MissingCommitUpdatePath)?;
    let next_sender_encryption_key = validate_commit_path_leaf(
        path_leaf,
        sender_member.credential.serialized_content(),
        &sender_member.signature_key,
        &sender_member.encryption_key,
    )?;
    if staged_commit
        .group_context()
        .extensions()
        .iter()
        .next()
        .is_some()
    {
        return Err(WireValidationError::UnsupportedExtensions);
    }
    let expected_next_epoch = prior_binding
        .epoch()
        .checked_add(1)
        .ok_or(WireValidationError::CommitCoordinateMismatch)?;
    let expected_next_state_version = prior_binding
        .state_version()
        .checked_add(1)
        .ok_or(WireValidationError::CommitCoordinateMismatch)?;
    if policy.expected_next_coordinate.conversation_id() != prior_binding.conversation_id()
        || policy.expected_next_coordinate.generation() != prior_binding.generation()
        || policy.expected_next_coordinate.state_version() != expected_next_state_version
        || policy.expected_next_coordinate.group_id() != prior_binding.group_id()
        || policy.expected_next_coordinate.epoch() != expected_next_epoch
        || policy.expected_next_coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
    {
        return Err(WireValidationError::CommitCoordinateMismatch);
    }
    if staged_commit.group_context().group_id().as_slice() != prior_binding.group_id()
        || staged_commit.group_context().epoch().as_u64() != expected_next_epoch
    {
        return Err(WireValidationError::CommitCoordinateMismatch);
    }

    let merge_result = {
        let (provider, public_group) = next_state.parts_mut();
        std::panic::catch_unwind(AssertUnwindSafe(|| {
            public_group.merge_commit(provider.storage(), *staged_commit)
        }))
    };
    merge_result
        .map_err(|_| WireValidationError::InvalidPublicCommit)?
        .map_err(|_| WireValidationError::InvalidPublicCommit)?;

    let next_snapshot = encode_public_group_snapshot(&next_state)
        .map_err(|_| WireValidationError::InvalidPublicState)?;
    let next_binding =
        public_group_snapshot_binding(&next_state, &next_snapshot, policy.expected_next_coordinate)
            .map_err(|_| WireValidationError::CommitCoordinateMismatch)?;
    // Reloading is both the atomicity boundary and the cross-record coherence
    // proof for the exact bytes handed to persistence.
    next_state = decode_public_group_snapshot(&next_snapshot, &next_binding)
        .map_err(|_| WireValidationError::InvalidPublicState)?;

    if next_binding.group_id() != prior_binding.group_id()
        || next_binding.epoch() != expected_next_epoch
        || next_binding.group_context_hash() == prior_binding.group_context_hash()
        || next_binding.confirmation_tag() == prior_binding.confirmation_tag()
    {
        return Err(WireValidationError::CommitCoordinateMismatch);
    }

    let next_members = next_state
        .public_group()
        .members()
        .map(|member| (member.index.u32(), member))
        .collect::<HashMap<_, _>>();
    let expected_member_count = prior_members
        .len()
        .checked_sub(removes.len())
        .and_then(|count| count.checked_add(pending_adds.len()))
        .ok_or(WireValidationError::InconsistentCommitEffects)?;
    if expected_member_count == 0
        || expected_member_count > maximum_members
        || next_members.len() != expected_member_count
    {
        return Err(WireValidationError::TooManyMembers {
            actual: next_members.len(),
            maximum: maximum_members,
        });
    }

    for member in next_members.values() {
        let leaf = next_state
            .public_group()
            .leaf(member.index)
            .ok_or(WireValidationError::InconsistentCommitEffects)?;
        validate_persisted_leaf(leaf)?;
    }
    for (index, prior_member) in &prior_members {
        if removed_indices.contains(index) {
            continue;
        }
        let next_member = next_members
            .get(index)
            .ok_or(WireValidationError::InconsistentCommitEffects)?;
        if next_member.credential != prior_member.credential
            || next_member.signature_key != prior_member.signature_key
            || (*index == sender_index && next_member.encryption_key != next_sender_encryption_key)
            || (*index != sender_index && next_member.encryption_key != prior_member.encryption_key)
        {
            return Err(WireValidationError::InconsistentCommitEffects);
        }
    }

    let mut matched_add_indices = HashSet::new();
    let mut adds = Vec::with_capacity(pending_adds.len());
    for pending in pending_adds {
        let member = next_members
            .values()
            .find(|member| {
                member.credential.serialized_content() == pending.basic_credential
                    && member.signature_key == pending.signature_key
                    && member.encryption_key == pending.key_package.leaf_encryption_key
            })
            .ok_or(WireValidationError::InconsistentCommitEffects)?;
        if !matched_add_indices.insert(member.index.u32()) {
            return Err(WireValidationError::InconsistentCommitEffects);
        }
        adds.push(ValidatedCommitAdd {
            leaf_index: member.index.u32(),
            basic_credential: pending.basic_credential,
            signature_key: pending.signature_key,
            key_package: pending.key_package,
        });
    }

    let expected_ciphertext_counts =
        expected_update_path_ciphertext_counts(&next_state, sender_index, &matched_add_indices)
            .map_err(|_| WireValidationError::InconsistentCommitEffects)?;
    if path_ciphertext_counts != expected_ciphertext_counts {
        return Err(WireValidationError::InvalidCommitUpdatePath);
    }

    Ok(ProcessedPublicCommit {
        next_state,
        next_snapshot,
        next_binding,
        adds,
        removes,
        sender_update: ValidatedCommitSenderUpdate {
            leaf_index: sender_index,
            basic_credential: sender_member.credential.serialized_content().to_vec(),
            signature_key: sender_member.signature_key.clone(),
            prior_encryption_key: sender_member.encryption_key.clone(),
            next_encryption_key: next_sender_encryption_key,
        },
    })
}

/// Verify the signature on one exact wire-format-4 GroupInfo under the closed
/// clean profile. The returned value owns a public-state `PublicGroup` seam.
/// Its confirmation tag is bound exactly but remains an opaque, client-verified
/// MAC because this public service has no epoch secrets.
pub fn validate_group_info(
    bytes: &[u8],
    policy: GroupInfoValidationPolicy<'_>,
) -> Result<ValidatedGroupInfo, WireValidationError> {
    if policy.max_ratchet_tree_bytes == 0 || policy.max_members == 0 {
        return Err(WireValidationError::InvalidLimit);
    }
    let message = preflight_exact_message(
        bytes,
        WireFormat::GroupInfo,
        policy.max_bytes,
        MAX_GROUP_INFO_WIRE_BYTES,
    )?;
    let verifiable_group_info = match message.extract() {
        MlsMessageBodyIn::GroupInfo(group_info) => group_info,
        _ => {
            return Err(WireValidationError::WrongWireFormat {
                expected: WireFormat::GroupInfo,
                actual: u16::from_be_bytes([bytes[2], bytes[3]]),
            })
        }
    };

    let envelope = tls_deserialize_exact_no_panic::<WireGroupInfoEnvelope>(bytes)
        .map_err(|_| WireValidationError::Malformed)?;
    let canonical = envelope
        .tls_serialize_detached()
        .map_err(|_| WireValidationError::Malformed)?;
    if canonical != bytes {
        return Err(WireValidationError::NonCanonicalEncoding);
    }
    if envelope.version != MLS_1_0_WIRE_VALUE
        || envelope.group_info.context.protocol_version != MLS_1_0_WIRE_VALUE
    {
        return Err(WireValidationError::UnsupportedProtocolVersion {
            actual: envelope.group_info.context.protocol_version,
        });
    }
    if envelope.wire_format != WireFormat::GroupInfo as u16 {
        return Err(WireValidationError::WrongWireFormat {
            expected: WireFormat::GroupInfo,
            actual: envelope.wire_format,
        });
    }
    if envelope.group_info.context.ciphersuite != XWING_CIPHERSUITE as u16 {
        return Err(WireValidationError::UnsupportedCiphersuite {
            actual: envelope.group_info.context.ciphersuite,
        });
    }
    let group_id_length = envelope.group_info.context.group_id.as_slice().len();
    if group_id_length != CLEAN_GROUP_ID_BYTES {
        return Err(WireValidationError::WrongGroupIdLength {
            actual: group_id_length,
        });
    }
    let tree_hash_length = envelope.group_info.context.tree_hash.as_slice().len();
    if tree_hash_length != XWING_HASH_BYTES {
        return Err(WireValidationError::WrongTreeHashLength {
            actual: tree_hash_length,
        });
    }
    let confirmation_tag_length = envelope.group_info.confirmation_tag.as_slice().len();
    if confirmation_tag_length != XWING_HASH_BYTES {
        return Err(WireValidationError::WrongConfirmationTagLength {
            actual: confirmation_tag_length,
        });
    }
    let group_info_extension_types = envelope
        .group_info
        .extensions
        .iter()
        .map(|extension| extension.extension_type)
        .collect::<Vec<_>>();
    if group_info_extension_types != [2, 4] || !envelope.group_info.context.extensions.is_empty() {
        return Err(WireValidationError::UnsupportedGroupInfoExtensions);
    }
    if envelope.group_info.context.epoch != 0 || envelope.group_info.signer != 0 {
        return Err(WireValidationError::GroupInfoNotSingletonGenesis);
    }
    if !envelope
        .group_info
        .context
        .confirmed_transcript_hash
        .as_slice()
        .is_empty()
    {
        return Err(WireValidationError::NonemptyGenesisConfirmedTranscriptHash);
    }

    let ratchet_tree_extension = &envelope.group_info.extensions[0];
    tls_deserialize_exact_no_panic::<RatchetTreeExtension>(
        ratchet_tree_extension.extension_data.as_slice(),
    )
    .map_err(|_| WireValidationError::NonCanonicalEncoding)?;
    let external_pub_extension = &envelope.group_info.extensions[1];
    let external_pub = tls_deserialize_exact_no_panic::<ExternalPubExtension>(
        external_pub_extension.extension_data.as_slice(),
    )
    .map_err(|_| WireValidationError::NonCanonicalEncoding)?;
    validate_xwing_public_key(external_pub.external_pub().as_slice())?;

    let creator_leaf =
        exact_singleton_ratchet_tree_leaf(ratchet_tree_extension.extension_data.as_slice())?;
    validate_clean_leaf_profile(&creator_leaf, policy.now_unix_seconds)?;
    let group_context_bytes = envelope
        .group_info
        .context
        .tls_serialize_detached()
        .map_err(|_| WireValidationError::Malformed)?;
    let group_context_hash: [u8; 32] = Sha256::digest(&group_context_bytes).into();
    let confirmation_tag: [u8; 32] = envelope
        .group_info
        .confirmation_tag
        .as_slice()
        .try_into()
        .map_err(|_| WireValidationError::WrongConfirmationTagLength {
            actual: confirmation_tag_length,
        })?;

    let ratchet_tree = verifiable_group_info
        .extensions()
        .ratchet_tree()
        .ok_or(WireValidationError::MissingRatchetTree)?
        .ratchet_tree()
        .clone();
    let ratchet_tree_bytes = ratchet_tree.tls_serialized_len();
    if ratchet_tree_bytes > policy.max_ratchet_tree_bytes {
        return Err(WireValidationError::RatchetTreeTooLarge {
            actual: ratchet_tree_bytes,
            maximum: policy.max_ratchet_tree_bytes,
        });
    }

    let provider = openmls_libcrux_crypto::Provider::new()
        .map_err(|_| WireValidationError::ProviderInitialization)?;
    let expected_public_key = SignaturePublicKey::from(policy.expected_signature_key)
        .into_signature_public_key_enriched(
            verifiable_group_info.ciphersuite().signature_algorithm(),
        );
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        verifiable_group_info.verify_no_out(provider.crypto(), &expected_public_key)
    }))
    .map_err(|_| WireValidationError::WrongGroupInfoSigner)?
    .map_err(|_| WireValidationError::WrongGroupInfoSigner)?;

    let (public_group, _group_info) = std::panic::catch_unwind(AssertUnwindSafe(|| {
        PublicGroup::from_external_at(
            provider.crypto(),
            provider.storage(),
            ratchet_tree,
            verifiable_group_info,
            ProposalStore::new(),
            openmls::prelude::UnixSeconds::new(policy.now_unix_seconds),
        )
    }))
    .map_err(|_| WireValidationError::InvalidGroupInfo)?
    .map_err(|_| WireValidationError::InvalidGroupInfo)?;

    if public_group.version() != openmls::prelude::ProtocolVersion::Mls10
        || public_group.ciphersuite() != XWING_CIPHERSUITE
        || public_group.group_context().epoch().as_u64() != 0
    {
        return Err(WireValidationError::GroupInfoNotSingletonGenesis);
    }
    let members = public_group.members().collect::<Vec<_>>();
    if members.len() > policy.max_members {
        return Err(WireValidationError::TooManyMembers {
            actual: members.len(),
            maximum: policy.max_members,
        });
    }
    let [member] = members.as_slice() else {
        return Err(WireValidationError::GroupInfoNotSingletonGenesis);
    };
    if member.signature_key.as_slice() != policy.expected_signature_key {
        return Err(WireValidationError::WrongGroupInfoSigner);
    }
    validate_xwing_public_key(&member.encryption_key)?;
    if member.credential.credential_type() != CredentialType::Basic
        || member.credential.serialized_content() != policy.expected_basic_credential
    {
        return Err(WireValidationError::WrongGroupInfoCredential);
    }

    Ok(ValidatedGroupInfo {
        canonical_bytes: canonical,
        group_context_hash,
        confirmation_tag,
        public_state: PublicGroupState::new(provider, public_group),
    })
}

/// Validate one exact wire-format-3 XWing Welcome without decrypting it.
pub fn validate_welcome(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<ValidatedWelcome, WireValidationError> {
    let message = preflight_exact_message(
        bytes,
        WireFormat::Welcome,
        max_bytes,
        MAX_WELCOME_WIRE_BYTES,
    )?;
    let welcome = match message.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => {
            return Err(WireValidationError::WrongWireFormat {
                expected: WireFormat::Welcome,
                actual: u16::from_be_bytes([bytes[2], bytes[3]]),
            })
        }
    };
    let canonical = canonical_wrapped(WireFormat::Welcome, &welcome)?;
    if canonical != bytes {
        return Err(WireValidationError::NonCanonicalEncoding);
    }
    let envelope = tls_deserialize_exact_no_panic::<WireWelcomeEnvelope>(&canonical)
        .map_err(|_| WireValidationError::Malformed)?;
    if envelope
        .tls_serialize_detached()
        .map_err(|_| WireValidationError::Malformed)?
        != canonical
    {
        return Err(WireValidationError::NonCanonicalEncoding);
    }
    let actual_ciphersuite = envelope.welcome.ciphersuite;
    if actual_ciphersuite != XWING_CIPHERSUITE as u16 {
        return Err(WireValidationError::UnsupportedCiphersuite {
            actual: actual_ciphersuite,
        });
    }
    if envelope.welcome.secrets.is_empty() {
        return Err(WireValidationError::EmptyWelcome);
    }
    if envelope.welcome.secrets.len() > MAX_WELCOME_RECIPIENTS {
        return Err(WireValidationError::TooManyWelcomeRecipients {
            actual: envelope.welcome.secrets.len(),
            maximum: MAX_WELCOME_RECIPIENTS,
        });
    }
    let mut seen = HashSet::with_capacity(envelope.welcome.secrets.len());
    let mut key_package_refs = Vec::with_capacity(envelope.welcome.secrets.len());
    for encrypted_group_secrets in &envelope.welcome.secrets {
        validate_xwing_kem_output(
            encrypted_group_secrets
                .encrypted_group_secrets
                .kem_output
                .as_slice(),
        )?;
        if encrypted_group_secrets
            .encrypted_group_secrets
            .ciphertext
            .as_slice()
            .len()
            < 16
        {
            return Err(WireValidationError::InvalidHpkeCiphertext);
        }
        let raw_ref: [u8; 32] = encrypted_group_secrets
            .new_member
            .as_slice()
            .try_into()
            .map_err(|_| WireValidationError::WrongWelcomeKeyPackageRefLength {
                actual: encrypted_group_secrets.new_member.as_slice().len(),
            })?;
        if !seen.insert(raw_ref) {
            return Err(WireValidationError::DuplicateWelcomeKeyPackageRef);
        }
        key_package_refs.push(raw_ref);
    }
    Ok(ValidatedWelcome {
        inner_bytes: canonical[4..].to_vec(),
        key_package_refs,
    })
}

/// Validate one exact wire-format-2 Application ciphertext and expose only
/// the metadata that RFC 9420 intentionally leaves visible. This function has
/// no group state or key material and cannot decrypt the message.
pub fn validate_private_application(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<ValidatedPrivateApplication, WireValidationError> {
    let message = preflight_exact_message(
        bytes,
        WireFormat::PrivateMessage,
        max_bytes,
        MAX_PRIVATE_MESSAGE_WIRE_BYTES,
    )?;
    let private_message = match message.extract() {
        MlsMessageBodyIn::PrivateMessage(message) => message,
        _ => {
            return Err(WireValidationError::WrongWireFormat {
                expected: WireFormat::PrivateMessage,
                actual: u16::from_be_bytes([bytes[2], bytes[3]]),
            })
        }
    };
    let canonical = canonical_wrapped(WireFormat::PrivateMessage, &private_message)?;
    if canonical != bytes {
        return Err(WireValidationError::NonCanonicalEncoding);
    }
    let aad = private_message.aad().to_vec();
    let protocol_message = ProtocolMessage::from(private_message);
    if protocol_message.content_type() != ContentType::Application {
        return Err(WireValidationError::WrongContentType {
            expected: ContentType::Application,
            actual: protocol_message.content_type(),
        });
    }
    let group_id_length = protocol_message.group_id().as_slice().len();
    if group_id_length != CLEAN_GROUP_ID_BYTES {
        return Err(WireValidationError::WrongGroupIdLength {
            actual: group_id_length,
        });
    }
    Ok(ValidatedPrivateApplication {
        group_id: protocol_message.group_id().as_slice().to_vec(),
        epoch: protocol_message.epoch().as_u64(),
        aad,
        inner_bytes: canonical[4..].to_vec(),
    })
}
