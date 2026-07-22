//! Canonical persistence for an OpenMLS [`PublicGroup`].
//!
//! The format is deliberately narrow: it contains exactly the four public
//! records written by OpenMLS' `PublicGroup`, never member secrets, private
//! keys, proposals, or provider randomness. Both dependency versions are part
//! of the envelope because the memory-storage JSON representation is not a
//! stable protocol format on its own.

use std::{
    collections::{HashMap, HashSet},
    panic::AssertUnwindSafe,
};

use openmls::{
    group::PublicGroup,
    prelude::{Ciphersuite, CredentialType, GroupId, ProtocolVersion},
};
use openmls_libcrux_crypto::Provider;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tls_codec::{
    Deserialize as TlsDeserialize, Serialize as TlsSerialize, TlsDeserialize, TlsSerialize,
    TlsSize, VLBytes,
};

use super::{xwing_public_key_is_valid, MAX_BASIC_CREDENTIAL_BYTES, MIN_BASIC_CREDENTIAL_BYTES};

const SNAPSHOT_MAGIC: &[u8; 8] = b"CBPGSNAP";
const SNAPSHOT_SCHEMA: u16 = 1;
const OPENMLS_VERSION: &[u8] = b"0.8.1";
const STORAGE_VERSION: &[u8] = b"0.5.0";
const PUBLIC_RECORD_COUNT: usize = 4;
const MAX_PUBLIC_GROUP_LEAVES: usize = 100;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const MAX_ENVELOPE_RECORDS: usize = 256;
const STORAGE_SCHEMA_BYTES: [u8; 2] = [0x00, 0x01];
const ALLOWED_PUBLIC_LABELS: [&[u8]; PUBLIC_RECORD_COUNT] = [
    b"Tree",
    b"GroupContext",
    b"InterimTranscriptHash",
    b"ConfirmationTag",
];

// TLS mirrors used only to recompute the RFC 9420 tree hash after loading the
// storage representation. OpenMLS deliberately keeps TreeSync's cached hash
// private, and PublicGroup::load performs no cross-record coherence checks.
#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct SnapshotWireLeafNode {
    payload: SnapshotWireLeafNodeTbs,
    signature: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct SnapshotWireLeafNodeTbs {
    encryption_key: VLBytes,
    signature_key: VLBytes,
    credential: SnapshotWireCredential,
    capabilities: SnapshotWireCapabilities,
    source: SnapshotWireLeafNodeSource,
    extensions: Vec<SnapshotWireExtension>,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct SnapshotWireCredential {
    credential_type: u16,
    serialized_content: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct SnapshotWireCapabilities {
    versions: Vec<u16>,
    ciphersuites: Vec<u16>,
    extensions: Vec<u16>,
    proposals: Vec<u16>,
    credentials: Vec<u16>,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
enum SnapshotWireLeafNodeSource {
    #[tls_codec(discriminant = 1)]
    KeyPackage(SnapshotWireLifetime),
    #[tls_codec(discriminant = 2)]
    Update,
    #[tls_codec(discriminant = 3)]
    Commit(VLBytes),
}

#[derive(Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct SnapshotWireLifetime {
    not_before: u64,
    not_after: u64,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct SnapshotWireExtension {
    extension_type: u16,
    extension_data: VLBytes,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct SnapshotWireParentNode {
    encryption_key: VLBytes,
    parent_hash: VLBytes,
    unmerged_leaves: Vec<u32>,
}

#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
enum SnapshotWireNode {
    #[tls_codec(discriminant = 1)]
    LeafNode(Box<SnapshotWireLeafNode>),
    #[tls_codec(discriminant = 2)]
    ParentNode(Box<SnapshotWireParentNode>),
}

#[derive(TlsSerialize, TlsSize)]
struct SnapshotLeafHashInput<'a> {
    leaf_index: u32,
    leaf_node: Option<&'a SnapshotWireLeafNode>,
}

#[derive(TlsSerialize, TlsSize)]
struct SnapshotParentHashInput<'a> {
    parent_node: Option<&'a SnapshotWireParentNode>,
    left_hash: VLBytes,
    right_hash: VLBytes,
}

#[derive(TlsSerialize, TlsSize)]
#[repr(u8)]
enum SnapshotTreeHashNode<'a> {
    #[tls_codec(discriminant = 1)]
    Leaf(SnapshotLeafHashInput<'a>),
    #[tls_codec(discriminant = 2)]
    Parent(SnapshotParentHashInput<'a>),
}

#[derive(TlsSerialize, TlsSize)]
struct SnapshotTreeHashInput<'a> {
    node: SnapshotTreeHashNode<'a>,
}

pub const MAX_PUBLIC_GROUP_SNAPSHOT_BYTES: usize = 8 * 1_048_576;
pub const MAX_SNAPSHOT_KEY_BYTES: usize = 65_536;
pub const MAX_SNAPSHOT_VALUE_BYTES: usize = 4_194_304;
/// Largest integer representable exactly by the protocol's JSON transport.
pub const MAX_PROTOCOL_INTEGER: u64 = 9_007_199_254_740_991;

/// A public MLS group and the exact provider storage that backs it.
///
/// Keeping these together prevents callers from accidentally merging a
/// validated commit into one `PublicGroup` while persisting through an empty or
/// unrelated provider.
pub struct PublicGroupState {
    provider: Provider,
    public_group: PublicGroup,
}

impl std::fmt::Debug for PublicGroupState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicGroupState")
            .field(
                "group_id_len",
                &self.public_group.group_id().as_slice().len(),
            )
            .field("epoch", &self.public_group.group_context().epoch().as_u64())
            .finish_non_exhaustive()
    }
}

impl PublicGroupState {
    pub(crate) fn new(provider: Provider, public_group: PublicGroup) -> Self {
        Self {
            provider,
            public_group,
        }
    }

    pub(crate) fn provider(&self) -> &Provider {
        &self.provider
    }

    pub fn public_group(&self) -> &PublicGroup {
        &self.public_group
    }

    /// Borrow the matched provider and group only inside the protocol module.
    /// External callers receive replacement states from the transactional
    /// Commit processor and cannot mutate persisted records independently.
    pub(crate) fn parts_mut(&mut self) -> (&Provider, &mut PublicGroup) {
        (&self.provider, &mut self.public_group)
    }
}

/// Lifecycle value carried by the separately authenticated conversation head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicGroupSnapshotLifecycle {
    Active,
    Superseded,
}

/// Full outer conversation coordinate, excluding only the snapshot digest.
///
/// This value must be decoded from and authenticated with the locked current
/// conversation head. It must never be reconstructed from snapshot contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicGroupSnapshotCoordinate {
    conversation_id: [u8; 16],
    generation: u64,
    state_version: u64,
    group_id: [u8; 32],
    epoch: u64,
    group_context_hash: [u8; 32],
    // Opaque client-verification evidence. Public-state code binds these exact
    // bytes but cannot verify the confirmation MAC without epoch secrets.
    confirmation_tag: [u8; 32],
    lifecycle: PublicGroupSnapshotLifecycle,
}

/// One exact public MLS leaf expected by the separately locked database head.
///
/// The clean profile fixes the credential type to `Basic`; the remaining
/// fields are compared byte-for-byte with OpenMLS' loaded member projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicGroupSnapshotLeaf {
    leaf_index: u32,
    basic_credential: Vec<u8>,
    signature_key: Vec<u8>,
    encryption_key: Vec<u8>,
}

impl PublicGroupSnapshotLeaf {
    pub fn new(
        leaf_index: u32,
        basic_credential: Vec<u8>,
        signature_key: Vec<u8>,
        encryption_key: Vec<u8>,
    ) -> Self {
        Self {
            leaf_index,
            basic_credential,
            signature_key,
            encryption_key,
        }
    }

    pub const fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    pub fn basic_credential(&self) -> &[u8] {
        &self.basic_credential
    }

    pub fn signature_key(&self) -> &[u8] {
        &self.signature_key
    }

    pub fn encryption_key(&self) -> &[u8] {
        &self.encryption_key
    }
}

/// Canonical public-tree summary persisted independently in the locked head.
///
/// The GroupContext hash already seals the full RFC tree, including leaf
/// sources, capabilities, parent hashes, extensions, and signatures. This
/// additional summary makes the database's exact logical leaf projection an
/// unavoidable load-time input rather than a transaction-layer convention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicGroupSnapshotTreeSummary {
    tree_hash: [u8; 32],
    leaves: Vec<PublicGroupSnapshotLeaf>,
}

impl PublicGroupSnapshotTreeSummary {
    pub fn new(tree_hash: [u8; 32], leaves: Vec<PublicGroupSnapshotLeaf>) -> Self {
        Self { tree_hash, leaves }
    }

    pub const fn tree_hash(&self) -> &[u8; 32] {
        &self.tree_hash
    }

    pub fn leaves(&self) -> &[PublicGroupSnapshotLeaf] {
        &self.leaves
    }
}

impl PublicGroupSnapshotCoordinate {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        conversation_id: [u8; 16],
        generation: u64,
        state_version: u64,
        group_id: [u8; 32],
        epoch: u64,
        group_context_hash: [u8; 32],
        confirmation_tag: [u8; 32],
        lifecycle: PublicGroupSnapshotLifecycle,
    ) -> Self {
        Self {
            conversation_id,
            generation,
            state_version,
            group_id,
            epoch,
            group_context_hash,
            confirmation_tag,
            lifecycle,
        }
    }

    pub const fn conversation_id(&self) -> &[u8; 16] {
        &self.conversation_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn state_version(&self) -> u64 {
        self.state_version
    }

    pub const fn group_id(&self) -> &[u8; 32] {
        &self.group_id
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn group_context_hash(&self) -> &[u8; 32] {
        &self.group_context_hash
    }

    /// Exact opaque confirmation-tag bytes carried by the MLS artifact.
    /// Clients with epoch secrets, not this public-state layer, verify the MAC.
    pub const fn confirmation_tag(&self) -> &[u8; 32] {
        &self.confirmation_tag
    }

    pub const fn lifecycle(&self) -> PublicGroupSnapshotLifecycle {
        self.lifecycle
    }
}

/// Database-authenticated coordinate for one exact public-state snapshot.
///
/// The digest prevents record splicing and substitution of another otherwise
/// valid snapshot when it is compared with the separately authenticated,
/// current binding. The MLS coordinate makes a mismatched database row fail
/// closed even if its blob column is accidentally paired with the wrong
/// metadata.
///
/// A snapshot cannot detect rollback of both the blob and its complete binding.
/// Callers must obtain this binding from a separately trusted monotonic
/// conversation coordinate (generation/state version), never from the snapshot
/// being decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicGroupSnapshotBinding {
    coordinate: PublicGroupSnapshotCoordinate,
    snapshot_sha256: [u8; 32],
    tree_summary: PublicGroupSnapshotTreeSummary,
}

impl PublicGroupSnapshotBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        conversation_id: [u8; 16],
        generation: u64,
        state_version: u64,
        group_id: [u8; 32],
        epoch: u64,
        group_context_hash: [u8; 32],
        confirmation_tag: [u8; 32],
        lifecycle: PublicGroupSnapshotLifecycle,
        snapshot_sha256: [u8; 32],
        tree_summary: PublicGroupSnapshotTreeSummary,
    ) -> Self {
        Self {
            coordinate: PublicGroupSnapshotCoordinate::new(
                conversation_id,
                generation,
                state_version,
                group_id,
                epoch,
                group_context_hash,
                confirmation_tag,
                lifecycle,
            ),
            snapshot_sha256,
            tree_summary,
        }
    }

    pub const fn coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.coordinate
    }

    pub const fn conversation_id(&self) -> &[u8; 16] {
        self.coordinate.conversation_id()
    }

    pub const fn generation(&self) -> u64 {
        self.coordinate.generation()
    }

    pub const fn state_version(&self) -> u64 {
        self.coordinate.state_version()
    }

    pub const fn group_id(&self) -> &[u8; 32] {
        self.coordinate.group_id()
    }

    pub const fn epoch(&self) -> u64 {
        self.coordinate.epoch()
    }

    pub const fn group_context_hash(&self) -> &[u8; 32] {
        self.coordinate.group_context_hash()
    }

    pub const fn confirmation_tag(&self) -> &[u8; 32] {
        self.coordinate.confirmation_tag()
    }

    pub const fn lifecycle(&self) -> PublicGroupSnapshotLifecycle {
        self.coordinate.lifecycle()
    }

    pub const fn snapshot_sha256(&self) -> &[u8; 32] {
        &self.snapshot_sha256
    }

    pub const fn tree_summary(&self) -> &PublicGroupSnapshotTreeSummary {
        &self.tree_summary
    }
}

pub fn public_group_snapshot_sha256(encoded: &[u8]) -> [u8; 32] {
    Sha256::digest(encoded).into()
}

/// Derive the canonical public-tree summary that transaction code must persist
/// beside the snapshot and full conversation coordinate.
pub fn public_group_snapshot_tree_summary(
    state: &PublicGroupState,
) -> Result<PublicGroupSnapshotTreeSummary, PublicGroupSnapshotError> {
    tree_summary_from_public_group(state.public_group())
}

/// Bind an encoded snapshot to the trusted in-memory state that produced it.
///
/// `trusted` must come from the separately authenticated, locked conversation
/// head. Every MLS-derivable field is compared with `state`, and `encoded` must
/// be the exact canonical encoding of that state, before the digest is added.
/// Confirmation-tag comparison is byte-for-byte binding only; it is not MAC
/// verification, which requires client-held epoch secrets.
pub fn public_group_snapshot_binding(
    state: &PublicGroupState,
    encoded: &[u8],
    trusted: &PublicGroupSnapshotCoordinate,
) -> Result<PublicGroupSnapshotBinding, PublicGroupSnapshotError> {
    validate_trusted_coordinate(trusted)?;
    if encode_public_group_snapshot(state)? != encoded {
        return Err(PublicGroupSnapshotError::SnapshotStateMismatch);
    }
    let group_id: [u8; 32] = state
        .public_group
        .group_id()
        .as_slice()
        .try_into()
        .map_err(|_| PublicGroupSnapshotError::WrongGroupIdLength)?;
    let context_bytes = state
        .public_group
        .group_context()
        .tls_serialize_detached()
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    let group_context_hash: [u8; 32] = Sha256::digest(context_bytes).into();
    let encoded_tag = state
        .public_group
        .confirmation_tag()
        .tls_serialize_detached()
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    let tag = VLBytes::tls_deserialize_exact(&encoded_tag)
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    let confirmation_tag: [u8; 32] = tag
        .as_slice()
        .try_into()
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    if trusted.group_id != group_id
        || trusted.epoch != state.public_group.group_context().epoch().as_u64()
        || trusted.group_context_hash != group_context_hash
        || trusted.confirmation_tag != confirmation_tag
    {
        return Err(PublicGroupSnapshotError::SnapshotCoordinateMismatch);
    }
    let tree_summary = public_group_snapshot_tree_summary(state)?;
    Ok(PublicGroupSnapshotBinding::new(
        trusted.conversation_id,
        trusted.generation,
        trusted.state_version,
        trusted.group_id,
        trusted.epoch,
        trusted.group_context_hash,
        trusted.confirmation_tag,
        trusted.lifecycle,
        public_group_snapshot_sha256(encoded),
        tree_summary,
    ))
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PublicGroupSnapshotError {
    #[error("public group snapshot is empty")]
    Empty,
    #[error("public group snapshot is {actual} bytes; maximum is {maximum}")]
    InputTooLarge { actual: usize, maximum: usize },
    #[error("public group snapshot is truncated")]
    Truncated,
    #[error("public group snapshot length arithmetic overflowed")]
    LengthOverflow,
    #[error("public group snapshot has trailing bytes")]
    TrailingData,
    #[error("public group snapshot magic is invalid")]
    InvalidMagic,
    #[error("unsupported public group snapshot schema {actual}")]
    UnsupportedSchema { actual: u16 },
    #[error("public group snapshot requires a different OpenMLS version")]
    UnsupportedOpenMlsVersion,
    #[error("public group snapshot requires a different storage version")]
    UnsupportedStorageVersion,
    #[error("snapshot envelope contains {actual} records; supported range is 1..={maximum}")]
    InvalidEnvelopeRecordCount { actual: usize, maximum: usize },
    #[error("public group snapshot contains {actual} records; expected exactly {expected}")]
    WrongPublicRecordCount { actual: usize, expected: usize },
    #[error("snapshot key length {actual} is invalid")]
    InvalidKeyLength { actual: usize },
    #[error("snapshot value length {actual} is invalid")]
    InvalidValueLength { actual: usize },
    #[error("snapshot record keys are not strictly sorted and unique")]
    RecordsNotStrictlySorted,
    #[error("snapshot contains a record outside the exact public allowlist")]
    UnexpectedPublicRecordKey,
    #[error("public group id is not exactly 32 bytes")]
    WrongGroupIdLength,
    #[error("failed to derive exact OpenMLS public record keys")]
    RecordKeyEncoding,
    #[error("OpenMLS provider initialization failed")]
    ProviderInitialization,
    #[error("public snapshot storage lock is poisoned")]
    StorageLockPoisoned,
    #[error("snapshot records do not decode to the expected OpenMLS public group")]
    InvalidStoredPublicGroup,
    #[error("public group snapshot digest does not match its authenticated database binding")]
    SnapshotDigestMismatch,
    #[error("conversation snapshot binding does not contain a canonical UUIDv4 identifier")]
    InvalidConversationId,
    #[error("conversation snapshot coordinate exceeds the protocol integer range")]
    CoordinateIntegerOutOfRange,
    #[error("only the active current conversation head is processable")]
    InactiveConversationState,
    #[error("encoded public group snapshot is not the exact state being bound")]
    SnapshotStateMismatch,
    #[error("public group snapshot MLS coordinate does not match its database binding")]
    SnapshotCoordinateMismatch,
    #[error("locked conversation head contains an invalid canonical public-tree summary")]
    InvalidExpectedTreeSummary,
    #[error("public group snapshot tree or leaf summary does not match its locked database head")]
    SnapshotTreeSummaryMismatch,
    #[error("public group snapshot records are internally incoherent")]
    IncoherentStoredPublicGroup,
}

/// Encode the four exact OpenMLS public records in deterministic key order.
pub fn encode_public_group_snapshot(
    state: &PublicGroupState,
) -> Result<Vec<u8>, PublicGroupSnapshotError> {
    let group_id: [u8; 32] = state
        .public_group
        .group_id()
        .as_slice()
        .try_into()
        .map_err(|_| PublicGroupSnapshotError::WrongGroupIdLength)?;
    let values = state
        .provider
        .storage()
        .values
        .read()
        .map_err(|_| PublicGroupSnapshotError::StorageLockPoisoned)?;
    if values.len() != PUBLIC_RECORD_COUNT {
        return Err(PublicGroupSnapshotError::WrongPublicRecordCount {
            actual: values.len(),
            expected: PUBLIC_RECORD_COUNT,
        });
    }
    let mut prospective_len = snapshot_header_len();
    for (key, value) in values.iter() {
        validate_key_length(key.len())?;
        validate_value_length(value.len())?;
        prospective_len = prospective_len
            .checked_add(4)
            .and_then(|length| length.checked_add(key.len()))
            .and_then(|length| length.checked_add(4))
            .and_then(|length| length.checked_add(value.len()))
            .ok_or(PublicGroupSnapshotError::LengthOverflow)?;
    }
    if prospective_len > MAX_PUBLIC_GROUP_SNAPSHOT_BYTES {
        return Err(PublicGroupSnapshotError::InputTooLarge {
            actual: prospective_len,
            maximum: MAX_PUBLIC_GROUP_SNAPSHOT_BYTES,
        });
    }
    let mut records = values
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    drop(values);
    records.sort_by(|left, right| left.0.cmp(&right.0));
    validate_public_records(&records, &group_id)?;
    encode_records(&records)
}

/// Decode a canonical snapshot into a new provider and load the expected
/// `PublicGroup` from that provider's storage.
///
/// `expected` must come from the caller's separately authenticated current
/// conversation coordinate. Supplying metadata stored and rolled back as one
/// unit with `encoded` cannot provide whole-row rollback detection.
pub fn decode_public_group_snapshot(
    encoded: &[u8],
    expected: &PublicGroupSnapshotBinding,
) -> Result<PublicGroupState, PublicGroupSnapshotError> {
    validate_trusted_coordinate(expected.coordinate())?;
    if !tree_summary_shape_is_valid(expected.tree_summary()) {
        return Err(PublicGroupSnapshotError::InvalidExpectedTreeSummary);
    }
    if encoded.is_empty() {
        return Err(PublicGroupSnapshotError::Empty);
    }
    if encoded.len() > MAX_PUBLIC_GROUP_SNAPSHOT_BYTES {
        return Err(PublicGroupSnapshotError::InputTooLarge {
            actual: encoded.len(),
            maximum: MAX_PUBLIC_GROUP_SNAPSHOT_BYTES,
        });
    }
    if public_group_snapshot_sha256(encoded) != expected.snapshot_sha256 {
        return Err(PublicGroupSnapshotError::SnapshotDigestMismatch);
    }
    let records = decode_records(encoded)?;
    validate_public_records(&records, expected.group_id())?;
    if records
        .iter()
        .any(|(_, value)| serde_json::from_slice::<serde_json::Value>(value).is_err())
    {
        return Err(PublicGroupSnapshotError::InvalidStoredPublicGroup);
    }

    let provider = Provider::new().map_err(|_| PublicGroupSnapshotError::ProviderInitialization)?;
    {
        let mut values = provider
            .storage()
            .values
            .write()
            .map_err(|_| PublicGroupSnapshotError::StorageLockPoisoned)?;
        if !values.is_empty() {
            return Err(PublicGroupSnapshotError::InvalidStoredPublicGroup);
        }
        *values = records.iter().cloned().collect::<HashMap<_, _>>();
    }

    // MemoryStorage 0.5.0 has infallible-looking public reads that internally
    // unwrap serde failures. Keep an attacker-controlled snapshot from turning
    // dependency behavior into a process abort. The exact version is also
    // pinned in the envelope and Cargo manifest.
    let public_group = std::panic::catch_unwind(AssertUnwindSafe(|| {
        PublicGroup::load(
            provider.storage(),
            &GroupId::from_slice(expected.group_id()),
        )
    }))
    .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?
    .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?
    .ok_or(PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    if public_group.group_id().as_slice() != expected.group_id().as_slice()
        || public_group.version() != ProtocolVersion::Mls10
        || public_group.ciphersuite() != Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
    {
        return Err(PublicGroupSnapshotError::InvalidStoredPublicGroup);
    }
    validate_snapshot_coordinate(&public_group, expected)?;
    validate_ratchet_tree_hash(&public_group)?;
    validate_interim_transcript_hash(&records, &public_group)?;
    validate_snapshot_tree_summary(&public_group, expected.tree_summary())?;

    Ok(PublicGroupState::new(provider, public_group))
}

fn tree_summary_shape_is_valid(summary: &PublicGroupSnapshotTreeSummary) -> bool {
    if !(1..=MAX_PUBLIC_GROUP_LEAVES).contains(&summary.leaves.len()) {
        return false;
    }
    let mut previous_index = None;
    for leaf in &summary.leaves {
        if previous_index.is_some_and(|previous| previous >= leaf.leaf_index)
            || !(MIN_BASIC_CREDENTIAL_BYTES..=MAX_BASIC_CREDENTIAL_BYTES)
                .contains(&leaf.basic_credential.len())
            || leaf.signature_key.len() != ED25519_PUBLIC_KEY_BYTES
            || !xwing_public_key_is_valid(&leaf.encryption_key)
        {
            return false;
        }
        previous_index = Some(leaf.leaf_index);
    }
    true
}

fn tree_summary_from_public_group(
    public_group: &PublicGroup,
) -> Result<PublicGroupSnapshotTreeSummary, PublicGroupSnapshotError> {
    let tree_hash: [u8; 32] = public_group
        .group_context()
        .tree_hash()
        .try_into()
        .map_err(|_| PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
    let mut leaves = public_group
        .members()
        .map(|member| {
            if member.credential.credential_type() != CredentialType::Basic {
                return Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup);
            }
            Ok(PublicGroupSnapshotLeaf::new(
                member.index.u32(),
                member.credential.serialized_content().to_vec(),
                member.signature_key,
                member.encryption_key,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    leaves.sort_by_key(PublicGroupSnapshotLeaf::leaf_index);
    let summary = PublicGroupSnapshotTreeSummary::new(tree_hash, leaves);
    if !tree_summary_shape_is_valid(&summary) {
        return Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup);
    }
    Ok(summary)
}

fn validate_snapshot_tree_summary(
    public_group: &PublicGroup,
    expected: &PublicGroupSnapshotTreeSummary,
) -> Result<(), PublicGroupSnapshotError> {
    let actual = tree_summary_from_public_group(public_group)?;
    if &actual != expected {
        return Err(PublicGroupSnapshotError::SnapshotTreeSummaryMismatch);
    }
    Ok(())
}

fn validate_trusted_coordinate(
    coordinate: &PublicGroupSnapshotCoordinate,
) -> Result<(), PublicGroupSnapshotError> {
    if coordinate.conversation_id[6] & 0xF0 != 0x40 || coordinate.conversation_id[8] & 0xC0 != 0x80
    {
        return Err(PublicGroupSnapshotError::InvalidConversationId);
    }
    if coordinate.generation > MAX_PROTOCOL_INTEGER
        || coordinate.state_version > MAX_PROTOCOL_INTEGER
        || coordinate.epoch > MAX_PROTOCOL_INTEGER
    {
        return Err(PublicGroupSnapshotError::CoordinateIntegerOutOfRange);
    }
    if coordinate.lifecycle != PublicGroupSnapshotLifecycle::Active {
        return Err(PublicGroupSnapshotError::InactiveConversationState);
    }
    Ok(())
}

fn validate_ratchet_tree_hash(public_group: &PublicGroup) -> Result<(), PublicGroupSnapshotError> {
    let encoded_tree = public_group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    let nodes = Vec::<Option<SnapshotWireNode>>::tls_deserialize_exact(&encoded_tree)
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    if nodes.is_empty() || nodes.len() % 2 == 0 {
        return Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup);
    }
    for node in nodes.iter().flatten() {
        let encryption_key = match node {
            SnapshotWireNode::LeafNode(leaf) => leaf.payload.encryption_key.as_slice(),
            SnapshotWireNode::ParentNode(parent) => parent.encryption_key.as_slice(),
        };
        if !xwing_public_key_is_valid(encryption_key) {
            return Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup);
        }
    }
    let conceptual_width = conceptual_tree_width(nodes.len())
        .ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
    let root =
        tree_root(conceptual_width).ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
    let computed = compute_tree_hash(&nodes, root, conceptual_width)?;
    if computed.as_slice() != public_group.group_context().tree_hash() {
        return Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup);
    }
    Ok(())
}

/// OpenMLS stores a complete left-balanced array whose width is `2^k - 1`,
/// while the RFC RatchetTree export trims blank nodes after the rightmost full
/// leaf. Recover the padded conceptual width so missing tail nodes remain
/// explicit blanks during tree hashing and path-resolution traversal.
fn conceptual_tree_width(trimmed_width: usize) -> Option<usize> {
    if trimmed_width == 0 || trimmed_width.is_multiple_of(2) {
        return None;
    }
    trimmed_width
        .checked_add(1)?
        .checked_next_power_of_two()?
        .checked_sub(1)
}

fn tree_root(width: usize) -> Option<usize> {
    if width == 0 {
        return None;
    }
    let shift = usize::BITS - 1 - width.leading_zeros();
    Some((1_usize << shift) - 1)
}

fn tree_level(index: usize) -> u32 {
    index.trailing_ones()
}

fn tree_left(index: usize) -> Option<usize> {
    let level = tree_level(index);
    (level > 0).then(|| index ^ (1_usize << (level - 1)))
}

fn tree_right(index: usize, width: usize) -> Option<usize> {
    let level = tree_level(index);
    if level == 0 {
        return None;
    }
    let mut right = index ^ (3_usize << (level - 1));
    while right >= width {
        right = tree_left(right)?;
    }
    Some(right)
}

fn tree_parent(index: usize) -> Option<usize> {
    let level = tree_level(index) as usize;
    let next_level = level.checked_add(1)?;
    let branch = (index >> next_level) & 1;
    Some((index | (1_usize << level)) ^ (branch << next_level))
}

fn tree_resolution_count(
    nodes: &[Option<SnapshotWireNode>],
    index: usize,
    conceptual_width: usize,
    excluded_leaves: &HashSet<u32>,
) -> Result<usize, PublicGroupSnapshotError> {
    if index >= conceptual_width {
        return Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup);
    }
    if tree_level(index) == 0 {
        let leaf_index = u32::try_from(index / 2)
            .map_err(|_| PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
        if excluded_leaves.contains(&leaf_index) {
            return Ok(0);
        }
        return match nodes.get(index).and_then(Option::as_ref) {
            Some(SnapshotWireNode::LeafNode(_)) => Ok(1),
            Some(SnapshotWireNode::ParentNode(_)) => {
                Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup)
            }
            None => Ok(0),
        };
    }

    match nodes.get(index).and_then(Option::as_ref) {
        Some(SnapshotWireNode::ParentNode(parent)) => {
            let mut count = 1_usize;
            for leaf_index in &parent.unmerged_leaves {
                if excluded_leaves.contains(leaf_index) {
                    continue;
                }
                let leaf_node_index = usize::try_from(*leaf_index)
                    .ok()
                    .and_then(|index| index.checked_mul(2))
                    .ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
                if !matches!(
                    nodes.get(leaf_node_index).and_then(Option::as_ref),
                    Some(SnapshotWireNode::LeafNode(_))
                ) {
                    return Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup);
                }
                count = count
                    .checked_add(1)
                    .ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
            }
            Ok(count)
        }
        Some(SnapshotWireNode::LeafNode(_)) => {
            Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup)
        }
        None => {
            let left =
                tree_left(index).ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
            let right = tree_right(index, conceptual_width)
                .ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
            tree_resolution_count(nodes, left, conceptual_width, excluded_leaves)?
                .checked_add(tree_resolution_count(
                    nodes,
                    right,
                    conceptual_width,
                    excluded_leaves,
                )?)
                .ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)
        }
    }
}

/// Expected encrypted-path-secret cardinality for every filtered direct-path
/// node, computed from the exact merged public tree. Newly added leaf indices
/// are excluded exactly as required by RFC 9420 path encryption.
pub(crate) fn expected_update_path_ciphertext_counts(
    state: &PublicGroupState,
    sender_leaf_index: u32,
    excluded_leaves: &HashSet<u32>,
) -> Result<Vec<usize>, PublicGroupSnapshotError> {
    let encoded_tree = state
        .public_group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    let nodes = Vec::<Option<SnapshotWireNode>>::tls_deserialize_exact(&encoded_tree)
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    let sender_node = usize::try_from(sender_leaf_index)
        .ok()
        .and_then(|index| index.checked_mul(2))
        .ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
    if !matches!(
        nodes.get(sender_node).and_then(Option::as_ref),
        Some(SnapshotWireNode::LeafNode(_))
    ) {
        return Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup);
    }
    let conceptual_width = conceptual_tree_width(nodes.len())
        .ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
    let root =
        tree_root(conceptual_width).ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
    let mut current = sender_node;
    let mut counts = Vec::new();
    let no_exclusions = HashSet::new();
    while current != root {
        let parent =
            tree_parent(current).ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
        let copath = if current < parent {
            tree_right(parent, conceptual_width)
        } else {
            tree_left(parent)
        }
        .ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
        if tree_resolution_count(&nodes, copath, conceptual_width, &no_exclusions)? > 0 {
            counts.push(tree_resolution_count(
                &nodes,
                copath,
                conceptual_width,
                excluded_leaves,
            )?);
        }
        current = parent;
    }
    Ok(counts)
}

fn compute_tree_hash(
    nodes: &[Option<SnapshotWireNode>],
    index: usize,
    conceptual_width: usize,
) -> Result<[u8; 32], PublicGroupSnapshotError> {
    if index >= conceptual_width {
        return Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup);
    }
    let encoded = if tree_level(index) == 0 {
        let leaf = match nodes.get(index).and_then(Option::as_ref) {
            Some(SnapshotWireNode::LeafNode(leaf)) => Some(leaf.as_ref()),
            Some(SnapshotWireNode::ParentNode(_)) => {
                return Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup)
            }
            None => None,
        };
        let leaf_index = u32::try_from(index / 2)
            .map_err(|_| PublicGroupSnapshotError::IncoherentStoredPublicGroup)?;
        SnapshotTreeHashInput {
            node: SnapshotTreeHashNode::Leaf(SnapshotLeafHashInput {
                leaf_index,
                leaf_node: leaf,
            }),
        }
        .tls_serialize_detached()
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?
    } else {
        let parent = match nodes.get(index).and_then(Option::as_ref) {
            Some(SnapshotWireNode::ParentNode(parent)) => Some(parent.as_ref()),
            Some(SnapshotWireNode::LeafNode(_)) => {
                return Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup)
            }
            None => None,
        };
        let left = tree_left(index)
            .ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)
            .and_then(|child| compute_tree_hash(nodes, child, conceptual_width))?;
        let right = tree_right(index, conceptual_width)
            .ok_or(PublicGroupSnapshotError::IncoherentStoredPublicGroup)
            .and_then(|child| compute_tree_hash(nodes, child, conceptual_width))?;
        SnapshotTreeHashInput {
            node: SnapshotTreeHashNode::Parent(SnapshotParentHashInput {
                parent_node: parent,
                left_hash: left.to_vec().into(),
                right_hash: right.to_vec().into(),
            }),
        }
        .tls_serialize_detached()
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?
    };
    Ok(Sha256::digest(encoded).into())
}

fn validate_snapshot_coordinate(
    public_group: &PublicGroup,
    expected: &PublicGroupSnapshotBinding,
) -> Result<(), PublicGroupSnapshotError> {
    let group_context = public_group.group_context();
    if group_context.epoch().as_u64() != expected.epoch()
        || group_context.extensions().iter().next().is_some()
    {
        return Err(PublicGroupSnapshotError::SnapshotCoordinateMismatch);
    }
    let context_bytes = group_context
        .tls_serialize_detached()
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    let context_hash: [u8; 32] = Sha256::digest(context_bytes).into();
    if &context_hash != expected.group_context_hash() {
        return Err(PublicGroupSnapshotError::SnapshotCoordinateMismatch);
    }
    let encoded_tag = public_group
        .confirmation_tag()
        .tls_serialize_detached()
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    let tag = VLBytes::tls_deserialize_exact(&encoded_tag)
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    if tag.as_slice() != expected.confirmation_tag().as_slice() {
        return Err(PublicGroupSnapshotError::SnapshotCoordinateMismatch);
    }
    Ok(())
}

fn validate_interim_transcript_hash(
    records: &[(Vec<u8>, Vec<u8>)],
    public_group: &PublicGroup,
) -> Result<(), PublicGroupSnapshotError> {
    let stored = records
        .iter()
        .find(|(key, _)| key.starts_with(b"InterimTranscriptHash"))
        .ok_or(PublicGroupSnapshotError::InvalidStoredPublicGroup)
        .and_then(|(_, value)| {
            serde_json::from_slice::<Vec<u8>>(value)
                .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)
        })?;
    let encoded_tag = public_group
        .confirmation_tag()
        .tls_serialize_detached()
        .map_err(|_| PublicGroupSnapshotError::InvalidStoredPublicGroup)?;
    let mut input = Vec::with_capacity(
        public_group
            .group_context()
            .confirmed_transcript_hash()
            .len()
            + encoded_tag.len(),
    );
    input.extend_from_slice(public_group.group_context().confirmed_transcript_hash());
    input.extend_from_slice(&encoded_tag);
    if stored.as_slice() != Sha256::digest(input).as_slice() {
        return Err(PublicGroupSnapshotError::IncoherentStoredPublicGroup);
    }
    Ok(())
}

fn validate_public_records(
    records: &[(Vec<u8>, Vec<u8>)],
    group_id: &[u8; 32],
) -> Result<(), PublicGroupSnapshotError> {
    if records.len() != PUBLIC_RECORD_COUNT {
        return Err(PublicGroupSnapshotError::WrongPublicRecordCount {
            actual: records.len(),
            expected: PUBLIC_RECORD_COUNT,
        });
    }

    let mut expected_keys = expected_public_record_keys(group_id)?;
    expected_keys.sort();
    for (index, (key, value)) in records.iter().enumerate() {
        validate_key_length(key.len())?;
        validate_value_length(value.len())?;
        if key != &expected_keys[index] {
            return Err(PublicGroupSnapshotError::UnexpectedPublicRecordKey);
        }
    }
    Ok(())
}

fn expected_public_record_keys(
    group_id: &[u8; 32],
) -> Result<Vec<Vec<u8>>, PublicGroupSnapshotError> {
    let serialized_group_id = serde_json::to_vec(&GroupId::from_slice(group_id))
        .map_err(|_| PublicGroupSnapshotError::RecordKeyEncoding)?;
    Ok(ALLOWED_PUBLIC_LABELS
        .iter()
        .map(|label| {
            let mut key = Vec::with_capacity(
                label.len() + serialized_group_id.len() + STORAGE_SCHEMA_BYTES.len(),
            );
            key.extend_from_slice(label);
            key.extend_from_slice(&serialized_group_id);
            key.extend_from_slice(&STORAGE_SCHEMA_BYTES);
            key
        })
        .collect())
}

fn encode_records(records: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<u8>, PublicGroupSnapshotError> {
    let mut encoded_len = snapshot_header_len();
    for (key, value) in records {
        encoded_len = encoded_len
            .checked_add(4)
            .and_then(|length| length.checked_add(key.len()))
            .and_then(|length| length.checked_add(4))
            .and_then(|length| length.checked_add(value.len()))
            .ok_or(PublicGroupSnapshotError::LengthOverflow)?;
        if encoded_len > MAX_PUBLIC_GROUP_SNAPSHOT_BYTES {
            return Err(PublicGroupSnapshotError::InputTooLarge {
                actual: encoded_len,
                maximum: MAX_PUBLIC_GROUP_SNAPSHOT_BYTES,
            });
        }
    }

    let mut output = Vec::with_capacity(encoded_len);
    output.extend_from_slice(SNAPSHOT_MAGIC);
    output.extend_from_slice(&SNAPSHOT_SCHEMA.to_be_bytes());
    push_u16_length_bytes(&mut output, OPENMLS_VERSION);
    push_u16_length_bytes(&mut output, STORAGE_VERSION);
    output.extend_from_slice(&(PUBLIC_RECORD_COUNT as u32).to_be_bytes());
    for (key, value) in records {
        output.extend_from_slice(&(key.len() as u32).to_be_bytes());
        output.extend_from_slice(key);
        output.extend_from_slice(&(value.len() as u32).to_be_bytes());
        output.extend_from_slice(value);
    }
    debug_assert_eq!(output.len(), encoded_len);
    Ok(output)
}

const fn snapshot_header_len() -> usize {
    SNAPSHOT_MAGIC.len() + 2 + 2 + OPENMLS_VERSION.len() + 2 + STORAGE_VERSION.len() + 4
}

fn push_u16_length_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);
}

fn decode_records(encoded: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, PublicGroupSnapshotError> {
    if encoded.is_empty() {
        return Err(PublicGroupSnapshotError::Empty);
    }
    if encoded.len() > MAX_PUBLIC_GROUP_SNAPSHOT_BYTES {
        return Err(PublicGroupSnapshotError::InputTooLarge {
            actual: encoded.len(),
            maximum: MAX_PUBLIC_GROUP_SNAPSHOT_BYTES,
        });
    }

    let mut cursor = SnapshotCursor::new(encoded);
    if cursor.take(SNAPSHOT_MAGIC.len())? != SNAPSHOT_MAGIC {
        return Err(PublicGroupSnapshotError::InvalidMagic);
    }
    let schema = cursor.take_u16()?;
    if schema != SNAPSHOT_SCHEMA {
        return Err(PublicGroupSnapshotError::UnsupportedSchema { actual: schema });
    }
    let openmls_version_len = usize::from(cursor.take_u16()?);
    if cursor.take(openmls_version_len)? != OPENMLS_VERSION {
        return Err(PublicGroupSnapshotError::UnsupportedOpenMlsVersion);
    }
    let storage_version_len = usize::from(cursor.take_u16()?);
    if cursor.take(storage_version_len)? != STORAGE_VERSION {
        return Err(PublicGroupSnapshotError::UnsupportedStorageVersion);
    }

    let record_count = usize::try_from(cursor.take_u32()?)
        .map_err(|_| PublicGroupSnapshotError::LengthOverflow)?;
    if !(1..=MAX_ENVELOPE_RECORDS).contains(&record_count) {
        return Err(PublicGroupSnapshotError::InvalidEnvelopeRecordCount {
            actual: record_count,
            maximum: MAX_ENVELOPE_RECORDS,
        });
    }
    if record_count != PUBLIC_RECORD_COUNT {
        return Err(PublicGroupSnapshotError::WrongPublicRecordCount {
            actual: record_count,
            expected: PUBLIC_RECORD_COUNT,
        });
    }

    let mut records = Vec::with_capacity(record_count);
    let mut previous_key: Option<Vec<u8>> = None;
    for _ in 0..record_count {
        let key_len = usize::try_from(cursor.take_u32()?)
            .map_err(|_| PublicGroupSnapshotError::LengthOverflow)?;
        validate_key_length(key_len)?;
        let key = cursor.take(key_len)?.to_vec();
        let value_len = usize::try_from(cursor.take_u32()?)
            .map_err(|_| PublicGroupSnapshotError::LengthOverflow)?;
        validate_value_length(value_len)?;
        let value = cursor.take(value_len)?.to_vec();
        if previous_key
            .as_ref()
            .is_some_and(|previous| previous.as_slice() >= key.as_slice())
        {
            return Err(PublicGroupSnapshotError::RecordsNotStrictlySorted);
        }
        previous_key = Some(key.clone());
        records.push((key, value));
    }
    if !cursor.is_eof() {
        return Err(PublicGroupSnapshotError::TrailingData);
    }
    Ok(records)
}

fn validate_key_length(length: usize) -> Result<(), PublicGroupSnapshotError> {
    if !(1..=MAX_SNAPSHOT_KEY_BYTES).contains(&length) {
        return Err(PublicGroupSnapshotError::InvalidKeyLength { actual: length });
    }
    Ok(())
}

fn validate_value_length(length: usize) -> Result<(), PublicGroupSnapshotError> {
    if !(1..=MAX_SNAPSHOT_VALUE_BYTES).contains(&length) {
        return Err(PublicGroupSnapshotError::InvalidValueLength { actual: length });
    }
    Ok(())
}

struct SnapshotCursor<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotCursor<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PublicGroupSnapshotError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PublicGroupSnapshotError::LengthOverflow)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(PublicGroupSnapshotError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u16(&mut self) -> Result<u16, PublicGroupSnapshotError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| PublicGroupSnapshotError::Truncated)?,
        ))
    }

    fn take_u32(&mut self) -> Result<u32, PublicGroupSnapshotError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PublicGroupSnapshotError::Truncated)?,
        ))
    }

    fn is_eof(&self) -> bool {
        self.offset == self.encoded.len()
    }
}
