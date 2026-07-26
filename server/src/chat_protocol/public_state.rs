// Public MLS state verification for the clean chat authority.
//
// This layer deliberately owns no persistence. It turns the frozen Task 1
// wire/snapshot primitives into immutable evidence that the transactional
// state machine may consume. Constructors that could bypass those validators
// are test-only.

use std::collections::BTreeSet;

use sha2::Digest;
use thiserror::Error;

#[cfg(not(test))]
use super::repository::core::LockedPublicStateHydrationGuard;

use super::{
    snapshot::{
        decode_public_group_snapshot, encode_public_group_snapshot, public_group_snapshot_binding,
        PublicGroupSnapshotBinding, PublicGroupSnapshotCoordinate, PublicGroupSnapshotError,
        PublicGroupSnapshotLeaf, PublicGroupSnapshotLifecycle, PublicGroupSnapshotTreeSummary,
    },
    wire::{
        process_public_commit, validate_group_info, validate_public_commit, validate_welcome,
        GroupInfoValidationPolicy, PublicCommitValidationPolicy, WireValidationError,
    },
};

const TREE_SUMMARY_MAGIC: &[u8; 8] = b"CBTSUM01";
const TREE_SUMMARY_SCHEMA: u16 = 1;
const MAX_TREE_SUMMARY_BYTES: usize = 256 * 1024;
const MAX_TREE_SUMMARY_LEAVES: usize = 100;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const XWING_PUBLIC_KEY_BYTES: usize = 1_216;
const MIN_BASIC_CREDENTIAL_BYTES: usize = 49;
const MAX_BASIC_CREDENTIAL_BYTES: usize = 298;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicStateError {
    #[error("genesis coordinate is not generation-zero active state")]
    InvalidGenesisCoordinate,
    #[error("reset successor is not the exact fresh active epoch-zero generation")]
    InvalidResetSuccessorCoordinate,
    #[error("authenticated MLS artifact does not match the signed coordinate")]
    CoordinateMismatch,
    #[error("public snapshot digest does not match the locked head")]
    SnapshotDigestMismatch,
    #[error("public snapshot is invalid or does not match the locked head")]
    InvalidSnapshot,
    #[error("MLS artifact is outside the frozen clean-chat profile")]
    InvalidWireArtifact,
    #[error("coordinate-only edge changed MLS state or was not exactly one state version")]
    CoordinateOnlyEdgeMismatch,
    #[error("Welcome is not the one exact request-bound KeyPackage delivery")]
    WelcomePackageMismatch,
    #[error("public tree-summary digest does not match the locked generation row")]
    TreeSummaryDigestMismatch,
    #[error("canonical public tree-summary bytes are invalid")]
    InvalidTreeSummary,
}

fn map_snapshot_error(error: PublicGroupSnapshotError) -> PublicStateError {
    match error {
        PublicGroupSnapshotError::SnapshotDigestMismatch => {
            PublicStateError::SnapshotDigestMismatch
        }
        _ => PublicStateError::InvalidSnapshot,
    }
}

fn map_wire_error(_error: WireValidationError) -> PublicStateError {
    PublicStateError::InvalidWireArtifact
}

/// Canonical, versioned persistence artifact for the public leaf projection.
/// The digest is stored in the separately locked generation row and is checked
/// before any attacker-controlled length or leaf field is decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncodedPublicTreeSummary {
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl EncodedPublicTreeSummary {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, [u8; 32]) {
        (self.bytes, self.sha256)
    }
}

pub(crate) fn encode_public_tree_summary(
    summary: &PublicGroupSnapshotTreeSummary,
) -> Result<EncodedPublicTreeSummary, PublicStateError> {
    validate_tree_summary_shape(summary)?;
    let mut bytes = Vec::with_capacity(
        TREE_SUMMARY_MAGIC.len()
            + 2
            + 32
            + 2
            + summary.leaves().len() * (4 + 2 + 64 + 32 + XWING_PUBLIC_KEY_BYTES),
    );
    bytes.extend_from_slice(TREE_SUMMARY_MAGIC);
    bytes.extend_from_slice(&TREE_SUMMARY_SCHEMA.to_be_bytes());
    bytes.extend_from_slice(summary.tree_hash());
    bytes.extend_from_slice(&(summary.leaves().len() as u16).to_be_bytes());
    for leaf in summary.leaves() {
        bytes.extend_from_slice(&leaf.leaf_index().to_be_bytes());
        let credential_len = u16::try_from(leaf.basic_credential().len())
            .map_err(|_| PublicStateError::InvalidTreeSummary)?;
        bytes.extend_from_slice(&credential_len.to_be_bytes());
        bytes.extend_from_slice(leaf.basic_credential());
        bytes.extend_from_slice(leaf.signature_key());
        bytes.extend_from_slice(leaf.encryption_key());
    }
    if bytes.len() > MAX_TREE_SUMMARY_BYTES {
        return Err(PublicStateError::InvalidTreeSummary);
    }
    let sha256 = sha2::Sha256::digest(&bytes).into();
    Ok(EncodedPublicTreeSummary { bytes, sha256 })
}

pub(crate) fn decode_public_tree_summary(
    bytes: &[u8],
    expected_sha256: &[u8; 32],
) -> Result<PublicGroupSnapshotTreeSummary, PublicStateError> {
    // The byte cap is an admission bound, not semantic parsing, and therefore
    // precedes even digest work on a corrupted oversized row.
    if bytes.len() > MAX_TREE_SUMMARY_BYTES {
        return Err(PublicStateError::InvalidTreeSummary);
    }
    if <[u8; 32]>::from(sha2::Sha256::digest(bytes)) != *expected_sha256 {
        return Err(PublicStateError::TreeSummaryDigestMismatch);
    }
    let mut cursor = TreeSummaryCursor::new(bytes);
    if cursor.take(TREE_SUMMARY_MAGIC.len())? != TREE_SUMMARY_MAGIC
        || cursor.take_u16()? != TREE_SUMMARY_SCHEMA
    {
        return Err(PublicStateError::InvalidTreeSummary);
    }
    let tree_hash: [u8; 32] = cursor
        .take(32)?
        .try_into()
        .map_err(|_| PublicStateError::InvalidTreeSummary)?;
    let leaf_count = usize::from(cursor.take_u16()?);
    if !(1..=MAX_TREE_SUMMARY_LEAVES).contains(&leaf_count) {
        return Err(PublicStateError::InvalidTreeSummary);
    }
    let mut leaves = Vec::with_capacity(leaf_count);
    for _ in 0..leaf_count {
        let leaf_index = cursor.take_u32()?;
        let credential_len = usize::from(cursor.take_u16()?);
        let basic_credential = cursor.take(credential_len)?.to_vec();
        let signature_key = cursor.take(ED25519_PUBLIC_KEY_BYTES)?.to_vec();
        let encryption_key = cursor.take(XWING_PUBLIC_KEY_BYTES)?.to_vec();
        leaves.push(PublicGroupSnapshotLeaf::new(
            leaf_index,
            basic_credential,
            signature_key,
            encryption_key,
        ));
    }
    if !cursor.is_eof() {
        return Err(PublicStateError::InvalidTreeSummary);
    }
    let summary = PublicGroupSnapshotTreeSummary::new(tree_hash, leaves);
    validate_tree_summary_shape(&summary)?;
    // Reject any accepted alternate encoding, including ignored/reserved data.
    let canonical = encode_public_tree_summary(&summary)?;
    if canonical.bytes() != bytes {
        return Err(PublicStateError::InvalidTreeSummary);
    }
    Ok(summary)
}

fn validate_tree_summary_shape(
    summary: &PublicGroupSnapshotTreeSummary,
) -> Result<(), PublicStateError> {
    if !(1..=MAX_TREE_SUMMARY_LEAVES).contains(&summary.leaves().len()) {
        return Err(PublicStateError::InvalidTreeSummary);
    }
    let mut prior_index = None;
    let mut credentials = BTreeSet::new();
    let mut signature_keys = BTreeSet::new();
    for leaf in summary.leaves() {
        if prior_index.is_some_and(|prior| prior >= leaf.leaf_index())
            || !(MIN_BASIC_CREDENTIAL_BYTES..=MAX_BASIC_CREDENTIAL_BYTES)
                .contains(&leaf.basic_credential().len())
            || leaf.signature_key().len() != ED25519_PUBLIC_KEY_BYTES
            || leaf.encryption_key().len() != XWING_PUBLIC_KEY_BYTES
            || !credentials.insert(leaf.basic_credential())
            || !signature_keys.insert(leaf.signature_key())
        {
            return Err(PublicStateError::InvalidTreeSummary);
        }
        prior_index = Some(leaf.leaf_index());
    }
    Ok(())
}

struct TreeSummaryCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TreeSummaryCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], PublicStateError> {
        let end = self
            .offset
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(PublicStateError::InvalidTreeSummary)?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn take_u16(&mut self) -> Result<u16, PublicStateError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| PublicStateError::InvalidTreeSummary)?,
        ))
    }

    fn take_u32(&mut self) -> Result<u32, PublicStateError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PublicStateError::InvalidTreeSummary)?,
        ))
    }

    fn is_eof(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Exact active public-state artifact validated against a separately trusted
/// conversation head. It contains only public OpenMLS state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActivePublicState {
    snapshot: Vec<u8>,
    binding: PublicGroupSnapshotBinding,
    /// Present only when this value was produced directly from the exact
    /// authenticated GroupInfo bytes.  A snapshot reload is intentionally not
    /// interchangeable with creation/reset proof: the state machine compares
    /// this digest and signer key with the signed transition before opening a
    /// new access interval.
    verified_group_info_sha256: Option<[u8; 32]>,
    verified_group_info_signature_key: Option<Vec<u8>>,
}

impl ActivePublicState {
    pub(crate) fn snapshot(&self) -> &[u8] {
        &self.snapshot
    }

    pub(crate) fn snapshot_sha256(&self) -> &[u8; 32] {
        self.binding.snapshot_sha256()
    }

    pub(crate) fn binding(&self) -> &PublicGroupSnapshotBinding {
        &self.binding
    }

    pub(crate) fn coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        self.binding.coordinate()
    }

    pub(crate) fn verified_group_info_sha256(&self) -> Option<&[u8; 32]> {
        self.verified_group_info_sha256.as_ref()
    }

    pub(crate) fn verified_group_info_signature_key(&self) -> Option<&[u8]> {
        self.verified_group_info_signature_key.as_deref()
    }

    /// Build a sealed-looking artifact for pure state-machine adversarial
    /// tests. Production code has no constructor that skips Task 1 validators.
    #[cfg(test)]
    pub(crate) fn for_test(template: &Self, coordinate: PublicGroupSnapshotCoordinate) -> Self {
        Self {
            snapshot: template.snapshot.clone(),
            binding: PublicGroupSnapshotBinding::new(
                *coordinate.conversation_id(),
                coordinate.generation(),
                coordinate.state_version(),
                *coordinate.group_id(),
                coordinate.epoch(),
                *coordinate.group_context_hash(),
                *coordinate.confirmation_tag(),
                coordinate.lifecycle(),
                *template.binding.snapshot_sha256(),
                template.binding.tree_summary().clone(),
            ),
            verified_group_info_sha256: template.verified_group_info_sha256,
            verified_group_info_signature_key: template.verified_group_info_signature_key.clone(),
        }
    }
}

pub(crate) struct GenesisGroupInfoExpectations<'a> {
    pub(crate) coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) expected_basic_credential: &'a [u8],
    pub(crate) expected_signature_key: &'a [u8],
    pub(crate) now_unix_seconds: u64,
    pub(crate) max_wire_bytes: usize,
    pub(crate) max_ratchet_tree_bytes: usize,
    pub(crate) max_members: usize,
}

pub(crate) struct ResetSuccessorGroupInfoExpectations<'a> {
    pub(crate) coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) expected_basic_credential: &'a [u8],
    pub(crate) expected_signature_key: &'a [u8],
    pub(crate) now_unix_seconds: u64,
    pub(crate) max_wire_bytes: usize,
    pub(crate) max_ratchet_tree_bytes: usize,
    pub(crate) max_members: usize,
}

/// Validate an actor-only epoch-zero GroupInfo, persist it canonically in
/// memory, bind it to the signed outer coordinate, and reload the exact bytes.
pub(crate) fn verify_genesis_group_info(
    bytes: &[u8],
    expectations: GenesisGroupInfoExpectations<'_>,
) -> Result<ActivePublicState, PublicStateError> {
    let coordinate = expectations.coordinate;
    if coordinate.generation() != 0
        || coordinate.state_version() != 0
        || coordinate.epoch() != 0
        || coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
    {
        return Err(PublicStateError::InvalidGenesisCoordinate);
    }

    verify_actor_only_group_info(
        bytes,
        coordinate,
        expectations.expected_basic_credential,
        expectations.expected_signature_key,
        expectations.now_unix_seconds,
        expectations.max_wire_bytes,
        expectations.max_ratchet_tree_bytes,
        expectations.max_members,
    )
}

/// Validate reset activation's actual GroupInfo rather than allowing a caller
/// to fabricate an `ActivePublicState`. The successor is bound to the same
/// conversation, exactly `prior.generation + 1`, a fresh group ID, state
/// version/epoch zero, and one actor leaf.
pub(crate) fn verify_reset_successor_group_info(
    bytes: &[u8],
    prior: &PublicGroupSnapshotCoordinate,
    expectations: ResetSuccessorGroupInfoExpectations<'_>,
) -> Result<ActivePublicState, PublicStateError> {
    let coordinate = expectations.coordinate;
    let expected_generation = prior
        .generation()
        .checked_add(1)
        .ok_or(PublicStateError::InvalidResetSuccessorCoordinate)?;
    if prior.lifecycle() != PublicGroupSnapshotLifecycle::Active
        || coordinate.conversation_id() != prior.conversation_id()
        || coordinate.generation() != expected_generation
        || coordinate.generation() == 0
        || coordinate.state_version() != 0
        || coordinate.epoch() != 0
        || coordinate.group_id() == prior.group_id()
        || coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
    {
        return Err(PublicStateError::InvalidResetSuccessorCoordinate);
    }

    verify_actor_only_group_info(
        bytes,
        coordinate,
        expectations.expected_basic_credential,
        expectations.expected_signature_key,
        expectations.now_unix_seconds,
        expectations.max_wire_bytes,
        expectations.max_ratchet_tree_bytes,
        expectations.max_members,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_actor_only_group_info(
    bytes: &[u8],
    coordinate: PublicGroupSnapshotCoordinate,
    expected_basic_credential: &[u8],
    expected_signature_key: &[u8],
    now_unix_seconds: u64,
    max_wire_bytes: usize,
    max_ratchet_tree_bytes: usize,
    max_members: usize,
) -> Result<ActivePublicState, PublicStateError> {
    let group_info = validate_group_info(
        bytes,
        GroupInfoValidationPolicy {
            expected_basic_credential,
            expected_signature_key,
            now_unix_seconds,
            max_bytes: max_wire_bytes,
            max_ratchet_tree_bytes,
            max_members,
        },
    )
    .map_err(map_wire_error)?;

    if group_info.group_id() != coordinate.group_id()
        || group_info.epoch() != coordinate.epoch()
        || group_info.group_context_hash() != coordinate.group_context_hash()
        || group_info.confirmation_tag() != coordinate.confirmation_tag()
    {
        return Err(PublicStateError::CoordinateMismatch);
    }

    let snapshot =
        encode_public_group_snapshot(group_info.public_state()).map_err(map_snapshot_error)?;
    let binding = public_group_snapshot_binding(group_info.public_state(), &snapshot, &coordinate)
        .map_err(map_snapshot_error)?;
    decode_public_group_snapshot(&snapshot, &binding).map_err(map_snapshot_error)?;

    Ok(ActivePublicState {
        snapshot,
        binding,
        verified_group_info_sha256: Some(sha2::Sha256::digest(bytes).into()),
        verified_group_info_signature_key: Some(expected_signature_key.to_vec()),
    })
}

fn load_active_snapshot_from_verified_binding(
    snapshot: &[u8],
    binding: &PublicGroupSnapshotBinding,
) -> Result<ActivePublicState, PublicStateError> {
    decode_public_group_snapshot(snapshot, binding).map_err(map_snapshot_error)?;
    Ok(ActivePublicState {
        snapshot: snapshot.to_vec(),
        binding: binding.clone(),
        verified_group_info_sha256: None,
        verified_group_info_signature_key: None,
    })
}

/// Reload one persisted snapshot only after independently checking the
/// canonical tree-summary artifact retained beside the locked generation row.
/// The summary size cap and digest check happen before parsing; the decoded
/// value must then equal the tree summary committed by the snapshot binding.
#[cfg(not(test))]
pub(crate) fn load_persisted_active_snapshot(
    locked: LockedPublicStateHydrationGuard,
) -> Result<ActivePublicState, PublicStateError> {
    let (
        transaction_id,
        conversation_id,
        coordinate,
        snapshot,
        binding,
        encoded_tree_summary,
        expected_tree_summary_sha256,
        locked_at,
        locked_generation_row_digest,
    ) = locked.into_parts();
    if transaction_id.is_empty()
        || coordinate.conversation_id() != conversation_id.as_bytes()
        || binding.coordinate() != &coordinate
        || locked_at.timestamp_millis() < 0
        || locked_generation_row_digest == [0; 32]
    {
        return Err(PublicStateError::InvalidSnapshot);
    }
    load_persisted_active_snapshot_from_parts(
        &snapshot,
        &binding,
        &encoded_tree_summary,
        &expected_tree_summary_sha256,
    )
}

fn load_persisted_active_snapshot_from_parts(
    snapshot: &[u8],
    binding: &PublicGroupSnapshotBinding,
    encoded_tree_summary: &[u8],
    expected_tree_summary_sha256: &[u8; 32],
) -> Result<ActivePublicState, PublicStateError> {
    let persisted_summary =
        decode_public_tree_summary(encoded_tree_summary, expected_tree_summary_sha256)?;
    if &persisted_summary != binding.tree_summary() {
        return Err(PublicStateError::TreeSummaryDigestMismatch);
    }
    load_active_snapshot_from_verified_binding(snapshot, binding)
}

#[cfg(test)]
pub(crate) fn load_persisted_active_snapshot(
    snapshot: &[u8],
    binding: &PublicGroupSnapshotBinding,
    encoded_tree_summary: &[u8],
    expected_tree_summary_sha256: &[u8; 32],
) -> Result<ActivePublicState, PublicStateError> {
    load_persisted_active_snapshot_from_parts(
        snapshot,
        binding,
        encoded_tree_summary,
        expected_tree_summary_sha256,
    )
}

/// Pure adversarial-test seam. Production reloads must pass through
/// `load_persisted_active_snapshot` so tree-summary storage cannot be skipped.
#[cfg(test)]
pub(crate) fn load_active_snapshot(
    snapshot: &[u8],
    binding: &PublicGroupSnapshotBinding,
) -> Result<ActivePublicState, PublicStateError> {
    load_active_snapshot_from_verified_binding(snapshot, binding)
}

fn is_coordinate_only_successor(
    prior: &PublicGroupSnapshotCoordinate,
    next: &PublicGroupSnapshotCoordinate,
) -> bool {
    prior
        .state_version()
        .checked_add(1)
        .is_some_and(|state_version| state_version == next.state_version())
        && prior.conversation_id() == next.conversation_id()
        && prior.generation() == next.generation()
        && prior.group_id() == next.group_id()
        && prior.epoch() == next.epoch()
        && prior.group_context_hash() == next.group_context_hash()
        && prior.confirmation_tag() == next.confirmation_tag()
        && prior.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && next.lifecycle() == PublicGroupSnapshotLifecycle::Active
}

/// Rebind one already verified MLS snapshot after a policy, acceptance, or
/// metadata edge that changes only the outer state version.
pub(crate) fn rebind_active_snapshot(
    prior: &ActivePublicState,
    next: PublicGroupSnapshotCoordinate,
) -> Result<ActivePublicState, PublicStateError> {
    if !is_coordinate_only_successor(prior.coordinate(), &next) {
        return Err(PublicStateError::CoordinateOnlyEdgeMismatch);
    }
    let binding = PublicGroupSnapshotBinding::new(
        *next.conversation_id(),
        next.generation(),
        next.state_version(),
        *next.group_id(),
        next.epoch(),
        *next.group_context_hash(),
        *next.confirmation_tag(),
        next.lifecycle(),
        *prior.binding.snapshot_sha256(),
        prior.binding.tree_summary().clone(),
    );
    decode_public_group_snapshot(&prior.snapshot, &binding).map_err(map_snapshot_error)?;
    Ok(ActivePublicState {
        snapshot: prior.snapshot.clone(),
        binding,
        verified_group_info_sha256: None,
        verified_group_info_signature_key: None,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommitAddEffect {
    leaf_index: u32,
    basic_credential: Vec<u8>,
    signature_key: Vec<u8>,
    encryption_key: Vec<u8>,
    key_package_ref: [u8; 32],
}

impl CommitAddEffect {
    pub(crate) fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    pub(crate) fn basic_credential(&self) -> &[u8] {
        &self.basic_credential
    }

    pub(crate) fn signature_key(&self) -> &[u8] {
        &self.signature_key
    }

    pub(crate) fn encryption_key(&self) -> &[u8] {
        &self.encryption_key
    }

    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommitRemoveEffect {
    leaf_index: u32,
    basic_credential: Vec<u8>,
    signature_key: Vec<u8>,
}

impl CommitRemoveEffect {
    pub(crate) fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    pub(crate) fn basic_credential(&self) -> &[u8] {
        &self.basic_credential
    }

    pub(crate) fn signature_key(&self) -> &[u8] {
        &self.signature_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommitSenderUpdateEffect {
    leaf_index: u32,
    basic_credential: Vec<u8>,
    signature_key: Vec<u8>,
    prior_encryption_key: Vec<u8>,
    next_encryption_key: Vec<u8>,
}

impl CommitSenderUpdateEffect {
    pub(crate) fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    pub(crate) fn basic_credential(&self) -> &[u8] {
        &self.basic_credential
    }

    pub(crate) fn signature_key(&self) -> &[u8] {
        &self.signature_key
    }

    pub(crate) fn prior_encryption_key(&self) -> &[u8] {
        &self.prior_encryption_key
    }

    pub(crate) fn next_encryption_key(&self) -> &[u8] {
        &self.next_encryption_key
    }
}

/// Complete verified public-state replacement for one epoch-changing Commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedCommitPublicState {
    prior_coordinate: PublicGroupSnapshotCoordinate,
    next: ActivePublicState,
    adds: Vec<CommitAddEffect>,
    removes: Vec<CommitRemoveEffect>,
    sender_update: CommitSenderUpdateEffect,
    verified_commit_sha256: Option<[u8; 32]>,
    verified_aad_sha256: Option<[u8; 32]>,
}

impl VerifiedCommitPublicState {
    pub(crate) fn prior_coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.prior_coordinate
    }

    pub(crate) fn next(&self) -> &ActivePublicState {
        &self.next
    }

    pub(crate) fn adds(&self) -> &[CommitAddEffect] {
        &self.adds
    }

    pub(crate) fn removes(&self) -> &[CommitRemoveEffect] {
        &self.removes
    }

    pub(crate) fn sender_update(&self) -> &CommitSenderUpdateEffect {
        &self.sender_update
    }

    pub(crate) fn verified_commit_sha256(&self) -> Option<&[u8; 32]> {
        self.verified_commit_sha256.as_ref()
    }

    pub(crate) fn verified_aad_sha256(&self) -> Option<&[u8; 32]> {
        self.verified_aad_sha256.as_ref()
    }

    pub(crate) fn into_next(self) -> ActivePublicState {
        self.next
    }

    /// Restore the one exact frozen ADD transition used by persistence tests.
    ///
    /// The caller must first restore `expected_prior` and `next` through the
    /// snapshot/binding path. This test-only seam requires the supplied prior
    /// to equal that exact restored artifact, pins both sender encryption keys,
    /// and accepts only one added leaf plus the sender self-update.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_add_from_frozen_snapshot(
        prior: &ActivePublicState,
        expected_prior: &ActivePublicState,
        next: ActivePublicState,
        sender_leaf_index: u32,
        expected_prior_sender_encryption_key: &[u8],
        expected_next_sender_encryption_key: &[u8],
        expected_added_basic_credential: &[u8],
        expected_added_signature_key: &[u8],
        added_key_package_ref: [u8; 32],
        verified_commit_sha256: [u8; 32],
        verified_aad_sha256: [u8; 32],
    ) -> Result<Self, PublicStateError> {
        let prior_coordinate = prior.coordinate();
        let next_coordinate = next.coordinate();
        if prior.snapshot != expected_prior.snapshot
            || prior.binding != expected_prior.binding
            || prior_coordinate.conversation_id() != next_coordinate.conversation_id()
            || prior_coordinate.generation() != next_coordinate.generation()
            || prior_coordinate.group_id() != next_coordinate.group_id()
            || prior_coordinate.state_version().checked_add(1)
                != Some(next_coordinate.state_version())
            || prior_coordinate.epoch().checked_add(1) != Some(next_coordinate.epoch())
            || prior_coordinate.group_context_hash() == next_coordinate.group_context_hash()
            || prior_coordinate.confirmation_tag() == next_coordinate.confirmation_tag()
            || prior_coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
            || next_coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
            || added_key_package_ref == [0; 32]
            || verified_commit_sha256 == [0; 32]
            || verified_aad_sha256 == [0; 32]
        {
            return Err(PublicStateError::CoordinateMismatch);
        }

        let prior_leaves = prior.binding.tree_summary().leaves();
        let next_leaves = next.binding.tree_summary().leaves();
        if prior_leaves.len().checked_add(1) != Some(next_leaves.len()) {
            return Err(PublicStateError::CoordinateMismatch);
        }
        let prior_sender = prior_leaves
            .iter()
            .find(|leaf| leaf.leaf_index() == sender_leaf_index)
            .ok_or(PublicStateError::CoordinateMismatch)?;
        let next_sender = next_leaves
            .iter()
            .find(|leaf| leaf.leaf_index() == sender_leaf_index)
            .ok_or(PublicStateError::CoordinateMismatch)?;
        if prior_sender.basic_credential() != next_sender.basic_credential()
            || prior_sender.signature_key() != next_sender.signature_key()
            || prior_sender.encryption_key() != expected_prior_sender_encryption_key
            || next_sender.encryption_key() != expected_next_sender_encryption_key
            || expected_prior_sender_encryption_key == expected_next_sender_encryption_key
        {
            return Err(PublicStateError::CoordinateMismatch);
        }

        for prior_leaf in prior_leaves {
            let next_leaf = next_leaves
                .iter()
                .find(|leaf| leaf.leaf_index() == prior_leaf.leaf_index())
                .ok_or(PublicStateError::CoordinateMismatch)?;
            if prior_leaf.basic_credential() != next_leaf.basic_credential()
                || prior_leaf.signature_key() != next_leaf.signature_key()
                || (prior_leaf.leaf_index() != sender_leaf_index
                    && prior_leaf.encryption_key() != next_leaf.encryption_key())
            {
                return Err(PublicStateError::CoordinateMismatch);
            }
        }
        let added = next_leaves
            .iter()
            .filter(|next_leaf| {
                !prior_leaves
                    .iter()
                    .any(|prior_leaf| prior_leaf.leaf_index() == next_leaf.leaf_index())
            })
            .collect::<Vec<_>>();
        if added.len() != 1
            || added[0].basic_credential() != expected_added_basic_credential
            || added[0].signature_key() != expected_added_signature_key
        {
            return Err(PublicStateError::CoordinateMismatch);
        }
        let added = added[0];
        let add_effect = CommitAddEffect {
            leaf_index: added.leaf_index(),
            basic_credential: added.basic_credential().to_vec(),
            signature_key: added.signature_key().to_vec(),
            encryption_key: added.encryption_key().to_vec(),
            key_package_ref: added_key_package_ref,
        };
        let sender_update = CommitSenderUpdateEffect {
            leaf_index: sender_leaf_index,
            basic_credential: prior_sender.basic_credential().to_vec(),
            signature_key: prior_sender.signature_key().to_vec(),
            prior_encryption_key: prior_sender.encryption_key().to_vec(),
            next_encryption_key: next_sender.encryption_key().to_vec(),
        };

        Ok(Self {
            prior_coordinate: *prior_coordinate,
            next,
            adds: vec![add_effect],
            removes: Vec::new(),
            sender_update,
            verified_commit_sha256: Some(verified_commit_sha256),
            verified_aad_sha256: Some(verified_aad_sha256),
        })
    }

    /// Construct internally coherent effect evidence for pure planner tests.
    /// Production has no route around `process_commit`.
    #[cfg(test)]
    pub(crate) fn for_test_remove(
        prior: &ActivePublicState,
        next_coordinate: PublicGroupSnapshotCoordinate,
        sender_leaf_index: u32,
        removed_leaf_indices: &[u32],
    ) -> Result<Self, PublicStateError> {
        let prior_coordinate = prior.coordinate();
        if prior_coordinate.conversation_id() != next_coordinate.conversation_id()
            || prior_coordinate.generation() != next_coordinate.generation()
            || prior_coordinate.group_id() != next_coordinate.group_id()
            || prior_coordinate.state_version().checked_add(1)
                != Some(next_coordinate.state_version())
            || prior_coordinate.epoch().checked_add(1) != Some(next_coordinate.epoch())
            || prior_coordinate.group_context_hash() == next_coordinate.group_context_hash()
            || prior_coordinate.confirmation_tag() == next_coordinate.confirmation_tag()
            || next_coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
            || removed_leaf_indices.is_empty()
        {
            return Err(PublicStateError::CoordinateMismatch);
        }
        let prior_leaves = prior.binding.tree_summary().leaves();
        let sender = prior_leaves
            .iter()
            .find(|leaf| leaf.leaf_index() == sender_leaf_index)
            .ok_or(PublicStateError::CoordinateMismatch)?;
        let mut removed = Vec::with_capacity(removed_leaf_indices.len());
        for leaf_index in removed_leaf_indices {
            if *leaf_index == sender_leaf_index
                || removed
                    .iter()
                    .any(|effect: &CommitRemoveEffect| effect.leaf_index == *leaf_index)
            {
                return Err(PublicStateError::CoordinateMismatch);
            }
            let leaf = prior_leaves
                .iter()
                .find(|leaf| leaf.leaf_index() == *leaf_index)
                .ok_or(PublicStateError::CoordinateMismatch)?;
            removed.push(CommitRemoveEffect {
                leaf_index: *leaf_index,
                basic_credential: leaf.basic_credential().to_vec(),
                signature_key: leaf.signature_key().to_vec(),
            });
        }
        let next_leaves = prior_leaves
            .iter()
            .filter(|leaf| !removed_leaf_indices.contains(&leaf.leaf_index()))
            .cloned()
            .collect::<Vec<_>>();
        if next_leaves.is_empty() {
            return Err(PublicStateError::CoordinateMismatch);
        }
        let next = ActivePublicState {
            snapshot: prior.snapshot.clone(),
            binding: PublicGroupSnapshotBinding::new(
                *next_coordinate.conversation_id(),
                next_coordinate.generation(),
                next_coordinate.state_version(),
                *next_coordinate.group_id(),
                next_coordinate.epoch(),
                *next_coordinate.group_context_hash(),
                *next_coordinate.confirmation_tag(),
                next_coordinate.lifecycle(),
                *prior.binding.snapshot_sha256(),
                PublicGroupSnapshotTreeSummary::new(
                    *prior.binding.tree_summary().tree_hash(),
                    next_leaves,
                ),
            ),
            verified_group_info_sha256: None,
            verified_group_info_signature_key: None,
        };
        Ok(Self {
            prior_coordinate: *prior_coordinate,
            next,
            adds: Vec::new(),
            removes: removed,
            sender_update: CommitSenderUpdateEffect {
                leaf_index: sender_leaf_index,
                basic_credential: sender.basic_credential().to_vec(),
                signature_key: sender.signature_key().to_vec(),
                prior_encryption_key: sender.encryption_key().to_vec(),
                next_encryption_key: sender.encryption_key().to_vec(),
            },
            verified_commit_sha256: None,
            verified_aad_sha256: None,
        })
    }

    /// Bind a synthetic remove fixture to the exact signed Commit artifact and
    /// MLS AAD digests carried by a cryptographically verified control entry.
    /// Production obtains both bindings only from `process_commit`.
    #[cfg(test)]
    pub(crate) fn with_verified_bindings_for_test(
        mut self,
        verified_commit_sha256: [u8; 32],
        verified_aad_sha256: [u8; 32],
    ) -> Result<Self, PublicStateError> {
        if verified_commit_sha256 == [0; 32] || verified_aad_sha256 == [0; 32] {
            return Err(PublicStateError::CoordinateMismatch);
        }
        self.verified_commit_sha256 = Some(verified_commit_sha256);
        self.verified_aad_sha256 = Some(verified_aad_sha256);
        Ok(self)
    }

    /// Synthetic ZERO-PROPOSAL commit (`sv+1`, `epoch+1`, fresh hash/tag; no
    /// adds/removes, sender self-update only). Mirrors `for_test_remove`'s pure
    /// public-state seam — the executor generic-commit arm is verified against this
    /// (the real `commit-generic-public-mls` parses via `validate_public_commit`,
    /// but `process_commit` reconstructing a NON-authoritative prior from an earlier
    /// public commit diverges cryptographically, which is exactly why the
    /// state-machine suite drives generic/remove commits synthetically too).
    #[cfg(test)]
    pub(crate) fn for_test_generic(
        prior: &ActivePublicState,
        next_coordinate: PublicGroupSnapshotCoordinate,
        sender_leaf_index: u32,
    ) -> Result<Self, PublicStateError> {
        let prior_coordinate = prior.coordinate();
        if prior_coordinate.conversation_id() != next_coordinate.conversation_id()
            || prior_coordinate.generation() != next_coordinate.generation()
            || prior_coordinate.group_id() != next_coordinate.group_id()
            || prior_coordinate.state_version().checked_add(1)
                != Some(next_coordinate.state_version())
            || prior_coordinate.epoch().checked_add(1) != Some(next_coordinate.epoch())
            || prior_coordinate.group_context_hash() == next_coordinate.group_context_hash()
            || prior_coordinate.confirmation_tag() == next_coordinate.confirmation_tag()
            || next_coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
        {
            return Err(PublicStateError::CoordinateMismatch);
        }
        let prior_leaves = prior.binding.tree_summary().leaves();
        let sender = prior_leaves
            .iter()
            .find(|leaf| leaf.leaf_index() == sender_leaf_index)
            .ok_or(PublicStateError::CoordinateMismatch)?;
        let next = ActivePublicState {
            snapshot: prior.snapshot.clone(),
            binding: PublicGroupSnapshotBinding::new(
                *next_coordinate.conversation_id(),
                next_coordinate.generation(),
                next_coordinate.state_version(),
                *next_coordinate.group_id(),
                next_coordinate.epoch(),
                *next_coordinate.group_context_hash(),
                *next_coordinate.confirmation_tag(),
                next_coordinate.lifecycle(),
                *prior.binding.snapshot_sha256(),
                PublicGroupSnapshotTreeSummary::new(
                    *prior.binding.tree_summary().tree_hash(),
                    prior_leaves.to_vec(),
                ),
            ),
            verified_group_info_sha256: None,
            verified_group_info_signature_key: None,
        };
        Ok(Self {
            prior_coordinate: *prior_coordinate,
            next,
            adds: Vec::new(),
            removes: Vec::new(),
            sender_update: CommitSenderUpdateEffect {
                leaf_index: sender_leaf_index,
                basic_credential: sender.basic_credential().to_vec(),
                signature_key: sender.signature_key().to_vec(),
                prior_encryption_key: sender.encryption_key().to_vec(),
                next_encryption_key: sender.encryption_key().to_vec(),
            },
            verified_commit_sha256: None,
            verified_aad_sha256: None,
        })
    }

    /// Synthetic REPLACE commit (`sv+1`, `epoch+1`, fresh hash/tag): a leaf
    /// recovery that ROTATES the same principal's leaf in place — the old leaf is
    /// REMOVED and a fresh leaf for the same basic credential is ADDED (reusing the
    /// vacated slot), carrying the recovery request's key package. A leaf recovery
    /// keeps the device's SIGNING identity key (the DS `member_devices` signing-key
    /// FK requires a registered device key); only the HPKE encryption key and the
    /// key-package origin rotate. The removed leaf's index/credential/signature key
    /// are sourced from the prior leaf at `replaced_leaf_index` (so the planner's
    /// `Replace` arm, which cross-checks the remove against `prior.leaf(target)`,
    /// accepts it); the add reuses that index and signature key with the caller's
    /// fresh encryption key and key-package ref. Because the credential AND the
    /// signature key are unchanged and both leaves occupy `replaced_leaf_index`,
    /// `materialize_next_leaves(prior, commit, Some(target))` reproduces exactly the
    /// `next` tree summary this constructs. Mirrors `for_test_remove`'s pure
    /// public-state seam (`process_commit` reconstructing a non-authoritative prior
    /// diverges cryptographically, so the state-machine suite drives replace
    /// fulfillments synthetically too).
    #[cfg(test)]
    pub(crate) fn for_test_replace(
        prior: &ActivePublicState,
        next_coordinate: PublicGroupSnapshotCoordinate,
        sender_leaf_index: u32,
        replaced_leaf_index: u32,
        new_encryption_key: Vec<u8>,
        new_key_package_ref: [u8; 32],
    ) -> Result<Self, PublicStateError> {
        let prior_coordinate = prior.coordinate();
        if prior_coordinate.conversation_id() != next_coordinate.conversation_id()
            || prior_coordinate.generation() != next_coordinate.generation()
            || prior_coordinate.group_id() != next_coordinate.group_id()
            || prior_coordinate.state_version().checked_add(1)
                != Some(next_coordinate.state_version())
            || prior_coordinate.epoch().checked_add(1) != Some(next_coordinate.epoch())
            || prior_coordinate.group_context_hash() == next_coordinate.group_context_hash()
            || prior_coordinate.confirmation_tag() == next_coordinate.confirmation_tag()
            || next_coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
            || replaced_leaf_index == sender_leaf_index
        {
            return Err(PublicStateError::CoordinateMismatch);
        }
        let prior_leaves = prior.binding.tree_summary().leaves();
        let sender = prior_leaves
            .iter()
            .find(|leaf| leaf.leaf_index() == sender_leaf_index)
            .ok_or(PublicStateError::CoordinateMismatch)?;
        let replaced = prior_leaves
            .iter()
            .find(|leaf| leaf.leaf_index() == replaced_leaf_index)
            .ok_or(PublicStateError::CoordinateMismatch)?;
        // A leaf recovery keeps the owner's basic credential AND signing key; only
        // the HPKE encryption key and the key-package origin change.
        let target_credential = replaced.basic_credential().to_vec();
        let target_signature_key = replaced.signature_key().to_vec();
        let removes = vec![CommitRemoveEffect {
            leaf_index: replaced_leaf_index,
            basic_credential: target_credential.clone(),
            signature_key: target_signature_key.clone(),
        }];
        let adds = vec![CommitAddEffect {
            leaf_index: replaced_leaf_index,
            basic_credential: target_credential.clone(),
            signature_key: target_signature_key.clone(),
            encryption_key: new_encryption_key.clone(),
            key_package_ref: new_key_package_ref,
        }];
        let mut next_leaves = prior_leaves
            .iter()
            .filter(|leaf| leaf.leaf_index() != replaced_leaf_index)
            .cloned()
            .collect::<Vec<_>>();
        next_leaves.push(PublicGroupSnapshotLeaf::new(
            replaced_leaf_index,
            target_credential,
            target_signature_key,
            new_encryption_key,
        ));
        next_leaves.sort_by_key(PublicGroupSnapshotLeaf::leaf_index);
        let next = ActivePublicState {
            snapshot: prior.snapshot.clone(),
            binding: PublicGroupSnapshotBinding::new(
                *next_coordinate.conversation_id(),
                next_coordinate.generation(),
                next_coordinate.state_version(),
                *next_coordinate.group_id(),
                next_coordinate.epoch(),
                *next_coordinate.group_context_hash(),
                *next_coordinate.confirmation_tag(),
                next_coordinate.lifecycle(),
                *prior.binding.snapshot_sha256(),
                PublicGroupSnapshotTreeSummary::new(
                    *prior.binding.tree_summary().tree_hash(),
                    next_leaves,
                ),
            ),
            verified_group_info_sha256: None,
            verified_group_info_signature_key: None,
        };
        Ok(Self {
            prior_coordinate: *prior_coordinate,
            next,
            adds,
            removes,
            sender_update: CommitSenderUpdateEffect {
                leaf_index: sender_leaf_index,
                basic_credential: sender.basic_credential().to_vec(),
                signature_key: sender.signature_key().to_vec(),
                prior_encryption_key: sender.encryption_key().to_vec(),
                next_encryption_key: sender.encryption_key().to_vec(),
            },
            verified_commit_sha256: None,
            verified_aad_sha256: None,
        })
    }
}

/// Validate and process a Commit against a fresh reload of the exact current
/// snapshot. The authoritative prior is never mutated.
pub(crate) fn process_commit(
    prior: &ActivePublicState,
    commit_bytes: &[u8],
    expected_aad: &[u8],
    expected_next_coordinate: PublicGroupSnapshotCoordinate,
    now_unix_seconds: u64,
    max_members: usize,
) -> Result<VerifiedCommitPublicState, PublicStateError> {
    let restored = decode_public_group_snapshot(&prior.snapshot, &prior.binding)
        .map_err(map_snapshot_error)?;
    let commit =
        validate_public_commit(commit_bytes, commit_bytes.len().max(1)).map_err(map_wire_error)?;
    let processed = process_public_commit(
        &restored,
        commit,
        PublicCommitValidationPolicy {
            expected_aad,
            trusted_prior_binding: &prior.binding,
            expected_next_coordinate: &expected_next_coordinate,
            now_unix_seconds,
            max_members,
        },
    )
    .map_err(map_wire_error)?;

    let next = load_active_snapshot_from_verified_binding(
        processed.next_snapshot(),
        processed.next_binding(),
    )?;
    let adds = processed
        .adds()
        .iter()
        .map(|effect| CommitAddEffect {
            leaf_index: effect.leaf_index(),
            basic_credential: effect.basic_credential().to_vec(),
            signature_key: effect.signature_key().to_vec(),
            encryption_key: effect.key_package().leaf_encryption_key().to_vec(),
            key_package_ref: *effect.key_package().key_package_ref(),
        })
        .collect();
    let removes = processed
        .removes()
        .iter()
        .map(|effect| CommitRemoveEffect {
            leaf_index: effect.leaf_index(),
            basic_credential: effect.basic_credential().to_vec(),
            signature_key: effect.signature_key().to_vec(),
        })
        .collect();
    let sender = processed.sender_update();
    let sender_update = CommitSenderUpdateEffect {
        leaf_index: sender.leaf_index(),
        basic_credential: sender.basic_credential().to_vec(),
        signature_key: sender.signature_key().to_vec(),
        prior_encryption_key: sender.prior_encryption_key().to_vec(),
        next_encryption_key: sender.next_encryption_key().to_vec(),
    };

    Ok(VerifiedCommitPublicState {
        prior_coordinate: *prior.coordinate(),
        next,
        adds,
        removes,
        sender_update,
        verified_commit_sha256: Some(sha2::Sha256::digest(commit_bytes).into()),
        verified_aad_sha256: Some(sha2::Sha256::digest(expected_aad).into()),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedRecoveryWelcome {
    wire_bytes: Vec<u8>,
    inner_bytes: Vec<u8>,
    key_package_ref: [u8; 32],
}

impl VerifiedRecoveryWelcome {
    pub(crate) fn wire_bytes(&self) -> &[u8] {
        &self.wire_bytes
    }

    pub(crate) fn inner_bytes(&self) -> &[u8] {
        &self.inner_bytes
    }

    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }

    /// Bind an already-trusted Welcome blob to a reserved key package for pure
    /// planner/executor tests. Production always arrives via
    /// `verify_recovery_welcome`, which cross-checks the INNER key-package refs;
    /// the planner and executor consume only `wire_bytes` + `key_package_ref`, so
    /// a synthetic bound Welcome exercises those paths for a FRESH reserved package
    /// that no corpus Welcome (bound to the already-consumed corpus ref) can name —
    /// the exact shape a `replace` fulfillment requires.
    #[cfg(test)]
    pub(crate) fn for_test_bound(wire_bytes: Vec<u8>, key_package_ref: [u8; 32]) -> Self {
        Self {
            inner_bytes: wire_bytes.clone(),
            wire_bytes,
            key_package_ref,
        }
    }
}

/// Enforce the version-1 one-request/one-Add/one-Welcome mapping.
pub(crate) fn verify_recovery_welcome(
    bytes: &[u8],
    expected_key_package_ref: [u8; 32],
    max_bytes: usize,
) -> Result<VerifiedRecoveryWelcome, PublicStateError> {
    let welcome = validate_welcome(bytes, max_bytes).map_err(map_wire_error)?;
    if welcome.key_package_refs() != [expected_key_package_ref] {
        return Err(PublicStateError::WelcomePackageMismatch);
    }
    Ok(VerifiedRecoveryWelcome {
        wire_bytes: bytes.to_vec(),
        inner_bytes: welcome.inner_bytes().to_vec(),
        key_package_ref: expected_key_package_ref,
    })
}
