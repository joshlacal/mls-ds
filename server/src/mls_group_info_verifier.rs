//! Strict authentication of externally supplied MLS `GroupInfo` objects.
//!
//! This module deliberately stops at public-state authenticity. A successful
//! verification proves that one uniquely identified member signed a coherent
//! `GroupInfo` and embedded ratchet tree. It does **not** prove that the public
//! state is the result of a separately supplied pure-ciphertext commit. That
//! later transition gate must process and bind the commit independently.

use std::sync::atomic::{AtomicUsize, Ordering};

use openmls::{
    ciphersuite::{signable::Verifiable, signature::SignaturePublicKey},
    group::{ProposalStore, PublicGroup},
    prelude::{Credential, LeafNodeIndex, MlsMessageBodyIn, MlsMessageIn},
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::{Ciphersuite, SignatureScheme};
use openmls_traits::OpenMlsProvider;
use thiserror::Error;
use tls_codec::{Deserialize as TlsDeserialize, Size as TlsSize};

pub const DEFAULT_MAX_GROUP_INFO_BYTES: usize = 1_048_576;
pub const DEFAULT_MAX_RATCHET_TREE_BYTES: usize = 786_432;
pub const DEFAULT_MAX_MEMBERS: usize = 1_024;
pub const DEFAULT_MAX_CONCURRENT_VERIFICATIONS: usize = 8;

static ACTIVE_VERIFICATIONS: AtomicUsize = AtomicUsize::new(0);

/// Resource limits applied before verified evidence is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupInfoVerifierLimits {
    pub max_group_info_bytes: usize,
    pub max_ratchet_tree_bytes: usize,
    pub max_members: usize,
    pub max_concurrent_verifications: usize,
}

impl Default for GroupInfoVerifierLimits {
    fn default() -> Self {
        Self {
            max_group_info_bytes: DEFAULT_MAX_GROUP_INFO_BYTES,
            max_ratchet_tree_bytes: DEFAULT_MAX_RATCHET_TREE_BYTES,
            max_members: DEFAULT_MAX_MEMBERS,
            max_concurrent_verifications: DEFAULT_MAX_CONCURRENT_VERIFICATIONS,
        }
    }
}

/// Registry/device binding can supply both fields once that layer lands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedGroupInfoSigner {
    signature_key: Vec<u8>,
    credential: Option<Credential>,
}

impl ExpectedGroupInfoSigner {
    pub fn by_signature_key(signature_key: impl AsRef<[u8]>) -> Self {
        Self {
            signature_key: signature_key.as_ref().to_vec(),
            credential: None,
        }
    }

    pub fn with_credential(mut self, credential: Credential) -> Self {
        self.credential = Some(credential);
        self
    }
}

/// The exact security statement made by [`VerifiedGroupInfo`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupInfoAssurance {
    /// Authentic public state only; no submitted commit has been processed.
    AuthenticityOnlyNotCommitEquivalence,
}

/// Authenticated public MLS state.
///
/// Construction and fields are private, and this type intentionally has no
/// Serde or TLS serialization implementation.
pub struct VerifiedGroupInfo {
    canonical_bytes: Vec<u8>,
    public_group: PublicGroup,
    epoch: u64,
    ratchet_tree_bytes: usize,
    member_count: usize,
    signer_signature_key: Vec<u8>,
    signer_credential: Credential,
    ciphersuite: Ciphersuite,
    signature_scheme: SignatureScheme,
}

impl std::fmt::Debug for VerifiedGroupInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedGroupInfo")
            .field("encoded_len", &self.canonical_bytes.len())
            .field("group_id_len", &self.group_id().len())
            .field("epoch", &self.epoch)
            .field("ratchet_tree_bytes", &self.ratchet_tree_bytes)
            .field("member_count", &self.member_count)
            .field("ciphersuite", &self.ciphersuite)
            .field("signature_scheme", &self.signature_scheme)
            .finish_non_exhaustive()
    }
}

impl VerifiedGroupInfo {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn public_group(&self) -> &PublicGroup {
        &self.public_group
    }

    pub fn group_id(&self) -> &[u8] {
        self.public_group.group_id().as_slice()
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn ratchet_tree_bytes(&self) -> usize {
        self.ratchet_tree_bytes
    }

    pub fn member_count(&self) -> usize {
        self.member_count
    }

    pub fn signer_signature_key(&self) -> &[u8] {
        &self.signer_signature_key
    }

    pub fn signer_credential(&self) -> &Credential {
        &self.signer_credential
    }

    pub fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }

    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    pub const fn assurance(&self) -> GroupInfoAssurance {
        GroupInfoAssurance::AuthenticityOnlyNotCommitEquivalence
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GroupInfoVerificationError {
    #[error("GroupInfo verifier limits must all be non-zero")]
    InvalidLimits,
    #[error("wrapped GroupInfo is too large: {actual} bytes exceeds {maximum}")]
    InputTooLarge { actual: usize, maximum: usize },
    #[error("wrapped GroupInfo is malformed")]
    Malformed,
    #[error("wrapped GroupInfo contains trailing bytes")]
    TrailingData,
    #[error("MLS message is not a GroupInfo")]
    WrongMessageType,
    #[error("GroupInfo is missing its embedded ratchet tree")]
    MissingRatchetTree,
    #[error("ratchet tree is too large: {actual} bytes exceeds {maximum}")]
    RatchetTreeTooLarge { actual: usize, maximum: usize },
    #[error("GroupInfo verification concurrency budget is exhausted")]
    ConcurrencyBudgetExceeded,
    #[error("GroupInfo public state failed cryptographic verification: {0}")]
    InvalidPublicState(String),
    #[error("expected signer did not sign this GroupInfo")]
    WrongExpectedSigner,
    #[error("expected signer evidence does not identify exactly one member")]
    ExpectedSignerNotUnique,
    #[error("group has too many members: {actual} exceeds {maximum}")]
    TooManyMembers { actual: usize, maximum: usize },
}

struct ActiveVerificationGuard;

impl ActiveVerificationGuard {
    fn acquire(maximum: usize) -> Result<Self, GroupInfoVerificationError> {
        ACTIVE_VERIFICATIONS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < maximum).then_some(active + 1)
            })
            .map_err(|_| GroupInfoVerificationError::ConcurrencyBudgetExceeded)?;
        Ok(Self)
    }
}

impl Drop for ActiveVerificationGuard {
    fn drop(&mut self) {
        ACTIVE_VERIFICATIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn count_nonblank_leaf_slots(
    ratchet_tree: &openmls::treesync::RatchetTreeIn,
) -> Result<(usize, usize), GroupInfoVerificationError> {
    let serialized = serde_json::to_value(ratchet_tree).map_err(|_| {
        GroupInfoVerificationError::InvalidPublicState(
            "ratchet tree member layout could not be inspected".to_owned(),
        )
    })?;
    let nodes = serialized.as_array().ok_or_else(|| {
        GroupInfoVerificationError::InvalidPublicState(
            "ratchet tree member layout is malformed".to_owned(),
        )
    })?;
    let member_count = nodes
        .iter()
        .step_by(2)
        .filter(|node| !node.is_null())
        .count();
    let leaf_capacity = nodes.len().div_ceil(2);
    Ok((member_count, leaf_capacity))
}

/// Strictly parse and authenticate one wrapped MLS `GroupInfo`.
pub fn verify_group_info(
    bytes: &[u8],
    expected_signer: &ExpectedGroupInfoSigner,
    limits: GroupInfoVerifierLimits,
) -> Result<VerifiedGroupInfo, GroupInfoVerificationError> {
    if limits.max_group_info_bytes == 0
        || limits.max_ratchet_tree_bytes == 0
        || limits.max_members == 0
        || limits.max_concurrent_verifications == 0
    {
        return Err(GroupInfoVerificationError::InvalidLimits);
    }
    if bytes.len() > limits.max_group_info_bytes {
        return Err(GroupInfoVerificationError::InputTooLarge {
            actual: bytes.len(),
            maximum: limits.max_group_info_bytes,
        });
    }

    let mut remaining = bytes;
    let message = MlsMessageIn::tls_deserialize(&mut remaining)
        .map_err(|_| GroupInfoVerificationError::Malformed)?;
    if !remaining.is_empty() {
        return Err(GroupInfoVerificationError::TrailingData);
    }
    let verifiable_group_info = match message.extract() {
        MlsMessageBodyIn::GroupInfo(group_info) => group_info,
        _ => return Err(GroupInfoVerificationError::WrongMessageType),
    };
    let ratchet_tree = verifiable_group_info
        .extensions()
        .ratchet_tree()
        .ok_or(GroupInfoVerificationError::MissingRatchetTree)?
        .ratchet_tree();
    let ratchet_tree_bytes = ratchet_tree.tls_serialized_len();
    if ratchet_tree_bytes > limits.max_ratchet_tree_bytes {
        return Err(GroupInfoVerificationError::RatchetTreeTooLarge {
            actual: ratchet_tree_bytes,
            maximum: limits.max_ratchet_tree_bytes,
        });
    }
    let (prevalidated_member_count, leaf_capacity) = count_nonblank_leaf_slots(ratchet_tree)?;
    if prevalidated_member_count > limits.max_members {
        return Err(GroupInfoVerificationError::TooManyMembers {
            actual: prevalidated_member_count,
            maximum: limits.max_members,
        });
    }

    let _active_guard = ActiveVerificationGuard::acquire(limits.max_concurrent_verifications)?;
    let provider = OpenMlsRustCrypto::default();
    let expected_public_key = SignaturePublicKey::from(expected_signer.signature_key.as_slice())
        .into_signature_public_key_enriched(
            verifiable_group_info.ciphersuite().signature_algorithm(),
        );
    verifiable_group_info
        .verify_no_out(provider.crypto(), &expected_public_key)
        .map_err(|_| GroupInfoVerificationError::WrongExpectedSigner)?;

    let (public_group, _group_info) = PublicGroup::from_external(
        provider.crypto(),
        provider.storage(),
        ratchet_tree.clone(),
        verifiable_group_info,
        ProposalStore::new(),
    )
    .map_err(|error| GroupInfoVerificationError::InvalidPublicState(error.to_string()))?;

    let mut member_count = 0;
    let mut matching_signer = None;
    for leaf_index in 0..leaf_capacity {
        let leaf_index = u32::try_from(leaf_index).map_err(|_| {
            GroupInfoVerificationError::InvalidPublicState(
                "ratchet tree leaf index exceeds MLS limits".to_owned(),
            )
        })?;
        let Some(leaf) = public_group.leaf(LeafNodeIndex::new(leaf_index)) else {
            continue;
        };
        member_count += 1;
        if leaf.signature_key().as_slice() == expected_signer.signature_key
            && expected_signer
                .credential
                .as_ref()
                .is_none_or(|credential| leaf.credential() == credential)
        {
            if matching_signer.is_some() {
                return Err(GroupInfoVerificationError::ExpectedSignerNotUnique);
            }
            matching_signer = Some(leaf);
        }
    }
    if member_count != prevalidated_member_count {
        return Err(GroupInfoVerificationError::InvalidPublicState(
            "ratchet tree member count changed during validation".to_owned(),
        ));
    }
    if member_count > limits.max_members {
        return Err(GroupInfoVerificationError::TooManyMembers {
            actual: member_count,
            maximum: limits.max_members,
        });
    }
    let signer = matching_signer.ok_or(GroupInfoVerificationError::ExpectedSignerNotUnique)?;
    let signer_signature_key = signer.signature_key().as_slice().to_vec();
    let signer_credential = signer.credential().clone();
    let ciphersuite = public_group.ciphersuite();

    Ok(VerifiedGroupInfo {
        canonical_bytes: bytes.to_vec(),
        epoch: public_group.group_context().epoch().as_u64(),
        ratchet_tree_bytes,
        member_count,
        signer_signature_key,
        signer_credential,
        ciphersuite,
        signature_scheme: ciphersuite.signature_algorithm(),
        public_group,
    })
}
