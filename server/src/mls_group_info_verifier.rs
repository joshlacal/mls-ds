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
    prelude::{BasicCredential, Credential, LeafNodeIndex, MlsMessageBodyIn, MlsMessageIn},
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

use crate::{auth::device_auth::VerifiedDeviceRequest, models::ResolvedMlsContext};

/// The exact security statement made by [`AuthenticatedGroupInfo`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupInfoAssurance {
    /// Authentic public state only; no submitted commit has been processed.
    AuthenticityOnlyNotCommitEquivalence,
}

/// Authenticated public MLS state that is not yet bound to server context.
///
/// Construction and fields are private, and this type intentionally has no
/// Serde or TLS serialization implementation.
pub struct AuthenticatedGroupInfo {
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

impl std::fmt::Debug for AuthenticatedGroupInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedGroupInfo")
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

impl AuthenticatedGroupInfo {
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

/// Cryptographically authenticated GroupInfo bound to one resolved server
/// conversation and one registry-verified device request.
///
/// This capability is intentionally opaque and has no Serde/TLS implementation.
/// It can only be constructed by [`verify_group_info_for_transition`].
pub struct VerifiedGroupInfo {
    authenticated: AuthenticatedGroupInfo,
    conversation_id: String,
    actor_did: String,
    actor_device_id: String,
    device_dpop_jkt: String,
    device_auth_generation: i64,
}

impl std::fmt::Debug for VerifiedGroupInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedGroupInfo")
            .field("conversation_id", &self.conversation_id)
            .field("actor_did", &self.actor_did)
            .field("actor_device_id", &self.actor_device_id)
            .field("device_auth_generation", &self.device_auth_generation)
            .field("encoded_len", &self.authenticated.canonical_bytes.len())
            .field("group_id_len", &self.authenticated.group_id().len())
            .field("epoch", &self.authenticated.epoch)
            .finish_non_exhaustive()
    }
}

impl VerifiedGroupInfo {
    pub fn canonical_bytes(&self) -> &[u8] {
        self.authenticated.canonical_bytes()
    }

    pub fn conversation_id(&self) -> &str {
        &self.conversation_id
    }

    pub fn actor_did(&self) -> &str {
        &self.actor_did
    }

    pub fn actor_device_id(&self) -> &str {
        &self.actor_device_id
    }

    pub fn device_auth_generation(&self) -> i64 {
        self.device_auth_generation
    }

    pub fn group_id(&self) -> &[u8] {
        self.authenticated.group_id()
    }

    pub fn epoch(&self) -> u64 {
        self.authenticated.epoch()
    }

    pub fn signer_signature_key(&self) -> &[u8] {
        self.authenticated.signer_signature_key()
    }

    pub fn signer_credential(&self) -> &Credential {
        self.authenticated.signer_credential()
    }

    pub(crate) fn device_dpop_jkt(&self) -> &str {
        &self.device_dpop_jkt
    }

    pub(crate) fn into_canonical_bytes(self) -> Vec<u8> {
        self.authenticated.canonical_bytes
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
    #[error("expected signer does not carry the verified bare-user BasicCredential")]
    WrongExpectedCredential,
    #[error("GroupInfo does not bind the resolved MLS group identifier")]
    UnexpectedGroupId,
    #[error("GroupInfo epoch is not exactly authoritative_epoch + 1")]
    UnexpectedEpoch,
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
) -> Result<AuthenticatedGroupInfo, GroupInfoVerificationError> {
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
    let mut signer_key_with_wrong_credential = false;
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
        if leaf.signature_key().as_slice() == expected_signer.signature_key {
            if expected_signer
                .credential
                .as_ref()
                .is_some_and(|credential| leaf.credential() != credential)
            {
                signer_key_with_wrong_credential = true;
                continue;
            }
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
    let signer = matching_signer.ok_or({
        if signer_key_with_wrong_credential {
            GroupInfoVerificationError::WrongExpectedCredential
        } else {
            GroupInfoVerificationError::ExpectedSignerNotUnique
        }
    })?;
    let signer_signature_key = signer.signature_key().as_slice().to_vec();
    let signer_credential = signer.credential().clone();
    let ciphersuite = public_group.ciphersuite();

    Ok(AuthenticatedGroupInfo {
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

/// Verify and bind a canonical GroupInfo for a server transition.
///
/// The TLS decoder rejects non-minimal variable-length encodings and this
/// function rejects any trailing bytes, so `canonical_bytes` is the exact,
/// canonical wire envelope that was authenticated. The expected credential is
/// derived internally from the verified request's bare user DID; callers cannot
/// substitute an arbitrary credential DTO.
pub fn verify_group_info_for_transition(
    bytes: &[u8],
    context: &ResolvedMlsContext,
    device: &VerifiedDeviceRequest,
    expected_registry_signature_key: &[u8],
    limits: GroupInfoVerifierLimits,
) -> Result<VerifiedGroupInfo, GroupInfoVerificationError> {
    let expected_credential =
        Credential::from(BasicCredential::new(device.user_did().as_bytes().to_vec()));
    let authenticated = verify_group_info(
        bytes,
        &ExpectedGroupInfoSigner::by_signature_key(expected_registry_signature_key)
            .with_credential(expected_credential),
        limits,
    )?;

    if hex::encode(authenticated.group_id()) != context.mls_group_id {
        return Err(GroupInfoVerificationError::UnexpectedGroupId);
    }
    let expected_epoch = u64::try_from(context.authoritative_epoch)
        .ok()
        .and_then(|epoch| epoch.checked_add(1))
        .ok_or(GroupInfoVerificationError::UnexpectedEpoch)?;
    if authenticated.epoch() != expected_epoch {
        return Err(GroupInfoVerificationError::UnexpectedEpoch);
    }
    if authenticated.signer_credential()
        != &Credential::from(BasicCredential::new(device.user_did().as_bytes().to_vec()))
    {
        return Err(GroupInfoVerificationError::WrongExpectedCredential);
    }

    Ok(VerifiedGroupInfo {
        authenticated,
        conversation_id: context.conversation_id.clone(),
        actor_did: device.user_did().to_owned(),
        actor_device_id: device.device_id().to_owned(),
        device_dpop_jkt: device.dpop_jkt().to_owned(),
        device_auth_generation: device.auth_generation(),
    })
}

#[cfg(test)]
pub(crate) mod context_binding_tests {
    use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::OpenMlsProvider;

    use crate::{auth::device_auth::VerifiedDeviceRequest, models::ResolvedMlsContext};

    use super::{
        verify_group_info_for_transition, GroupInfoVerificationError, GroupInfoVerifierLimits,
    };

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const GROUP_ID: &[u8] = b"group-info-verifier-test";

    pub(crate) struct BoundFixture {
        pub bytes: Vec<u8>,
        pub signer_key: Vec<u8>,
        pub context: ResolvedMlsContext,
        pub device: VerifiedDeviceRequest,
    }

    pub(crate) fn bound_fixture() -> BoundFixture {
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("signer");
        signer.store(provider.storage()).expect("store signer");
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(b"did:plc:alice".to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let mut group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            GroupId::from_slice(GROUP_ID),
            credential_with_key,
        )
        .expect("create group");
        group
            .self_update(&provider, &signer, LeafNodeParameters::default())
            .expect("self update");
        group
            .merge_pending_commit(&provider)
            .expect("merge self update");
        let bytes = group
            .export_group_info(provider.crypto(), &signer, true)
            .expect("export group info")
            .tls_serialize_detached()
            .expect("serialize wrapped GroupInfo");
        BoundFixture {
            bytes,
            signer_key: signer.to_public_vec(),
            context: ResolvedMlsContext {
                conversation_id: "convo-1".into(),
                crypto_session_id: "session-1".into(),
                mls_group_id: hex::encode(GROUP_ID),
                reset_generation: 2,
                state: "active".into(),
                authoritative_epoch: 0,
                confirmation_tag: None,
                group_info: None,
                group_info_epoch: None,
                sequencer_did: "did:web:mls.example.com".into(),
                sequencer_term: 4,
                receipt: None,
            },
            device: VerifiedDeviceRequest::fixture_for_policy_test(
                "did:plc:alice",
                "device-a",
                &"a".repeat(43),
                7,
            ),
        }
    }

    #[test]
    fn verified_group_info_binds_context_device_registry_key_and_canonical_bytes() {
        let fixture = bound_fixture();
        let verified = verify_group_info_for_transition(
            &fixture.bytes,
            &fixture.context,
            &fixture.device,
            &fixture.signer_key,
            GroupInfoVerifierLimits::default(),
        )
        .expect("context-bound GroupInfo");

        assert_eq!(verified.conversation_id(), "convo-1");
        assert_eq!(verified.actor_did(), "did:plc:alice");
        assert_eq!(verified.actor_device_id(), "device-a");
        assert_eq!(verified.device_auth_generation(), 7);
        assert_eq!(verified.group_id(), GROUP_ID);
        assert_eq!(verified.epoch(), 1);
        assert_eq!(verified.canonical_bytes(), fixture.bytes);
        assert_eq!(verified.signer_signature_key(), fixture.signer_key);
        assert_eq!(
            verified.signer_credential().clone(),
            Credential::from(BasicCredential::new(b"did:plc:alice".to_vec()))
        );
    }

    #[test]
    fn context_bound_verification_rejects_wrong_group_epoch_and_credential() {
        let fixture = bound_fixture();

        let mut wrong_group = fixture.context.clone();
        wrong_group.mls_group_id = hex::encode(b"other-group");
        assert_eq!(
            verify_group_info_for_transition(
                &fixture.bytes,
                &wrong_group,
                &fixture.device,
                &fixture.signer_key,
                GroupInfoVerifierLimits::default(),
            )
            .expect_err("wrong group"),
            GroupInfoVerificationError::UnexpectedGroupId
        );

        let mut wrong_epoch = fixture.context.clone();
        wrong_epoch.authoritative_epoch = 1;
        assert_eq!(
            verify_group_info_for_transition(
                &fixture.bytes,
                &wrong_epoch,
                &fixture.device,
                &fixture.signer_key,
                GroupInfoVerifierLimits::default(),
            )
            .expect_err("wrong epoch"),
            GroupInfoVerificationError::UnexpectedEpoch
        );

        let wrong_device = VerifiedDeviceRequest::fixture_for_policy_test(
            "did:plc:mallory",
            "device-m",
            &"m".repeat(43),
            1,
        );
        assert_eq!(
            verify_group_info_for_transition(
                &fixture.bytes,
                &fixture.context,
                &wrong_device,
                &fixture.signer_key,
                GroupInfoVerifierLimits::default(),
            )
            .expect_err("credential identity must be the verified bare user DID"),
            GroupInfoVerificationError::WrongExpectedCredential
        );
    }
}
