use catbird_server::mls_group_info_verifier::{
    verify_group_info, ExpectedGroupInfoSigner, GroupInfoAssurance, GroupInfoVerificationError,
    GroupInfoVerifierLimits,
};
use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, OpenMlsProvider};
use std::sync::{Arc, Barrier};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, TlsDeserialize, TlsSerialize, TlsSize, VLByteSlice, VLBytes,
};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct Fixture {
    bytes: Vec<u8>,
    signer_key: Vec<u8>,
}

// Minimal test-local TLS shapes for mutating one embedded RatchetTree leaf. Keeping these
// wire-only avoids the OpenMLS `test-utils` feature and its unmaintained transitive dependencies.
#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct TestGroupInfoEnvelope {
    version: u16,
    wire_format: u16,
    group_info: TestGroupInfo,
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct TestGroupInfo {
    context: TestGroupContext,
    extensions: Vec<TestExtension>,
    confirmation_tag: VLBytes,
    signer: u32,
    signature: VLBytes,
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct TestGroupContext {
    version: u16,
    ciphersuite: u16,
    group_id: VLBytes,
    epoch: u64,
    tree_hash: VLBytes,
    confirmed_transcript_hash: VLBytes,
    extensions: Vec<TestExtension>,
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct TestExtension {
    extension_type: u16,
    data: VLBytes,
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct TestRatchetTree {
    nodes: Vec<Option<TestNode>>,
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
enum TestNode {
    #[tls_codec(discriminant = 1)]
    Leaf(TestLeaf),
    #[tls_codec(discriminant = 2)]
    Parent(TestParent),
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct TestLeaf {
    payload: TestLeafPayload,
    signature: VLBytes,
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct TestLeafPayload {
    encryption_key: VLBytes,
    signature_key: VLBytes,
    credential: TestCredential,
    capabilities: TestCapabilities,
    source: TestLeafSource,
    extensions: Vec<TestExtension>,
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct TestCredential {
    credential_type: u16,
    serialized_content: VLBytes,
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct TestCapabilities {
    versions: Vec<u16>,
    ciphersuites: Vec<u16>,
    extensions: Vec<u16>,
    proposals: Vec<u16>,
    credentials: Vec<u16>,
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
enum TestLeafSource {
    #[tls_codec(discriminant = 1)]
    KeyPackage(TestLifetime),
    #[tls_codec(discriminant = 2)]
    Update,
    #[tls_codec(discriminant = 3)]
    Commit(VLBytes),
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct TestLifetime {
    not_before: u64,
    not_after: u64,
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
struct TestParent {
    encryption_key: VLBytes,
    parent_hash: VLBytes,
    unmerged_leaves: Vec<u32>,
}

#[derive(Debug, TlsSerialize, TlsSize)]
struct TestSignContent {
    label: VLBytes,
    content: VLBytes,
}

#[derive(Debug, TlsSerialize, TlsSize)]
#[repr(u8)]
enum TestTreeHashNode<'a> {
    #[tls_codec(discriminant = 1)]
    Leaf(TestLeafHashInput<'a>),
    #[tls_codec(discriminant = 2)]
    Parent(TestParentTreeHashInput<'a>),
}

#[derive(Debug, TlsSerialize, TlsSize)]
struct TestTreeHashInput<'a> {
    node: TestTreeHashNode<'a>,
}

#[derive(Debug, TlsSerialize, TlsSize)]
struct TestLeafHashInput<'a> {
    leaf_index: u32,
    leaf: Option<&'a TestLeaf>,
}

#[derive(Debug, TlsSerialize, TlsSize)]
struct TestParentTreeHashInput<'a> {
    parent: Option<&'a TestParent>,
    left_hash: VLByteSlice<'a>,
    right_hash: VLByteSlice<'a>,
}

#[derive(Debug, TlsSerialize, TlsSize)]
struct TestParentHashInput<'a> {
    encryption_key: &'a VLBytes,
    parent_hash: &'a VLBytes,
    original_sibling_tree_hash: VLByteSlice<'a>,
}

#[derive(Debug, TlsSerialize, TlsSize)]
struct TestTreePosition<'a> {
    group_id: &'a VLBytes,
    leaf_index: u32,
}

#[derive(Debug, TlsSerialize, TlsSize)]
struct TestCommitLeafTbs<'a> {
    payload: &'a TestLeafPayload,
    tree_position: TestTreePosition<'a>,
}

fn test_leaf_hash(leaf_index: u32, leaf: &TestLeaf, crypto: &impl OpenMlsCrypto) -> Vec<u8> {
    let input = TestTreeHashInput {
        node: TestTreeHashNode::Leaf(TestLeafHashInput {
            leaf_index,
            leaf: Some(leaf),
        }),
    }
    .tls_serialize_detached()
    .expect("serialize leaf tree-hash input");
    crypto
        .hash(CIPHERSUITE.hash_algorithm(), &input)
        .expect("hash leaf")
}

fn duplicate_second_leaf_signature_key(
    bytes: &[u8],
    replacement_key: &[u8],
    signer: &impl Signer,
    crypto: &impl OpenMlsCrypto,
) -> Vec<u8> {
    let mut input = bytes;
    let mut envelope = TestGroupInfoEnvelope::tls_deserialize(&mut input)
        .expect("deserialize production GroupInfo fixture");
    assert!(input.is_empty(), "fixture must contain one exact envelope");
    assert_eq!(envelope.version, 1);
    assert_eq!(envelope.wire_format, 4);

    let group_id = envelope.group_info.context.group_id.clone();
    let tree_extension = envelope
        .group_info
        .extensions
        .iter_mut()
        .find(|extension| extension.extension_type == 2)
        .expect("embedded ratchet tree extension");
    let mut tree_input = tree_extension.data.as_slice();
    let mut tree = TestRatchetTree::tls_deserialize(&mut tree_input)
        .expect("deserialize embedded ratchet tree");
    assert!(tree_input.is_empty(), "ratchet tree payload must be exact");
    {
        let leaf = match tree.nodes.get_mut(2).and_then(Option::as_mut) {
            Some(TestNode::Leaf(leaf)) => leaf,
            _ => panic!("second member leaf"),
        };
        assert!(matches!(leaf.payload.source, TestLeafSource::KeyPackage(_)));
        leaf.payload.signature_key = replacement_key.to_vec().into();
        let leaf_payload = leaf
            .payload
            .tls_serialize_detached()
            .expect("serialize mutated leaf payload");
        let sign_content = TestSignContent {
            label: b"MLS 1.0 LeafNodeTBS".to_vec().into(),
            content: leaf_payload.into(),
        }
        .tls_serialize_detached()
        .expect("serialize labeled leaf signature input");
        leaf.signature = signer
            .sign(&sign_content)
            .expect("re-sign mutated leaf")
            .into();
    }

    let second_leaf = match tree.nodes.get(2).and_then(Option::as_ref) {
        Some(TestNode::Leaf(leaf)) => leaf,
        _ => panic!("second member leaf"),
    };
    let second_leaf_hash = test_leaf_hash(1, second_leaf, crypto);
    let root = match tree.nodes.get(1).and_then(Option::as_ref) {
        Some(TestNode::Parent(parent)) => parent,
        _ => panic!("root parent node"),
    };
    let parent_hash_input = TestParentHashInput {
        encryption_key: &root.encryption_key,
        parent_hash: &root.parent_hash,
        original_sibling_tree_hash: VLByteSlice(&second_leaf_hash),
    }
    .tls_serialize_detached()
    .expect("serialize parent-hash input");
    let parent_hash = crypto
        .hash(CIPHERSUITE.hash_algorithm(), &parent_hash_input)
        .expect("hash parent node");
    let first_leaf = match tree.nodes.get_mut(0).and_then(Option::as_mut) {
        Some(TestNode::Leaf(leaf)) => leaf,
        _ => panic!("first member leaf"),
    };
    match &mut first_leaf.payload.source {
        TestLeafSource::Commit(current_parent_hash) => {
            *current_parent_hash = parent_hash.into();
        }
        _ => panic!("first member commit leaf"),
    }
    let first_leaf_tbs = TestCommitLeafTbs {
        payload: &first_leaf.payload,
        tree_position: TestTreePosition {
            group_id: &group_id,
            leaf_index: 0,
        },
    }
    .tls_serialize_detached()
    .expect("serialize first leaf TBS");
    let sign_content = TestSignContent {
        label: b"MLS 1.0 LeafNodeTBS".to_vec().into(),
        content: first_leaf_tbs.into(),
    }
    .tls_serialize_detached()
    .expect("serialize labeled first-leaf signature input");
    first_leaf.signature = signer
        .sign(&sign_content)
        .expect("re-sign first leaf")
        .into();
    let first_leaf_hash = test_leaf_hash(0, first_leaf, crypto);
    let root = match tree.nodes.get(1).and_then(Option::as_ref) {
        Some(TestNode::Parent(parent)) => parent,
        _ => panic!("root parent node"),
    };
    let root_hash_input = TestTreeHashInput {
        node: TestTreeHashNode::Parent(TestParentTreeHashInput {
            parent: Some(root),
            left_hash: VLByteSlice(&first_leaf_hash),
            right_hash: VLByteSlice(&second_leaf_hash),
        }),
    }
    .tls_serialize_detached()
    .expect("serialize root tree-hash input");
    let root_hash = crypto
        .hash(CIPHERSUITE.hash_algorithm(), &root_hash_input)
        .expect("hash root node");
    tree_extension.data = tree
        .tls_serialize_detached()
        .expect("serialize mutated ratchet tree")
        .into();
    envelope.group_info.context.tree_hash = root_hash.into();
    let mut group_info_tbs = Vec::new();
    envelope
        .group_info
        .context
        .tls_serialize(&mut group_info_tbs)
        .expect("serialize GroupContext");
    envelope
        .group_info
        .extensions
        .tls_serialize(&mut group_info_tbs)
        .expect("serialize GroupInfo extensions");
    envelope
        .group_info
        .confirmation_tag
        .tls_serialize(&mut group_info_tbs)
        .expect("serialize confirmation tag");
    tls_codec::Serialize::tls_serialize(&envelope.group_info.signer, &mut group_info_tbs)
        .expect("serialize GroupInfo signer");
    let sign_content = TestSignContent {
        label: b"MLS 1.0 GroupInfoTBS".to_vec().into(),
        content: group_info_tbs.into(),
    }
    .tls_serialize_detached()
    .expect("serialize labeled GroupInfo signature input");
    envelope.group_info.signature = signer
        .sign(&sign_content)
        .expect("re-sign GroupInfo")
        .into();
    envelope
        .tls_serialize_detached()
        .expect("serialize mutated GroupInfo fixture")
}

fn fixture_with_options(with_ratchet_tree: bool, lifetime: Option<Lifetime>) -> Fixture {
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("signer");
    signer.store(provider.storage()).expect("store signer");
    let credential = BasicCredential::new(b"did:plc:alice".to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    let mut config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(with_ratchet_tree);
    if let Some(lifetime) = lifetime {
        config = config.lifetime(lifetime);
    }
    let config = config.build();
    let group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &config,
        GroupId::from_slice(b"group-info-verifier-test"),
        credential_with_key,
    )
    .expect("create group");
    let message = group
        .export_group_info(provider.crypto(), &signer, with_ratchet_tree)
        .expect("export group info");

    Fixture {
        bytes: message
            .tls_serialize_detached()
            .expect("serialize wrapped GroupInfo"),
        signer_key: signer.to_public_vec(),
    }
}

fn valid_fixture() -> Fixture {
    fixture_with_options(true, None)
}

fn assert_invalid_public_state(error: GroupInfoVerificationError) {
    assert!(
        matches!(error, GroupInfoVerificationError::InvalidPublicState(_)),
        "unexpected error: {error:?}"
    );
}

fn two_member_fixture(duplicate_signature_key: bool) -> Fixture {
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let alice_signer =
        SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("alice signer");
    alice_signer
        .store(provider.storage())
        .expect("store alice signer");
    let alice_credential = CredentialWithKey {
        credential: BasicCredential::new(b"did:plc:alice".to_vec()).into(),
        signature_key: alice_signer.to_public_vec().into(),
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let mut group = MlsGroup::new_with_group_id(
        &provider,
        &alice_signer,
        &config,
        GroupId::from_slice(b"group-info-verifier-test"),
        alice_credential,
    )
    .expect("create group");

    let bob_signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("bob signer");
    bob_signer
        .store(provider.storage())
        .expect("store bob signer");
    let bob_signature_key = bob_signer.to_public_vec();
    let bob_credential = CredentialWithKey {
        credential: BasicCredential::new(b"did:plc:bob".to_vec()).into(),
        signature_key: bob_signature_key.clone().into(),
    };
    let bob_key_package = KeyPackage::builder()
        .build(CIPHERSUITE, &provider, &bob_signer, bob_credential)
        .expect("bob key package");
    group
        .add_members(
            &provider,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        )
        .expect("add bob");
    group
        .merge_pending_commit(&provider)
        .expect("merge add commit");
    let message = group
        .export_group_info(provider.crypto(), &alice_signer, true)
        .expect("export group info");
    let mut bytes = message
        .tls_serialize_detached()
        .expect("serialize two-member fixture");
    let alice_signature_key = alice_signer.to_public_vec();
    if duplicate_signature_key {
        bytes = duplicate_second_leaf_signature_key(
            &bytes,
            &alice_signature_key,
            &alice_signer,
            provider.crypto(),
        );
    }
    Fixture {
        bytes,
        signer_key: alice_signature_key,
    }
}

#[test]
fn valid_wrapped_group_info_yields_scoped_verified_evidence() {
    let fixture = valid_fixture();
    let verified = verify_group_info(
        &fixture.bytes,
        &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
        GroupInfoVerifierLimits::default(),
    )
    .expect("valid GroupInfo");

    assert_eq!(verified.canonical_bytes(), fixture.bytes);
    assert_eq!(verified.group_id(), b"group-info-verifier-test");
    assert_eq!(verified.epoch(), 0);
    assert_eq!(verified.member_count(), 1);
    assert_eq!(verified.signer_signature_key(), fixture.signer_key);
    assert_eq!(
        verified.assurance(),
        GroupInfoAssurance::AuthenticityOnlyNotCommitEquivalence
    );
}

#[test]
fn verified_capability_debug_output_is_bounded_and_redacted() {
    let fixture = valid_fixture();
    let verified = verify_group_info(
        &fixture.bytes,
        &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
        GroupInfoVerifierLimits::default(),
    )
    .expect("valid GroupInfo");
    let debug = format!("{verified:?}");
    assert!(!debug.contains("canonical_bytes"));
    assert!(!debug.contains("signer_credential"));
    assert!(debug.len() < 512);
}

#[test]
fn malformed_input_is_rejected() {
    let error = verify_group_info(
        b"not an MLS message",
        &ExpectedGroupInfoSigner::by_signature_key([0u8; 32]),
        GroupInfoVerifierLimits::default(),
    )
    .expect_err("malformed input must fail");
    assert_eq!(error, GroupInfoVerificationError::Malformed);
}

#[test]
fn trailing_bytes_are_rejected() {
    let fixture = valid_fixture();
    let mut bytes = fixture.bytes;
    bytes.push(0);
    let error = verify_group_info(
        &bytes,
        &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
        GroupInfoVerifierLimits::default(),
    )
    .expect_err("trailing bytes must fail");
    assert_eq!(error, GroupInfoVerificationError::TrailingData);
}

#[test]
fn noncanonical_variable_length_encoding_is_rejected() {
    let fixture = valid_fixture();
    let mut bytes = fixture.bytes;
    // MLSMessage header (version + wire format), GroupContext version and
    // ciphersuite occupy the first eight bytes. The group_id VL length follows.
    let canonical_length = bytes[8];
    assert!(
        canonical_length < 64,
        "fixture group id uses one-byte VL encoding"
    );
    bytes[8] = 0x40;
    bytes.insert(9, canonical_length);

    assert_eq!(
        verify_group_info(
            &bytes,
            &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
            GroupInfoVerifierLimits::default(),
        )
        .expect_err("non-minimal VL encoding must fail"),
        GroupInfoVerificationError::Malformed
    );
}

#[test]
fn raw_legacy_group_info_framing_is_rejected() {
    let fixture = valid_fixture();
    let error = verify_group_info(
        &fixture.bytes[4..],
        &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
        GroupInfoVerifierLimits::default(),
    )
    .expect_err("raw GroupInfo must fail");
    assert!(matches!(
        error,
        GroupInfoVerificationError::Malformed | GroupInfoVerificationError::WrongMessageType
    ));
}

#[test]
fn oversized_input_is_rejected_before_parsing() {
    let fixture = valid_fixture();
    let limits = GroupInfoVerifierLimits {
        max_group_info_bytes: fixture.bytes.len() - 1,
        ..GroupInfoVerifierLimits::default()
    };
    let error = verify_group_info(
        &fixture.bytes,
        &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
        limits,
    )
    .expect_err("oversized GroupInfo must fail");
    assert!(matches!(
        error,
        GroupInfoVerificationError::InputTooLarge { .. }
    ));
}

#[test]
fn missing_embedded_ratchet_tree_is_rejected() {
    let fixture = fixture_with_options(false, None);
    let error = verify_group_info(
        &fixture.bytes,
        &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
        GroupInfoVerifierLimits::default(),
    )
    .expect_err("missing embedded tree must fail");
    assert_eq!(error, GroupInfoVerificationError::MissingRatchetTree);
}

#[test]
fn ratchet_tree_budget_is_enforced() {
    let fixture = valid_fixture();
    let verified = verify_group_info(
        &fixture.bytes,
        &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
        GroupInfoVerifierLimits::default(),
    )
    .expect("fixture");
    let limits = GroupInfoVerifierLimits {
        max_ratchet_tree_bytes: verified.ratchet_tree_bytes() - 1,
        ..GroupInfoVerifierLimits::default()
    };
    let error = verify_group_info(
        &fixture.bytes,
        &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
        limits,
    )
    .expect_err("oversized tree must fail");
    assert!(matches!(
        error,
        GroupInfoVerificationError::RatchetTreeTooLarge { .. }
    ));
}

#[test]
fn signature_bitflip_is_rejected() {
    let fixture = valid_fixture();
    let mut bytes = fixture.bytes;
    *bytes.last_mut().expect("signature byte") ^= 1;
    assert_eq!(
        verify_group_info(
            &bytes,
            &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
            GroupInfoVerifierLimits::default(),
        )
        .expect_err("signature bitflip must fail"),
        GroupInfoVerificationError::WrongExpectedSigner
    );
}

#[test]
fn tree_hash_bitflip_is_rejected() {
    let fixture = valid_fixture();
    let mut bytes = fixture.bytes;
    let group_id = b"group-info-verifier-test";
    let group_id_start = bytes
        .windows(group_id.len())
        .position(|window| window == group_id)
        .expect("group id in GroupContext");
    let tree_hash_length_offset = group_id_start + group_id.len() + 8;
    assert_eq!(bytes[tree_hash_length_offset], 32);
    bytes[tree_hash_length_offset + 1] ^= 1;
    assert_eq!(
        verify_group_info(
            &bytes,
            &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
            GroupInfoVerifierLimits::default(),
        )
        .expect_err("tree hash bitflip must fail"),
        GroupInfoVerificationError::WrongExpectedSigner
    );
}

#[test]
fn wrong_expected_signer_is_rejected() {
    let fixture = valid_fixture();
    let other = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("other signer");
    let error = verify_group_info(
        &fixture.bytes,
        &ExpectedGroupInfoSigner::by_signature_key(other.to_public_vec()),
        GroupInfoVerifierLimits::default(),
    )
    .expect_err("wrong signer must fail");
    assert_eq!(error, GroupInfoVerificationError::WrongExpectedSigner);
}

#[test]
fn wrong_expected_signer_fails_before_public_state_crypto() {
    let fixture = valid_fixture();
    let other = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("other signer");
    let mut bytes = fixture.bytes;
    let group_id = b"group-info-verifier-test";
    let group_id_start = bytes
        .windows(group_id.len())
        .position(|window| window == group_id)
        .expect("group id in GroupContext");
    let tree_hash_length_offset = group_id_start + group_id.len() + 8;
    bytes[tree_hash_length_offset + 1] ^= 1;

    let error = verify_group_info(
        &bytes,
        &ExpectedGroupInfoSigner::by_signature_key(other.to_public_vec()),
        GroupInfoVerifierLimits::default(),
    )
    .expect_err("wrong signer must fail before tree verification");
    assert_eq!(error, GroupInfoVerificationError::WrongExpectedSigner);
}

#[test]
fn expired_leaf_is_rejected() {
    let fixture = fixture_with_options(true, Some(Lifetime::new(0)));
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert_invalid_public_state(
        verify_group_info(
            &fixture.bytes,
            &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
            GroupInfoVerifierLimits::default(),
        )
        .expect_err("expired leaf must fail"),
    );
}

#[test]
fn duplicate_member_signature_keys_are_rejected() {
    let fixture = two_member_fixture(true);
    let error = verify_group_info(
        &fixture.bytes,
        &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
        GroupInfoVerifierLimits::default(),
    )
    .expect_err("duplicate member keys must fail");
    let debug = format!("{error:?}");
    assert_invalid_public_state(error);
    assert!(
        debug.contains("ratchet tree contains duplcate signature keys"),
        "fixture must reach OpenMLS duplicate-key rejection: {debug}"
    );
}

#[test]
fn member_budget_is_enforced() {
    let fixture = two_member_fixture(false);
    let error = verify_group_info(
        &fixture.bytes,
        &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
        GroupInfoVerifierLimits {
            max_members: 1,
            ..GroupInfoVerifierLimits::default()
        },
    )
    .expect_err("two members must exceed a one-member budget");
    assert_eq!(
        error,
        GroupInfoVerificationError::TooManyMembers {
            actual: 2,
            maximum: 1
        }
    );
}

#[test]
fn member_budget_is_enforced_before_public_state_crypto() {
    let fixture = two_member_fixture(false);
    let mut bytes = fixture.bytes;
    *bytes.last_mut().expect("GroupInfo signature byte") ^= 1;
    let error = verify_group_info(
        &bytes,
        &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
        GroupInfoVerifierLimits {
            max_members: 1,
            ..GroupInfoVerifierLimits::default()
        },
    )
    .expect_err("member budget must fail before signature verification");
    assert_eq!(
        error,
        GroupInfoVerificationError::TooManyMembers {
            actual: 2,
            maximum: 1
        }
    );
}

#[test]
fn concurrent_verification_budget_fails_closed() {
    let fixture = valid_fixture();
    let fixture = Arc::new(fixture);
    let barrier = Arc::new(Barrier::new(16));
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let fixture = Arc::clone(&fixture);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                verify_group_info(
                    &fixture.bytes,
                    &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
                    GroupInfoVerifierLimits {
                        max_concurrent_verifications: 1,
                        ..GroupInfoVerifierLimits::default()
                    },
                )
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker"))
        .collect();
    assert!(results.iter().any(|result| {
        matches!(
            result,
            Err(GroupInfoVerificationError::ConcurrencyBudgetExceeded)
        )
    }));
    verify_group_info(
        &fixture.bytes,
        &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
        GroupInfoVerifierLimits::default(),
    )
    .expect("budget permits work again after all guards are dropped");
}
