use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    time::{SystemTime, UNIX_EPOCH},
};

use catbird_server::chat_protocol::snapshot::{
    decode_public_group_snapshot, encode_public_group_snapshot, public_group_snapshot_binding,
    PublicGroupSnapshotBinding, PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle,
};
use catbird_server::chat_protocol::wire::{
    process_public_commit, validate_group_info, validate_key_package, validate_private_application,
    validate_public_commit, validate_welcome, GroupInfoValidationPolicy,
    KeyPackageValidationPolicy, PublicCommitValidationPolicy, ValidatedGroupInfo,
    WireValidationError, MAX_GROUP_INFO_WIRE_BYTES, MAX_KEY_PACKAGE_LIFETIME_SECONDS,
    MAX_KEY_PACKAGE_WIRE_BYTES, MAX_PRIVATE_MESSAGE_WIRE_BYTES, MAX_PUBLIC_MESSAGE_WIRE_BYTES,
    MAX_WELCOME_WIRE_BYTES, MIN_KEY_PACKAGE_REMAINING_SECONDS, XWING_CIPHERSUITE,
};
use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer, OpenMlsProvider};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, VLBytes};

const TEST_ALICE_CREDENTIAL: &[u8] = b"did:web:a.co#00000000-0000-4000-8000-000000000001";
const TEST_BOB_CREDENTIAL: &[u8] = b"did:web:b.co#00000000-0000-4000-8000-000000000002";

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestWelcomeEnvelope {
    version: u16,
    wire_format: u16,
    welcome: TestWelcome,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestWelcome {
    ciphersuite: u16,
    secrets: Vec<TestEncryptedGroupSecrets>,
    encrypted_group_info: VLBytes,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestEncryptedGroupSecrets {
    new_member: VLBytes,
    encrypted_group_secrets: TestHpkeCiphertext,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestHpkeCiphertext {
    kem_output: VLBytes,
    ciphertext: VLBytes,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestWireUpdatePathNode {
    public_key: VLBytes,
    encrypted_path_secrets: Vec<TestHpkeCiphertext>,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestWireUpdatePath {
    leaf_node: TestWireLeafNode,
    nodes: Vec<TestWireUpdatePathNode>,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupInfoEnvelope {
    version: u16,
    wire_format: u16,
    group_info: TestGroupInfo,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupInfo {
    context: TestGroupContext,
    extensions: Vec<TestExtension>,
    confirmation_tag: VLBytes,
    signer: u32,
    signature: VLBytes,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupContext {
    protocol_version: u16,
    ciphersuite: u16,
    group_id: VLBytes,
    epoch: u64,
    tree_hash: VLBytes,
    confirmed_transcript_hash: VLBytes,
    extensions: Vec<TestExtension>,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestExtension {
    extension_type: u16,
    extension_data: VLBytes,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestWireKeyPackage {
    payload: TestWireKeyPackageTbs,
    signature: VLBytes,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestWireKeyPackageTbs {
    protocol_version: u16,
    ciphersuite: u16,
    init_key: VLBytes,
    leaf_node: TestWireLeafNode,
    extensions: Vec<TestExtension>,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestWireLeafNode {
    payload: TestWireLeafNodeTbs,
    signature: VLBytes,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestWireLeafNodeTbs {
    encryption_key: VLBytes,
    signature_key: VLBytes,
    credential: TestWireCredential,
    capabilities: TestWireCapabilities,
    source: TestWireLeafNodeSource,
    extensions: Vec<TestExtension>,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestWireCredential {
    credential_type: u16,
    serialized_content: VLBytes,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestWireCapabilities {
    versions: Vec<u16>,
    ciphersuites: Vec<u16>,
    extensions: Vec<u16>,
    proposals: Vec<u16>,
    credentials: Vec<u16>,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
#[repr(u8)]
enum TestWireLeafNodeSource {
    #[tls_codec(discriminant = 1)]
    KeyPackage(TestWireLifetime),
    #[tls_codec(discriminant = 2)]
    Update,
    #[tls_codec(discriminant = 3)]
    Commit(VLBytes),
}

#[derive(
    Clone, Copy, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize,
)]
struct TestWireLifetime {
    not_before: u64,
    not_after: u64,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
#[repr(u8)]
enum TestWireNode {
    #[tls_codec(discriminant = 1)]
    LeafNode(Box<TestWireLeafNode>),
    #[tls_codec(discriminant = 2)]
    ParentNode(Box<TestWireParentNode>),
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestWireParentNode {
    encryption_key: VLBytes,
    parent_hash: VLBytes,
    unmerged_leaves: Vec<u32>,
}

#[derive(tls_codec::TlsSerialize, tls_codec::TlsSize)]
struct TestGroupInfoTbs<'a> {
    context: &'a TestGroupContext,
    extensions: &'a [TestExtension],
    confirmation_tag: &'a VLBytes,
    signer: u32,
}

#[derive(tls_codec::TlsSerialize, tls_codec::TlsSize)]
struct TestLeafNodeHashInput<'a> {
    leaf_index: u32,
    leaf_node: Option<&'a TestWireLeafNode>,
}

#[derive(tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[repr(u8)]
enum TestTreeHashNode<'a> {
    #[tls_codec(discriminant = 1)]
    Leaf(TestLeafNodeHashInput<'a>),
}

#[derive(tls_codec::TlsSerialize, tls_codec::TlsSize)]
struct TestTreeHashInput<'a> {
    node: TestTreeHashNode<'a>,
}

#[derive(Debug, tls_codec::TlsSerialize, tls_codec::TlsSize)]
struct TestMlsSignContent {
    label: VLBytes,
    content: VLBytes,
}

fn frozen_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_secs()
}

struct KeyPackageFixture {
    wrapped: Vec<u8>,
    inner: Vec<u8>,
    key_package_ref: Vec<u8>,
    signature_key: Vec<u8>,
    signer: SignatureKeyPair,
}

fn key_package_fixture(credential: &[u8], lifetime: Lifetime) -> KeyPackageFixture {
    key_package_fixture_with_profile(credential, lifetime, true, false)
}

fn key_package_fixture_with_profile(
    credential: &[u8],
    lifetime: Lifetime,
    exact_capabilities: bool,
    last_resort: bool,
) -> KeyPackageFixture {
    let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
    let signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("Ed25519 signer");
    signer.store(provider.storage()).expect("store signer");
    let capabilities = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[XWING_CIPHERSUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );
    let mut builder = KeyPackage::builder().key_package_lifetime(lifetime);
    if exact_capabilities {
        builder = builder.leaf_node_capabilities(capabilities);
    }
    if last_resort {
        builder = builder.mark_as_last_resort();
    }
    let bundle = builder
        .build(
            XWING_CIPHERSUITE,
            &provider,
            &signer,
            CredentialWithKey {
                credential: BasicCredential::new(credential.to_vec()).into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect("build XWing KeyPackage");
    let inner = bundle
        .key_package()
        .tls_serialize_detached()
        .expect("serialize inner KeyPackage");
    let wrapped = MlsMessageOut::from(bundle.key_package().clone())
        .tls_serialize_detached()
        .expect("serialize wire-format 5 MLSMessage");
    let key_package_ref = bundle
        .key_package()
        .hash_ref(provider.crypto())
        .expect("OpenMLS hash_ref")
        .as_slice()
        .to_vec();
    KeyPackageFixture {
        wrapped,
        inner,
        key_package_ref,
        signature_key: signer.to_public_vec(),
        signer,
    }
}

fn key_package_policy<'a>(
    fixture: &'a KeyPackageFixture,
    expected_credential: &'a [u8],
    now_unix_seconds: u64,
) -> KeyPackageValidationPolicy<'a> {
    KeyPackageValidationPolicy {
        expected_basic_credential: expected_credential,
        expected_signature_key: &fixture.signature_key,
        now_unix_seconds,
        max_bytes: MAX_KEY_PACKAGE_WIRE_BYTES,
    }
}

fn wrap_test_key_package(key_package: &TestWireKeyPackage) -> Vec<u8> {
    let inner = key_package
        .tls_serialize_detached()
        .expect("serialize test KeyPackage");
    let mut wrapped = vec![0, 1, 0, 5];
    wrapped.extend_from_slice(&inner);
    wrapped
}

fn resign_test_key_package(key_package: &mut TestWireKeyPackage, signer: &SignatureKeyPair) {
    let payload = key_package
        .payload
        .tls_serialize_detached()
        .expect("serialize mutated KeyPackageTBS");
    let sign_content = TestMlsSignContent {
        label: b"MLS 1.0 KeyPackageTBS".to_vec().into(),
        content: payload.into(),
    }
    .tls_serialize_detached()
    .expect("serialize MLS sign content");
    key_package.signature = signer
        .sign(&sign_content)
        .expect("re-sign mutated KeyPackageTBS")
        .into();
}

fn resign_test_leaf_node(leaf_node: &mut TestWireLeafNode, signer: &SignatureKeyPair) {
    let payload = leaf_node
        .payload
        .tls_serialize_detached()
        .expect("serialize mutated LeafNodeTBS");
    let sign_content = TestMlsSignContent {
        label: b"MLS 1.0 LeafNodeTBS".to_vec().into(),
        content: payload.into(),
    }
    .tls_serialize_detached()
    .expect("serialize leaf MLS sign content");
    leaf_node.signature = signer
        .sign(&sign_content)
        .expect("re-sign mutated LeafNodeTBS")
        .into();
}

fn resign_test_group_info(envelope: &mut TestGroupInfoEnvelope, signer: &SignatureKeyPair) {
    let payload = TestGroupInfoTbs {
        context: &envelope.group_info.context,
        extensions: &envelope.group_info.extensions,
        confirmation_tag: &envelope.group_info.confirmation_tag,
        signer: envelope.group_info.signer,
    }
    .tls_serialize_detached()
    .expect("serialize mutated GroupInfoTBS");
    let sign_content = TestMlsSignContent {
        label: b"MLS 1.0 GroupInfoTBS".to_vec().into(),
        content: payload.into(),
    }
    .tls_serialize_detached()
    .expect("serialize GroupInfo MLS sign content");
    envelope.group_info.signature = signer
        .sign(&sign_content)
        .expect("re-sign mutated GroupInfoTBS")
        .into();
}

fn mutate_singleton_leaf(
    envelope: &mut TestGroupInfoEnvelope,
    signer: &SignatureKeyPair,
    mutate: impl FnOnce(&mut TestWireLeafNode),
) {
    let ratchet_tree = envelope
        .group_info
        .extensions
        .first_mut()
        .expect("ratchet_tree extension");
    assert_eq!(ratchet_tree.extension_type, 2);
    let mut nodes =
        <Vec<Option<TestWireNode>>>::tls_deserialize_exact(ratchet_tree.extension_data.as_slice())
            .expect("parse singleton ratchet tree");
    assert_eq!(nodes.len(), 1, "expected singleton ratchet tree");
    let Some(Some(TestWireNode::LeafNode(leaf_node))) = nodes.first_mut() else {
        panic!("expected singleton leaf node");
    };
    mutate(leaf_node);
    resign_test_leaf_node(leaf_node, signer);
    let tree_hash_input = TestTreeHashInput {
        node: TestTreeHashNode::Leaf(TestLeafNodeHashInput {
            leaf_index: 0,
            leaf_node: Some(leaf_node),
        }),
    }
    .tls_serialize_detached()
    .expect("serialize singleton tree hash input");
    envelope.group_info.context.tree_hash = Sha256::digest(tree_hash_input).to_vec().into();
    ratchet_tree.extension_data = nodes
        .tls_serialize_detached()
        .expect("serialize mutated singleton ratchet tree")
        .into();
    resign_test_group_info(envelope, signer);
}

fn widen_two_byte_varint(bytes: &[u8], offset: usize) -> Vec<u8> {
    assert_eq!(
        bytes[offset] & 0xC0,
        0x40,
        "expected two-byte TLS vector length"
    );
    let value = (u32::from(bytes[offset] & 0x3F) << 8) | u32::from(bytes[offset + 1]);
    let nonminimal = (value | 0x8000_0000).to_be_bytes();
    let mut widened = Vec::with_capacity(bytes.len() + 2);
    widened.extend_from_slice(&bytes[..offset]);
    widened.extend_from_slice(&nonminimal);
    widened.extend_from_slice(&bytes[offset + 2..]);
    widened
}

fn replace_public_commit_proposals(commit: &[u8], proposals: Vec<u8>) -> Vec<u8> {
    let mut inner = &commit[4..];
    let _ = VLBytes::tls_deserialize(&mut inner).expect("commit group id");
    let _ = u64::tls_deserialize(&mut inner).expect("commit epoch");
    let _ = Sender::tls_deserialize(&mut inner).expect("commit sender");
    let _ = VLBytes::tls_deserialize(&mut inner).expect("commit aad");
    let content_type = u8::tls_deserialize(&mut inner).expect("commit content type");
    assert_eq!(content_type, ContentType::Commit as u8);
    let vector_start = commit.len() - inner.len();
    let before = inner.len();
    let _ = VLBytes::tls_deserialize(&mut inner).expect("commit proposals vector");
    let vector_end = vector_start + before - inner.len();
    let encoded_proposals = VLBytes::from(proposals)
        .tls_serialize_detached()
        .expect("serialize replacement proposals vector");
    let mut replaced =
        Vec::with_capacity(commit.len() - (vector_end - vector_start) + encoded_proposals.len());
    replaced.extend_from_slice(&commit[..vector_start]);
    replaced.extend_from_slice(&encoded_proposals);
    replaced.extend_from_slice(&commit[vector_end..]);
    replaced
}

fn public_commit_proposal_bytes(commit: &[u8]) -> Vec<u8> {
    let mut inner = &commit[4..];
    let _ = VLBytes::tls_deserialize(&mut inner).expect("commit group id");
    let _ = u64::tls_deserialize(&mut inner).expect("commit epoch");
    let _ = Sender::tls_deserialize(&mut inner).expect("commit sender");
    let _ = VLBytes::tls_deserialize(&mut inner).expect("commit aad");
    let _ = u8::tls_deserialize(&mut inner).expect("commit content type");
    VLBytes::tls_deserialize(&mut inner)
        .expect("commit proposals vector")
        .as_slice()
        .to_vec()
}

fn mutate_public_commit_update_path(
    commit: &[u8],
    mutate: impl FnOnce(&mut TestWireUpdatePath),
) -> Vec<u8> {
    let mut inner = &commit[4..];
    let _ = VLBytes::tls_deserialize(&mut inner).expect("commit group id");
    let _ = u64::tls_deserialize(&mut inner).expect("commit epoch");
    let _ = Sender::tls_deserialize(&mut inner).expect("commit sender");
    let _ = VLBytes::tls_deserialize(&mut inner).expect("commit aad");
    let _ = u8::tls_deserialize(&mut inner).expect("commit content type");
    let _ = VLBytes::tls_deserialize(&mut inner).expect("commit proposals");
    assert_eq!(u8::tls_deserialize(&mut inner).expect("path presence"), 1);
    let path_start = commit.len() - inner.len();
    let before = inner.len();
    let mut path = TestWireUpdatePath::tls_deserialize(&mut inner).expect("Commit update path");
    let path_end = path_start + before - inner.len();
    mutate(&mut path);
    let replacement = path
        .tls_serialize_detached()
        .expect("serialize mutated Commit update path");
    let mut mutated =
        Vec::with_capacity(commit.len() - (path_end - path_start) + replacement.len());
    mutated.extend_from_slice(&commit[..path_start]);
    mutated.extend_from_slice(&replacement);
    mutated.extend_from_slice(&commit[path_end..]);
    mutated
}

const X25519_P_PLUS_TWO_LE: [u8; 32] = [
    0xEF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
];

fn set_x25519_high_bit(bytes: &mut [u8]) {
    assert!(bytes.len() >= 32);
    *bytes.last_mut().expect("X25519 tail") |= 0x80;
}

fn set_x25519_p_plus_two(bytes: &mut [u8]) {
    assert!(bytes.len() >= 32);
    let offset = bytes.len() - 32;
    bytes[offset..].copy_from_slice(&X25519_P_PLUS_TWO_LE);
}

type X25519AliasMutation = (&'static str, fn(&mut [u8]));

fn x25519_noncanonical_aliases() -> [X25519AliasMutation; 2] {
    [
        ("high-bit alias", set_x25519_high_bit),
        ("p+2 alias", set_x25519_p_plus_two),
    ]
}

#[test]
fn wrapped_key_package_exposes_exact_inner_bytes_and_rfc_hash_ref() {
    let now = frozen_now();
    let credential = b"did:plc:alice#phone";
    let fixture = key_package_fixture(credential, Lifetime::init(now - 60, now + 3_600));

    let validated = validate_key_package(
        &fixture.wrapped,
        KeyPackageValidationPolicy {
            expected_basic_credential: credential,
            expected_signature_key: &fixture.signature_key,
            now_unix_seconds: now,
            max_bytes: MAX_KEY_PACKAGE_WIRE_BYTES,
        },
    )
    .expect("strict wrapped KeyPackage validation");

    assert_eq!(validated.inner_bytes(), fixture.inner);
    assert_eq!(
        validated.key_package_ref(),
        fixture.key_package_ref.as_slice()
    );
    assert_eq!(validated.key_package_ref().len(), 32);
    let parsed = TestWireKeyPackage::tls_deserialize_exact(&fixture.inner)
        .expect("parse validated KeyPackage mirror");
    assert_eq!(validated.init_key(), parsed.payload.init_key.as_slice());
    assert_eq!(
        validated.leaf_encryption_key(),
        parsed.payload.leaf_node.payload.encryption_key.as_slice()
    );
}

#[test]
fn key_package_lifetime_uses_only_the_caller_supplied_frozen_time() {
    let credential = b"did:plc:alice#archived-device";
    let fixture = key_package_fixture(credential, Lifetime::init(100, 1_000));

    let validated = validate_key_package(
        &fixture.wrapped,
        KeyPackageValidationPolicy {
            expected_basic_credential: credential,
            expected_signature_key: &fixture.signature_key,
            now_unix_seconds: 150,
            max_bytes: MAX_KEY_PACKAGE_WIRE_BYTES,
        },
    )
    .expect("frozen time inside the signed lifetime is authoritative");

    assert_eq!(
        (validated.not_before(), validated.not_after()),
        (100, 1_000)
    );
}

#[test]
fn key_package_rejects_raw_inner_wrong_wrapper_trailing_truncation_and_nonminimal_tls() {
    let credential = b"did:plc:alice#framing";
    let fixture = key_package_fixture(credential, Lifetime::init(100, 1_000));
    let policy = key_package_policy(&fixture, credential, 150);

    assert!(matches!(
        validate_key_package(&fixture.inner, policy),
        Err(WireValidationError::WrongWireFormat { actual: 0x004D, .. })
    ));

    let mut wrong_version = fixture.wrapped.clone();
    wrong_version[..2].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        validate_key_package(&wrong_version, policy),
        Err(WireValidationError::UnsupportedProtocolVersion { actual: 2 })
    );

    let mut wrong_wrapper = fixture.wrapped.clone();
    wrong_wrapper[2..4].copy_from_slice(&(WireFormat::Welcome as u16).to_be_bytes());
    assert!(matches!(
        validate_key_package(&wrong_wrapper, policy),
        Err(WireValidationError::WrongWireFormat { actual, .. })
            if actual == WireFormat::Welcome as u16
    ));

    let mut trailing = fixture.wrapped.clone();
    trailing.push(0);
    assert_eq!(
        validate_key_package(&trailing, policy),
        Err(WireValidationError::TrailingData)
    );

    let mut truncated = fixture.wrapped.clone();
    truncated.pop();
    assert_eq!(
        validate_key_package(&truncated, policy),
        Err(WireValidationError::Truncated)
    );

    // The first KeyPackage VLBytes is init_key at wrapper offset 8. XWing's
    // public key needs a two-byte minimal length; encode that same length in
    // four bytes to exercise the MLS non-minimal-vector rejection.
    let nonminimal = widen_two_byte_varint(&fixture.wrapped, 8);
    assert_eq!(
        validate_key_package(&nonminimal, policy),
        Err(WireValidationError::NonCanonicalEncoding)
    );

    assert_eq!(
        validate_key_package(
            &fixture.wrapped,
            KeyPackageValidationPolicy {
                max_bytes: fixture.wrapped.len() - 1,
                ..policy
            },
        ),
        Err(WireValidationError::InputTooLarge {
            actual: fixture.wrapped.len(),
            maximum: fixture.wrapped.len() - 1,
        })
    );
}

#[test]
fn key_package_suite_identity_signer_and_ref_input_are_strict() {
    let credential = b"did:plc:alice#identity";
    let fixture = key_package_fixture(credential, Lifetime::init(100, 1_000));
    let policy = key_package_policy(&fixture, credential, 150);

    let mut wrong_suite = fixture.wrapped.clone();
    wrong_suite[6..8].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(
        validate_key_package(&wrong_suite, policy),
        Err(WireValidationError::UnsupportedCiphersuite { actual: 1 })
    );
    assert_eq!(
        validate_key_package(
            &fixture.wrapped,
            KeyPackageValidationPolicy {
                expected_basic_credential: b"did:plc:mallory#identity",
                ..policy
            },
        ),
        Err(WireValidationError::WrongBasicCredential)
    );
    assert_eq!(
        validate_key_package(
            &fixture.wrapped,
            KeyPackageValidationPolicy {
                expected_signature_key: &[0xA5; 32],
                ..policy
            },
        ),
        Err(WireValidationError::WrongSignatureKey)
    );

    let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
    let wrapper_ref = openmls::ciphersuite::hash_ref::make_key_package_ref(
        &fixture.wrapped,
        XWING_CIPHERSUITE,
        provider.crypto(),
    )
    .expect("compute deliberately wrong wrapper-based ref");
    assert_ne!(wrapper_ref.as_slice(), fixture.key_package_ref);
}

#[test]
fn key_package_lifetime_boundaries_are_closed_and_checked() {
    let credential = b"did:plc:alice#lifetime";
    let fixture = key_package_fixture(credential, Lifetime::init(100, 1_000));

    for now in [100, 1_000] {
        assert!(matches!(
            validate_key_package(
                &fixture.wrapped,
                key_package_policy(&fixture, credential, now),
            ),
            Err(WireValidationError::InvalidLifetime { now: actual, .. }) if actual == now
        ));
    }
    validate_key_package(
        &fixture.wrapped,
        key_package_policy(
            &fixture,
            credential,
            1_000 - MIN_KEY_PACKAGE_REMAINING_SECONDS,
        ),
    )
    .expect("exactly ten minutes remaining is accepted");
    assert_eq!(
        validate_key_package(
            &fixture.wrapped,
            key_package_policy(
                &fixture,
                credential,
                1_001 - MIN_KEY_PACKAGE_REMAINING_SECONDS,
            ),
        ),
        Err(WireValidationError::InsufficientRemainingLifetime)
    );

    let exact_max = key_package_fixture(
        credential,
        Lifetime::init(100, 100 + MAX_KEY_PACKAGE_LIFETIME_SECONDS),
    );
    validate_key_package(
        &exact_max.wrapped,
        key_package_policy(&exact_max, credential, 101),
    )
    .expect("exact maximum total lifetime is accepted");

    let too_long = key_package_fixture(
        credential,
        Lifetime::init(100, 101 + MAX_KEY_PACKAGE_LIFETIME_SECONDS),
    );
    assert_eq!(
        validate_key_package(
            &too_long.wrapped,
            key_package_policy(&too_long, credential, 101),
        ),
        Err(WireValidationError::LifetimeTooLong)
    );
}

#[test]
fn key_package_rejects_capabilities_last_resort_reused_keys_and_bad_signatures() {
    let credential = b"did:plc:alice#profile";
    let now = 150;

    let default_capabilities =
        key_package_fixture_with_profile(credential, Lifetime::init(100, 1_000), false, false);
    assert_eq!(
        validate_key_package(
            &default_capabilities.wrapped,
            key_package_policy(&default_capabilities, credential, now),
        ),
        Err(WireValidationError::UnsupportedCapabilities)
    );

    let last_resort =
        key_package_fixture_with_profile(credential, Lifetime::init(100, 1_000), true, true);
    assert_eq!(
        validate_key_package(
            &last_resort.wrapped,
            key_package_policy(&last_resort, credential, now),
        ),
        Err(WireValidationError::UnsupportedExtensions)
    );

    let fixture = key_package_fixture(credential, Lifetime::init(100, 1_000));
    let policy = key_package_policy(&fixture, credential, now);
    let mut reused = TestWireKeyPackage::tls_deserialize_exact(&fixture.inner)
        .expect("parse KeyPackage into RFC wire mirror");
    reused.payload.init_key = reused.payload.leaf_node.payload.encryption_key.clone();
    resign_test_key_package(&mut reused, &fixture.signer);
    assert_eq!(
        validate_key_package(&wrap_test_key_package(&reused), policy),
        Err(WireValidationError::ReusedEncryptionKey)
    );

    let mut bad_leaf = TestWireKeyPackage::tls_deserialize_exact(&fixture.inner)
        .expect("parse KeyPackage into RFC wire mirror");
    let mut signature = bad_leaf.payload.leaf_node.signature.as_slice().to_vec();
    *signature.last_mut().expect("nonempty leaf signature") ^= 0x80;
    bad_leaf.payload.leaf_node.signature = signature.into();
    assert_eq!(
        validate_key_package(&wrap_test_key_package(&bad_leaf), policy),
        Err(WireValidationError::InvalidLeafNodeSignature)
    );

    let mut bad_package = TestWireKeyPackage::tls_deserialize_exact(&fixture.inner)
        .expect("parse KeyPackage into RFC wire mirror");
    let mut signature = bad_package.signature.as_slice().to_vec();
    *signature.last_mut().expect("nonempty KeyPackage signature") ^= 0x40;
    bad_package.signature = signature.into();
    assert_eq!(
        validate_key_package(&wrap_test_key_package(&bad_package), policy),
        Err(WireValidationError::InvalidKeyPackageSignature)
    );
}

#[test]
fn key_package_rejects_malformed_xwing_public_keys() {
    let credential = b"did:plc:alice#malformed-xwing";
    let fixture = key_package_fixture(credential, Lifetime::init(100, 1_000));
    let policy = key_package_policy(&fixture, credential, 150);

    let mut short_init = TestWireKeyPackage::tls_deserialize_exact(&fixture.inner)
        .expect("parse KeyPackage into RFC wire mirror");
    short_init.payload.init_key = vec![0x01].into();
    resign_test_key_package(&mut short_init, &fixture.signer);
    assert!(
        validate_key_package(&wrap_test_key_package(&short_init), policy).is_err(),
        "a signed short XWing init key must not enter inventory"
    );

    let mut invalid_leaf = TestWireKeyPackage::tls_deserialize_exact(&fixture.inner)
        .expect("parse KeyPackage into RFC wire mirror");
    invalid_leaf.payload.leaf_node.payload.encryption_key = vec![0xFF; 1_216].into();
    resign_test_leaf_node(&mut invalid_leaf.payload.leaf_node, &fixture.signer);
    resign_test_key_package(&mut invalid_leaf, &fixture.signer);
    assert!(
        validate_key_package(&wrap_test_key_package(&invalid_leaf), policy).is_err(),
        "a signed non-canonical ML-KEM public key must not enter inventory"
    );

    let mut unusable_init = TestWireKeyPackage::tls_deserialize_exact(&fixture.inner)
        .expect("parse KeyPackage into RFC wire mirror");
    let mut init_key = unusable_init.payload.init_key.as_slice().to_vec();
    init_key[1_184..].fill(0);
    unusable_init.payload.init_key = init_key.into();
    resign_test_key_package(&mut unusable_init, &fixture.signer);
    assert_eq!(
        validate_key_package(&wrap_test_key_package(&unusable_init), policy),
        Err(WireValidationError::InvalidXwingPublicKey),
        "a signed X-Wing key with an all-zero X25519 component must be rejected"
    );

    let mut unusable_leaf = TestWireKeyPackage::tls_deserialize_exact(&fixture.inner)
        .expect("parse KeyPackage into RFC wire mirror");
    let mut leaf_key = unusable_leaf
        .payload
        .leaf_node
        .payload
        .encryption_key
        .as_slice()
        .to_vec();
    leaf_key[1_184..].fill(0);
    unusable_leaf.payload.leaf_node.payload.encryption_key = leaf_key.into();
    resign_test_leaf_node(&mut unusable_leaf.payload.leaf_node, &fixture.signer);
    resign_test_key_package(&mut unusable_leaf, &fixture.signer);
    assert_eq!(
        validate_key_package(&wrap_test_key_package(&unusable_leaf), policy),
        Err(WireValidationError::InvalidXwingPublicKey),
        "an unusable signed X-Wing leaf encryption key must be rejected"
    );

    for (alias_name, apply_alias) in x25519_noncanonical_aliases() {
        let mut noncanonical_init = TestWireKeyPackage::tls_deserialize_exact(&fixture.inner)
            .expect("parse KeyPackage into RFC wire mirror");
        let mut init_key = noncanonical_init.payload.init_key.as_slice().to_vec();
        apply_alias(&mut init_key);
        noncanonical_init.payload.init_key = init_key.into();
        resign_test_key_package(&mut noncanonical_init, &fixture.signer);
        assert_eq!(
            validate_key_package(&wrap_test_key_package(&noncanonical_init), policy),
            Err(WireValidationError::InvalidXwingPublicKey),
            "signed init-key {alias_name} entered inventory"
        );

        let mut noncanonical_leaf = TestWireKeyPackage::tls_deserialize_exact(&fixture.inner)
            .expect("parse KeyPackage into RFC wire mirror");
        let mut leaf_key = noncanonical_leaf
            .payload
            .leaf_node
            .payload
            .encryption_key
            .as_slice()
            .to_vec();
        apply_alias(&mut leaf_key);
        noncanonical_leaf.payload.leaf_node.payload.encryption_key = leaf_key.into();
        resign_test_leaf_node(&mut noncanonical_leaf.payload.leaf_node, &fixture.signer);
        resign_test_key_package(&mut noncanonical_leaf, &fixture.signer);
        assert_eq!(
            validate_key_package(&wrap_test_key_package(&noncanonical_leaf), policy),
            Err(WireValidationError::InvalidXwingPublicKey),
            "signed leaf-key {alias_name} entered inventory"
        );
    }
}

#[test]
fn caller_limits_cannot_relax_the_protocol_key_package_cap() {
    let mut oversized = vec![0u8; MAX_KEY_PACKAGE_WIRE_BYTES + 1];
    oversized[..4].copy_from_slice(&[0, 1, 0, 5]);
    assert_eq!(
        validate_key_package(
            &oversized,
            KeyPackageValidationPolicy {
                expected_basic_credential: b"did:plc:alice#oversized",
                expected_signature_key: &[0xA5; 32],
                now_unix_seconds: 150,
                max_bytes: usize::MAX,
            },
        ),
        Err(WireValidationError::InputTooLarge {
            actual: MAX_KEY_PACKAGE_WIRE_BYTES + 1,
            maximum: MAX_KEY_PACKAGE_WIRE_BYTES,
        })
    );
}

struct CoherentWireFixture {
    group_id: Vec<u8>,
    alice_signature_key: Vec<u8>,
    alice_signer: SignatureKeyPair,
    now_unix_seconds: u64,
    genesis_group_info: Vec<u8>,
    public_add_commit: Vec<u8>,
    add_group_context_hash: [u8; 32],
    add_confirmation_tag: [u8; 32],
    public_remove_commit: Vec<u8>,
    remove_group_context_hash: [u8; 32],
    remove_confirmation_tag: [u8; 32],
    welcome: Vec<u8>,
    bob_key_package_ref: [u8; 32],
    private_application: Vec<u8>,
}

struct RightmostSenderTransition {
    aad: Vec<u8>,
    commit: Vec<u8>,
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
    sender_index: u32,
    expected_member_count: usize,
    expected_add_count: usize,
    expected_remove_count: usize,
}

struct RightmostSenderFixture {
    alice_signature_key: Vec<u8>,
    now_unix_seconds: u64,
    genesis_group_info: Vec<u8>,
    transitions: Vec<RightmostSenderTransition>,
}

const TEST_CONVERSATION_ID: [u8; 16] = [
    0xd4, 0xe3, 0xc7, 0x14, 0x41, 0xb5, 0x43, 0xa8, 0xb2, 0xdf, 0x6d, 0x1d, 0x1f, 0x78, 0x99, 0x54,
];

fn exported_group_coordinate(
    group: &MlsGroup,
    provider: &openmls_libcrux_crypto::Provider,
    signer: &SignatureKeyPair,
) -> ([u8; 32], [u8; 32]) {
    let encoded = group
        .export_group_info(provider.crypto(), signer, true)
        .expect("export coordinate GroupInfo")
        .tls_serialize_detached()
        .expect("serialize coordinate GroupInfo");
    let envelope =
        TestGroupInfoEnvelope::tls_deserialize_exact(&encoded).expect("parse coordinate GroupInfo");
    let context_hash = Sha256::digest(
        envelope
            .group_info
            .context
            .tls_serialize_detached()
            .expect("serialize coordinate GroupContext"),
    )
    .into();
    let confirmation_tag = envelope
        .group_info
        .confirmation_tag
        .as_slice()
        .try_into()
        .expect("32-byte confirmation tag");
    (context_hash, confirmation_tag)
}

struct GenesisGroupInfoFixture {
    bytes: Vec<u8>,
    signature_key: Vec<u8>,
    now_unix_seconds: u64,
}

#[derive(Clone, Copy)]
enum StatefulCommitVariant {
    EmptySelfUpdate,
    EmptyWithDefaultPathCapabilities,
    EmptyWithChangedPathCredential,
    AddWithDefaultPathCapabilities,
    AddWithChangedPathCredential,
}

struct StatefulCommitFixture {
    group_info: Vec<u8>,
    commit: Vec<u8>,
    signature_key: Vec<u8>,
    now_unix_seconds: u64,
    next_group_context_hash: [u8; 32],
    next_confirmation_tag: [u8; 32],
}

fn stateful_commit_fixture(variant: StatefulCommitVariant) -> StatefulCommitFixture {
    let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
    let signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("Alice signer");
    signer
        .store(provider.storage())
        .expect("store Alice signer");
    let signature_key = signer.to_public_vec();
    let now_unix_seconds = frozen_now();
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(XWING_CIPHERSUITE)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(exact_capabilities())
        .lifetime(Lifetime::init(
            now_unix_seconds - 60,
            now_unix_seconds + 3_600,
        ))
        .build();
    let mut group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &config,
        GroupId::from_slice(&[0xC7; 32]),
        CredentialWithKey {
            credential: BasicCredential::new(TEST_ALICE_CREDENTIAL.to_vec()).into(),
            signature_key: signature_key.clone().into(),
        },
    )
    .expect("create variant group");
    let group_info = group
        .export_group_info(provider.crypto(), &signer, true)
        .expect("export variant GroupInfo")
        .tls_serialize_detached()
        .expect("serialize variant GroupInfo");
    group.set_aad(b"variant-aad".to_vec());

    let commit = match variant {
        StatefulCommitVariant::EmptySelfUpdate => group
            .self_update(&provider, &signer, LeafNodeParameters::default())
            .expect("create empty self-update")
            .commit()
            .tls_serialize_detached()
            .expect("serialize empty self-update"),
        StatefulCommitVariant::EmptyWithDefaultPathCapabilities => group
            .self_update(
                &provider,
                &signer,
                LeafNodeParameters::builder()
                    .with_capabilities(Capabilities::default())
                    .build(),
            )
            .expect("create default-capabilities self-update")
            .commit()
            .tls_serialize_detached()
            .expect("serialize default-capabilities self-update"),
        StatefulCommitVariant::EmptyWithChangedPathCredential => group
            .self_update(
                &provider,
                &signer,
                LeafNodeParameters::builder()
                    .with_credential_with_key(CredentialWithKey {
                        credential: BasicCredential::new(b"did:plc:mallory#same-key".to_vec())
                            .into(),
                        signature_key: signature_key.clone().into(),
                    })
                    .build(),
            )
            .expect("create changed-credential self-update")
            .commit()
            .tls_serialize_detached()
            .expect("serialize changed-credential self-update"),
        StatefulCommitVariant::AddWithDefaultPathCapabilities
        | StatefulCommitVariant::AddWithChangedPathCredential => {
            let bob_signer =
                SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("Bob signer");
            bob_signer
                .store(provider.storage())
                .expect("store Bob signer");
            let bob = KeyPackage::builder()
                .leaf_node_capabilities(exact_capabilities())
                .key_package_lifetime(Lifetime::init(
                    now_unix_seconds - 60,
                    now_unix_seconds + 3_600,
                ))
                .build(
                    XWING_CIPHERSUITE,
                    &provider,
                    &bob_signer,
                    CredentialWithKey {
                        credential: BasicCredential::new(TEST_BOB_CREDENTIAL.to_vec()).into(),
                        signature_key: bob_signer.to_public_vec().into(),
                    },
                )
                .expect("build Bob package")
                .key_package()
                .clone();
            let leaf_parameters = match variant {
                StatefulCommitVariant::AddWithDefaultPathCapabilities => {
                    LeafNodeParameters::builder()
                        .with_capabilities(Capabilities::default())
                        .build()
                }
                StatefulCommitVariant::AddWithChangedPathCredential => {
                    LeafNodeParameters::builder()
                        .with_credential_with_key(CredentialWithKey {
                            credential: BasicCredential::new(b"did:plc:mallory#same-key".to_vec())
                                .into(),
                            signature_key: signature_key.clone().into(),
                        })
                        .build()
                }
                StatefulCommitVariant::EmptySelfUpdate
                | StatefulCommitVariant::EmptyWithDefaultPathCapabilities
                | StatefulCommitVariant::EmptyWithChangedPathCredential => unreachable!(),
            };
            group
                .commit_builder()
                .propose_adds([bob])
                .leaf_node_parameters(leaf_parameters)
                .load_psks(provider.storage())
                .expect("load no PSKs")
                .build(provider.rand(), provider.crypto(), &signer, |_| true)
                .expect("build variant Commit")
                .stage_commit(&provider)
                .expect("stage variant Commit")
                .commit()
                .tls_serialize_detached()
                .expect("serialize variant Commit")
        }
    };
    group
        .merge_pending_commit(&provider)
        .expect("merge variant Commit for exact successor coordinate");
    let (next_group_context_hash, next_confirmation_tag) =
        exported_group_coordinate(&group, &provider, &signer);

    StatefulCommitFixture {
        group_info,
        commit,
        signature_key,
        now_unix_seconds,
        next_group_context_hash,
        next_confirmation_tag,
    }
}

fn stateful_fixture_group_info(
    fixture: &StatefulCommitFixture,
) -> catbird_server::chat_protocol::wire::ValidatedGroupInfo {
    validate_group_info(
        &fixture.group_info,
        GroupInfoValidationPolicy {
            expected_basic_credential: TEST_ALICE_CREDENTIAL,
            expected_signature_key: &fixture.signature_key,
            now_unix_seconds: fixture.now_unix_seconds,
            max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_ratchet_tree_bytes: 786_432,
            max_members: 1,
        },
    )
    .expect("validate variant prior GroupInfo")
}

fn genesis_group_info_fixture(
    capabilities: Option<Capabilities>,
    lifetime: Option<Lifetime>,
) -> GenesisGroupInfoFixture {
    genesis_group_info_fixture_with_credential(capabilities, lifetime, b"did:plc:alice#genesis")
}

fn genesis_group_info_fixture_with_credential(
    capabilities: Option<Capabilities>,
    lifetime: Option<Lifetime>,
    credential: &[u8],
) -> GenesisGroupInfoFixture {
    let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
    let signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("genesis signer");
    signer
        .store(provider.storage())
        .expect("store genesis signer");
    let now_unix_seconds = frozen_now();
    let mut builder = MlsGroupCreateConfig::builder()
        .ciphersuite(XWING_CIPHERSUITE)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true);
    if let Some(capabilities) = capabilities {
        builder = builder.capabilities(capabilities);
    }
    if let Some(lifetime) = lifetime {
        builder = builder.lifetime(lifetime);
    }
    let group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &builder.build(),
        GroupId::from_slice(&[0xD0; 32]),
        CredentialWithKey {
            credential: BasicCredential::new(credential.to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        },
    )
    .expect("create genesis fixture group");
    let bytes = group
        .export_group_info(provider.crypto(), &signer, true)
        .expect("export genesis fixture GroupInfo")
        .tls_serialize_detached()
        .expect("serialize genesis fixture GroupInfo");
    GenesisGroupInfoFixture {
        bytes,
        signature_key: signer.to_public_vec(),
        now_unix_seconds,
    }
}

fn exact_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[XWING_CIPHERSUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}

fn rightmost_sender_fixture(member_count: usize) -> RightmostSenderFixture {
    assert!((3..=100).contains(&member_count));
    let alice_provider = openmls_libcrux_crypto::Provider::new().expect("Alice libcrux provider");
    let alice_signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("Alice signer");
    alice_signer
        .store(alice_provider.storage())
        .expect("store Alice signer");
    let alice_signature_key = alice_signer.to_public_vec();
    let now_unix_seconds = frozen_now();
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(XWING_CIPHERSUITE)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(exact_capabilities())
        .lifetime(Lifetime::init(
            now_unix_seconds - 60,
            now_unix_seconds + 3_600,
        ))
        .build();
    let mut alice_group = MlsGroup::new_with_group_id(
        &alice_provider,
        &alice_signer,
        &group_config,
        GroupId::from_slice(&[0xC8; 32]),
        CredentialWithKey {
            credential: BasicCredential::new(TEST_ALICE_CREDENTIAL.to_vec()).into(),
            signature_key: alice_signature_key.clone().into(),
        },
    )
    .expect("create rightmost-sender group");
    let genesis_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, true)
        .expect("export rightmost-sender genesis GroupInfo")
        .tls_serialize_detached()
        .expect("serialize rightmost-sender genesis GroupInfo");

    let member_provider = openmls_libcrux_crypto::Provider::new().expect("member libcrux provider");
    let mut member_signers = Vec::with_capacity(member_count - 1);
    let mut member_key_packages = Vec::with_capacity(member_count - 1);
    for leaf_index in 1..member_count {
        let signer =
            SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("member signer");
        signer
            .store(member_provider.storage())
            .expect("store member signer");
        let credential =
            format!("did:web:m{leaf_index}.co#00000000-0000-4000-8000-{leaf_index:012}")
                .into_bytes();
        let key_package = KeyPackage::builder()
            .leaf_node_capabilities(exact_capabilities())
            .key_package_lifetime(Lifetime::init(
                now_unix_seconds - 60,
                now_unix_seconds + 3_600,
            ))
            .build(
                XWING_CIPHERSUITE,
                &member_provider,
                &signer,
                CredentialWithKey {
                    credential: BasicCredential::new(credential).into(),
                    signature_key: signer.to_public_vec().into(),
                },
            )
            .expect("build member KeyPackage")
            .key_package()
            .clone();
        member_signers.push(signer);
        member_key_packages.push(key_package);
    }

    let mut transitions = Vec::with_capacity(member_count);
    let mut final_welcome = None;
    for (offset, key_package) in member_key_packages.into_iter().enumerate() {
        let next_member_count = offset + 2;
        let aad = format!("grow-to-{next_member_count}").into_bytes();
        alice_group.set_aad(aad.clone());
        let (commit, welcome, _) = alice_group
            .add_members(&alice_provider, &alice_signer, &[key_package])
            .expect("create sequential Add Commit");
        let commit = commit
            .tls_serialize_detached()
            .expect("serialize sequential Add Commit");
        let welcome = welcome
            .tls_serialize_detached()
            .expect("serialize sequential Welcome");
        alice_group
            .merge_pending_commit(&alice_provider)
            .expect("merge sequential Add Commit");
        let (group_context_hash, confirmation_tag) =
            exported_group_coordinate(&alice_group, &alice_provider, &alice_signer);
        transitions.push(RightmostSenderTransition {
            aad,
            commit,
            group_context_hash,
            confirmation_tag,
            sender_index: 0,
            expected_member_count: next_member_count,
            expected_add_count: 1,
            expected_remove_count: 0,
        });
        final_welcome = Some(welcome);
    }

    let welcome_message =
        MlsMessageIn::tls_deserialize_exact(final_welcome.expect("rightmost member Welcome"))
            .expect("parse rightmost member Welcome");
    let MlsMessageBodyIn::Welcome(welcome) = welcome_message.extract() else {
        panic!("rightmost member fixture must contain Welcome");
    };
    let mut rightmost_group = StagedWelcome::new_from_welcome(
        &member_provider,
        group_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("stage rightmost member Welcome")
    .into_group(&member_provider)
    .expect("join rightmost member");
    let rightmost_signer = member_signers.pop().expect("rightmost signer");
    let remove_aad = b"rightmost-remove".to_vec();
    rightmost_group.set_aad(remove_aad.clone());
    let (remove, _, _) = rightmost_group
        .remove_members(
            &member_provider,
            &rightmost_signer,
            &[LeafNodeIndex::new(1)],
        )
        .expect("rightmost member creates Remove Commit");
    let remove = remove
        .tls_serialize_detached()
        .expect("serialize rightmost-member Remove Commit");
    rightmost_group
        .merge_pending_commit(&member_provider)
        .expect("merge rightmost-member Remove Commit");
    let (group_context_hash, confirmation_tag) =
        exported_group_coordinate(&rightmost_group, &member_provider, &rightmost_signer);
    transitions.push(RightmostSenderTransition {
        aad: remove_aad,
        commit: remove,
        group_context_hash,
        confirmation_tag,
        sender_index: u32::try_from(member_count - 1).expect("bounded leaf index"),
        expected_member_count: member_count - 1,
        expected_add_count: 0,
        expected_remove_count: 1,
    });

    let replacement_signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("replacement signer");
    replacement_signer
        .store(member_provider.storage())
        .expect("store replacement signer");
    let replacement_key_package = KeyPackage::builder()
        .leaf_node_capabilities(exact_capabilities())
        .key_package_lifetime(Lifetime::init(
            now_unix_seconds - 60,
            now_unix_seconds + 3_600,
        ))
        .build(
            XWING_CIPHERSUITE,
            &member_provider,
            &replacement_signer,
            CredentialWithKey {
                credential: BasicCredential::new(
                    format!(
                        "did:web:r{member_count}.co#00000000-0000-4000-8000-{:012}",
                        member_count + 100
                    )
                    .into_bytes(),
                )
                .into(),
                signature_key: replacement_signer.to_public_vec().into(),
            },
        )
        .expect("build replacement KeyPackage")
        .key_package()
        .clone();
    let add_aad = b"rightmost-add".to_vec();
    rightmost_group.set_aad(add_aad.clone());
    let (add, _, _) = rightmost_group
        .add_members(
            &member_provider,
            &rightmost_signer,
            &[replacement_key_package],
        )
        .expect("rightmost member creates Add Commit");
    let add = add
        .tls_serialize_detached()
        .expect("serialize rightmost-member Add Commit");
    rightmost_group
        .merge_pending_commit(&member_provider)
        .expect("merge rightmost-member Add Commit");
    let (group_context_hash, confirmation_tag) =
        exported_group_coordinate(&rightmost_group, &member_provider, &rightmost_signer);
    transitions.push(RightmostSenderTransition {
        aad: add_aad,
        commit: add,
        group_context_hash,
        confirmation_tag,
        sender_index: u32::try_from(member_count - 1).expect("bounded leaf index"),
        expected_member_count: member_count,
        expected_add_count: 1,
        expected_remove_count: 0,
    });

    RightmostSenderFixture {
        alice_signature_key,
        now_unix_seconds,
        genesis_group_info,
        transitions,
    }
}

fn coherent_wire_fixture_with_group_id(group_id: &[u8]) -> CoherentWireFixture {
    let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
    let alice_signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("Alice signer");
    alice_signer
        .store(provider.storage())
        .expect("store Alice signer");
    let alice_signature_key = alice_signer.to_public_vec();
    let now_unix_seconds = frozen_now();
    let exact_capabilities = || {
        Capabilities::new(
            Some(&[ProtocolVersion::Mls10]),
            Some(&[XWING_CIPHERSUITE]),
            Some(&[]),
            Some(&[]),
            Some(&[CredentialType::Basic]),
        )
    };
    let group_id = group_id.to_vec();
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(XWING_CIPHERSUITE)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(exact_capabilities())
        .lifetime(Lifetime::init(
            now_unix_seconds - 60,
            now_unix_seconds + 3_600,
        ))
        .build();
    let mut alice_group = MlsGroup::new_with_group_id(
        &provider,
        &alice_signer,
        &group_config,
        GroupId::from_slice(&group_id),
        CredentialWithKey {
            credential: BasicCredential::new(TEST_ALICE_CREDENTIAL.to_vec()).into(),
            signature_key: alice_signature_key.clone().into(),
        },
    )
    .expect("create singleton XWing group");
    let genesis_group_info = alice_group
        .export_group_info(provider.crypto(), &alice_signer, true)
        .expect("export singleton GroupInfo")
        .tls_serialize_detached()
        .expect("serialize wire-format 4 GroupInfo");

    let bob_signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("Bob signer");
    bob_signer
        .store(provider.storage())
        .expect("store Bob signer");
    let bob_key_package = KeyPackage::builder()
        .leaf_node_capabilities(exact_capabilities())
        .key_package_lifetime(Lifetime::init(
            now_unix_seconds - 60,
            now_unix_seconds + 3_600,
        ))
        .build(
            XWING_CIPHERSUITE,
            &provider,
            &bob_signer,
            CredentialWithKey {
                credential: BasicCredential::new(TEST_BOB_CREDENTIAL.to_vec()).into(),
                signature_key: bob_signer.to_public_vec().into(),
            },
        )
        .expect("build Bob KeyPackage")
        .key_package()
        .clone();
    let bob_key_package_ref = bob_key_package
        .hash_ref(provider.crypto())
        .expect("Bob KeyPackageRef")
        .as_slice()
        .try_into()
        .expect("SHA-256 KeyPackageRef");
    alice_group.set_aad(b"commit-aad".to_vec());
    let (public_add_commit, welcome, _) = alice_group
        .add_members(&provider, &alice_signer, &[bob_key_package])
        .expect("create public Add commit and Welcome");
    let public_add_commit = public_add_commit
        .tls_serialize_detached()
        .expect("serialize wire-format 1 commit");
    let welcome = welcome
        .tls_serialize_detached()
        .expect("serialize wire-format 3 Welcome");
    alice_group
        .merge_pending_commit(&provider)
        .expect("advance Alice to epoch 1");
    let (add_group_context_hash, add_confirmation_tag) =
        exported_group_coordinate(&alice_group, &provider, &alice_signer);
    alice_group.set_aad(b"application-aad".to_vec());
    let private_application = alice_group
        .create_message(&provider, &alice_signer, b"ciphertext-blind payload")
        .expect("create epoch-1 private application")
        .tls_serialize_detached()
        .expect("serialize wire-format 2 private application");
    alice_group.set_aad(b"remove-aad".to_vec());
    let (public_remove_commit, _, _) = alice_group
        .remove_members(&provider, &alice_signer, &[LeafNodeIndex::new(1)])
        .expect("create public Remove commit");
    let public_remove_commit = public_remove_commit
        .tls_serialize_detached()
        .expect("serialize public Remove commit");
    alice_group
        .merge_pending_commit(&provider)
        .expect("advance Alice to epoch 2");
    let (remove_group_context_hash, remove_confirmation_tag) =
        exported_group_coordinate(&alice_group, &provider, &alice_signer);

    CoherentWireFixture {
        group_id,
        alice_signature_key,
        alice_signer,
        now_unix_seconds,
        genesis_group_info,
        public_add_commit,
        add_group_context_hash,
        add_confirmation_tag,
        public_remove_commit,
        remove_group_context_hash,
        remove_confirmation_tag,
        welcome,
        bob_key_package_ref,
        private_application,
    }
}

fn coherent_wire_fixture() -> CoherentWireFixture {
    coherent_wire_fixture_with_group_id(b"0123456789abcdef0123456789abcdef")
}

fn group_info_policy(fixture: &CoherentWireFixture) -> GroupInfoValidationPolicy<'_> {
    GroupInfoValidationPolicy {
        expected_basic_credential: TEST_ALICE_CREDENTIAL,
        expected_signature_key: &fixture.alice_signature_key,
        now_unix_seconds: fixture.now_unix_seconds,
        max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
        max_ratchet_tree_bytes: 786_432,
        max_members: 1,
    }
}

fn standalone_group_info_policy(
    fixture: &GenesisGroupInfoFixture,
) -> GroupInfoValidationPolicy<'_> {
    GroupInfoValidationPolicy {
        expected_basic_credential: b"did:plc:alice#genesis",
        expected_signature_key: &fixture.signature_key,
        now_unix_seconds: fixture.now_unix_seconds,
        max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
        max_ratchet_tree_bytes: 786_432,
        max_members: 1,
    }
}

fn coordinate_for_validated_group(
    group_info: &ValidatedGroupInfo,
    generation: u64,
    state_version: u64,
) -> PublicGroupSnapshotCoordinate {
    PublicGroupSnapshotCoordinate::new(
        TEST_CONVERSATION_ID,
        generation,
        state_version,
        group_info.group_id().try_into().expect("32-byte group id"),
        group_info.epoch(),
        *group_info.group_context_hash(),
        *group_info.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    )
}

fn binding_for_validated_group(
    group_info: &ValidatedGroupInfo,
    generation: u64,
    state_version: u64,
) -> PublicGroupSnapshotBinding {
    let encoded = encode_public_group_snapshot(group_info.public_state())
        .expect("encode exact validated public state");
    public_group_snapshot_binding(
        group_info.public_state(),
        &encoded,
        &coordinate_for_validated_group(group_info, generation, state_version),
    )
    .expect("bind validated state to trusted test coordinate")
}

fn successor_coordinate(
    prior: &PublicGroupSnapshotBinding,
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
) -> PublicGroupSnapshotCoordinate {
    PublicGroupSnapshotCoordinate::new(
        *prior.conversation_id(),
        prior.generation(),
        prior.state_version().checked_add(1).expect("state version"),
        *prior.group_id(),
        prior.epoch().checked_add(1).expect("epoch"),
        group_context_hash,
        confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    )
}

fn commit_policy<'a>(
    expected_aad: &'a [u8],
    trusted_prior_binding: &'a PublicGroupSnapshotBinding,
    expected_next_coordinate: &'a PublicGroupSnapshotCoordinate,
    now_unix_seconds: u64,
    max_members: usize,
) -> PublicCommitValidationPolicy<'a> {
    PublicCommitValidationPolicy {
        expected_aad,
        trusted_prior_binding,
        expected_next_coordinate,
        now_unix_seconds,
        max_members,
    }
}

fn wrong_content_type_artifacts() -> (Vec<u8>, Vec<u8>) {
    fn new_group(
        provider: &openmls_libcrux_crypto::Provider,
        signer: &SignatureKeyPair,
        policy: WireFormatPolicy,
        group_byte: u8,
    ) -> MlsGroup {
        MlsGroup::new_with_group_id(
            provider,
            signer,
            &MlsGroupCreateConfig::builder()
                .ciphersuite(XWING_CIPHERSUITE)
                .wire_format_policy(policy)
                .build(),
            GroupId::from_slice(&[group_byte; 32]),
            CredentialWithKey {
                credential: BasicCredential::new(b"did:plc:alice#content".to_vec()).into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect("create content-type test group")
    }

    fn bob_key_package(provider: &openmls_libcrux_crypto::Provider, group_byte: u8) -> KeyPackage {
        let signer =
            SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("Bob signer");
        signer.store(provider.storage()).expect("store Bob signer");
        KeyPackage::builder()
            .build(
                XWING_CIPHERSUITE,
                provider,
                &signer,
                CredentialWithKey {
                    credential: BasicCredential::new(vec![group_byte; 16]).into(),
                    signature_key: signer.to_public_vec().into(),
                },
            )
            .expect("build Bob KeyPackage")
            .key_package()
            .clone()
    }

    let public_provider = openmls_libcrux_crypto::Provider::new().expect("public libcrux provider");
    let public_signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("public signer");
    public_signer
        .store(public_provider.storage())
        .expect("store public signer");
    let mut public_group = new_group(
        &public_provider,
        &public_signer,
        openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        0x51,
    );
    let (public_proposal, _) = public_group
        .propose_add_member(
            &public_provider,
            &public_signer,
            &bob_key_package(&public_provider, 0x51),
        )
        .expect("create public Add proposal");

    let private_provider =
        openmls_libcrux_crypto::Provider::new().expect("private libcrux provider");
    let private_signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("private signer");
    private_signer
        .store(private_provider.storage())
        .expect("store private signer");
    let mut private_group = new_group(
        &private_provider,
        &private_signer,
        openmls::group::PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        0x52,
    );
    let (private_commit, _, _) = private_group
        .add_members(
            &private_provider,
            &private_signer,
            &[bob_key_package(&private_provider, 0x52)],
        )
        .expect("create private Add commit");

    (
        public_proposal
            .tls_serialize_detached()
            .expect("serialize public Proposal"),
        private_commit
            .tls_serialize_detached()
            .expect("serialize private Commit"),
    )
}

fn external_commit_wire() -> Vec<u8> {
    let alice_provider = openmls_libcrux_crypto::Provider::new().expect("Alice libcrux provider");
    let alice_signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("Alice signer");
    alice_signer
        .store(alice_provider.storage())
        .expect("store Alice signer");
    let alice_group = MlsGroup::new_with_group_id(
        &alice_provider,
        &alice_signer,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(XWING_CIPHERSUITE)
            .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build(),
        GroupId::from_slice(&[0xEC; 32]),
        CredentialWithKey {
            credential: BasicCredential::new(b"did:plc:alice#external-source".to_vec()).into(),
            signature_key: alice_signer.to_public_vec().into(),
        },
    )
    .expect("create external-commit source group");
    let group_info_bytes = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, true)
        .expect("export external-commit GroupInfo")
        .tls_serialize_detached()
        .expect("serialize external-commit GroupInfo");
    let group_info = match MlsMessageIn::tls_deserialize_exact(&group_info_bytes)
        .expect("parse external-commit GroupInfo")
        .extract()
    {
        MlsMessageBodyIn::GroupInfo(group_info) => group_info,
        _ => panic!("exported GroupInfo must use the GroupInfo wrapper"),
    };

    let joiner_provider = openmls_libcrux_crypto::Provider::new().expect("joiner libcrux provider");
    let joiner_signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("joiner signer");
    joiner_signer
        .store(joiner_provider.storage())
        .expect("store joiner signer");
    let (_, bundle) = MlsGroup::external_commit_builder()
        .build_group(
            &joiner_provider,
            group_info,
            CredentialWithKey {
                credential: BasicCredential::new(b"did:plc:mallory#external-joiner".to_vec())
                    .into(),
                signature_key: joiner_signer.to_public_vec().into(),
            },
        )
        .expect("build external-commit group")
        .load_psks(joiner_provider.storage())
        .expect("load external-commit PSKs")
        .build(
            joiner_provider.rand(),
            joiner_provider.crypto(),
            &joiner_signer,
            |_| true,
        )
        .expect("build external Commit")
        .finalize(&joiner_provider)
        .expect("finalize external Commit");

    bundle
        .commit()
        .tls_serialize_detached()
        .expect("serialize external Commit")
}

#[test]
fn coherent_xwing_artifacts_validate_with_visible_metadata_and_public_group_seam() {
    let fixture = coherent_wire_fixture();

    let group_info = validate_group_info(&fixture.genesis_group_info, group_info_policy(&fixture))
        .expect("strict singleton GroupInfo");
    assert_eq!(group_info.group_id(), fixture.group_id);
    assert_eq!(group_info.epoch(), 0);
    assert_eq!(group_info.public_group().ciphersuite(), XWING_CIPHERSUITE);
    let encoded_group_info =
        TestGroupInfoEnvelope::tls_deserialize_exact(&fixture.genesis_group_info)
            .expect("parse generated GroupInfo into RFC wire mirror");
    let context_bytes = encoded_group_info
        .group_info
        .context
        .tls_serialize_detached()
        .expect("serialize exact GroupContext");
    let expected_context_hash: [u8; 32] = Sha256::digest(context_bytes).into();
    assert_eq!(group_info.group_context_hash(), &expected_context_hash);
    assert_eq!(
        group_info.confirmation_tag().as_slice(),
        encoded_group_info.group_info.confirmation_tag.as_slice()
    );
    let public_snapshot = encode_public_group_snapshot(group_info.public_state())
        .expect("snapshot validated GroupInfo state with its original provider");
    let trusted_coordinate = coordinate_for_validated_group(&group_info, 0, 0);
    let snapshot_binding = public_group_snapshot_binding(
        group_info.public_state(),
        &public_snapshot,
        &trusted_coordinate,
    )
    .expect("bind exact GroupInfo state to trusted outer coordinate");
    let restored = decode_public_group_snapshot(&public_snapshot, &snapshot_binding)
        .expect("restore validated GroupInfo state into a fresh provider");
    assert_eq!(
        restored.public_group().group_id().as_slice(),
        fixture.group_id
    );
    assert_eq!(restored.public_group().group_context().epoch().as_u64(), 0);

    let commit = validate_public_commit(&fixture.public_add_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("strict public Add commit");
    assert_eq!(commit.group_id(), fixture.group_id);
    assert_eq!(commit.epoch(), 0);
    assert_eq!(commit.aad(), b"commit-aad");
    assert!(matches!(commit.sender(), Sender::Member(index) if index.u32() == 0));
    let expected_next_coordinate = successor_coordinate(
        &snapshot_binding,
        fixture.add_group_context_hash,
        fixture.add_confirmation_tag,
    );
    let processed = process_public_commit(
        group_info.public_state(),
        commit,
        commit_policy(
            b"commit-aad",
            &snapshot_binding,
            &expected_next_coordinate,
            fixture.now_unix_seconds,
            100,
        ),
    )
    .expect("signature-check, policy-check, and merge Add Commit in disposable state");
    assert_eq!(
        group_info.public_group().group_context().epoch().as_u64(),
        0,
        "processing must not mutate the authoritative prior state"
    );
    assert_eq!(processed.next_binding().epoch(), 1);
    assert_eq!(processed.next_state().public_group().members().count(), 2);
    assert_eq!(processed.adds().len(), 1);
    assert!(processed.removes().is_empty());
    assert_eq!(processed.adds()[0].basic_credential(), TEST_BOB_CREDENTIAL);
    assert_eq!(
        processed.adds()[0].key_package().key_package_ref(),
        &fixture.bob_key_package_ref
    );
    assert_eq!(processed.sender_update().leaf_index(), 0);
    assert_ne!(
        processed.sender_update().prior_encryption_key(),
        processed.sender_update().next_encryption_key()
    );
    let reloaded =
        decode_public_group_snapshot(processed.next_snapshot(), processed.next_binding())
            .expect("returned merged snapshot must be self-consistent and exactly bound");
    assert_eq!(reloaded.public_group().group_context().epoch().as_u64(), 1);

    let welcome =
        validate_welcome(&fixture.welcome, MAX_WELCOME_WIRE_BYTES).expect("strict XWing Welcome");
    assert_eq!(welcome.inner_bytes(), &fixture.welcome[4..]);
    assert_eq!(welcome.key_package_refs(), &[fixture.bob_key_package_ref]);

    let private =
        validate_private_application(&fixture.private_application, MAX_PRIVATE_MESSAGE_WIRE_BYTES)
            .expect("strict private application");
    assert_eq!(private.group_id(), fixture.group_id);
    assert_eq!(private.epoch(), 1);
    assert_eq!(private.aad(), b"application-aad");
}

#[test]
fn snapshot_binding_and_load_accept_exact_basic_credential_boundaries() {
    let maximum_hostname = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let maximum_bare_did = format!("did:web:{maximum_hostname}");
    for credential in [
        b"did:web:a.co#00000000-0000-4000-8000-000000000000".to_vec(),
        format!("{maximum_bare_did}#00000000-0000-4000-8000-000000000000").into_bytes(),
    ] {
        assert!(matches!(credential.len(), 49 | 298));
        let fixture = genesis_group_info_fixture_with_credential(
            Some(exact_capabilities()),
            Some(Lifetime::init(frozen_now() - 60, frozen_now() + 3_600)),
            &credential,
        );
        let validated = validate_group_info(
            &fixture.bytes,
            GroupInfoValidationPolicy {
                expected_basic_credential: &credential,
                expected_signature_key: &fixture.signature_key,
                now_unix_seconds: fixture.now_unix_seconds,
                max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_ratchet_tree_bytes: 786_432,
                max_members: 1,
            },
        )
        .expect("validate boundary-credential GroupInfo");
        let snapshot = encode_public_group_snapshot(validated.public_state())
            .expect("encode boundary-credential public state");
        let coordinate = coordinate_for_validated_group(&validated, 0, 0);
        let binding =
            public_group_snapshot_binding(validated.public_state(), &snapshot, &coordinate)
                .expect("bind boundary-credential public state");
        let restored = decode_public_group_snapshot(&snapshot, &binding)
            .expect("reload boundary-credential public state");
        assert_eq!(
            restored
                .public_group()
                .members()
                .next()
                .expect("singleton member")
                .credential
                .serialized_content(),
            credential
        );
    }
}

#[test]
fn stateful_commit_rejects_wrong_aad_coordinate_signature_lifetime_and_member_bound_atomically() {
    let fixture = coherent_wire_fixture();
    let group_info = validate_group_info(&fixture.genesis_group_info, group_info_policy(&fixture))
        .expect("strict prior state");
    let prior_binding = binding_for_validated_group(&group_info, 0, 0);
    let expected_add_coordinate = successor_coordinate(
        &prior_binding,
        fixture.add_group_context_hash,
        fixture.add_confirmation_tag,
    );

    let commit = validate_public_commit(&fixture.public_add_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("structural Commit");
    assert_eq!(
        process_public_commit(
            group_info.public_state(),
            commit,
            commit_policy(
                b"wrong-aad",
                &prior_binding,
                &expected_add_coordinate,
                fixture.now_unix_seconds,
                100,
            ),
        )
        .expect_err("AAD mismatch"),
        WireValidationError::CommitAadMismatch
    );
    assert_eq!(group_info.epoch(), 0);

    let foreign = coherent_wire_fixture_with_group_id(b"fedcba9876543210fedcba9876543210");
    let commit = validate_public_commit(&foreign.public_add_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("foreign structurally valid Commit");
    assert_eq!(
        process_public_commit(
            group_info.public_state(),
            commit,
            commit_policy(
                b"commit-aad",
                &prior_binding,
                &expected_add_coordinate,
                fixture.now_unix_seconds,
                100,
            ),
        )
        .expect_err("wrong group coordinate"),
        WireValidationError::CommitCoordinateMismatch
    );
    assert_eq!(group_info.epoch(), 0);

    let mut bad_signature = fixture.public_add_commit.clone();
    let signature_byte = bad_signature.len() - 67;
    bad_signature[signature_byte] ^= 0x80;
    let commit = validate_public_commit(&bad_signature, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("signature mutation remains canonical TLS");
    assert_eq!(
        process_public_commit(
            group_info.public_state(),
            commit,
            commit_policy(
                b"commit-aad",
                &prior_binding,
                &expected_add_coordinate,
                fixture.now_unix_seconds,
                100,
            ),
        )
        .expect_err("invalid member signature"),
        WireValidationError::InvalidPublicCommit
    );
    assert_eq!(group_info.epoch(), 0);

    let commit = validate_public_commit(&fixture.public_add_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("structural Commit");
    assert_eq!(
        process_public_commit(
            group_info.public_state(),
            commit,
            commit_policy(
                b"commit-aad",
                &prior_binding,
                &expected_add_coordinate,
                fixture.now_unix_seconds + 3_600,
                100,
            ),
        )
        .expect_err("Add lifetime is closed at not_after"),
        WireValidationError::InvalidCommitAdd
    );
    assert_eq!(group_info.epoch(), 0);

    let commit = validate_public_commit(&fixture.public_add_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("structural Commit");
    assert_eq!(
        process_public_commit(
            group_info.public_state(),
            commit,
            commit_policy(
                b"commit-aad",
                &prior_binding,
                &expected_add_coordinate,
                fixture.now_unix_seconds,
                1,
            ),
        )
        .expect_err("post-state member bound"),
        WireValidationError::TooManyMembers {
            actual: 2,
            maximum: 1,
        }
    );
    assert_eq!(group_info.epoch(), 0);

    let commit = validate_public_commit(&fixture.public_add_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("structural Commit");
    let applied = process_public_commit(
        group_info.public_state(),
        commit,
        commit_policy(
            b"commit-aad",
            &prior_binding,
            &expected_add_coordinate,
            fixture.now_unix_seconds,
            100,
        ),
    )
    .expect("first application");
    let replay = validate_public_commit(&fixture.public_add_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("structural replay");
    let replay_next_coordinate =
        successor_coordinate(applied.next_binding(), [0x33; 32], [0x44; 32]);
    assert_eq!(
        process_public_commit(
            applied.next_state(),
            replay,
            commit_policy(
                b"commit-aad",
                applied.next_binding(),
                &replay_next_coordinate,
                fixture.now_unix_seconds,
                100,
            ),
        )
        .expect_err("epoch-zero replay against epoch one"),
        WireValidationError::CommitCoordinateMismatch
    );
    assert_eq!(applied.next_binding().epoch(), 1);
}

#[test]
fn stateful_commit_requires_every_signed_successor_outer_coordinate_field() {
    let fixture = coherent_wire_fixture();
    let prior = validate_group_info(&fixture.genesis_group_info, group_info_policy(&fixture))
        .expect("strict prior state");
    let prior_binding = binding_for_validated_group(&prior, 0, 0);
    let correct = successor_coordinate(
        &prior_binding,
        fixture.add_group_context_hash,
        fixture.add_confirmation_tag,
    );
    let coordinate = |conversation_id,
                      generation,
                      state_version,
                      group_id,
                      epoch,
                      group_context_hash,
                      confirmation_tag,
                      lifecycle| {
        PublicGroupSnapshotCoordinate::new(
            conversation_id,
            generation,
            state_version,
            group_id,
            epoch,
            group_context_hash,
            confirmation_tag,
            lifecycle,
        )
    };
    let mut wrong_conversation_id = *correct.conversation_id();
    wrong_conversation_id[15] ^= 1;
    let mut wrong_group_id = *correct.group_id();
    wrong_group_id[0] ^= 1;
    let mut wrong_context_hash = *correct.group_context_hash();
    wrong_context_hash[0] ^= 1;
    let mut wrong_confirmation_tag = *correct.confirmation_tag();
    wrong_confirmation_tag[0] ^= 1;
    let bad_coordinates = [
        (
            "conversationId",
            coordinate(
                wrong_conversation_id,
                correct.generation(),
                correct.state_version(),
                *correct.group_id(),
                correct.epoch(),
                *correct.group_context_hash(),
                *correct.confirmation_tag(),
                correct.lifecycle(),
            ),
        ),
        (
            "generation",
            coordinate(
                *correct.conversation_id(),
                correct.generation() + 1,
                correct.state_version(),
                *correct.group_id(),
                correct.epoch(),
                *correct.group_context_hash(),
                *correct.confirmation_tag(),
                correct.lifecycle(),
            ),
        ),
        (
            "stateVersion",
            coordinate(
                *correct.conversation_id(),
                correct.generation(),
                correct.state_version() + 1,
                *correct.group_id(),
                correct.epoch(),
                *correct.group_context_hash(),
                *correct.confirmation_tag(),
                correct.lifecycle(),
            ),
        ),
        (
            "groupId",
            coordinate(
                *correct.conversation_id(),
                correct.generation(),
                correct.state_version(),
                wrong_group_id,
                correct.epoch(),
                *correct.group_context_hash(),
                *correct.confirmation_tag(),
                correct.lifecycle(),
            ),
        ),
        (
            "epoch",
            coordinate(
                *correct.conversation_id(),
                correct.generation(),
                correct.state_version(),
                *correct.group_id(),
                correct.epoch() + 1,
                *correct.group_context_hash(),
                *correct.confirmation_tag(),
                correct.lifecycle(),
            ),
        ),
        (
            "groupContextHash",
            coordinate(
                *correct.conversation_id(),
                correct.generation(),
                correct.state_version(),
                *correct.group_id(),
                correct.epoch(),
                wrong_context_hash,
                *correct.confirmation_tag(),
                correct.lifecycle(),
            ),
        ),
        (
            "confirmationTag",
            coordinate(
                *correct.conversation_id(),
                correct.generation(),
                correct.state_version(),
                *correct.group_id(),
                correct.epoch(),
                *correct.group_context_hash(),
                wrong_confirmation_tag,
                correct.lifecycle(),
            ),
        ),
        (
            "lifecycle",
            coordinate(
                *correct.conversation_id(),
                correct.generation(),
                correct.state_version(),
                *correct.group_id(),
                correct.epoch(),
                *correct.group_context_hash(),
                *correct.confirmation_tag(),
                PublicGroupSnapshotLifecycle::Superseded,
            ),
        ),
    ];

    for (field, bad_coordinate) in bad_coordinates {
        let commit =
            validate_public_commit(&fixture.public_add_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
                .expect("structural Add Commit");
        assert_eq!(
            process_public_commit(
                prior.public_state(),
                commit,
                commit_policy(
                    b"commit-aad",
                    &prior_binding,
                    &bad_coordinate,
                    fixture.now_unix_seconds,
                    100,
                ),
            )
            .expect_err("mismatched signed successor coordinate"),
            WireValidationError::CommitCoordinateMismatch,
            "successor {field} mismatch escaped validation"
        );
        assert_eq!(prior.epoch(), 0, "{field} mismatch mutated prior state");
    }
}

#[test]
fn public_commit_raw_profile_rejects_duplicate_reference_and_overflow_before_deduplication() {
    let fixture = coherent_wire_fixture();
    let one_add = public_commit_proposal_bytes(&fixture.public_add_commit);
    assert!(!one_add.is_empty());

    let duplicate_add = replace_public_commit_proposals(
        &fixture.public_add_commit,
        [one_add.as_slice(), one_add.as_slice()].concat(),
    );
    assert_eq!(
        validate_public_commit(&duplicate_add, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .expect_err("duplicate Add"),
        WireValidationError::DuplicateCommitProposal
    );

    let remove = [
        vec![ProposalOrRefType::Proposal as u8, 0, 3],
        7_u32.to_be_bytes().to_vec(),
    ]
    .concat();
    let duplicate_remove = replace_public_commit_proposals(
        &fixture.public_add_commit,
        [remove.as_slice(), remove.as_slice()].concat(),
    );
    assert_eq!(
        validate_public_commit(&duplicate_remove, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .expect_err("duplicate Remove"),
        WireValidationError::DuplicateCommitProposal
    );

    let mut reference = vec![ProposalOrRefType::Reference as u8];
    reference.extend_from_slice(
        &VLBytes::from(vec![0xA5; 32])
            .tls_serialize_detached()
            .expect("serialize ProposalRef"),
    );
    let by_reference = replace_public_commit_proposals(&fixture.public_add_commit, reference);
    assert_eq!(
        validate_public_commit(&by_reference, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .expect_err("proposal reference"),
        WireValidationError::ReferencedCommitProposal
    );

    let mut too_many = Vec::new();
    for leaf_index in 0_u32..101 {
        too_many.push(ProposalOrRefType::Proposal as u8);
        too_many.extend_from_slice(&3_u16.to_be_bytes());
        too_many.extend_from_slice(&leaf_index.to_be_bytes());
    }
    let over_limit = replace_public_commit_proposals(&fixture.public_add_commit, too_many);
    assert_eq!(
        validate_public_commit(&over_limit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .expect_err("more than 100 proposals"),
        WireValidationError::TooManyCommitProposals
    );
}

#[test]
fn public_commit_raw_profile_rejects_every_unsupported_proposal_family() {
    let fixture = coherent_wire_fixture();
    let one_add = public_commit_proposal_bytes(&fixture.public_add_commit);
    let mut encoded_key_package = &one_add[3..];
    let key_package = TestWireKeyPackage::tls_deserialize(&mut encoded_key_package)
        .expect("parse Add KeyPackage");
    assert!(encoded_key_package.is_empty());
    let update_leaf = key_package
        .payload
        .leaf_node
        .tls_serialize_detached()
        .expect("serialize Update leaf");

    // Each body is syntactically valid for OpenMLS' structural preflight. The
    // clean profile rejects the proposal type itself before state processing.
    let unsupported = [
        ("Update", 2_u16, update_leaf),
        ("PreSharedKey", 4, vec![1, 0, 0]),
        ("ReInit", 5, vec![0, 0, 1, 0, 77, 0]),
        ("ExternalInit", 6, vec![0]),
        ("GroupContextExtensions", 7, vec![0]),
        ("draft proposal", 8, vec![0]),
        ("SelfRemove", 10, vec![]),
        ("GREASE", 0x0A0A, vec![0]),
        ("private-use Custom", 0xF000, vec![0]),
    ];
    for (name, proposal_type, body) in unsupported {
        let mut proposal = vec![ProposalOrRefType::Proposal as u8];
        proposal.extend_from_slice(&proposal_type.to_be_bytes());
        proposal.extend_from_slice(&body);
        let mutated = replace_public_commit_proposals(&fixture.public_add_commit, proposal);
        assert_eq!(
            validate_public_commit(&mutated, MAX_PUBLIC_MESSAGE_WIRE_BYTES).expect_err(name),
            WireValidationError::UnsupportedCommitProposal,
            "{name} escaped the closed Add/Remove profile"
        );
    }
}

#[test]
fn public_commit_rejects_noncanonical_xwing_path_keys_and_kem_outputs() {
    let fixture = coherent_wire_fixture();
    let welcome = TestWelcomeEnvelope::tls_deserialize_exact(&fixture.welcome)
        .expect("parse Welcome KEM output fixture");
    let canonical_kem_output = welcome.welcome.secrets[0]
        .encrypted_group_secrets
        .kem_output
        .clone();

    for (alias_name, apply_alias) in x25519_noncanonical_aliases() {
        let bad_leaf = mutate_public_commit_update_path(&fixture.public_add_commit, |path| {
            let mut key = path.leaf_node.payload.encryption_key.as_slice().to_vec();
            apply_alias(&mut key);
            path.leaf_node.payload.encryption_key = key.into();
        });
        assert_eq!(
            validate_public_commit(&bad_leaf, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
                .expect_err("noncanonical update-path leaf"),
            WireValidationError::InvalidXwingPublicKey,
            "Commit update-path leaf {alias_name} escaped validation"
        );

        let bad_parent = mutate_public_commit_update_path(&fixture.public_add_commit, |path| {
            let node = path.nodes.first_mut().expect("nonempty direct path");
            let mut key = node.public_key.as_slice().to_vec();
            apply_alias(&mut key);
            node.public_key = key.into();
        });
        assert_eq!(
            validate_public_commit(&bad_parent, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
                .expect_err("noncanonical update-path parent"),
            WireValidationError::InvalidXwingPublicKey,
            "Commit update-path parent {alias_name} escaped validation"
        );

        let bad_kem_output = mutate_public_commit_update_path(&fixture.public_add_commit, |path| {
            let node = path.nodes.first_mut().expect("nonempty direct path");
            let mut kem_output = canonical_kem_output.as_slice().to_vec();
            apply_alias(&mut kem_output);
            node.encrypted_path_secrets.push(TestHpkeCiphertext {
                kem_output: kem_output.into(),
                ciphertext: vec![0xA5; 48].into(),
            });
        });
        assert_eq!(
            validate_public_commit(&bad_kem_output, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
                .expect_err("noncanonical path KEM output"),
            WireValidationError::InvalidXwingKemOutput,
            "Commit update-path KEM output {alias_name} escaped validation"
        );
    }

    for ciphertext_length in [0, 16, 47, 49] {
        let wrong_ciphertext =
            mutate_public_commit_update_path(&fixture.public_add_commit, |path| {
                path.nodes
                    .first_mut()
                    .expect("nonempty direct path")
                    .encrypted_path_secrets
                    .push(TestHpkeCiphertext {
                        kem_output: canonical_kem_output.clone(),
                        ciphertext: vec![0xA5; ciphertext_length].into(),
                    });
            });
        assert_eq!(
            validate_public_commit(&wrong_ciphertext, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
                .expect_err("wrong path ciphertext length"),
            WireValidationError::InvalidHpkeCiphertext
        );
    }
}

#[test]
fn stateful_commit_accepts_a_clean_sender_refresh_and_rejects_sender_path_mutation() {
    let empty = stateful_commit_fixture(StatefulCommitVariant::EmptySelfUpdate);
    let prior = stateful_fixture_group_info(&empty);
    let prior_binding = binding_for_validated_group(&prior, 0, 0);
    let expected_next_coordinate = successor_coordinate(
        &prior_binding,
        empty.next_group_context_hash,
        empty.next_confirmation_tag,
    );
    let commit = validate_public_commit(&empty.commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("structural self-update Commit");
    let refreshed = process_public_commit(
        prior.public_state(),
        commit,
        commit_policy(
            b"variant-aad",
            &prior_binding,
            &expected_next_coordinate,
            empty.now_unix_seconds,
            100,
        ),
    )
    .expect("proposal-free member refresh is a sender-key effect");
    assert!(refreshed.adds().is_empty());
    assert!(refreshed.removes().is_empty());
    assert_ne!(
        refreshed.sender_update().prior_encryption_key(),
        refreshed.sender_update().next_encryption_key(),
        "the authenticated update path must rotate the sender encryption key"
    );
    assert_eq!(refreshed.next_binding().epoch(), 1);
    assert_eq!(prior.epoch(), 0);

    for (variant, reason) in [
        (
            StatefulCommitVariant::EmptyWithDefaultPathCapabilities,
            "proposal-free refresh path capabilities outside the exact singleton profile",
        ),
        (
            StatefulCommitVariant::EmptyWithChangedPathCredential,
            "proposal-free refresh path changes the sender identity",
        ),
        (
            StatefulCommitVariant::AddWithDefaultPathCapabilities,
            "path capabilities outside the exact singleton profile",
        ),
        (
            StatefulCommitVariant::AddWithChangedPathCredential,
            "path changes the sender identity",
        ),
    ] {
        let fixture = stateful_commit_fixture(variant);
        let prior = stateful_fixture_group_info(&fixture);
        let prior_binding = binding_for_validated_group(&prior, 0, 0);
        let expected_next_coordinate = successor_coordinate(&prior_binding, [0x33; 32], [0x44; 32]);
        let commit = validate_public_commit(&fixture.commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .expect("structural Add Commit");
        assert_eq!(
            process_public_commit(
                prior.public_state(),
                commit,
                commit_policy(
                    b"variant-aad",
                    &prior_binding,
                    &expected_next_coordinate,
                    fixture.now_unix_seconds,
                    100,
                ),
            )
            .expect_err(reason),
            WireValidationError::InvalidCommitUpdatePath,
            "{reason}"
        );
        assert_eq!(prior.epoch(), 0, "failure mutated prior state: {reason}");
    }
}

#[test]
fn stateful_remove_commit_derives_exact_removed_identity_and_next_snapshot() {
    let fixture = coherent_wire_fixture();
    let prior = validate_group_info(&fixture.genesis_group_info, group_info_policy(&fixture))
        .expect("genesis prior");
    let prior_binding = binding_for_validated_group(&prior, 0, 0);
    let expected_add_coordinate = successor_coordinate(
        &prior_binding,
        fixture.add_group_context_hash,
        fixture.add_confirmation_tag,
    );
    let add = validate_public_commit(&fixture.public_add_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("Add Commit");
    let epoch_one = process_public_commit(
        prior.public_state(),
        add,
        commit_policy(
            b"commit-aad",
            &prior_binding,
            &expected_add_coordinate,
            fixture.now_unix_seconds,
            100,
        ),
    )
    .expect("apply Add");

    let remove =
        validate_public_commit(&fixture.public_remove_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .expect("Remove Commit");
    let expected_remove_coordinate = successor_coordinate(
        epoch_one.next_binding(),
        fixture.remove_group_context_hash,
        fixture.remove_confirmation_tag,
    );
    let epoch_two = process_public_commit(
        epoch_one.next_state(),
        remove,
        commit_policy(
            b"remove-aad",
            epoch_one.next_binding(),
            &expected_remove_coordinate,
            fixture.now_unix_seconds,
            100,
        ),
    )
    .expect("apply Remove");
    assert_eq!(epoch_one.next_binding().epoch(), 1);
    assert_eq!(epoch_two.next_binding().epoch(), 2);
    assert!(epoch_two.adds().is_empty());
    assert_eq!(epoch_two.removes().len(), 1);
    assert_eq!(epoch_two.removes()[0].leaf_index(), 1);
    assert_eq!(
        epoch_two.removes()[0].basic_credential(),
        TEST_BOB_CREDENTIAL
    );
    assert_eq!(epoch_two.next_state().public_group().members().count(), 1);
    decode_public_group_snapshot(epoch_two.next_snapshot(), epoch_two.next_binding())
        .expect("Remove snapshot is exact and coherent");
}

#[test]
fn rightmost_member_commits_round_trip_across_trimmed_non_power_of_two_trees() {
    for member_count in [3_usize, 5, 6, 7] {
        let fixture = rightmost_sender_fixture(member_count);
        let genesis = validate_group_info(
            &fixture.genesis_group_info,
            GroupInfoValidationPolicy {
                expected_basic_credential: TEST_ALICE_CREDENTIAL,
                expected_signature_key: &fixture.alice_signature_key,
                now_unix_seconds: fixture.now_unix_seconds,
                max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_ratchet_tree_bytes: 786_432,
                max_members: 1,
            },
        )
        .expect("validate rightmost-sender genesis state");
        let mut binding = binding_for_validated_group(&genesis, 0, 0);
        let mut state = genesis.into_public_state();

        for transition in fixture.transitions {
            let commit = validate_public_commit(&transition.commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
                .expect("validate rightmost-sender Commit wire profile");
            let expected_coordinate = successor_coordinate(
                &binding,
                transition.group_context_hash,
                transition.confirmation_tag,
            );
            let processed = process_public_commit(
                &state,
                commit,
                commit_policy(
                    &transition.aad,
                    &binding,
                    &expected_coordinate,
                    fixture.now_unix_seconds,
                    100,
                ),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "{member_count}-leaf tree rejected sender leaf {}: {error:?}",
                    transition.sender_index
                )
            });
            assert_eq!(
                processed.sender_update().leaf_index(),
                transition.sender_index
            );
            assert_eq!(
                processed.next_state().public_group().members().count(),
                transition.expected_member_count
            );
            assert_eq!(processed.adds().len(), transition.expected_add_count);
            assert_eq!(processed.removes().len(), transition.expected_remove_count);
            decode_public_group_snapshot(processed.next_snapshot(), processed.next_binding())
                .expect("round-trip non-power-of-two public snapshot");
            binding = processed.next_binding().clone();
            state = processed.into_next_state();
        }
    }
}

#[test]
fn group_info_rejects_openmls_default_creator_capabilities() {
    let now = frozen_now();
    let fixture = genesis_group_info_fixture(None, Some(Lifetime::init(now - 60, now + 3_600)));
    assert!(
        validate_group_info(&fixture.bytes, standalone_group_info_policy(&fixture)).is_err(),
        "OpenMLS defaults advertise four suites and must not pass the closed profile"
    );
}

#[test]
fn group_info_rejects_short_remaining_and_excessive_creator_lifetimes() {
    let now = frozen_now();
    let short = genesis_group_info_fixture(
        Some(exact_capabilities()),
        Some(Lifetime::init(now - 60, now + 599)),
    );
    assert!(
        validate_group_info(&short.bytes, standalone_group_info_policy(&short)).is_err(),
        "genesis leaf must retain at least ten minutes at frozen validation time"
    );

    let long = genesis_group_info_fixture(
        Some(exact_capabilities()),
        Some(Lifetime::init(
            now - 60,
            now - 60 + MAX_KEY_PACKAGE_LIFETIME_SECONDS + 1,
        )),
    );
    assert!(
        validate_group_info(&long.bytes, standalone_group_info_policy(&long)).is_err(),
        "genesis leaf lifetime span must obey the clean maximum"
    );
}

#[test]
fn group_info_rejects_nested_trailing_bytes_in_known_extensions() {
    let fixture = coherent_wire_fixture();
    let envelope = TestGroupInfoEnvelope::tls_deserialize_exact(&fixture.genesis_group_info)
        .expect("parse generated GroupInfo into RFC wire mirror");

    for extension_index in 0..2 {
        let mut padded = envelope.clone();
        let mut data = padded.group_info.extensions[extension_index]
            .extension_data
            .as_slice()
            .to_vec();
        data.push(0xA5);
        padded.group_info.extensions[extension_index].extension_data = data.into();
        let bytes = padded
            .tls_serialize_detached()
            .expect("serialize internally padded GroupInfo");
        assert!(
            validate_group_info(&bytes, group_info_policy(&fixture)).is_err(),
            "known extension {} accepted unsigned nested trailing data",
            padded.group_info.extensions[extension_index].extension_type
        );
    }
}

#[test]
fn group_info_rejects_nonempty_epoch_zero_confirmed_transcript_hash() {
    let fixture = coherent_wire_fixture();
    let mut malformed = TestGroupInfoEnvelope::tls_deserialize_exact(&fixture.genesis_group_info)
        .expect("parse generated GroupInfo into RFC wire mirror");
    malformed.group_info.context.confirmed_transcript_hash = vec![0xCC; 32].into();
    resign_test_group_info(&mut malformed, &fixture.alice_signer);
    let bytes = malformed
        .tls_serialize_detached()
        .expect("serialize signed nonempty genesis transcript hash");
    assert!(
        validate_group_info(&bytes, group_info_policy(&fixture)).is_err(),
        "epoch-zero confirmed transcript hash must be empty"
    );
}

#[test]
fn group_info_binds_but_does_not_verify_a_well_shaped_confirmation_tag_mac() {
    let fixture = coherent_wire_fixture();
    let original = validate_group_info(&fixture.genesis_group_info, group_info_policy(&fixture))
        .expect("validate original GroupInfo");
    let mut forged = TestGroupInfoEnvelope::tls_deserialize_exact(&fixture.genesis_group_info)
        .expect("parse generated GroupInfo into RFC wire mirror");
    let forged_tag = [0xA7; 32];
    assert_ne!(forged.group_info.confirmation_tag.as_slice(), forged_tag);
    forged.group_info.confirmation_tag = forged_tag.to_vec().into();
    resign_test_group_info(&mut forged, &fixture.alice_signer);
    let forged_bytes = forged
        .tls_serialize_detached()
        .expect("serialize signature-valid GroupInfo with forged confirmation tag");

    // A PublicGroup has no epoch secrets. It can verify the GroupInfo
    // signature and bind the exact received tag into transcript/snapshot
    // state, but only a client can verify the confirmation MAC. A client MAC
    // failure must therefore reject this transition and enter recovery.
    let structurally_valid = validate_group_info(&forged_bytes, group_info_policy(&fixture))
        .expect("public service accepts signature-valid, well-shaped opaque tag");
    assert_eq!(structurally_valid.confirmation_tag(), &forged_tag);
    assert_eq!(
        structurally_valid.group_context_hash(),
        original.group_context_hash(),
        "changing only the confirmation tag must not alter GroupContext"
    );

    let snapshot = encode_public_group_snapshot(structurally_valid.public_state())
        .expect("encode public state carrying the exact received tag");
    let forged_coordinate = coordinate_for_validated_group(&structurally_valid, 0, 0);
    public_group_snapshot_binding(
        structurally_valid.public_state(),
        &snapshot,
        &forged_coordinate,
    )
    .expect("snapshot binding preserves the exact opaque tag");

    let original_tag_coordinate = PublicGroupSnapshotCoordinate::new(
        *forged_coordinate.conversation_id(),
        forged_coordinate.generation(),
        forged_coordinate.state_version(),
        *forged_coordinate.group_id(),
        forged_coordinate.epoch(),
        *forged_coordinate.group_context_hash(),
        *original.confirmation_tag(),
        forged_coordinate.lifecycle(),
    );
    assert!(
        public_group_snapshot_binding(
            structurally_valid.public_state(),
            &snapshot,
            &original_tag_coordinate,
        )
        .is_err(),
        "the service must never substitute a different tag while persisting"
    );
}

#[test]
fn group_info_rejects_malformed_creator_xwing_encryption_key() {
    let fixture = coherent_wire_fixture();
    let mut malformed = TestGroupInfoEnvelope::tls_deserialize_exact(&fixture.genesis_group_info)
        .expect("parse generated GroupInfo into RFC wire mirror");
    mutate_singleton_leaf(&mut malformed, &fixture.alice_signer, |leaf| {
        leaf.payload.encryption_key = vec![0xFF; 1_216].into();
    });
    let bytes = malformed
        .tls_serialize_detached()
        .expect("serialize signed GroupInfo with invalid XWing leaf key");
    assert!(
        validate_group_info(&bytes, group_info_policy(&fixture)).is_err(),
        "invalid ML-KEM bytes must not enter genesis public state"
    );

    for (alias_name, apply_alias) in x25519_noncanonical_aliases() {
        let mut noncanonical_leaf =
            TestGroupInfoEnvelope::tls_deserialize_exact(&fixture.genesis_group_info)
                .expect("parse generated GroupInfo into RFC wire mirror");
        mutate_singleton_leaf(&mut noncanonical_leaf, &fixture.alice_signer, |leaf| {
            let mut key = leaf.payload.encryption_key.as_slice().to_vec();
            apply_alias(&mut key);
            leaf.payload.encryption_key = key.into();
        });
        assert_eq!(
            validate_group_info(
                &noncanonical_leaf
                    .tls_serialize_detached()
                    .expect("serialize noncanonical creator leaf"),
                group_info_policy(&fixture),
            )
            .expect_err("noncanonical creator leaf"),
            WireValidationError::InvalidXwingPublicKey,
            "GroupInfo creator {alias_name} entered public state"
        );

        let mut noncanonical_external =
            TestGroupInfoEnvelope::tls_deserialize_exact(&fixture.genesis_group_info)
                .expect("parse generated GroupInfo into RFC wire mirror");
        let external_extension = &mut noncanonical_external.group_info.extensions[1];
        assert_eq!(external_extension.extension_type, 4);
        let mut external_key =
            VLBytes::tls_deserialize_exact(external_extension.extension_data.as_slice())
                .expect("parse ExternalPub HPKE key")
                .as_slice()
                .to_vec();
        apply_alias(&mut external_key);
        external_extension.extension_data = VLBytes::from(external_key)
            .tls_serialize_detached()
            .expect("serialize noncanonical ExternalPub")
            .into();
        resign_test_group_info(&mut noncanonical_external, &fixture.alice_signer);
        assert_eq!(
            validate_group_info(
                &noncanonical_external
                    .tls_serialize_detached()
                    .expect("serialize noncanonical ExternalPub GroupInfo"),
                group_info_policy(&fixture),
            )
            .expect_err("noncanonical ExternalPub"),
            WireValidationError::InvalidXwingPublicKey,
            "GroupInfo ExternalPub {alias_name} entered public state"
        );
    }
}

#[test]
fn group_info_rejects_non_key_package_creator_leaf_source() {
    let fixture = coherent_wire_fixture();
    let mut malformed = TestGroupInfoEnvelope::tls_deserialize_exact(&fixture.genesis_group_info)
        .expect("parse generated GroupInfo into RFC wire mirror");
    mutate_singleton_leaf(&mut malformed, &fixture.alice_signer, |leaf| {
        leaf.payload.source = TestWireLeafNodeSource::Update;
    });
    let bytes = malformed
        .tls_serialize_detached()
        .expect("serialize GroupInfo with Update-source creator leaf");
    assert_eq!(
        validate_group_info(&bytes, group_info_policy(&fixture))
            .expect_err("Update-source creator leaf must be rejected"),
        WireValidationError::UnsupportedLeafSource
    );
}

#[test]
fn group_info_rejects_creator_leaf_extensions() {
    let fixture = coherent_wire_fixture();
    let mut malformed = TestGroupInfoEnvelope::tls_deserialize_exact(&fixture.genesis_group_info)
        .expect("parse generated GroupInfo into RFC wire mirror");
    mutate_singleton_leaf(&mut malformed, &fixture.alice_signer, |leaf| {
        leaf.payload.extensions.push(TestExtension {
            extension_type: 0xF001,
            extension_data: vec![0x01].into(),
        });
    });
    let bytes = malformed
        .tls_serialize_detached()
        .expect("serialize GroupInfo with creator leaf extension");
    assert_eq!(
        validate_group_info(&bytes, group_info_policy(&fixture))
            .expect_err("creator leaf extensions must be rejected"),
        WireValidationError::UnsupportedExtensions
    );
}

#[test]
fn welcome_rejects_more_than_one_hundred_encrypted_recipients() {
    let fixture = coherent_wire_fixture();
    let mut envelope = TestWelcomeEnvelope::tls_deserialize_exact(&fixture.welcome)
        .expect("parse generated Welcome into RFC wire mirror");
    let secret = envelope.welcome.secrets[0].clone();
    envelope.welcome.secrets = vec![secret; 101];
    let bytes = envelope
        .tls_serialize_detached()
        .expect("serialize oversized-recipient Welcome");
    assert_eq!(
        validate_welcome(&bytes, MAX_WELCOME_WIRE_BYTES),
        Err(WireValidationError::TooManyWelcomeRecipients {
            actual: 101,
            maximum: 100,
        })
    );
}

#[test]
fn welcome_rejects_non_sha256_and_duplicate_new_member_refs() {
    let fixture = coherent_wire_fixture();
    let mut envelope = TestWelcomeEnvelope::tls_deserialize_exact(&fixture.welcome)
        .expect("parse generated Welcome into the RFC wire mirror");

    let mut empty = envelope.clone();
    empty.welcome.secrets.clear();
    assert_eq!(
        validate_welcome(
            &empty
                .tls_serialize_detached()
                .expect("serialize empty Welcome"),
            MAX_WELCOME_WIRE_BYTES,
        ),
        Err(WireValidationError::EmptyWelcome)
    );

    envelope.welcome.secrets[0].new_member = vec![0xA5; 31].into();
    let wrong_length = envelope
        .tls_serialize_detached()
        .expect("serialize wrong-length Welcome");
    assert_eq!(
        validate_welcome(&wrong_length, MAX_WELCOME_WIRE_BYTES),
        Err(WireValidationError::WrongWelcomeKeyPackageRefLength { actual: 31 })
    );

    let mut envelope = TestWelcomeEnvelope::tls_deserialize_exact(&fixture.welcome)
        .expect("parse generated Welcome into the RFC wire mirror");
    envelope
        .welcome
        .secrets
        .push(envelope.welcome.secrets[0].clone());
    let duplicate = envelope
        .tls_serialize_detached()
        .expect("serialize duplicate-ref Welcome");
    assert_eq!(
        validate_welcome(&duplicate, MAX_WELCOME_WIRE_BYTES),
        Err(WireValidationError::DuplicateWelcomeKeyPackageRef)
    );
}

#[test]
fn welcome_rejects_noncanonical_or_unusable_xwing_kem_outputs() {
    let fixture = coherent_wire_fixture();
    for (alias_name, apply_alias) in x25519_noncanonical_aliases() {
        let mut envelope = TestWelcomeEnvelope::tls_deserialize_exact(&fixture.welcome)
            .expect("parse generated Welcome into RFC wire mirror");
        let mut kem_output = envelope.welcome.secrets[0]
            .encrypted_group_secrets
            .kem_output
            .as_slice()
            .to_vec();
        apply_alias(&mut kem_output);
        envelope.welcome.secrets[0]
            .encrypted_group_secrets
            .kem_output = kem_output.into();
        assert_eq!(
            validate_welcome(
                &envelope
                    .tls_serialize_detached()
                    .expect("serialize noncanonical Welcome KEM output"),
                MAX_WELCOME_WIRE_BYTES,
            ),
            Err(WireValidationError::InvalidXwingKemOutput),
            "Welcome KEM output {alias_name} escaped validation"
        );
    }

    for kem_output in [vec![0xA5; 1_119], vec![0xA5; 1_121], {
        let mut output = TestWelcomeEnvelope::tls_deserialize_exact(&fixture.welcome)
            .expect("parse Welcome")
            .welcome
            .secrets[0]
            .encrypted_group_secrets
            .kem_output
            .as_slice()
            .to_vec();
        output[1_088..].fill(0);
        output
    }] {
        let mut envelope = TestWelcomeEnvelope::tls_deserialize_exact(&fixture.welcome)
            .expect("parse generated Welcome into RFC wire mirror");
        envelope.welcome.secrets[0]
            .encrypted_group_secrets
            .kem_output = kem_output.into();
        assert_eq!(
            validate_welcome(
                &envelope
                    .tls_serialize_detached()
                    .expect("serialize unusable Welcome KEM output"),
                MAX_WELCOME_WIRE_BYTES,
            ),
            Err(WireValidationError::InvalidXwingKemOutput)
        );
    }

    for ciphertext_length in [0, 15] {
        let mut envelope = TestWelcomeEnvelope::tls_deserialize_exact(&fixture.welcome)
            .expect("parse generated Welcome into RFC wire mirror");
        envelope.welcome.secrets[0]
            .encrypted_group_secrets
            .ciphertext = vec![0xA5; ciphertext_length].into();
        assert_eq!(
            validate_welcome(
                &envelope
                    .tls_serialize_detached()
                    .expect("serialize short Welcome ciphertext"),
                MAX_WELCOME_WIRE_BYTES,
            ),
            Err(WireValidationError::InvalidHpkeCiphertext)
        );
    }
}

#[test]
fn malformed_wire_decoders_never_let_dependency_panics_escape() {
    let mut rng = StdRng::seed_from_u64(0x4341_5442_4952_4457);
    let expected_signature_key = [0_u8; 32];
    for wire_format in [
        WireFormat::PublicMessage,
        WireFormat::PrivateMessage,
        WireFormat::Welcome,
        WireFormat::GroupInfo,
        WireFormat::KeyPackage,
    ] {
        for case in 0..512 {
            let mut encoded = vec![0_u8; 4 + usize::try_from(rng.next_u32() % 2_048).unwrap()];
            rng.fill_bytes(&mut encoded);
            encoded[..2].copy_from_slice(&1_u16.to_be_bytes());
            encoded[2..4].copy_from_slice(&(wire_format as u16).to_be_bytes());
            let outcome = catch_unwind(AssertUnwindSafe(|| match wire_format {
                WireFormat::PublicMessage => {
                    let _ = validate_public_commit(&encoded, MAX_PUBLIC_MESSAGE_WIRE_BYTES);
                }
                WireFormat::PrivateMessage => {
                    let _ = validate_private_application(&encoded, MAX_PRIVATE_MESSAGE_WIRE_BYTES);
                }
                WireFormat::Welcome => {
                    let _ = validate_welcome(&encoded, MAX_WELCOME_WIRE_BYTES);
                }
                WireFormat::GroupInfo => {
                    let _ = validate_group_info(
                        &encoded,
                        GroupInfoValidationPolicy {
                            expected_basic_credential: b"did:plc:fuzz#device",
                            expected_signature_key: &expected_signature_key,
                            now_unix_seconds: 1_000,
                            max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                            max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                            max_members: 100,
                        },
                    );
                }
                WireFormat::KeyPackage => {
                    let _ = validate_key_package(
                        &encoded,
                        KeyPackageValidationPolicy {
                            expected_basic_credential: b"did:plc:fuzz#device",
                            expected_signature_key: &expected_signature_key,
                            now_unix_seconds: 1_000,
                            max_bytes: MAX_KEY_PACKAGE_WIRE_BYTES,
                        },
                    );
                }
            }));
            assert!(
                outcome.is_ok(),
                "wire format {} case {case} escaped as a panic",
                wire_format as u16
            );
        }
    }
}

#[test]
fn all_visible_group_ids_must_be_exactly_32_bytes() {
    let fixture = coherent_wire_fixture_with_group_id(&[0x42; 31]);

    assert_eq!(
        validate_group_info(&fixture.genesis_group_info, group_info_policy(&fixture))
            .expect_err("short GroupInfo group ID must fail"),
        WireValidationError::WrongGroupIdLength { actual: 31 }
    );
    assert_eq!(
        validate_public_commit(&fixture.public_add_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .expect_err("short public Commit group ID must fail"),
        WireValidationError::WrongGroupIdLength { actual: 31 }
    );
    assert_eq!(
        validate_private_application(&fixture.private_application, MAX_PRIVATE_MESSAGE_WIRE_BYTES,)
            .expect_err("short private Application group ID must fail"),
        WireValidationError::WrongGroupIdLength { actual: 31 }
    );
}

#[test]
fn group_info_hashes_and_confirmation_tag_must_match_sha256_length() {
    let fixture = coherent_wire_fixture();
    let envelope = TestGroupInfoEnvelope::tls_deserialize_exact(&fixture.genesis_group_info)
        .expect("parse generated GroupInfo into RFC wire mirror");

    let mut malformed = envelope.clone();
    malformed.group_info.context.tree_hash = vec![0x11; 31].into();
    let bytes = malformed
        .tls_serialize_detached()
        .expect("serialize short tree hash");
    assert_eq!(
        validate_group_info(&bytes, group_info_policy(&fixture))
            .expect_err("short tree hash must fail"),
        WireValidationError::WrongTreeHashLength { actual: 31 }
    );

    let mut malformed = envelope;
    malformed.group_info.confirmation_tag = vec![0x33; 31].into();
    let bytes = malformed
        .tls_serialize_detached()
        .expect("serialize short confirmation tag");
    assert_eq!(
        validate_group_info(&bytes, group_info_policy(&fixture))
            .expect_err("short GroupInfo confirmation tag must fail"),
        WireValidationError::WrongConfirmationTagLength { actual: 31 }
    );
}

#[test]
fn group_info_rejects_wrong_suite_extensions_signer_identity_and_limits() {
    let fixture = coherent_wire_fixture();

    let mut wrong_suite = TestGroupInfoEnvelope::tls_deserialize_exact(&fixture.genesis_group_info)
        .expect("parse generated GroupInfo into RFC wire mirror");
    wrong_suite.group_info.context.ciphersuite = 1;
    assert_eq!(
        validate_group_info(
            &wrong_suite
                .tls_serialize_detached()
                .expect("serialize wrong-suite GroupInfo"),
            group_info_policy(&fixture),
        )
        .expect_err("wrong suite must fail before signature use"),
        WireValidationError::UnsupportedCiphersuite { actual: 1 }
    );

    let mut missing_external_pub =
        TestGroupInfoEnvelope::tls_deserialize_exact(&fixture.genesis_group_info)
            .expect("parse generated GroupInfo into RFC wire mirror");
    assert_eq!(
        missing_external_pub.group_info.extensions[1].extension_type,
        4
    );
    missing_external_pub.group_info.extensions.pop();
    assert_eq!(
        validate_group_info(
            &missing_external_pub
                .tls_serialize_detached()
                .expect("serialize missing-extension GroupInfo"),
            group_info_policy(&fixture),
        )
        .expect_err("missing ExternalPub must fail"),
        WireValidationError::UnsupportedGroupInfoExtensions
    );

    let wrong_signer =
        SignatureKeyPair::new(XWING_CIPHERSUITE.signature_algorithm()).expect("wrong signer");
    assert_eq!(
        validate_group_info(
            &fixture.genesis_group_info,
            GroupInfoValidationPolicy {
                expected_signature_key: &wrong_signer.to_public_vec(),
                ..group_info_policy(&fixture)
            },
        )
        .expect_err("foreign GroupInfo signer must fail"),
        WireValidationError::WrongGroupInfoSigner
    );
    assert_eq!(
        validate_group_info(
            &fixture.genesis_group_info,
            GroupInfoValidationPolicy {
                expected_basic_credential: b"did:plc:mallory#phone",
                ..group_info_policy(&fixture)
            },
        )
        .expect_err("foreign GroupInfo credential must fail"),
        WireValidationError::WrongGroupInfoCredential
    );

    assert!(matches!(
        validate_group_info(
            &fixture.genesis_group_info,
            GroupInfoValidationPolicy {
                max_ratchet_tree_bytes: 1,
                ..group_info_policy(&fixture)
            },
        ),
        Err(WireValidationError::RatchetTreeTooLarge { maximum: 1, .. })
    ));
    assert_eq!(
        validate_group_info(
            &fixture.genesis_group_info,
            GroupInfoValidationPolicy {
                max_members: 0,
                ..group_info_policy(&fixture)
            },
        )
        .expect_err("zero member budget must fail"),
        WireValidationError::InvalidLimit
    );
}

#[test]
fn all_artifacts_reject_alternate_wrappers_trailing_bytes_and_truncation() {
    let fixture = coherent_wire_fixture();

    assert!(matches!(
        validate_group_info(&fixture.welcome, group_info_policy(&fixture)),
        Err(WireValidationError::WrongWireFormat { actual, .. })
            if actual == WireFormat::Welcome as u16
    ));
    assert!(matches!(
        validate_welcome(&fixture.genesis_group_info, MAX_WELCOME_WIRE_BYTES),
        Err(WireValidationError::WrongWireFormat { actual, .. })
            if actual == WireFormat::GroupInfo as u16
    ));
    assert!(matches!(
        validate_public_commit(
            &fixture.private_application,
            MAX_PUBLIC_MESSAGE_WIRE_BYTES,
        ),
        Err(WireValidationError::WrongWireFormat { actual, .. })
            if actual == WireFormat::PrivateMessage as u16
    ));
    assert!(matches!(
        validate_private_application(
            &fixture.public_add_commit,
            MAX_PRIVATE_MESSAGE_WIRE_BYTES,
        ),
        Err(WireValidationError::WrongWireFormat { actual, .. })
            if actual == WireFormat::PublicMessage as u16
    ));

    let mut group_info_trailing = fixture.genesis_group_info.clone();
    group_info_trailing.push(0);
    assert_eq!(
        validate_group_info(&group_info_trailing, group_info_policy(&fixture))
            .expect_err("GroupInfo trailing byte must fail"),
        WireValidationError::TrailingData
    );
    let mut commit_truncated = fixture.public_add_commit.clone();
    commit_truncated.pop();
    assert_eq!(
        validate_public_commit(&commit_truncated, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .expect_err("Commit truncation must fail"),
        WireValidationError::Truncated
    );
    let mut welcome_trailing = fixture.welcome.clone();
    welcome_trailing.push(0);
    assert_eq!(
        validate_welcome(&welcome_trailing, MAX_WELCOME_WIRE_BYTES),
        Err(WireValidationError::TrailingData)
    );
    let mut private_truncated = fixture.private_application.clone();
    private_truncated.pop();
    assert_eq!(
        validate_private_application(&private_truncated, MAX_PRIVATE_MESSAGE_WIRE_BYTES),
        Err(WireValidationError::Truncated)
    );
}

#[test]
fn welcome_rejects_wrong_ciphersuite() {
    let fixture = coherent_wire_fixture();
    let mut wrong_suite = fixture.welcome;
    wrong_suite[4..6].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(
        validate_welcome(&wrong_suite, MAX_WELCOME_WIRE_BYTES),
        Err(WireValidationError::UnsupportedCiphersuite { actual: 1 })
    );
}

#[test]
fn public_commit_and_private_application_reject_wrong_content_types() {
    let (public_proposal, private_commit) = wrong_content_type_artifacts();

    assert!(matches!(
        validate_public_commit(&public_proposal, MAX_PUBLIC_MESSAGE_WIRE_BYTES),
        Err(WireValidationError::WrongContentType {
            expected: ContentType::Commit,
            actual: ContentType::Proposal,
        })
    ));
    assert!(matches!(
        validate_private_application(&private_commit, MAX_PRIVATE_MESSAGE_WIRE_BYTES),
        Err(WireValidationError::WrongContentType {
            expected: ContentType::Application,
            actual: ContentType::Commit,
        })
    ));
}

#[test]
fn public_commit_rejects_real_new_member_external_commit_sender() {
    let external_commit = external_commit_wire();
    let parsed = MlsMessageIn::tls_deserialize_exact(&external_commit)
        .expect("parse generated external Commit");
    let MlsMessageBodyIn::PublicMessage(message) = parsed.extract() else {
        panic!("external Commit must be a PublicMessage");
    };
    assert_eq!(message.content_type(), ContentType::Commit);
    assert_eq!(message.sender(), &Sender::NewMemberCommit);

    assert_eq!(
        validate_public_commit(&external_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .expect_err("clean protocol must reject a structurally valid signed external Commit"),
        WireValidationError::NonMemberCommitSender
    );
}
