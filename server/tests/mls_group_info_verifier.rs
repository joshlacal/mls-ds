use catbird_server::mls_group_info_verifier::{
    verify_group_info, ExpectedGroupInfoSigner, GroupInfoAssurance, GroupInfoVerificationError,
    GroupInfoVerifierLimits,
};
use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
use openmls::test_utils::frankenstein::{
    FrankenExtension, FrankenMlsMessage, FrankenMlsMessageBody, FrankenNode,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use std::sync::{Arc, Barrier};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct Fixture {
    bytes: Vec<u8>,
    signer_key: Vec<u8>,
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
    let bob_credential = CredentialWithKey {
        credential: BasicCredential::new(b"did:plc:bob".to_vec()).into(),
        signature_key: bob_signer.to_public_vec().into(),
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
    if !duplicate_signature_key {
        return Fixture {
            bytes: message
                .tls_serialize_detached()
                .expect("serialize two-member fixture"),
            signer_key: alice_signer.to_public_vec(),
        };
    }

    let mut franken: FrankenMlsMessage = message.into();
    let group_info = match &mut franken.body {
        FrankenMlsMessageBody::GroupInfo(group_info) => group_info,
        _ => panic!("expected GroupInfo"),
    };
    let ratchet_tree = group_info
        .extensions
        .iter_mut()
        .find_map(|extension| match extension {
            FrankenExtension::RatchetTree(tree) => Some(tree),
            _ => None,
        })
        .expect("ratchet tree extension");
    let alice_key = match ratchet_tree.ratchet_tree[0].as_ref().expect("alice leaf") {
        FrankenNode::LeafNode(leaf) => leaf.signature_key.clone(),
        _ => panic!("alice leaf node"),
    };
    let bob_leaf = match ratchet_tree.ratchet_tree[2].as_mut().expect("bob leaf") {
        FrankenNode::LeafNode(leaf) => leaf,
        _ => panic!("bob leaf node"),
    };
    bob_leaf.signature_key = alice_key;
    bob_leaf.resign(None, &alice_signer);

    Fixture {
        bytes: franken
            .tls_serialize_detached()
            .expect("serialize duplicate-key fixture"),
        signer_key: alice_signer.to_public_vec(),
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
    assert_invalid_public_state(
        verify_group_info(
            &bytes,
            &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
            GroupInfoVerifierLimits::default(),
        )
        .expect_err("signature bitflip must fail"),
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
    assert_invalid_public_state(
        verify_group_info(
            &bytes,
            &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
            GroupInfoVerifierLimits::default(),
        )
        .expect_err("tree hash bitflip must fail"),
    );
}

#[test]
fn wrong_expected_signer_is_rejected_after_public_state_verification() {
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
    assert_invalid_public_state(
        verify_group_info(
            &fixture.bytes,
            &ExpectedGroupInfoSigner::by_signature_key(&fixture.signer_key),
            GroupInfoVerifierLimits::default(),
        )
        .expect_err("duplicate member keys must fail"),
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
