use std::{fs, path::PathBuf};

use catbird_server::chat_protocol::snapshot::{
    decode_public_group_snapshot, encode_public_group_snapshot, public_group_snapshot_binding,
    public_group_snapshot_sha256, PublicGroupSnapshotBinding, PublicGroupSnapshotError,
    PublicGroupSnapshotLeaf, PublicGroupSnapshotLifecycle, PublicGroupSnapshotTreeSummary,
    MAX_PROTOCOL_INTEGER, MAX_PUBLIC_GROUP_SNAPSHOT_BYTES, MAX_SNAPSHOT_KEY_BYTES,
    MAX_SNAPSHOT_VALUE_BYTES,
};
use openmls::prelude::{
    tls_codec::Serialize as TlsSerialize, BasicCredential, Capabilities, Ciphersuite,
    CredentialType, CredentialWithKey, GroupId, KeyPackage, Lifetime, MlsGroup,
    MlsGroupCreateConfig, ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use tls_codec::Deserialize as _;

const MAGIC: &[u8; 8] = b"CBPGSNAP";
const SCHEMA: u16 = 2;
const TEST_ALICE_CREDENTIAL: &[u8] = b"did:web:a.co#00000000-0000-4000-8000-000000000001";
const TEST_BOB_CREDENTIAL: &[u8] = b"did:web:b.co#00000000-0000-4000-8000-000000000002";
#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupInfoEnvelope {
    group_info: TestGroupInfo,
    signature: tls_codec::VLBytes,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupInfo {
    context: TestGroupContext,
    extensions: Vec<TestExtension>,
    confirmation_tag: tls_codec::VLBytes,
    signer: u32,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestGroupContext {
    protocol_version: u16,
    ciphersuite: u16,
    group_id: tls_codec::VLBytes,
    epoch: u64,
    tree_hash: tls_codec::VLBytes,
    confirmed_transcript_hash: tls_codec::VLBytes,
    extensions: Vec<TestExtension>,
}

#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct TestExtension {
    extension_type: u16,
    extension_data: tls_codec::VLBytes,
}
const OPENMLS_VERSION: &[u8] = b"0.9.0-rc.3";
const STORAGE_VERSION: &[u8] = b"0.6.0-rc.3";
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustedCorpusIdentifiers {
    conversation_id_hex: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustedCorpusChain {
    generation: u64,
    genesis_state_version: u64,
    genesis_epoch: u64,
    genesis_group_context_hash_hex: String,
    genesis_confirmation_tag_hex: String,
    committed_state_version: u64,
    committed_epoch: u64,
    committed_group_context_hash_hex: String,
    committed_confirmation_tag_hex: String,
    group_id_hex: String,
}

#[derive(serde::Deserialize)]
struct TrustedCorpusManifest {
    identifiers: TrustedCorpusIdentifiers,
    chain: TrustedCorpusChain,
}

fn frozen_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_secs()
}
fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("valid test hex")
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N}-byte test value"))
}

fn trusted_corpus_manifest() -> TrustedCorpusManifest {
    serde_json::from_slice(&corpus_file("manifest.json")).expect("trusted corpus manifest")
}

fn trusted_conversation_id() -> [u8; 16] {
    hex_array(&trusted_corpus_manifest().identifiers.conversation_id_hex)
}

fn trusted_group_id() -> [u8; 32] {
    hex_array(&trusted_corpus_manifest().chain.group_id_hex)
}

fn exact_test_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}
struct Schema2Fixture {
    state: catbird_server::chat_protocol::snapshot::PublicGroupState,
    encoded: Vec<u8>,
    binding: PublicGroupSnapshotBinding,
    raw: RawSnapshot,
}

fn create_schema2_fixtures() -> (Schema2Fixture, Schema2Fixture) {
    let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
    let alice_signer = SignatureKeyPair::new(
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519.signature_algorithm(),
    )
    .expect("alice signer");
    alice_signer
        .store(provider.storage())
        .expect("store alice signer");
    let alice_signature_key = alice_signer.to_public_vec();
    let now = frozen_now();
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(exact_test_capabilities())
        .lifetime(Lifetime::init(now - 60, now + 3600))
        .build();
    let mut group = MlsGroup::new_with_group_id(
        &provider,
        &alice_signer,
        &config,
        GroupId::from_slice(trusted_group_id().as_slice()),
        CredentialWithKey {
            credential: BasicCredential::new(TEST_ALICE_CREDENTIAL.to_vec()).into(),
            signature_key: alice_signature_key.clone().into(),
        },
    )
    .expect("create genesis group");
    let genesis_group_info_bytes = group
        .export_group_info(provider.crypto(), &alice_signer, true)
        .expect("export GroupInfo")
        .tls_serialize_detached()
        .expect("serialize GroupInfo");
    let genesis_validated = catbird_server::chat_protocol::wire::validate_group_info(
        &genesis_group_info_bytes,
        catbird_server::chat_protocol::wire::GroupInfoValidationPolicy {
            expected_basic_credential: TEST_ALICE_CREDENTIAL,
            expected_signature_key: &alice_signature_key,
            now_unix_seconds: now,
            max_bytes: catbird_server::chat_protocol::wire::MAX_GROUP_INFO_WIRE_BYTES,
            max_ratchet_tree_bytes: 786_432,
            max_members: 1,
        },
    )
    .expect("validate genesis group info");
    let genesis_group_context_hash = *genesis_validated.group_context_hash();
    let genesis_confirmation_tag = *genesis_validated.confirmation_tag();
    let genesis_state = genesis_validated.into_public_state();
    let genesis_encoded =
        encode_public_group_snapshot(&genesis_state).expect("encode schema 2 snapshot");
    let genesis_coordinate =
        catbird_server::chat_protocol::snapshot::PublicGroupSnapshotCoordinate::new(
            trusted_conversation_id(),
            0,
            0,
            trusted_group_id(),
            0,
            genesis_group_context_hash,
            genesis_confirmation_tag,
            PublicGroupSnapshotLifecycle::Active,
        );
    let genesis_binding =
        public_group_snapshot_binding(&genesis_state, &genesis_encoded, &genesis_coordinate)
            .expect("bind schema 2 snapshot");
    let genesis_raw = parse_valid_snapshot(&genesis_encoded);
    let genesis_fixture = Schema2Fixture {
        state: genesis_state,
        encoded: genesis_encoded,
        binding: genesis_binding,
        raw: genesis_raw,
    };

    let bob_signer = SignatureKeyPair::new(
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519.signature_algorithm(),
    )
    .expect("bob signer");
    bob_signer
        .store(provider.storage())
        .expect("store bob signer");
    let bob_package = KeyPackage::builder()
        .leaf_node_capabilities(exact_test_capabilities())
        .key_package_lifetime(Lifetime::init(now - 60, now + 3600))
        .build(
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            &provider,
            &bob_signer,
            CredentialWithKey {
                credential: BasicCredential::new(TEST_BOB_CREDENTIAL.to_vec()).into(),
                signature_key: bob_signer.to_public_vec().into(),
            },
        )
        .expect("build bob package")
        .key_package()
        .clone();
    let (commit, _, _) = group
        .add_members(&provider, &alice_signer, &[bob_package])
        .expect("add bob");
    let commit_bytes = commit.tls_serialize_detached().expect("serialize commit");
    group
        .merge_pending_commit(&provider)
        .expect("merge commit into group");
    let validated_commit = catbird_server::chat_protocol::wire::validate_public_commit(
        &commit_bytes,
        catbird_server::chat_protocol::wire::MAX_PUBLIC_MESSAGE_WIRE_BYTES,
    )
    .expect("validate commit");

    let committed_group_info_bytes = group
        .export_group_info(provider.crypto(), &alice_signer, true)
        .expect("export GroupInfo")
        .tls_serialize_detached()
        .expect("serialize GroupInfo");
    let envelope = TestGroupInfoEnvelope::tls_deserialize_exact(&committed_group_info_bytes[4..])
        .expect("deserialize TestGroupInfoEnvelope");
    let group_context_bytes = envelope
        .group_info
        .context
        .tls_serialize_detached()
        .expect("serialize group context");
    let committed_group_context_hash: [u8; 32] = Sha256::digest(&group_context_bytes).into();
    let committed_confirmation_tag: [u8; 32] = envelope
        .group_info
        .confirmation_tag
        .as_slice()
        .try_into()
        .expect("confirmation tag");

    let next_coord = catbird_server::chat_protocol::snapshot::PublicGroupSnapshotCoordinate::new(
        trusted_conversation_id(),
        0,
        1,
        trusted_group_id(),
        1,
        committed_group_context_hash,
        committed_confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    );
    let processed = catbird_server::chat_protocol::wire::process_public_commit(
        &genesis_fixture.state,
        validated_commit,
        catbird_server::chat_protocol::wire::PublicCommitValidationPolicy {
            expected_aad: b"",
            trusted_prior_binding: &genesis_fixture.binding,
            expected_next_coordinate: &next_coord,
            now_unix_seconds: now,
            max_members: 10,
        },
    )
    .expect("process public commit");
    let committed_state = processed.into_next_state();
    let committed_encoded =
        encode_public_group_snapshot(&committed_state).expect("encode committed snapshot");
    let committed_binding =
        public_group_snapshot_binding(&committed_state, &committed_encoded, &next_coord)
            .expect("bind committed snapshot");
    let committed_raw = parse_valid_snapshot(&committed_encoded);
    let committed_fixture = Schema2Fixture {
        state: committed_state,
        encoded: committed_encoded,
        binding: committed_binding,
        raw: committed_raw,
    };
    (genesis_fixture, committed_fixture)
}

fn create_schema2_genesis_fixture() -> Schema2Fixture {
    create_schema2_fixtures().0
}

fn create_schema2_committed_fixture() -> Schema2Fixture {
    create_schema2_fixtures().1
}
static GENESIS_FIXTURE: once_cell::sync::Lazy<Schema2Fixture> =
    once_cell::sync::Lazy::new(create_schema2_genesis_fixture);

fn raw_genesis() -> RawSnapshot {
    GENESIS_FIXTURE.raw.clone()
}

fn decode_genesis(
    encoded: &[u8],
) -> Result<catbird_server::chat_protocol::snapshot::PublicGroupState, PublicGroupSnapshotError> {
    let trusted = &GENESIS_FIXTURE.binding;
    let binding = PublicGroupSnapshotBinding::new(
        *trusted.conversation_id(),
        trusted.generation(),
        trusted.state_version(),
        *trusted.group_id(),
        trusted.epoch(),
        *trusted.group_context_hash(),
        *trusted.confirmation_tag(),
        trusted.lifecycle(),
        public_group_snapshot_sha256(encoded),
        trusted.tree_summary().clone(),
    );
    decode_public_group_snapshot(encoded, &binding)
}

#[derive(Clone)]
struct RawSnapshot {
    magic: [u8; 8],
    schema: u16,
    openmls_version: Vec<u8>,
    storage_version: Vec<u8>,
    records: Vec<(Vec<u8>, Vec<u8>)>,
}

fn corpus_file(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/crypto-wire")
        .join(name);
    fs::read(path).expect("read frozen crypto-wire corpus artifact")
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> &'a [u8] {
    let end = offset.checked_add(length).expect("test snapshot offset");
    let value = bytes.get(*offset..end).expect("valid test snapshot");
    *offset = end;
    value
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> u16 {
    u16::from_be_bytes(take(bytes, offset, 2).try_into().expect("two bytes"))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> u32 {
    u32::from_be_bytes(take(bytes, offset, 4).try_into().expect("four bytes"))
}

fn parse_valid_snapshot(bytes: &[u8]) -> RawSnapshot {
    let mut offset = 0;
    let magic = take(bytes, &mut offset, 8)
        .try_into()
        .expect("eight-byte magic");
    let schema = take_u16(bytes, &mut offset);
    let openmls_version_len = usize::from(take_u16(bytes, &mut offset));
    let openmls_version = take(bytes, &mut offset, openmls_version_len).to_vec();
    let storage_version_len = usize::from(take_u16(bytes, &mut offset));
    let storage_version = take(bytes, &mut offset, storage_version_len).to_vec();
    let count = usize::try_from(take_u32(bytes, &mut offset)).expect("record count");
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let key_len = usize::try_from(take_u32(bytes, &mut offset)).expect("key length");
        let key = take(bytes, &mut offset, key_len).to_vec();
        let value_len = usize::try_from(take_u32(bytes, &mut offset)).expect("value length");
        let value = take(bytes, &mut offset, value_len).to_vec();
        records.push((key, value));
    }
    assert_eq!(offset, bytes.len(), "fixture is an exact snapshot");
    RawSnapshot {
        magic,
        schema,
        openmls_version,
        storage_version,
        records,
    }
}

fn json_bytes(value: &serde_json::Value) -> Vec<u8> {
    value
        .as_array()
        .expect("trusted fixture byte array")
        .iter()
        .map(|byte| {
            u8::try_from(byte.as_u64().expect("trusted fixture byte")).expect("trusted fixture u8")
        })
        .collect()
}

fn trusted_tree_summary(encoded: &[u8]) -> PublicGroupSnapshotTreeSummary {
    let raw = parse_valid_snapshot(encoded);
    let group_context = raw
        .records
        .iter()
        .find(|(key, _)| key.starts_with(b"GroupContext"))
        .map(|(_, value)| serde_json::from_slice::<serde_json::Value>(value).expect("GroupContext"))
        .expect("GroupContext record");
    let tree_hash: [u8; 32] = json_bytes(&group_context["tree_hash"]["vec"])
        .try_into()
        .expect("trusted 32-byte tree hash");
    let tree = raw
        .records
        .iter()
        .find(|(key, _)| key.starts_with(b"Tree"))
        .map(|(_, value)| serde_json::from_slice::<serde_json::Value>(value).expect("Tree"))
        .expect("Tree record");
    let leaves = tree["tree"]["leaf_nodes"]
        .as_array()
        .expect("trusted leaf array")
        .iter()
        .enumerate()
        .filter_map(|(leaf_index, stored)| {
            let node = stored.get("node")?;
            if node.is_null() {
                return None;
            }
            let payload = &node["payload"];
            assert_eq!(payload["credential"]["credential_type"], "Basic");
            Some(PublicGroupSnapshotLeaf::new(
                u32::try_from(leaf_index).expect("trusted leaf index"),
                json_bytes(&payload["credential"]["serialized_credential_content"]["vec"]),
                json_bytes(&payload["signature_key"]["value"]["vec"]),
                json_bytes(&payload["encryption_key"]["key"]["vec"]),
            ))
        })
        .collect();
    PublicGroupSnapshotTreeSummary::new(tree_hash, leaves)
}

fn push_u16_len(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(
        &u16::try_from(value.len())
            .expect("test u16 length")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}

fn encode_raw_snapshot(snapshot: &RawSnapshot) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&snapshot.magic);
    output.extend_from_slice(&snapshot.schema.to_be_bytes());
    push_u16_len(&mut output, &snapshot.openmls_version);
    push_u16_len(&mut output, &snapshot.storage_version);
    output.extend_from_slice(
        &u32::try_from(snapshot.records.len())
            .expect("test record count")
            .to_be_bytes(),
    );
    for (key, value) in &snapshot.records {
        output.extend_from_slice(
            &u32::try_from(key.len())
                .expect("test key length")
                .to_be_bytes(),
        );
        output.extend_from_slice(key);
        output.extend_from_slice(
            &u32::try_from(value.len())
                .expect("test value length")
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
    }
    output
}

fn header_with_count(count: u32) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&SCHEMA.to_be_bytes());
    push_u16_len(&mut output, OPENMLS_VERSION);
    push_u16_len(&mut output, STORAGE_VERSION);
    output.extend_from_slice(&count.to_be_bytes());
    output
}

#[test]
fn frozen_public_group_snapshots_load_and_round_trip_canonically() {
    let genesis = create_schema2_genesis_fixture();
    let committed = create_schema2_committed_fixture();

    for fixture in [&genesis, &committed] {
        let state = decode_public_group_snapshot(&fixture.encoded, &fixture.binding)
            .expect("load schema 2 public snapshot into a fresh provider");
        assert_eq!(
            state.public_group().group_id().as_slice(),
            trusted_group_id()
        );
        assert_eq!(
            state.public_group().group_context().epoch().as_u64(),
            fixture.binding.epoch()
        );
        assert_eq!(
            encode_public_group_snapshot(&state).expect("re-encode public state"),
            fixture.encoded,
            "snapshot encoding must be deterministic and exact"
        );
        assert_eq!(
            public_group_snapshot_binding(&state, &fixture.encoded, fixture.binding.coordinate())
                .expect("bind exact state to separately trusted coordinate"),
            fixture.binding
        );
    }

    // Historical schema-1 / OpenMLS 0.8.1 snapshots must be strictly rejected
    for legacy_filename in ["genesis-public-state.bin", "committed-public-state.bin"] {
        let legacy_bytes = corpus_file(legacy_filename);
        let dummy_binding = PublicGroupSnapshotBinding::new(
            trusted_conversation_id(),
            0,
            0,
            trusted_group_id(),
            0,
            [0x11; 32],
            [0x22; 32],
            PublicGroupSnapshotLifecycle::Active,
            public_group_snapshot_sha256(&legacy_bytes),
            genesis.binding.tree_summary().clone(),
        );
        let err = decode_public_group_snapshot(&legacy_bytes, &dummy_binding)
            .expect_err("legacy schema 1 snapshot must be rejected");
        assert_eq!(
            err,
            PublicGroupSnapshotError::UnsupportedSchema { actual: 1 }
        );
    }
}

#[test]
fn snapshot_rejects_wrong_magic_schema_and_dependency_versions() {
    let mut malformed = raw_genesis();
    malformed.magic = *b"NOTSNAP!";
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("wrong magic"),
        PublicGroupSnapshotError::InvalidMagic
    );

    let mut malformed = raw_genesis();
    malformed.schema = 1;
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("schema 1 rejected"),
        PublicGroupSnapshotError::UnsupportedSchema { actual: 1 }
    );

    let mut malformed = raw_genesis();
    malformed.schema = 3;
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("schema 3 rejected"),
        PublicGroupSnapshotError::UnsupportedSchema { actual: 3 }
    );

    let mut malformed = raw_genesis();
    malformed.openmls_version = b"0.8.1".to_vec();
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("0.8.1 OpenMLS version"),
        PublicGroupSnapshotError::UnsupportedOpenMlsVersion
    );

    let mut malformed = raw_genesis();
    malformed.openmls_version = b"0.9.0".to_vec();
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("0.9.0 OpenMLS version"),
        PublicGroupSnapshotError::UnsupportedOpenMlsVersion
    );

    let mut malformed = raw_genesis();
    malformed.storage_version = b"0.5.0".to_vec();
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("0.5.0 storage version"),
        PublicGroupSnapshotError::UnsupportedStorageVersion
    );

    let mut malformed = raw_genesis();
    malformed.storage_version = b"0.6.0".to_vec();
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("0.6.0 storage version"),
        PublicGroupSnapshotError::UnsupportedStorageVersion
    );
}
#[test]
fn snapshot_envelope_count_is_bounded_and_public_state_is_exactly_four_records() {
    assert_eq!(
        decode_genesis(&header_with_count(0)).expect_err("empty envelope"),
        PublicGroupSnapshotError::InvalidEnvelopeRecordCount {
            actual: 0,
            maximum: 256,
        }
    );
    assert_eq!(
        decode_genesis(&header_with_count(257)).expect_err("unbounded envelope"),
        PublicGroupSnapshotError::InvalidEnvelopeRecordCount {
            actual: 257,
            maximum: 256,
        }
    );

    let mut malformed = raw_genesis();
    malformed.records.truncate(3);
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("incomplete public record set"),
        PublicGroupSnapshotError::WrongPublicRecordCount {
            actual: 3,
            expected: 4,
        }
    );
}

#[test]
fn snapshot_rejects_unsorted_duplicate_secret_and_foreign_group_keys() {
    let mut malformed = raw_genesis();
    malformed.records.swap(0, 1);
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("unsorted keys"),
        PublicGroupSnapshotError::RecordsNotStrictlySorted
    );

    let mut malformed = raw_genesis();
    malformed.records[1].0 = malformed.records[0].0.clone();
    malformed
        .records
        .sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("duplicate key"),
        PublicGroupSnapshotError::RecordsNotStrictlySorted
    );

    let mut malformed = raw_genesis();
    malformed.records[0].0 = b"KeyPackage-secret-material\0\x01".to_vec();
    malformed
        .records
        .sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed))
            .expect_err("secret-bearing storage record"),
        PublicGroupSnapshotError::UnexpectedPublicRecordKey
    );

    let mut malformed = raw_genesis();
    let group_key_byte = malformed.records[0].0.len() - 3;
    malformed.records[0].0[group_key_byte] ^= 0x01;
    malformed
        .records
        .sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("record key for another group"),
        PublicGroupSnapshotError::UnexpectedPublicRecordKey
    );
}

#[test]
fn snapshot_rejects_invalid_lengths_truncation_trailing_data_and_whole_file_overflow() {
    let mut malformed = raw_genesis();
    malformed.records[0].0.clear();
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("empty key"),
        PublicGroupSnapshotError::InvalidKeyLength { actual: 0 }
    );

    let genesis_fixture = create_schema2_genesis_fixture();
    const HEADER_LEN: usize =
        MAGIC.len() + 2 + 2 + OPENMLS_VERSION.len() + 2 + STORAGE_VERSION.len() + 4;
    let mut encoded = genesis_fixture.encoded.clone();
    encoded[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(
        &u32::try_from(MAX_SNAPSHOT_KEY_BYTES + 1)
            .expect("key cap")
            .to_be_bytes(),
    );
    assert_eq!(
        decode_genesis(&encoded).expect_err("oversized key"),
        PublicGroupSnapshotError::InvalidKeyLength {
            actual: MAX_SNAPSHOT_KEY_BYTES + 1,
        }
    );

    let encoded = genesis_fixture.encoded.clone();
    let first_key_len = usize::try_from(u32::from_be_bytes(
        encoded[HEADER_LEN..HEADER_LEN + 4]
            .try_into()
            .expect("first key length"),
    ))
    .expect("key length usize");
    let first_value_len_offset = HEADER_LEN + 4 + first_key_len;
    let mut malformed = encoded.clone();
    malformed[first_value_len_offset..first_value_len_offset + 4]
        .copy_from_slice(&0_u32.to_be_bytes());
    assert_eq!(
        decode_genesis(&malformed).expect_err("empty value"),
        PublicGroupSnapshotError::InvalidValueLength { actual: 0 }
    );

    let mut malformed = encoded.clone();
    malformed[first_value_len_offset..first_value_len_offset + 4].copy_from_slice(
        &u32::try_from(MAX_SNAPSHOT_VALUE_BYTES + 1)
            .expect("value cap")
            .to_be_bytes(),
    );
    assert_eq!(
        decode_genesis(&malformed).expect_err("oversized value"),
        PublicGroupSnapshotError::InvalidValueLength {
            actual: MAX_SNAPSHOT_VALUE_BYTES + 1,
        }
    );

    assert_eq!(
        decode_genesis(&[]).expect_err("empty snapshot"),
        PublicGroupSnapshotError::Empty
    );
    for prefix_len in 1..encoded.len() {
        assert!(
            decode_genesis(&encoded[..prefix_len]).is_err(),
            "truncated prefix of length {prefix_len} was accepted"
        );
    }

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        decode_genesis(&trailing).expect_err("trailing byte"),
        PublicGroupSnapshotError::TrailingData
    );

    let oversized = vec![0_u8; MAX_PUBLIC_GROUP_SNAPSHOT_BYTES + 1];
    assert_eq!(
        decode_genesis(&oversized).expect_err("oversized file"),
        PublicGroupSnapshotError::InputTooLarge {
            actual: MAX_PUBLIC_GROUP_SNAPSHOT_BYTES + 1,
            maximum: MAX_PUBLIC_GROUP_SNAPSHOT_BYTES,
        }
    );
}

#[test]
fn snapshot_rejects_corrupt_values_and_wrong_expected_group() {
    let mut malformed = raw_genesis();
    malformed.records[0].1[0] ^= 0xff;
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("corrupt stored OpenMLS value"),
        PublicGroupSnapshotError::InvalidStoredPublicGroup
    );

    let mut wrong_group_id = trusted_group_id();
    wrong_group_id[0] ^= 0x01;
    let genesis_fixture = create_schema2_genesis_fixture();
    let encoded = genesis_fixture.encoded;
    let correct = genesis_fixture.binding;
    let wrong_binding = PublicGroupSnapshotBinding::new(
        *correct.conversation_id(),
        correct.generation(),
        correct.state_version(),
        wrong_group_id,
        correct.epoch(),
        *correct.group_context_hash(),
        *correct.confirmation_tag(),
        correct.lifecycle(),
        *correct.snapshot_sha256(),
        correct.tree_summary().clone(),
    );
    assert_eq!(
        decode_public_group_snapshot(&encoded, &wrong_binding)
            .expect_err("wrong expected group id"),
        PublicGroupSnapshotError::UnexpectedPublicRecordKey
    );
}

#[test]
fn snapshot_requires_an_active_bounded_uuidv4_outer_coordinate() {
    let genesis_fixture = create_schema2_genesis_fixture();
    let encoded = genesis_fixture.encoded;
    let correct = genesis_fixture.binding;
    assert_eq!(correct.conversation_id(), &trusted_conversation_id());
    assert_eq!(correct.generation(), 0);
    assert_eq!(correct.state_version(), 0);
    assert_eq!(correct.lifecycle(), PublicGroupSnapshotLifecycle::Active);

    let binding = |conversation_id, generation, state_version, epoch, lifecycle| {
        PublicGroupSnapshotBinding::new(
            conversation_id,
            generation,
            state_version,
            trusted_group_id(),
            epoch,
            *correct.group_context_hash(),
            *correct.confirmation_tag(),
            lifecycle,
            *correct.snapshot_sha256(),
            correct.tree_summary().clone(),
        )
    };
    for (invalid, expected_error) in [
        (
            binding([0; 16], 0, 0, 0, PublicGroupSnapshotLifecycle::Active),
            PublicGroupSnapshotError::InvalidConversationId,
        ),
        (
            binding(
                trusted_conversation_id(),
                MAX_PROTOCOL_INTEGER + 1,
                0,
                0,
                PublicGroupSnapshotLifecycle::Active,
            ),
            PublicGroupSnapshotError::CoordinateIntegerOutOfRange,
        ),
        (
            binding(
                trusted_conversation_id(),
                0,
                MAX_PROTOCOL_INTEGER + 1,
                0,
                PublicGroupSnapshotLifecycle::Active,
            ),
            PublicGroupSnapshotError::CoordinateIntegerOutOfRange,
        ),
        (
            binding(
                trusted_conversation_id(),
                0,
                0,
                MAX_PROTOCOL_INTEGER + 1,
                PublicGroupSnapshotLifecycle::Active,
            ),
            PublicGroupSnapshotError::CoordinateIntegerOutOfRange,
        ),
        (
            binding(
                trusted_conversation_id(),
                0,
                0,
                0,
                PublicGroupSnapshotLifecycle::Superseded,
            ),
            PublicGroupSnapshotError::InactiveConversationState,
        ),
    ] {
        assert_eq!(
            decode_public_group_snapshot(&encoded, &invalid).expect_err("untrusted outer head"),
            expected_error
        );
    }
}

#[test]
fn snapshot_binding_rejects_digest_coordinate_stale_blob_and_record_splicing() {
    let genesis_fixture = create_schema2_genesis_fixture();
    let committed_fixture = create_schema2_committed_fixture();
    let genesis = genesis_fixture.encoded;
    let committed = committed_fixture.encoded;
    let genesis_binding = genesis_fixture.binding;
    let committed_binding = committed_fixture.binding;
    let genesis_state = genesis_fixture.state;

    assert_eq!(
        public_group_snapshot_binding(&genesis_state, &committed, genesis_binding.coordinate())
            .expect_err("bind bytes from another state"),
        PublicGroupSnapshotError::SnapshotStateMismatch
    );
    assert_eq!(
        public_group_snapshot_binding(&genesis_state, &genesis, committed_binding.coordinate())
            .expect_err("bind state under a different trusted MLS coordinate"),
        PublicGroupSnapshotError::SnapshotCoordinateMismatch
    );

    let mut tampered = genesis.clone();
    *tampered.last_mut().expect("nonempty snapshot") ^= 1;
    assert_eq!(
        decode_public_group_snapshot(&tampered, &genesis_binding).expect_err("digest mismatch"),
        PublicGroupSnapshotError::SnapshotDigestMismatch
    );
    assert_eq!(
        decode_public_group_snapshot(&genesis, &committed_binding)
            .expect_err("stale blob under the current binding"),
        PublicGroupSnapshotError::SnapshotDigestMismatch
    );

    for bad_binding in [
        PublicGroupSnapshotBinding::new(
            *genesis_binding.conversation_id(),
            genesis_binding.generation(),
            genesis_binding.state_version(),
            trusted_group_id(),
            1,
            *genesis_binding.group_context_hash(),
            *genesis_binding.confirmation_tag(),
            genesis_binding.lifecycle(),
            *genesis_binding.snapshot_sha256(),
            genesis_binding.tree_summary().clone(),
        ),
        PublicGroupSnapshotBinding::new(
            *genesis_binding.conversation_id(),
            genesis_binding.generation(),
            genesis_binding.state_version(),
            trusted_group_id(),
            0,
            [0xA5; 32],
            *genesis_binding.confirmation_tag(),
            genesis_binding.lifecycle(),
            *genesis_binding.snapshot_sha256(),
            genesis_binding.tree_summary().clone(),
        ),
        PublicGroupSnapshotBinding::new(
            *genesis_binding.conversation_id(),
            genesis_binding.generation(),
            genesis_binding.state_version(),
            trusted_group_id(),
            0,
            *genesis_binding.group_context_hash(),
            [0x5A; 32],
            genesis_binding.lifecycle(),
            *genesis_binding.snapshot_sha256(),
            genesis_binding.tree_summary().clone(),
        ),
    ] {
        assert_eq!(
            decode_public_group_snapshot(&genesis, &bad_binding).expect_err("wrong MLS coordinate"),
            PublicGroupSnapshotError::SnapshotCoordinateMismatch
        );
    }

    let genesis_raw = genesis_fixture.raw;
    let committed_raw = committed_fixture.raw;
    for record_index in 0..4 {
        let mut spliced = genesis_raw.clone();
        spliced.records[record_index].1 = committed_raw.records[record_index].1.clone();
        let spliced = encode_raw_snapshot(&spliced);
        assert_eq!(
            decode_public_group_snapshot(&spliced, &genesis_binding)
                .expect_err("same-group record splice"),
            PublicGroupSnapshotError::SnapshotDigestMismatch,
            "record {record_index} splice escaped the exact snapshot binding"
        );
    }
}

#[test]
fn snapshot_rejects_coordinate_consistent_stale_and_spliced_tree_summaries() {
    let genesis_fixture = create_schema2_genesis_fixture();
    let committed_fixture = create_schema2_committed_fixture();
    let correct = committed_fixture.binding.clone();
    let genesis_summary = genesis_fixture.binding.tree_summary().clone();
    let committed_summary = correct.tree_summary();
    assert_eq!(committed_summary.leaves().len(), 2);

    let bind = |summary| {
        PublicGroupSnapshotBinding::new(
            *correct.conversation_id(),
            correct.generation(),
            correct.state_version(),
            *correct.group_id(),
            correct.epoch(),
            *correct.group_context_hash(),
            *correct.confirmation_tag(),
            correct.lifecycle(),
            *correct.snapshot_sha256(),
            summary,
        )
    };
    let alice = committed_summary.leaves()[0].clone();
    let bob = committed_summary.leaves()[1].clone();

    let mut wrong_credential = bob.basic_credential().to_vec();
    wrong_credential.push(b'x');
    let mut wrong_signature_key = bob.signature_key().to_vec();
    wrong_signature_key[0] ^= 1;
    let extra_leaf = PublicGroupSnapshotLeaf::new(
        2,
        alice.basic_credential().to_vec(),
        alice.signature_key().to_vec(),
        alice.encryption_key().to_vec(),
    );
    let wrong_leaf_summaries = [
        (
            "stale missing leaf",
            PublicGroupSnapshotTreeSummary::new(
                *committed_summary.tree_hash(),
                vec![alice.clone()],
            ),
        ),
        (
            "wrong leaf index",
            PublicGroupSnapshotTreeSummary::new(
                *committed_summary.tree_hash(),
                vec![
                    alice.clone(),
                    PublicGroupSnapshotLeaf::new(
                        2,
                        bob.basic_credential().to_vec(),
                        bob.signature_key().to_vec(),
                        bob.encryption_key().to_vec(),
                    ),
                ],
            ),
        ),
        (
            "wrong BasicCredential bytes",
            PublicGroupSnapshotTreeSummary::new(
                *committed_summary.tree_hash(),
                vec![
                    alice.clone(),
                    PublicGroupSnapshotLeaf::new(
                        bob.leaf_index(),
                        wrong_credential,
                        bob.signature_key().to_vec(),
                        bob.encryption_key().to_vec(),
                    ),
                ],
            ),
        ),
        (
            "wrong signature key",
            PublicGroupSnapshotTreeSummary::new(
                *committed_summary.tree_hash(),
                vec![
                    alice.clone(),
                    PublicGroupSnapshotLeaf::new(
                        bob.leaf_index(),
                        bob.basic_credential().to_vec(),
                        wrong_signature_key,
                        bob.encryption_key().to_vec(),
                    ),
                ],
            ),
        ),
        (
            "stale encryption key spliced from genesis",
            PublicGroupSnapshotTreeSummary::new(
                *committed_summary.tree_hash(),
                vec![genesis_summary.leaves()[0].clone(), bob.clone()],
            ),
        ),
        (
            "wrong tree hash",
            PublicGroupSnapshotTreeSummary::new([0xA5; 32], vec![alice.clone(), bob.clone()]),
        ),
        (
            "extra shape-valid leaf",
            PublicGroupSnapshotTreeSummary::new(
                *committed_summary.tree_hash(),
                vec![alice, bob, extra_leaf],
            ),
        ),
    ];

    for (case, summary) in wrong_leaf_summaries {
        assert_eq!(
            decode_public_group_snapshot(&committed_fixture.encoded, &bind(summary))
                .expect_err("coordinate-consistent wrong tree summary"),
            PublicGroupSnapshotError::SnapshotTreeSummaryMismatch,
            "{case} escaped exact locked-head comparison"
        );
    }
}

#[test]
fn snapshot_rejects_noncanonical_locked_head_tree_summary_shape() {
    let committed_fixture = create_schema2_committed_fixture();
    let encoded = committed_fixture.encoded;
    let correct = committed_fixture.binding;
    let expected = correct.tree_summary();
    let alice = expected.leaves()[0].clone();
    let bob = expected.leaves()[1].clone();
    let bind = |summary| {
        PublicGroupSnapshotBinding::new(
            *correct.conversation_id(),
            correct.generation(),
            correct.state_version(),
            *correct.group_id(),
            correct.epoch(),
            *correct.group_context_hash(),
            *correct.confirmation_tag(),
            correct.lifecycle(),
            *correct.snapshot_sha256(),
            summary,
        )
    };

    let mut too_many = Vec::with_capacity(101);
    for leaf_index in 0_u32..101 {
        too_many.push(PublicGroupSnapshotLeaf::new(
            leaf_index,
            alice.basic_credential().to_vec(),
            alice.signature_key().to_vec(),
            alice.encryption_key().to_vec(),
        ));
    }
    let mut short_signature_key = bob.signature_key().to_vec();
    short_signature_key.pop();
    let mut short_encryption_key = bob.encryption_key().to_vec();
    short_encryption_key.pop();
    let mut noncanonical_encryption_key = bob.encryption_key().to_vec();
    *noncanonical_encryption_key
        .last_mut()
        .expect("XWing X25519 component") |= 0x80;
    let invalid = vec![
        (
            "empty summary",
            PublicGroupSnapshotTreeSummary::new(*expected.tree_hash(), vec![]),
        ),
        (
            "more than 100 leaves",
            PublicGroupSnapshotTreeSummary::new(*expected.tree_hash(), too_many),
        ),
        (
            "duplicate leaf index",
            PublicGroupSnapshotTreeSummary::new(
                *expected.tree_hash(),
                vec![
                    alice.clone(),
                    PublicGroupSnapshotLeaf::new(
                        alice.leaf_index(),
                        bob.basic_credential().to_vec(),
                        bob.signature_key().to_vec(),
                        bob.encryption_key().to_vec(),
                    ),
                ],
            ),
        ),
        (
            "out-of-order leaf indices",
            PublicGroupSnapshotTreeSummary::new(
                *expected.tree_hash(),
                vec![bob.clone(), alice.clone()],
            ),
        ),
        (
            "BasicCredential below the shortest DID plus device-id identity",
            PublicGroupSnapshotTreeSummary::new(
                *expected.tree_hash(),
                vec![PublicGroupSnapshotLeaf::new(
                    alice.leaf_index(),
                    vec![b'x'; 48],
                    alice.signature_key().to_vec(),
                    alice.encryption_key().to_vec(),
                )],
            ),
        ),
        (
            "BasicCredential above the exact DID plus device-id maximum",
            PublicGroupSnapshotTreeSummary::new(
                *expected.tree_hash(),
                vec![PublicGroupSnapshotLeaf::new(
                    alice.leaf_index(),
                    vec![b'x'; 299],
                    alice.signature_key().to_vec(),
                    alice.encryption_key().to_vec(),
                )],
            ),
        ),
        (
            "wrong signature-key length",
            PublicGroupSnapshotTreeSummary::new(
                *expected.tree_hash(),
                vec![PublicGroupSnapshotLeaf::new(
                    bob.leaf_index(),
                    bob.basic_credential().to_vec(),
                    short_signature_key,
                    bob.encryption_key().to_vec(),
                )],
            ),
        ),
        (
            "wrong XWing encryption-key length",
            PublicGroupSnapshotTreeSummary::new(
                *expected.tree_hash(),
                vec![PublicGroupSnapshotLeaf::new(
                    bob.leaf_index(),
                    bob.basic_credential().to_vec(),
                    bob.signature_key().to_vec(),
                    short_encryption_key,
                )],
            ),
        ),
        (
            "noncanonical XWing X25519 component",
            PublicGroupSnapshotTreeSummary::new(
                *expected.tree_hash(),
                vec![PublicGroupSnapshotLeaf::new(
                    bob.leaf_index(),
                    bob.basic_credential().to_vec(),
                    bob.signature_key().to_vec(),
                    noncanonical_encryption_key,
                )],
            ),
        ),
    ];

    for (case, summary) in invalid {
        assert_eq!(
            decode_public_group_snapshot(&encoded, &bind(summary))
                .expect_err("invalid locked-head tree summary"),
            PublicGroupSnapshotError::InvalidExpectedTreeSummary,
            "{case} escaped expected-summary validation"
        );
    }

    let maximum_hostname = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    for (case, credential) in [
        (
            "minimum",
            b"did:web:a.co#00000000-0000-4000-8000-000000000000".to_vec(),
        ),
        (
            "maximum",
            format!("did:web:{maximum_hostname}#00000000-0000-4000-8000-000000000000").into_bytes(),
        ),
    ] {
        assert!(matches!(credential.len(), 49 | 298));
        let boundary_summary = PublicGroupSnapshotTreeSummary::new(
            *expected.tree_hash(),
            vec![PublicGroupSnapshotLeaf::new(
                alice.leaf_index(),
                credential,
                alice.signature_key().to_vec(),
                alice.encryption_key().to_vec(),
            )],
        );
        assert_eq!(
            decode_public_group_snapshot(&encoded, &bind(boundary_summary))
                .expect_err("shape-valid boundary credential differs from the loaded leaf"),
            PublicGroupSnapshotError::SnapshotTreeSummaryMismatch,
            "the exact {case} BasicCredential boundary must remain accepted"
        );
    }
}
