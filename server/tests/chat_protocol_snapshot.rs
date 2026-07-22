use std::{fs, path::PathBuf};

use catbird_server::chat_protocol::snapshot::{
    decode_public_group_snapshot, encode_public_group_snapshot, public_group_snapshot_binding,
    public_group_snapshot_sha256, PublicGroupSnapshotBinding, PublicGroupSnapshotError,
    PublicGroupSnapshotLifecycle, MAX_PROTOCOL_INTEGER, MAX_PUBLIC_GROUP_SNAPSHOT_BYTES,
    MAX_SNAPSHOT_KEY_BYTES, MAX_SNAPSHOT_VALUE_BYTES,
};

const MAGIC: &[u8; 8] = b"CBPGSNAP";
const SCHEMA: u16 = 1;
const OPENMLS_VERSION: &[u8] = b"0.8.1";
const STORAGE_VERSION: &[u8] = b"0.5.0";
const CONVERSATION_ID: [u8; 16] = [
    0xd4, 0xe3, 0xc7, 0x14, 0x41, 0xb5, 0x43, 0xa8, 0xb2, 0xdf, 0x6d, 0x1d, 0x1f, 0x78, 0x99, 0x54,
];
const GROUP_ID: [u8; 32] = [
    0x10, 0x2f, 0x52, 0x11, 0x83, 0x65, 0x4c, 0x7d, 0xb4, 0xc9, 0xfa, 0xf3, 0x21, 0xa7, 0x3e, 0x00,
    0xca, 0xc2, 0xf8, 0xce, 0xf3, 0xbd, 0x1c, 0x87, 0xa1, 0x88, 0xc3, 0x85, 0x2a, 0xac, 0x20, 0xb1,
];

fn hex32(value: &str) -> [u8; 32] {
    hex::decode(value)
        .expect("valid test hex")
        .try_into()
        .expect("32-byte test value")
}

fn snapshot_binding(encoded: &[u8], epoch: u64) -> PublicGroupSnapshotBinding {
    let (context_hash, confirmation_tag) = match epoch {
        0 => (
            "5f79e703f1b0813b12b141ae108297567d2c10025554cc42efd37e0c9ad1e102",
            "d9c06dcf2a42924b9f91e48ce2201b9827a43b0cd9f19c0f6e042792de7db71a",
        ),
        1 => (
            "a1d6f53e64ab5b4e8eb9309b3b8eb7f32c64a7d406609cf0a0ab0e138d6ad37f",
            "a38367abdc76779da5e786aaf73abd95763f33a5e1a030c0a76c48f29f3ebb9b",
        ),
        _ => panic!("unsupported test epoch"),
    };
    PublicGroupSnapshotBinding::new(
        CONVERSATION_ID,
        0,
        epoch,
        GROUP_ID,
        epoch,
        hex32(context_hash),
        hex32(confirmation_tag),
        PublicGroupSnapshotLifecycle::Active,
        public_group_snapshot_sha256(encoded),
    )
}

fn decode_genesis(
    encoded: &[u8],
) -> Result<catbird_server::chat_protocol::snapshot::PublicGroupState, PublicGroupSnapshotError> {
    decode_public_group_snapshot(encoded, &snapshot_binding(encoded, 0))
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
        .join("../../docs/generated-artifacts/mls-chat-v1/crypto-wire")
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

fn raw_genesis() -> RawSnapshot {
    parse_valid_snapshot(&corpus_file("genesis-public-state.bin"))
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
    for (filename, expected_epoch, expected_members) in [
        ("genesis-public-state.bin", 0, 1),
        ("committed-public-state.bin", 1, 2),
    ] {
        let encoded = corpus_file(filename);
        let binding = snapshot_binding(&encoded, expected_epoch);
        let state = decode_public_group_snapshot(&encoded, &binding)
            .expect("load frozen public snapshot into a fresh provider");
        assert_eq!(state.public_group().group_id().as_slice(), GROUP_ID);
        assert_eq!(
            state.public_group().group_context().epoch().as_u64(),
            expected_epoch
        );
        assert_eq!(state.public_group().members().count(), expected_members);
        assert_eq!(
            encode_public_group_snapshot(&state).expect("re-encode public state"),
            encoded,
            "snapshot encoding must be deterministic and corpus-exact"
        );
        assert_eq!(
            public_group_snapshot_binding(&state, &encoded, binding.coordinate())
                .expect("bind exact state to separately trusted coordinate"),
            binding
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
    malformed.schema = 2;
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("wrong schema"),
        PublicGroupSnapshotError::UnsupportedSchema { actual: 2 }
    );

    let mut malformed = raw_genesis();
    malformed.openmls_version = b"0.8.2".to_vec();
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("wrong OpenMLS version"),
        PublicGroupSnapshotError::UnsupportedOpenMlsVersion
    );

    let mut malformed = raw_genesis();
    malformed.storage_version = b"0.5.1".to_vec();
    assert_eq!(
        decode_genesis(&encode_raw_snapshot(&malformed)).expect_err("wrong storage version"),
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

    let mut encoded = corpus_file("genesis-public-state.bin");
    encoded[28..32].copy_from_slice(
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

    let encoded = corpus_file("genesis-public-state.bin");
    let first_key_len = usize::try_from(u32::from_be_bytes(
        encoded[28..32].try_into().expect("first key length"),
    ))
    .expect("key length usize");
    let first_value_len_offset = 32 + first_key_len;

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

    let mut wrong_group_id = GROUP_ID;
    wrong_group_id[0] ^= 0x01;
    let encoded = corpus_file("genesis-public-state.bin");
    let correct = snapshot_binding(&encoded, 0);
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
    );
    assert_eq!(
        decode_public_group_snapshot(&encoded, &wrong_binding)
            .expect_err("wrong expected group id"),
        PublicGroupSnapshotError::UnexpectedPublicRecordKey
    );
}

#[test]
fn snapshot_requires_an_active_bounded_uuidv4_outer_coordinate() {
    let encoded = corpus_file("genesis-public-state.bin");
    let correct = snapshot_binding(&encoded, 0);
    assert_eq!(correct.conversation_id(), &CONVERSATION_ID);
    assert_eq!(correct.generation(), 0);
    assert_eq!(correct.state_version(), 0);
    assert_eq!(correct.lifecycle(), PublicGroupSnapshotLifecycle::Active);

    let binding = |conversation_id, generation, state_version, epoch, lifecycle| {
        PublicGroupSnapshotBinding::new(
            conversation_id,
            generation,
            state_version,
            GROUP_ID,
            epoch,
            *correct.group_context_hash(),
            *correct.confirmation_tag(),
            lifecycle,
            *correct.snapshot_sha256(),
        )
    };
    for (invalid, expected_error) in [
        (
            binding([0; 16], 0, 0, 0, PublicGroupSnapshotLifecycle::Active),
            PublicGroupSnapshotError::InvalidConversationId,
        ),
        (
            binding(
                CONVERSATION_ID,
                MAX_PROTOCOL_INTEGER + 1,
                0,
                0,
                PublicGroupSnapshotLifecycle::Active,
            ),
            PublicGroupSnapshotError::CoordinateIntegerOutOfRange,
        ),
        (
            binding(
                CONVERSATION_ID,
                0,
                MAX_PROTOCOL_INTEGER + 1,
                0,
                PublicGroupSnapshotLifecycle::Active,
            ),
            PublicGroupSnapshotError::CoordinateIntegerOutOfRange,
        ),
        (
            binding(
                CONVERSATION_ID,
                0,
                0,
                MAX_PROTOCOL_INTEGER + 1,
                PublicGroupSnapshotLifecycle::Active,
            ),
            PublicGroupSnapshotError::CoordinateIntegerOutOfRange,
        ),
        (
            binding(
                CONVERSATION_ID,
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
    let genesis = corpus_file("genesis-public-state.bin");
    let committed = corpus_file("committed-public-state.bin");
    let genesis_binding = snapshot_binding(&genesis, 0);
    let committed_binding = snapshot_binding(&committed, 1);
    let genesis_state =
        decode_public_group_snapshot(&genesis, &genesis_binding).expect("load exact genesis state");

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
            GROUP_ID,
            1,
            *genesis_binding.group_context_hash(),
            *genesis_binding.confirmation_tag(),
            genesis_binding.lifecycle(),
            *genesis_binding.snapshot_sha256(),
        ),
        PublicGroupSnapshotBinding::new(
            *genesis_binding.conversation_id(),
            genesis_binding.generation(),
            genesis_binding.state_version(),
            GROUP_ID,
            0,
            [0xA5; 32],
            *genesis_binding.confirmation_tag(),
            genesis_binding.lifecycle(),
            *genesis_binding.snapshot_sha256(),
        ),
        PublicGroupSnapshotBinding::new(
            *genesis_binding.conversation_id(),
            genesis_binding.generation(),
            genesis_binding.state_version(),
            GROUP_ID,
            0,
            *genesis_binding.group_context_hash(),
            [0x5A; 32],
            genesis_binding.lifecycle(),
            *genesis_binding.snapshot_sha256(),
        ),
    ] {
        assert_eq!(
            decode_public_group_snapshot(&genesis, &bad_binding).expect_err("wrong MLS coordinate"),
            PublicGroupSnapshotError::SnapshotCoordinateMismatch
        );
    }

    let genesis_raw = parse_valid_snapshot(&genesis);
    let committed_raw = parse_valid_snapshot(&committed);
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

        // Even with a recomputed digest, cross-record coherence/coordinate
        // validation rejects the hybrid state.
        assert!(
            decode_public_group_snapshot(&spliced, &snapshot_binding(&spliced, 0)).is_err(),
            "record {record_index} splice escaped semantic coherence validation"
        );
    }
}
