//! Hash-bound restoration for the frozen MLS public-state corpus.
//!
//! Frozen snapshots are persistence fixtures, not indefinitely valid wire
//! fixtures.  This helper deliberately reconstructs the independently trusted
//! binding from the manifest and snapshot records, then exercises the same
//! snapshot/tree-summary verification path used by persisted production state.

use std::{collections::BTreeMap, fs, path::PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::chat_protocol::{
    public_state::{
        encode_public_tree_summary, load_persisted_active_snapshot, ActivePublicState,
        VerifiedCommitPublicState,
    },
    snapshot::{
        public_group_snapshot_sha256, PublicGroupSnapshotBinding, PublicGroupSnapshotCoordinate,
        PublicGroupSnapshotLeaf, PublicGroupSnapshotLifecycle, PublicGroupSnapshotTreeSummary,
    },
    wire::{validate_public_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES},
};

const MANIFEST_SHA256: [u8; 32] = [
    0xc4, 0xaf, 0x29, 0x3b, 0xdc, 0x3e, 0x44, 0x29, 0xf9, 0xe1, 0x3d, 0xf6, 0x6a, 0x4f, 0xc4, 0x49,
    0x91, 0x43, 0xfd, 0x82, 0xe8, 0x79, 0x3b, 0x47, 0x1e, 0xca, 0xb2, 0xda, 0x40, 0x45, 0xc8, 0x64,
];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    identifiers: ManifestIdentifiers,
    identity: ManifestIdentity,
    chain: ManifestChain,
    files: BTreeMap<String, ManifestFile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestIdentifiers {
    conversation_id_hex: String,
}

#[derive(Deserialize)]
struct ManifestIdentity {
    bob: ManifestActor,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestActor {
    credential_identity: String,
    signature_public_key_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestChain {
    generation: u64,
    genesis_state_version: u64,
    genesis_epoch: u64,
    genesis_group_context_hash_hex: String,
    genesis_confirmation_tag_hex: String,
    committed_epoch: u64,
    committed_group_context_hash_hex: String,
    committed_confirmation_tag_hex: String,
    group_id_hex: String,
    inner_key_package_ref_hex: String,
    commit_aad_sha256_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestFile {
    length: usize,
    sha256_hex: String,
}

struct RawSnapshot {
    records: Vec<(Vec<u8>, Vec<u8>)>,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/generated-artifacts/mls-chat-v1/crypto-wire")
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("valid frozen-corpus hex")
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N}-byte frozen-corpus value"))
}

fn manifest() -> Manifest {
    let bytes = fs::read(corpus_dir().join("manifest.json")).expect("read frozen corpus manifest");
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&bytes)),
        MANIFEST_SHA256,
        "frozen corpus manifest must remain pinned"
    );
    serde_json::from_slice(&bytes).expect("parse hash-bound frozen corpus manifest")
}

fn artifact(manifest: &Manifest, name: &str) -> Vec<u8> {
    let bytes = fs::read(corpus_dir().join(name)).expect("read frozen corpus artifact");
    let expected = manifest
        .files
        .get(name)
        .expect("artifact is manifest-bound");
    assert_eq!(bytes.len(), expected.length, "{name} manifest length");
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&bytes)),
        hex_array::<32>(&expected.sha256_hex),
        "{name} manifest digest"
    );
    bytes
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> &'a [u8] {
    let end = offset.checked_add(length).expect("snapshot offset");
    let value = bytes.get(*offset..end).expect("valid frozen snapshot");
    *offset = end;
    value
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> u16 {
    u16::from_be_bytes(take(bytes, offset, 2).try_into().expect("two bytes"))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> u32 {
    u32::from_be_bytes(take(bytes, offset, 4).try_into().expect("four bytes"))
}

fn parse_snapshot(bytes: &[u8]) -> RawSnapshot {
    let mut offset = 0;
    assert_eq!(take(bytes, &mut offset, 8), b"CBPGSNAP");
    assert_eq!(take_u16(bytes, &mut offset), 1);
    let openmls_len = usize::from(take_u16(bytes, &mut offset));
    assert_eq!(take(bytes, &mut offset, openmls_len), b"0.8.1");
    let storage_len = usize::from(take_u16(bytes, &mut offset));
    assert_eq!(take(bytes, &mut offset, storage_len), b"0.5.0");
    let count = usize::try_from(take_u32(bytes, &mut offset)).expect("snapshot record count");
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let key_len = usize::try_from(take_u32(bytes, &mut offset)).expect("snapshot key length");
        let key = take(bytes, &mut offset, key_len).to_vec();
        let value_len =
            usize::try_from(take_u32(bytes, &mut offset)).expect("snapshot value length");
        let value = take(bytes, &mut offset, value_len).to_vec();
        records.push((key, value));
    }
    assert_eq!(offset, bytes.len(), "frozen snapshot has exact EOF");
    RawSnapshot { records }
}

fn json_bytes(value: &serde_json::Value) -> Vec<u8> {
    value
        .as_array()
        .expect("frozen snapshot byte array")
        .iter()
        .map(|byte| {
            u8::try_from(byte.as_u64().expect("frozen snapshot byte")).expect("frozen snapshot u8")
        })
        .collect()
}

fn tree_summary(snapshot: &[u8]) -> PublicGroupSnapshotTreeSummary {
    let raw = parse_snapshot(snapshot);
    let group_context = raw
        .records
        .iter()
        .find(|(key, _)| key.starts_with(b"GroupContext"))
        .map(|(_, value)| serde_json::from_slice::<serde_json::Value>(value).expect("GroupContext"))
        .expect("GroupContext record");
    let tree_hash = json_bytes(&group_context["tree_hash"]["vec"])
        .try_into()
        .expect("32-byte tree hash");
    let tree = raw
        .records
        .iter()
        .find(|(key, _)| key.starts_with(b"Tree"))
        .map(|(_, value)| serde_json::from_slice::<serde_json::Value>(value).expect("Tree"))
        .expect("Tree record");
    let leaves = tree["tree"]["leaf_nodes"]
        .as_array()
        .expect("frozen leaf array")
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
                u32::try_from(leaf_index).expect("leaf index"),
                json_bytes(&payload["credential"]["serialized_credential_content"]["vec"]),
                json_bytes(&payload["signature_key"]["value"]["vec"]),
                json_bytes(&payload["encryption_key"]["key"]["vec"]),
            ))
        })
        .collect();
    PublicGroupSnapshotTreeSummary::new(tree_hash, leaves)
}

fn coordinate(
    manifest: &Manifest,
    conversation_id: [u8; 16],
    state_version: u64,
    committed: bool,
) -> PublicGroupSnapshotCoordinate {
    let (epoch, context_hash, confirmation_tag) = if committed {
        (
            manifest.chain.committed_epoch,
            manifest.chain.committed_group_context_hash_hex.as_str(),
            manifest.chain.committed_confirmation_tag_hex.as_str(),
        )
    } else {
        (
            manifest.chain.genesis_epoch,
            manifest.chain.genesis_group_context_hash_hex.as_str(),
            manifest.chain.genesis_confirmation_tag_hex.as_str(),
        )
    };
    PublicGroupSnapshotCoordinate::new(
        conversation_id,
        manifest.chain.generation,
        state_version,
        hex_array(&manifest.chain.group_id_hex),
        epoch,
        hex_array(context_hash),
        hex_array(confirmation_tag),
        PublicGroupSnapshotLifecycle::Active,
    )
}

fn restore(snapshot: Vec<u8>, coordinate: PublicGroupSnapshotCoordinate) -> ActivePublicState {
    let binding = PublicGroupSnapshotBinding::new(
        *coordinate.conversation_id(),
        coordinate.generation(),
        coordinate.state_version(),
        *coordinate.group_id(),
        coordinate.epoch(),
        *coordinate.group_context_hash(),
        *coordinate.confirmation_tag(),
        coordinate.lifecycle(),
        public_group_snapshot_sha256(&snapshot),
        tree_summary(&snapshot),
    );
    let encoded_summary =
        encode_public_tree_summary(binding.tree_summary()).expect("encode frozen tree summary");
    load_persisted_active_snapshot(
        &snapshot,
        &binding,
        encoded_summary.bytes(),
        encoded_summary.sha256(),
    )
    .expect("restore hash-bound frozen public snapshot")
}

pub fn restore_genesis() -> ActivePublicState {
    let manifest = manifest();
    let snapshot = artifact(&manifest, "genesis-public-state.bin");
    restore(
        snapshot,
        coordinate(
            &manifest,
            hex_array(&manifest.identifiers.conversation_id_hex),
            manifest.chain.genesis_state_version,
            false,
        ),
    )
}

pub fn restore_add_commit(
    prior: &ActivePublicState,
    next_coordinate: PublicGroupSnapshotCoordinate,
    sender_leaf_index: u32,
) -> VerifiedCommitPublicState {
    let manifest = manifest();
    let next = restore(
        artifact(&manifest, "committed-public-state.bin"),
        next_coordinate,
    );
    let commit_bytes = artifact(&manifest, "commit-public.mls");
    let parsed = validate_public_commit(&commit_bytes, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("frozen Commit remains structurally parseable");
    let aad = parsed.aad();
    let commit_sha256 = <[u8; 32]>::from(Sha256::digest(&commit_bytes));
    let aad_sha256 = <[u8; 32]>::from(Sha256::digest(aad));
    assert_eq!(
        aad_sha256,
        hex_array(&manifest.chain.commit_aad_sha256_hex),
        "frozen Commit AAD is manifest-bound"
    );
    VerifiedCommitPublicState::for_test_add_from_frozen_snapshot(
        prior,
        next,
        sender_leaf_index,
        manifest.identity.bob.credential_identity.as_bytes(),
        &hex::decode(&manifest.identity.bob.signature_public_key_hex).expect("Bob signature key"),
        hex_array(&manifest.chain.inner_key_package_ref_hex),
        commit_sha256,
        aad_sha256,
    )
    .expect("restore strict manifest-bound frozen Add commit")
}
