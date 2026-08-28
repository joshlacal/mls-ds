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
        encode_public_tree_summary, load_persisted_active_snapshot_from_parts_for_test,
        ActivePublicState, PublicStateError, VerifiedCommitPublicState,
    },
    snapshot::{
        public_group_snapshot_sha256, PublicGroupSnapshotBinding, PublicGroupSnapshotCoordinate,
        PublicGroupSnapshotLeaf, PublicGroupSnapshotLifecycle, PublicGroupSnapshotTreeSummary,
    },
    wire::{validate_public_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES},
};

const MANIFEST_SHA256: [u8; 32] = [
    0xd1, 0xc4, 0x3d, 0xe1, 0xfe, 0x8c, 0xe5, 0x37, 0x3d, 0x41, 0x3f, 0xce, 0x1c, 0x34, 0x64, 0xd0,
    0x7a, 0xb5, 0xa0, 0x3a, 0x4c, 0x77, 0xa1, 0x73, 0x61, 0xcc, 0x4f, 0xe2, 0xfe, 0xba, 0x1b, 0xeb,
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
    alice: ManifestActor,
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
    #[serde(default)]
    generation: u64,
    genesis_state_version: u64,
    genesis_epoch: u64,
    genesis_group_context_hash_hex: String,
    genesis_confirmation_tag_hex: String,
    #[serde(rename = "addNextEpoch")]
    committed_epoch: u64,
    committed_group_context_hash_hex: String,
    committed_confirmation_tag_hex: String,
    group_id_hex: String,
    commit_aad_sha256_hex: String,
    #[serde(rename = "removeCommitNextEpoch")]
    remove_committed_epoch: u64,
    remove_committed_group_context_hash_hex: String,
    remove_committed_confirmation_tag_hex: String,
    rejoin_prior_state_version: u64,
    #[serde(rename = "rejoinNextStateVersion")]
    rejoin_state_version: u64,
    #[serde(rename = "rejoinNextEpoch")]
    rejoin_epoch: u64,
    rejoin_group_context_hash_hex: String,
    rejoin_confirmation_tag_hex: String,
    rejoin_commit_aad_sha256_hex: String,
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crypto-wire-v09")
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

fn artifact_32(manifest: &Manifest, name: &str) -> [u8; 32] {
    artifact(manifest, name)
        .try_into()
        .unwrap_or_else(|_| panic!("{name} must be exactly 32 bytes"))
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
    assert_eq!(take_u16(bytes, &mut offset), 2);
    let openmls_len = usize::from(take_u16(bytes, &mut offset));
    assert_eq!(take(bytes, &mut offset, openmls_len), b"0.9.0-rc.3");
    let storage_len = usize::from(take_u16(bytes, &mut offset));
    assert_eq!(take(bytes, &mut offset, storage_len), b"0.6.0-rc.3");
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
    load_persisted_active_snapshot_from_parts_for_test(
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
    sender_leaf_index: u32,
) -> VerifiedCommitPublicState {
    let manifest = manifest();
    let expected_prior = restore(
        artifact(&manifest, "genesis-public-state.bin"),
        coordinate(
            &manifest,
            *prior.coordinate().conversation_id(),
            prior.coordinate().state_version(),
            false,
        ),
    );
    let next_coordinate = coordinate(
        &manifest,
        *prior.coordinate().conversation_id(),
        prior
            .coordinate()
            .state_version()
            .checked_add(1)
            .expect("frozen Add state version"),
        true,
    );
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
    let expected_prior_sender_encryption_key = expected_prior
        .binding()
        .tree_summary()
        .leaves()
        .iter()
        .find(|leaf| leaf.leaf_index() == sender_leaf_index)
        .expect("frozen prior sender leaf")
        .encryption_key()
        .to_vec();
    let expected_next_sender_encryption_key = next
        .binding()
        .tree_summary()
        .leaves()
        .iter()
        .find(|leaf| leaf.leaf_index() == sender_leaf_index)
        .expect("frozen next sender leaf")
        .encryption_key()
        .to_vec();
    VerifiedCommitPublicState::for_test_add_from_frozen_snapshot(
        prior,
        &expected_prior,
        next,
        sender_leaf_index,
        &expected_prior_sender_encryption_key,
        &expected_next_sender_encryption_key,
        manifest.identity.bob.credential_identity.as_bytes(),
        &hex::decode(&manifest.identity.bob.signature_public_key_hex).expect("Bob signature key"),
        artifact_32(&manifest, "key-package-ref.bin"),
        commit_sha256,
        aad_sha256,
    )
    .expect("restore strict manifest-bound frozen Add commit")
}

fn restore_rejoin_prior_from_manifest(manifest: &Manifest) -> ActivePublicState {
    restore(
        artifact(manifest, "committed-remove-public-state.bin"),
        PublicGroupSnapshotCoordinate::new(
            hex_array(&manifest.identifiers.conversation_id_hex),
            manifest.chain.generation,
            manifest.chain.rejoin_prior_state_version,
            hex_array(&manifest.chain.group_id_hex),
            manifest.chain.remove_committed_epoch,
            hex_array(&manifest.chain.remove_committed_group_context_hash_hex),
            hex_array(&manifest.chain.remove_committed_confirmation_tag_hex),
            PublicGroupSnapshotLifecycle::Active,
        ),
    )
}

fn restore_rejoin_next_from_manifest(manifest: &Manifest) -> ActivePublicState {
    restore(
        artifact(manifest, "committed-rejoin-public-state.bin"),
        PublicGroupSnapshotCoordinate::new(
            hex_array(&manifest.identifiers.conversation_id_hex),
            manifest.chain.generation,
            manifest.chain.rejoin_state_version,
            hex_array(&manifest.chain.group_id_hex),
            manifest.chain.rejoin_epoch,
            hex_array(&manifest.chain.rejoin_group_context_hash_hex),
            hex_array(&manifest.chain.rejoin_confirmation_tag_hex),
            PublicGroupSnapshotLifecycle::Active,
        ),
    )
}

pub fn restore_rejoin_commit(
    prior: &ActivePublicState,
) -> Result<VerifiedCommitPublicState, PublicStateError> {
    const ALICE_CREDENTIAL: &str =
        "did:plc:alicefixtureaaaaaaaaaaaa#2f93a82d-b061-4c75-8f61-57f23146b910";
    const ALICE_SIGNATURE_KEY_HEX: &str =
        "42fc27cde96276aaaddd99907272d7d786d63757cbdd080fcfb8adb595f677f3";
    const BOB_CREDENTIAL: &str =
        "did:plc:bobterminalccccccccccccc#b40c12d9-b1ff-4b24-94e5-15742d9ea6cf";
    const BOB_SIGNATURE_KEY_HEX: &str =
        "2bf5a667aa32fc2e05db907f7ff503c3c276ab8adbde93df7c80e9306d704d60";
    const PRIOR_ALICE_ENCRYPTION_KEY_SHA256_HEX: &str =
        "99c0c52982128c7c9a8506e165aa26f2eb5f61adbf9bb53c696e0d2337fe0f7b";
    const NEXT_ALICE_ENCRYPTION_KEY_SHA256_HEX: &str =
        "69603de1cc196e6e437af00431305b58d6bce99e166c09ac4a5d01d071e12e71";
    const NEXT_BOB_ENCRYPTION_KEY_SHA256_HEX: &str =
        "577a8705fc466722d993af46523a592d3dc6767066214a8a0d3b5a5c990e7662";
    const COMMIT_SHA256_HEX: &str =
        "bbe9ba8a9ec658dd0ed597f6d23432825eec8494290904fc877600955115fe23";
    const AAD_SHA256_HEX: &str = "726f97f842b38065822d5d92a1421198515ac4d4b2e3cf34b564890c6a6b457a";
    const KEY_PACKAGE_REF_HEX: &str =
        "1a208d32f60042fcd0b1d6e2547478ff84335a363e3b412a423e1683e6f97a16";

    let manifest = manifest();
    let key_package_ref = artifact_32(&manifest, "rejoin-key-package-ref.bin");
    if manifest.identity.alice.credential_identity != ALICE_CREDENTIAL
        || manifest.identity.alice.signature_public_key_hex != ALICE_SIGNATURE_KEY_HEX
        || manifest.identity.bob.credential_identity != BOB_CREDENTIAL
        || manifest.identity.bob.signature_public_key_hex != BOB_SIGNATURE_KEY_HEX
        || key_package_ref != hex_array(KEY_PACKAGE_REF_HEX)
        || manifest.chain.rejoin_commit_aad_sha256_hex != AAD_SHA256_HEX
    {
        return Err(PublicStateError::CoordinateMismatch);
    }

    let expected_prior = restore_rejoin_prior_from_manifest(&manifest);
    if prior.snapshot() != expected_prior.snapshot() || prior.binding() != expected_prior.binding()
    {
        return Err(PublicStateError::CoordinateMismatch);
    }
    let next = restore_rejoin_next_from_manifest(&manifest);

    let prior_alice = expected_prior
        .binding()
        .tree_summary()
        .leaves()
        .iter()
        .filter(|leaf| {
            leaf.basic_credential() == ALICE_CREDENTIAL.as_bytes()
                && leaf.signature_key() == hex_array::<32>(ALICE_SIGNATURE_KEY_HEX)
        })
        .collect::<Vec<_>>();
    let next_alice = next
        .binding()
        .tree_summary()
        .leaves()
        .iter()
        .filter(|leaf| {
            leaf.basic_credential() == ALICE_CREDENTIAL.as_bytes()
                && leaf.signature_key() == hex_array::<32>(ALICE_SIGNATURE_KEY_HEX)
        })
        .collect::<Vec<_>>();
    let next_bob = next
        .binding()
        .tree_summary()
        .leaves()
        .iter()
        .filter(|leaf| {
            leaf.basic_credential() == BOB_CREDENTIAL.as_bytes()
                && leaf.signature_key() == hex_array::<32>(BOB_SIGNATURE_KEY_HEX)
        })
        .collect::<Vec<_>>();
    if prior_alice.len() != 1
        || next_alice.len() != 1
        || next_bob.len() != 1
        || expected_prior.binding().tree_summary().leaves().len() != 1
        || next.binding().tree_summary().leaves().len() != 2
        || prior_alice[0].leaf_index() != 0
        || next_alice[0].leaf_index() != 0
        || next_bob[0].leaf_index() != 1
    {
        return Err(PublicStateError::CoordinateMismatch);
    }

    let prior_alice_encryption_key = prior_alice[0].encryption_key().to_vec();
    let next_alice_encryption_key = next_alice[0].encryption_key().to_vec();
    if <[u8; 32]>::from(Sha256::digest(&prior_alice_encryption_key))
        != hex_array(PRIOR_ALICE_ENCRYPTION_KEY_SHA256_HEX)
        || <[u8; 32]>::from(Sha256::digest(&next_alice_encryption_key))
            != hex_array(NEXT_ALICE_ENCRYPTION_KEY_SHA256_HEX)
        || <[u8; 32]>::from(Sha256::digest(next_bob[0].encryption_key()))
            != hex_array(NEXT_BOB_ENCRYPTION_KEY_SHA256_HEX)
        || prior_alice_encryption_key == next_alice_encryption_key
    {
        return Err(PublicStateError::CoordinateMismatch);
    }

    let commit_bytes = artifact(&manifest, "commit-rejoin-public.mls");
    let parsed = validate_public_commit(&commit_bytes, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .map_err(|_| PublicStateError::CoordinateMismatch)?;
    let commit_sha256 = <[u8; 32]>::from(Sha256::digest(&commit_bytes));
    let aad_sha256 = <[u8; 32]>::from(Sha256::digest(parsed.aad()));
    if commit_sha256 != hex_array(COMMIT_SHA256_HEX)
        || aad_sha256 != hex_array(AAD_SHA256_HEX)
        || key_package_ref != hex_array(KEY_PACKAGE_REF_HEX)
    {
        return Err(PublicStateError::CoordinateMismatch);
    }

    VerifiedCommitPublicState::for_test_add_from_frozen_snapshot(
        prior,
        &expected_prior,
        next,
        prior_alice[0].leaf_index(),
        &prior_alice_encryption_key,
        &next_alice_encryption_key,
        BOB_CREDENTIAL.as_bytes(),
        &hex_array::<32>(BOB_SIGNATURE_KEY_HEX),
        key_package_ref,
        commit_sha256,
        aad_sha256,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frozen_commit_evidence(manifest: &Manifest) -> ([u8; 32], [u8; 32]) {
        let commit_bytes = artifact(manifest, "commit-public.mls");
        let parsed = validate_public_commit(&commit_bytes, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .expect("frozen Commit parses");
        (
            Sha256::digest(&commit_bytes).into(),
            Sha256::digest(parsed.aad()).into(),
        )
    }

    #[test]
    fn frozen_add_rejects_non_manifest_prior_coordinate() {
        let manifest = manifest();
        let genesis = restore_genesis();
        let tampered_coordinate = PublicGroupSnapshotCoordinate::new(
            *genesis.coordinate().conversation_id(),
            genesis.coordinate().generation(),
            genesis.coordinate().state_version(),
            *genesis.coordinate().group_id(),
            genesis.coordinate().epoch(),
            [0xa5; 32],
            [0xa6; 32],
            PublicGroupSnapshotLifecycle::Active,
        );
        let tampered_prior = ActivePublicState::for_test(&genesis, tampered_coordinate);
        let next_coordinate = coordinate(
            &manifest,
            *tampered_prior.coordinate().conversation_id(),
            tampered_prior.coordinate().state_version() + 1,
            true,
        );
        let next = restore(
            artifact(&manifest, "committed-public-state.bin"),
            next_coordinate,
        );
        let sender_leaf_index = tampered_prior.binding().tree_summary().leaves()[0].leaf_index();
        let next_sender_encryption_key = next
            .binding()
            .tree_summary()
            .leaves()
            .iter()
            .find(|leaf| leaf.leaf_index() == sender_leaf_index)
            .expect("frozen next sender")
            .encryption_key()
            .to_vec();
        let (commit_sha256, aad_sha256) = frozen_commit_evidence(&manifest);

        assert!(matches!(
            VerifiedCommitPublicState::for_test_add_from_frozen_snapshot(
                &tampered_prior,
                &genesis,
                next,
                sender_leaf_index,
                genesis.binding().tree_summary().leaves()[0].encryption_key(),
                &next_sender_encryption_key,
                manifest.identity.bob.credential_identity.as_bytes(),
                &hex::decode(&manifest.identity.bob.signature_public_key_hex)
                    .expect("Bob signature key"),
                artifact_32(&manifest, "key-package-ref.bin"),
                commit_sha256,
                aad_sha256,
            ),
            Err(PublicStateError::CoordinateMismatch)
        ));
    }

    #[test]
    fn frozen_add_rejects_unchanged_sender_encryption_key() {
        let manifest = manifest();
        let prior = restore_genesis();
        let exact_next_coordinate = coordinate(
            &manifest,
            *prior.coordinate().conversation_id(),
            prior.coordinate().state_version() + 1,
            true,
        );
        let exact_next = restore(
            artifact(&manifest, "committed-public-state.bin"),
            exact_next_coordinate,
        );
        let sender = &prior.binding().tree_summary().leaves()[0];
        let bob = exact_next
            .binding()
            .tree_summary()
            .leaves()
            .iter()
            .find(|leaf| {
                leaf.basic_credential() == manifest.identity.bob.credential_identity.as_bytes()
            })
            .expect("Bob leaf");
        let synthetic_coordinate = PublicGroupSnapshotCoordinate::new(
            *exact_next.coordinate().conversation_id(),
            exact_next.coordinate().generation(),
            exact_next.coordinate().state_version() + 1,
            *exact_next.coordinate().group_id(),
            exact_next.coordinate().epoch() + 1,
            [0xb5; 32],
            [0xb6; 32],
            PublicGroupSnapshotLifecycle::Active,
        );
        let synthetic_next = VerifiedCommitPublicState::for_test_replace(
            &exact_next,
            synthetic_coordinate,
            bob.leaf_index(),
            sender.leaf_index(),
            sender.encryption_key().to_vec(),
            [0xb7; 32],
        )
        .expect("build adversarial unchanged-sender tree")
        .into_next();
        let synthetic_next = ActivePublicState::for_test(&synthetic_next, exact_next_coordinate);
        let (commit_sha256, aad_sha256) = frozen_commit_evidence(&manifest);

        assert!(matches!(
            VerifiedCommitPublicState::for_test_add_from_frozen_snapshot(
                &prior,
                &prior,
                synthetic_next,
                sender.leaf_index(),
                sender.encryption_key(),
                sender.encryption_key(),
                manifest.identity.bob.credential_identity.as_bytes(),
                &hex::decode(&manifest.identity.bob.signature_public_key_hex)
                    .expect("Bob signature key"),
                artifact_32(&manifest, "key-package-ref.bin"),
                commit_sha256,
                aad_sha256,
            ),
            Err(PublicStateError::CoordinateMismatch)
        ));
    }

    #[test]
    fn frozen_rejoin_rejects_non_manifest_prior_coordinate() {
        let manifest = manifest();
        let exact_prior = restore_rejoin_prior_from_manifest(&manifest);
        let tampered_coordinate = PublicGroupSnapshotCoordinate::new(
            [0xc1; 16],
            exact_prior.coordinate().generation(),
            exact_prior.coordinate().state_version(),
            *exact_prior.coordinate().group_id(),
            exact_prior.coordinate().epoch(),
            *exact_prior.coordinate().group_context_hash(),
            *exact_prior.coordinate().confirmation_tag(),
            PublicGroupSnapshotLifecycle::Active,
        );
        let tampered_prior = ActivePublicState::for_test(&exact_prior, tampered_coordinate);

        assert!(matches!(
            restore_rejoin_commit(&tampered_prior),
            Err(PublicStateError::CoordinateMismatch)
        ));
    }

    #[test]
    fn frozen_rejoin_rejects_non_manifest_prior_snapshot() {
        let manifest = manifest();
        let exact_prior = restore_rejoin_prior_from_manifest(&manifest);
        let genesis = restore_genesis();
        let spliced_prior = ActivePublicState::for_test(&genesis, *exact_prior.coordinate());

        assert!(matches!(
            restore_rejoin_commit(&spliced_prior),
            Err(PublicStateError::CoordinateMismatch)
        ));
    }
}
