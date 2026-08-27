//! Sealer helper for the authoritative `blue.catbird.chat` v1 OpenMLS 0.9 wire corpus.
//!
//! Consumes the candidate wire artifacts emitted by `catbird-mls`, verifies them
//! through production server validation and commit processing paths, encodes the
//! authoritative schema 2 `PublicGroupSnapshot` files, and finalizes the sealed
//! `manifest.json`.

use catbird_server::chat_protocol::snapshot::{
    decode_public_group_snapshot, encode_public_group_snapshot, public_group_snapshot_binding,
    PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle, PublicGroupState,
};
use catbird_server::chat_protocol::wire::{
    process_public_commit, validate_group_info, validate_public_commit, GroupInfoValidationPolicy,
    PublicCommitValidationPolicy, MAX_GROUP_INFO_WIRE_BYTES, MAX_PUBLIC_MESSAGE_WIRE_BYTES,
};
use openmls::prelude::*;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct SealerError(String);

impl fmt::Display for SealerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for SealerError {}

type Result<T, E = Box<dyn Error>> = std::result::Result<T, E>;

fn fail(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(SealerError(message.into()))
}

fn ensure(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(fail(message))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| fail("output path has no UTF-8 filename"))?;
    let temp = path.with_file_name(format!(".{filename}.{}.tmp", std::process::id()));
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    fs::write(&temp, bytes)?;
    fs::rename(&temp, path)?;
    Ok(())
}

fn decode_hex_16(value: &str, label: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(value).map_err(|e| fail(format!("invalid hex for {label}: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| fail(format!("{label} is not 16 bytes")))
}

fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).map_err(|e| fail(format!("invalid hex for {label}: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| fail(format!("{label} is not 32 bytes")))
}

fn expected_public_snapshot_keys(group_id: &[u8; 32]) -> Result<Vec<String>> {
    let labels: [&[u8]; 4] = [
        b"ConfirmationTag",
        b"GroupContext",
        b"InterimTranscriptHash",
        b"Tree",
    ];
    let serialized_group_id = serde_json::to_vec(&GroupId::from_slice(group_id))?;
    let mut keys = Vec::new();
    for label in labels {
        let mut key = Vec::new();
        key.extend_from_slice(label);
        key.extend_from_slice(&serialized_group_id);
        key.extend_from_slice(&[0x00, 0x01]);
        keys.push(hex::encode(&key));
    }
    Ok(keys)
}
/// One sealed link of the public commit chain: the reconstructed state, its
/// authoritative schema-2 snapshot bytes, and the coordinate material a
/// successor commit must be bound against.
struct SealedLink {
    state: PublicGroupState,
    snapshot_bytes: Vec<u8>,
    epoch: u64,
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
}

/// Per-link constants: which candidate file to seal, which manifest `chain`
/// fields carry its expected coordinates, and the state versions the prior and
/// successor snapshots are bound at.
struct CommitLinkSpec<'a> {
    label: &'a str,
    commit_file: &'a str,
    aad_field: &'a str,
    group_context_hash_field: &'a str,
    confirmation_tag_field: &'a str,
    prior_state_version: u64,
    next_state_version: u64,
    next_epoch: u64,
    snapshot_file: &'a str,
}

/// Validate one public commit against `prior`, process it through the production
/// server commit path, then encode, bind, verify, and write its authoritative
/// schema-2 successor snapshot.
fn seal_commit_link(
    target_dir: &Path,
    manifest: &Value,
    conversation_id: [u8; 16],
    group_id: [u8; 32],
    evaluation_unix_seconds: u64,
    prior: &SealedLink,
    spec: &CommitLinkSpec<'_>,
) -> Result<SealedLink> {
    let label = spec.label;
    let commit_bytes = fs::read(target_dir.join(spec.commit_file))?;
    let validated = validate_public_commit(&commit_bytes, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .map_err(|e| fail(format!("validate {label} failed: {e}")))?;

    let group_context_hash = decode_hex_32(
        manifest["chain"][spec.group_context_hash_field]
            .as_str()
            .ok_or_else(|| fail(format!("missing {}", spec.group_context_hash_field)))?,
        spec.group_context_hash_field,
    )?;
    let confirmation_tag = decode_hex_32(
        manifest["chain"][spec.confirmation_tag_field]
            .as_str()
            .ok_or_else(|| fail(format!("missing {}", spec.confirmation_tag_field)))?,
        spec.confirmation_tag_field,
    )?;

    let next_coordinate = PublicGroupSnapshotCoordinate::new(
        conversation_id,
        0,
        spec.next_state_version,
        group_id,
        spec.next_epoch,
        group_context_hash,
        confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    );
    let prior_coordinate = PublicGroupSnapshotCoordinate::new(
        conversation_id,
        0,
        spec.prior_state_version,
        group_id,
        prior.epoch,
        prior.group_context_hash,
        prior.confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    );
    let prior_binding =
        public_group_snapshot_binding(&prior.state, &prior.snapshot_bytes, &prior_coordinate)
            .map_err(|e| fail(format!("bind {label} prior snapshot failed: {e}")))?;

    let aad = validated_commit_aad(&validated, manifest, spec.aad_field)?;
    let processed = process_public_commit(
        &prior.state,
        validated,
        PublicCommitValidationPolicy {
            expected_aad: &aad,
            trusted_prior_binding: &prior_binding,
            expected_next_coordinate: &next_coordinate,
            now_unix_seconds: evaluation_unix_seconds,
            max_members: 10,
        },
    )
    .map_err(|e| fail(format!("process {label} failed: {e}")))?;

    let state = processed.into_next_state();
    let snapshot_bytes = encode_public_group_snapshot(&state)
        .map_err(|e| fail(format!("encode {label} snapshot failed: {e}")))?;
    let binding = public_group_snapshot_binding(&state, &snapshot_bytes, &next_coordinate)
        .map_err(|e| fail(format!("bind {label} snapshot failed: {e}")))?;
    decode_public_group_snapshot(&snapshot_bytes, &binding)
        .map_err(|e| fail(format!("decode {label} snapshot failed: {e}")))?;

    write_atomic(&target_dir.join(spec.snapshot_file), &snapshot_bytes)?;

    Ok(SealedLink {
        state,
        snapshot_bytes,
        epoch: spec.next_epoch,
        group_context_hash,
        confirmation_tag,
    })
}

fn main() -> Result<()> {
    let target_dir = match std::env::args().nth(1) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => match std::env::var("CATBIRD_MLS_CHAT_CRYPTO_WIRE_OUT_DIR") {
            Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => {
                let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                let stack_root = manifest_dir
                    .parent()
                    .and_then(|p| p.parent())
                    .ok_or_else(|| fail("no stack root found"))?;
                stack_root.join("docs/generated-artifacts/mls-chat-v1/crypto-wire-v09")
            }
        },
    };

    println!("Sealing candidate corpus at: {}", target_dir.display());
    ensure(
        target_dir.is_dir(),
        format!("target directory does not exist: {}", target_dir.display()),
    )?;

    let candidate_manifest_path = target_dir.join("candidate-manifest.json");
    ensure(
        candidate_manifest_path.is_file(),
        format!(
            "missing candidate-manifest.json at {}",
            candidate_manifest_path.display()
        ),
    )?;
    let mut manifest: Value = serde_json::from_slice(&fs::read(&candidate_manifest_path)?)?;

    let evaluation_unix_seconds = manifest["evaluationUnixSeconds"]
        .as_u64()
        .ok_or_else(|| fail("invalid evaluationUnixSeconds"))?;
    let conversation_id = decode_hex_16(
        manifest["identifiers"]["conversationIdHex"]
            .as_str()
            .ok_or_else(|| fail("missing conversationIdHex"))?,
        "conversationId",
    )?;
    let group_id = decode_hex_32(
        manifest["chain"]["groupIdHex"]
            .as_str()
            .ok_or_else(|| fail("missing groupIdHex"))?,
        "groupId",
    )?;

    let alice_cred = manifest["identity"]["alice"]["credentialIdentity"]
        .as_str()
        .ok_or_else(|| fail("missing alice credentialIdentity"))?;
    let alice_pub = hex::decode(
        manifest["identity"]["alice"]["signaturePublicKeyHex"]
            .as_str()
            .ok_or_else(|| fail("missing alice signaturePublicKeyHex"))?,
    )?;

    // ── 1. Validate GroupInfo and write genesis snapshot ────────────────────────
    let group_info_bytes = fs::read(target_dir.join("group-info.mls"))?;
    let genesis_validated = validate_group_info(
        &group_info_bytes,
        GroupInfoValidationPolicy {
            expected_basic_credential: alice_cred.as_bytes(),
            expected_signature_key: &alice_pub,
            now_unix_seconds: evaluation_unix_seconds,
            max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_ratchet_tree_bytes: 786_432,
            max_members: 1,
        },
    )
    .map_err(|e| fail(format!("validate_group_info failed: {e}")))?;

    let genesis_group_context_hash = *genesis_validated.group_context_hash();
    let genesis_confirmation_tag = *genesis_validated.confirmation_tag();
    let genesis_state = genesis_validated.into_public_state();
    let genesis_snapshot_bytes = encode_public_group_snapshot(&genesis_state)
        .map_err(|e| fail(format!("encode genesis snapshot failed: {e}")))?;

    let genesis_coordinate = PublicGroupSnapshotCoordinate::new(
        conversation_id,
        0,
        0,
        group_id,
        0,
        genesis_group_context_hash,
        genesis_confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    );
    let genesis_binding =
        public_group_snapshot_binding(&genesis_state, &genesis_snapshot_bytes, &genesis_coordinate)
            .map_err(|e| fail(format!("bind genesis snapshot failed: {e}")))?;

    decode_public_group_snapshot(&genesis_snapshot_bytes, &genesis_binding)
        .map_err(|e| fail(format!("decode genesis snapshot failed: {e}")))?;

    write_atomic(
        &target_dir.join("genesis-public-state.bin"),
        &genesis_snapshot_bytes,
    )?;

    // ── 2-5. Seal the public commit chain through the production commit path ────
    let mut link = SealedLink {
        state: genesis_state,
        snapshot_bytes: genesis_snapshot_bytes,
        epoch: 0,
        group_context_hash: genesis_group_context_hash,
        confirmation_tag: genesis_confirmation_tag,
    };
    let chain = [
        CommitLinkSpec {
            label: "Add commit",
            commit_file: "commit-public.mls",
            aad_field: "commitAadSha256Hex",
            group_context_hash_field: "committedGroupContextHashHex",
            confirmation_tag_field: "committedConfirmationTagHex",
            prior_state_version: 2,
            next_state_version: 3,
            next_epoch: 1,
            snapshot_file: "committed-public-state.bin",
        },
        CommitLinkSpec {
            label: "generic commit",
            commit_file: "commit-generic-public.mls",
            aad_field: "genericCommitAadSha256Hex",
            group_context_hash_field: "genericCommittedGroupContextHashHex",
            confirmation_tag_field: "genericCommittedConfirmationTagHex",
            prior_state_version: 3,
            next_state_version: 4,
            next_epoch: 2,
            snapshot_file: "committed-generic-public-state.bin",
        },
        CommitLinkSpec {
            label: "remove commit",
            commit_file: "commit-remove-public.mls",
            aad_field: "removeCommitAadSha256Hex",
            group_context_hash_field: "removeCommittedGroupContextHashHex",
            confirmation_tag_field: "removeCommittedConfirmationTagHex",
            prior_state_version: 4,
            next_state_version: 5,
            next_epoch: 3,
            snapshot_file: "committed-remove-public-state.bin",
        },
        CommitLinkSpec {
            label: "rejoin commit",
            commit_file: "commit-rejoin-public.mls",
            aad_field: "rejoinCommitAadSha256Hex",
            group_context_hash_field: "rejoinGroupContextHashHex",
            confirmation_tag_field: "rejoinConfirmationTagHex",
            prior_state_version: 7,
            next_state_version: 8,
            next_epoch: 4,
            snapshot_file: "committed-rejoin-public-state.bin",
        },
    ];
    for spec in &chain {
        link = seal_commit_link(
            &target_dir,
            &manifest,
            conversation_id,
            group_id,
            evaluation_unix_seconds,
            &link,
            spec,
        )?;
    }

    // ── 6. Assemble complete file inventory and manifest ────────────────────────
    let expected_keys = expected_public_snapshot_keys(&group_id)?;

    let public_snapshots_profile = json!({
        "schema": 2,
        "openmlsVersion": "0.9.0-rc.3",
        "storageVersion": "0.6.0-rc.3",
        "recordLabels": ["Tree", "GroupContext", "InterimTranscriptHash", "ConfirmationTag"],
        "recordCount": 4,
        "storageSchemaSuffixHex": "0001",
        "genesisRecordKeyHex": expected_keys.clone(),
        "committedRecordKeyHex": expected_keys.clone(),
        "rejoinRecordKeyHex": expected_keys,
        "containsSecrets": false
    });

    let payload_files: [(&str, &'static str, Option<u16>, Option<u64>); 21] = [
        ("key-package.mls", "mlsMessageKeyPackage", Some(5), None),
        ("key-package-inner.tls", "innerKeyPackageTls", None, None),
        ("key-package-ref.bin", "rfc9420KeyPackageRef", None, None),
        ("group-info.mls", "mlsMessageGroupInfo", Some(4), Some(0)),
        (
            "commit-public.mls",
            "mlsMessagePublicCommit",
            Some(1),
            Some(0),
        ),
        ("welcome.mls", "mlsMessageWelcome", Some(3), Some(1)),
        (
            "application-frame.cbor",
            "canonicalDagCborApplicationFrame",
            None,
            Some(1),
        ),
        (
            "application-private.mls",
            "mlsMessagePrivateApplication",
            Some(2),
            Some(1),
        ),
        (
            "genesis-public-state.bin",
            "publicGroupSnapshot",
            None,
            Some(0),
        ),
        (
            "committed-public-state.bin",
            "publicGroupSnapshot",
            None,
            Some(1),
        ),
        (
            "commit-generic-public.mls",
            "mlsMessagePublicCommit",
            Some(1),
            Some(1),
        ),
        (
            "committed-generic-public-state.bin",
            "publicGroupSnapshot",
            None,
            Some(2),
        ),
        (
            "commit-remove-public.mls",
            "mlsMessagePublicCommit",
            Some(1),
            Some(2),
        ),
        (
            "committed-remove-public-state.bin",
            "publicGroupSnapshot",
            None,
            Some(3),
        ),
        (
            "rejoin-key-package.mls",
            "mlsMessageKeyPackage",
            Some(5),
            None,
        ),
        (
            "rejoin-key-package-inner.tls",
            "innerKeyPackageTls",
            None,
            None,
        ),
        (
            "rejoin-key-package-ref.bin",
            "rfc9420KeyPackageRef",
            None,
            None,
        ),
        (
            "commit-rejoin-public.mls",
            "mlsMessagePublicCommit",
            Some(1),
            Some(3),
        ),
        ("rejoin-welcome.mls", "mlsMessageWelcome", Some(3), Some(4)),
        (
            "committed-rejoin-public-state.bin",
            "publicGroupSnapshot",
            None,
            Some(4),
        ),
        (
            "creation-signed-request.cbor",
            "canonicalDagCborSignedCreation",
            None,
            Some(0),
        ),
    ];

    let mut file_manifest = Map::new();
    for (filename, kind, wire_format, epoch) in payload_files {
        let file_path = target_dir.join(filename);
        ensure(
            file_path.is_file(),
            format!("missing payload file: {}", file_path.display()),
        )?;
        let bytes = fs::read(&file_path)?;
        let mut record = Map::new();
        record.insert("length".into(), json!(bytes.len()));
        record.insert("sha256Hex".into(), json!(sha256_hex(&bytes)));
        record.insert("kind".into(), json!(kind));
        if let Some(wf) = wire_format {
            record.insert("wireFormat".into(), json!(wf));
        }
        if let Some(ep) = epoch {
            record.insert("epoch".into(), json!(ep));
        }
        file_manifest.insert(filename.to_owned(), Value::Object(record));
    }

    manifest["publicSnapshots"] = public_snapshots_profile;
    manifest["files"] = Value::Object(file_manifest);

    // Consumed: the sealed manifest.json replaces the candidate.
    let _ = fs::remove_file(&candidate_manifest_path);

    let mut final_manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    final_manifest_bytes.push(b'\n');
    write_atomic(&target_dir.join("manifest.json"), &final_manifest_bytes)?;

    println!("Sealed 21 payload files + manifest.json successfully!");
    Ok(())
}

fn validated_commit_aad(
    commit: &catbird_server::chat_protocol::wire::ValidatedPublicCommit,
    manifest: &Value,
    sha_field: &str,
) -> Result<Vec<u8>> {
    let expected_sha = manifest["chain"][sha_field]
        .as_str()
        .ok_or_else(|| fail(format!("missing {sha_field}")))?;
    let actual_sha = sha256_hex(commit.aad());
    ensure(
        actual_sha == expected_sha,
        format!("AAD sha256 mismatch for {sha_field}: {actual_sha} != {expected_sha}"),
    )?;
    Ok(commit.aad().to_vec())
}
