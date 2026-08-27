//! Sealer helper for the authoritative `blue.catbird.chat` v1 OpenMLS 0.9 wire corpus.
//!
//! Consumes the candidate wire artifacts emitted by `catbird-mls`, verifies them
//! through production server validation and commit processing paths, encodes the
//! authoritative schema 2 `PublicGroupSnapshot` files, and finalizes the sealed
//! `manifest.json`.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use catbird_server::chat_protocol::snapshot::{
    decode_public_group_snapshot, encode_public_group_snapshot, public_group_snapshot_binding,
    PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle,
};
use catbird_server::chat_protocol::wire::{
    process_public_commit, validate_group_info, validate_public_commit,
    GroupInfoValidationPolicy, PublicCommitValidationPolicy, MAX_GROUP_INFO_WIRE_BYTES,
    MAX_PUBLIC_MESSAGE_WIRE_BYTES,
};
use openmls::prelude::*;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

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
        format!("missing candidate-manifest.json at {}", candidate_manifest_path.display()),
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
    let genesis_binding = public_group_snapshot_binding(
        &genesis_state,
        &genesis_snapshot_bytes,
        &genesis_coordinate,
    )
    .map_err(|e| fail(format!("bind genesis snapshot failed: {e}")))?;

    decode_public_group_snapshot(&genesis_snapshot_bytes, &genesis_binding)
        .map_err(|e| fail(format!("decode genesis snapshot failed: {e}")))?;

    write_atomic(
        &target_dir.join("genesis-public-state.bin"),
        &genesis_snapshot_bytes,
    )?;

    // ── 2. Validate Add Commit and write committed snapshot ─────────────────────
    let commit_bytes = fs::read(target_dir.join("commit-public.mls"))?;
    let validated_commit = validate_public_commit(&commit_bytes, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .map_err(|e| fail(format!("validate Add commit failed: {e}")))?;

    let committed_group_context_hash = decode_hex_32(
        manifest["chain"]["committedGroupContextHashHex"]
            .as_str()
            .ok_or_else(|| fail("missing committedGroupContextHashHex"))?,
        "committedGroupContextHash",
    )?;
    let committed_confirmation_tag = decode_hex_32(
        manifest["chain"]["committedConfirmationTagHex"]
            .as_str()
            .ok_or_else(|| fail("missing committedConfirmationTagHex"))?,
        "committedConfirmationTag",
    )?;

    let add_coord = PublicGroupSnapshotCoordinate::new(
        conversation_id,
        0,
        3,
        group_id,
        1,
        committed_group_context_hash,
        committed_confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    );

    let add_prior_coord = PublicGroupSnapshotCoordinate::new(
        conversation_id,
        0,
        2,
        group_id,
        0,
        genesis_group_context_hash,
        genesis_confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    );
    let add_prior_binding = public_group_snapshot_binding(
        &genesis_state,
        &genesis_snapshot_bytes,
        &add_prior_coord,
    )
    .map_err(|e| fail(format!("bind add prior snapshot failed: {e}")))?;

    let commit_aad = validated_commit_aad(&validated_commit, &manifest, "commitAadSha256Hex")?;
    let processed_commit = process_public_commit(
        &genesis_state,
        validated_commit,
        PublicCommitValidationPolicy {
            expected_aad: &commit_aad,
            trusted_prior_binding: &add_prior_binding,
            expected_next_coordinate: &add_coord,
            now_unix_seconds: evaluation_unix_seconds,
            max_members: 10,
        },
    )
    .map_err(|e| fail(format!("process Add commit failed: {e}")))?;

    let committed_state = processed_commit.into_next_state();
    let committed_snapshot_bytes = encode_public_group_snapshot(&committed_state)
        .map_err(|e| fail(format!("encode committed snapshot failed: {e}")))?;
    let committed_binding = public_group_snapshot_binding(
        &committed_state,
        &committed_snapshot_bytes,
        &add_coord,
    )
    .map_err(|e| fail(format!("bind committed snapshot failed: {e}")))?;

    decode_public_group_snapshot(&committed_snapshot_bytes, &committed_binding)
        .map_err(|e| fail(format!("decode committed snapshot failed: {e}")))?;

    write_atomic(
        &target_dir.join("committed-public-state.bin"),
        &committed_snapshot_bytes,
    )?;

    // ── 3. Validate Generic Commit and write generic snapshot ───────────────────
    let generic_commit_bytes = fs::read(target_dir.join("commit-generic-public.mls"))?;
    let validated_generic_commit =
        validate_public_commit(&generic_commit_bytes, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .map_err(|e| fail(format!("validate generic commit failed: {e}")))?;

    let generic_committed_group_context_hash = decode_hex_32(
        manifest["chain"]["genericCommittedGroupContextHashHex"]
            .as_str()
            .ok_or_else(|| fail("missing genericCommittedGroupContextHashHex"))?,
        "genericCommittedGroupContextHash",
    )?;
    let generic_committed_confirmation_tag = decode_hex_32(
        manifest["chain"]["genericCommittedConfirmationTagHex"]
            .as_str()
            .ok_or_else(|| fail("missing genericCommittedConfirmationTagHex"))?,
        "genericCommittedConfirmationTag",
    )?;

    let generic_next_coord = PublicGroupSnapshotCoordinate::new(
        conversation_id,
        0,
        4,
        group_id,
        2,
        generic_committed_group_context_hash,
        generic_committed_confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    );

    let generic_commit_aad = validated_commit_aad(&validated_generic_commit, &manifest, "genericCommitAadSha256Hex")?;
    let processed_generic = process_public_commit(
        &committed_state,
        validated_generic_commit,
        PublicCommitValidationPolicy {
            expected_aad: &generic_commit_aad,
            trusted_prior_binding: &committed_binding,
            expected_next_coordinate: &generic_next_coord,
            now_unix_seconds: evaluation_unix_seconds,
            max_members: 10,
        },
    )
    .map_err(|e| fail(format!("process generic commit failed: {e}")))?;
    let generic_committed_state = processed_generic.into_next_state();
    let generic_snapshot_bytes = encode_public_group_snapshot(&generic_committed_state)
        .map_err(|e| fail(format!("encode generic committed snapshot failed: {e}")))?;
    let generic_binding = public_group_snapshot_binding(
        &generic_committed_state,
        &generic_snapshot_bytes,
        &generic_next_coord,
    )
    .map_err(|e| fail(format!("bind generic committed snapshot failed: {e}")))?;

    decode_public_group_snapshot(&generic_snapshot_bytes, &generic_binding)
        .map_err(|e| fail(format!("decode generic committed snapshot failed: {e}")))?;

    write_atomic(
        &target_dir.join("committed-generic-public-state.bin"),
        &generic_snapshot_bytes,
    )?;

    // ── 4. Validate Remove Commit and write remove snapshot ────────────────────
    let remove_commit_bytes = fs::read(target_dir.join("commit-remove-public.mls"))?;
    let validated_remove_commit =
        validate_public_commit(&remove_commit_bytes, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .map_err(|e| fail(format!("validate remove commit failed: {e}")))?;

    let remove_committed_group_context_hash = decode_hex_32(
        manifest["chain"]["removeCommittedGroupContextHashHex"]
            .as_str()
            .ok_or_else(|| fail("missing removeCommittedGroupContextHashHex"))?,
        "removeCommittedGroupContextHash",
    )?;
    let remove_committed_confirmation_tag = decode_hex_32(
        manifest["chain"]["removeCommittedConfirmationTagHex"]
            .as_str()
            .ok_or_else(|| fail("missing removeCommittedConfirmationTagHex"))?,
        "removeCommittedConfirmationTag",
    )?;

    let remove_next_coord = PublicGroupSnapshotCoordinate::new(
        conversation_id,
        0,
        5,
        group_id,
        3,
        remove_committed_group_context_hash,
        remove_committed_confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    );

    let remove_commit_aad = validated_commit_aad(&validated_remove_commit, &manifest, "removeCommitAadSha256Hex")?;
    let processed_remove = process_public_commit(
        &generic_committed_state,
        validated_remove_commit,
        PublicCommitValidationPolicy {
            expected_aad: &remove_commit_aad,
            trusted_prior_binding: &generic_binding,
            expected_next_coordinate: &remove_next_coord,
            now_unix_seconds: evaluation_unix_seconds,
            max_members: 10,
        },
    )
    .map_err(|e| fail(format!("process remove commit failed: {e}")))?;

    let remove_committed_state = processed_remove.into_next_state();
    let remove_snapshot_bytes = encode_public_group_snapshot(&remove_committed_state)
        .map_err(|e| fail(format!("encode remove committed snapshot failed: {e}")))?;
    let remove_binding = public_group_snapshot_binding(
        &remove_committed_state,
        &remove_snapshot_bytes,
        &remove_next_coord,
    )
    .map_err(|e| fail(format!("bind remove committed snapshot failed: {e}")))?;

    decode_public_group_snapshot(&remove_snapshot_bytes, &remove_binding)
        .map_err(|e| fail(format!("decode remove committed snapshot failed: {e}")))?;

    write_atomic(
        &target_dir.join("committed-remove-public-state.bin"),
        &remove_snapshot_bytes,
    )?;

    // ── 5. Validate Rejoin Commit and write rejoin snapshot ────────────────────
    let rejoin_commit_bytes = fs::read(target_dir.join("commit-rejoin-public.mls"))?;
    let validated_rejoin_commit =
        validate_public_commit(&rejoin_commit_bytes, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
            .map_err(|e| fail(format!("validate rejoin commit failed: {e}")))?;

    let rejoin_committed_group_context_hash = decode_hex_32(
        manifest["chain"]["rejoinGroupContextHashHex"]
            .as_str()
            .ok_or_else(|| fail("missing rejoinGroupContextHashHex"))?,
        "rejoinGroupContextHash",
    )?;
    let rejoin_committed_confirmation_tag = decode_hex_32(
        manifest["chain"]["rejoinConfirmationTagHex"]
            .as_str()
            .ok_or_else(|| fail("missing rejoinConfirmationTagHex"))?,
        "rejoinConfirmationTag",
    )?;

    let rejoin_next_coord = PublicGroupSnapshotCoordinate::new(
        conversation_id,
        0,
        8,
        group_id,
        4,
        rejoin_committed_group_context_hash,
        rejoin_committed_confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    );

    let rejoin_prior_coord = PublicGroupSnapshotCoordinate::new(
        conversation_id,
        0,
        7,
        group_id,
        3,
        remove_committed_group_context_hash,
        remove_committed_confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    );
    let rejoin_prior_binding = public_group_snapshot_binding(
        &remove_committed_state,
        &remove_snapshot_bytes,
        &rejoin_prior_coord,
    )
    .map_err(|e| fail(format!("bind rejoin prior snapshot failed: {e}")))?;

    let rejoin_commit_aad = validated_commit_aad(&validated_rejoin_commit, &manifest, "rejoinCommitAadSha256Hex")?;
    let processed_rejoin = process_public_commit(
        &remove_committed_state,
        validated_rejoin_commit,
        PublicCommitValidationPolicy {
            expected_aad: &rejoin_commit_aad,
            trusted_prior_binding: &rejoin_prior_binding,
            expected_next_coordinate: &rejoin_next_coord,
            now_unix_seconds: evaluation_unix_seconds,
            max_members: 10,
        },
    )
    .map_err(|e| fail(format!("process rejoin commit failed: {e}")))?;

    let rejoin_committed_state = processed_rejoin.into_next_state();
    let rejoin_snapshot_bytes = encode_public_group_snapshot(&rejoin_committed_state)
        .map_err(|e| fail(format!("encode rejoin committed snapshot failed: {e}")))?;
    let rejoin_binding = public_group_snapshot_binding(
        &rejoin_committed_state,
        &rejoin_snapshot_bytes,
        &rejoin_next_coord,
    )
    .map_err(|e| fail(format!("bind rejoin committed snapshot failed: {e}")))?;

    decode_public_group_snapshot(&rejoin_snapshot_bytes, &rejoin_binding)
        .map_err(|e| fail(format!("decode rejoin committed snapshot failed: {e}")))?;

    write_atomic(
        &target_dir.join("committed-rejoin-public-state.bin"),
        &rejoin_snapshot_bytes,
    )?;

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
        ("commit-public.mls", "mlsMessagePublicCommit", Some(1), Some(0)),
        ("welcome.mls", "mlsMessageWelcome", Some(3), Some(1)),
        ("application-frame.cbor", "canonicalDagCborApplicationFrame", None, Some(1)),
        ("application-private.mls", "mlsMessagePrivateApplication", Some(2), Some(1)),
        ("genesis-public-state.bin", "publicGroupSnapshot", None, Some(0)),
        ("committed-public-state.bin", "publicGroupSnapshot", None, Some(1)),
        ("commit-generic-public.mls", "mlsMessagePublicCommit", Some(1), Some(1)),
        ("committed-generic-public-state.bin", "publicGroupSnapshot", None, Some(2)),
        ("commit-remove-public.mls", "mlsMessagePublicCommit", Some(1), Some(2)),
        ("committed-remove-public-state.bin", "publicGroupSnapshot", None, Some(3)),
        ("rejoin-key-package.mls", "mlsMessageKeyPackage", Some(5), None),
        ("rejoin-key-package-inner.tls", "innerKeyPackageTls", None, None),
        ("rejoin-key-package-ref.bin", "rfc9420KeyPackageRef", None, None),
        ("commit-rejoin-public.mls", "mlsMessagePublicCommit", Some(1), Some(3)),
        ("rejoin-welcome.mls", "mlsMessageWelcome", Some(3), Some(4)),
        ("committed-rejoin-public-state.bin", "publicGroupSnapshot", None, Some(4)),
        ("creation-signed-request.cbor", "canonicalDagCborSignedCreation", None, Some(0)),
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

    // Remove candidate-manifest.json if present
    if candidate_manifest_path.exists() {
        let _ = fs::remove_file(&candidate_manifest_path);
    }

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
