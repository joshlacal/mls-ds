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
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const EXPECTED_FORK_REVISION: &str = "3ea192fc346663fba5db63aa8c90ccc3ae49f12b";

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

fn lock_string_field(block: &str, field: &str) -> Option<String> {
    let prefix = format!("{field} = \"");
    block.lines().find_map(|line| {
        let rest = line.strip_prefix(&prefix)?;
        Some(rest.strip_suffix('"')?.to_owned())
    })
}

fn verify_server_fork_lock(lock_path: &Path) -> Result<(String, String)> {
    let lock_text = fs::read_to_string(lock_path)?;
    for block in lock_text.split("[[package]]").skip(1) {
        if lock_string_field(block, "name").as_deref() == Some("openmls") {
            let source = lock_string_field(block, "source")
                .ok_or_else(|| fail("server Cargo.lock openmls package has no source"))?;
            let version = lock_string_field(block, "version")
                .ok_or_else(|| fail("server Cargo.lock openmls package has no version"))?;
            ensure(
                source.starts_with("git+https://github.com/joshlacal/openmls")
                    || source.starts_with("git+https://github.com/openmls/openmls"),
                format!("openmls source must be git, got {source}"),
            )?;
            ensure(
                source.contains(EXPECTED_FORK_REVISION),
                format!("openmls fork revision in server Cargo.lock must match {EXPECTED_FORK_REVISION}, got {source}"),
            )?;
            ensure(
                lock_string_field(block, "checksum").is_none(),
                "openmls git package must not have a checksum",
            )?;
            return Ok((source, version));
        }
    }
    Err(fail("openmls package not found in server Cargo.lock"))
}

macro_rules! creation_fixed_bytes {
    ($module:ident, $length:expr) => {
        mod $module {
            use serde::Serializer;
            pub fn serialize<S>(bytes: &[u8; $length], serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(bytes)
            }
        }
    };
}
creation_fixed_bytes!(cbytes16, 16);
creation_fixed_bytes!(cbytes32, 32);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PriorConversationContext<'a> {
    #[serde(with = "cbytes16")]
    conversation_id: [u8; 16],
    generation: u64,
    state_version: u64,
    #[serde(with = "cbytes32")]
    group_id: [u8; 32],
    epoch: u64,
    #[serde(with = "cbytes32")]
    group_context_hash: [u8; 32],
    #[serde(with = "cbytes32")]
    confirmation_tag: [u8; 32],
    lifecycle: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommitAad<'a> {
    protocol_version: &'static str,
    #[serde(with = "cbytes16")]
    conversation_id: [u8; 16],
    generation: u64,
    #[serde(with = "cbytes16")]
    transition_id: [u8; 16],
    prior: PriorConversationContext<'a>,
}
#[allow(clippy::too_many_arguments)]
fn derive_expected_commit_aad(
    conversation_id: [u8; 16],
    generation: u64,
    transition_id: [u8; 16],
    prior_state_version: u64,
    group_id: [u8; 32],
    prior_epoch: u64,
    prior_group_context_hash: [u8; 32],
    prior_confirmation_tag: [u8; 32],
) -> Result<Vec<u8>> {
    let aad_body = CommitAad {
        protocol_version: "1",
        conversation_id,
        generation,
        transition_id,
        prior: PriorConversationContext {
            conversation_id,
            generation,
            state_version: prior_state_version,
            group_id,
            epoch: prior_epoch,
            group_context_hash: prior_group_context_hash,
            confirmation_tag: prior_confirmation_tag,
            lifecycle: "active",
        },
    };
    let cbor = serde_ipld_dagcbor::to_vec(&aad_body)?;
    let mut out = Vec::with_capacity(b"CATBIRD-CHAT-MLS-AAD-COMMIT\0".len() + cbor.len());
    out.extend_from_slice(b"CATBIRD-CHAT-MLS-AAD-COMMIT\0");
    out.extend_from_slice(&cbor);
    Ok(out)
}

struct SealedLink {
    state: PublicGroupState,
    snapshot_bytes: Vec<u8>,
    epoch: u64,
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
}

struct CommitLinkSpec<'a> {
    label: &'a str,
    commit_file: &'a str,
    transition_id_field: &'a str,
    group_context_hash_field: &'a str,
    confirmation_tag_field: &'a str,
    prior_state_version: u64,
    next_state_version: u64,
    next_epoch: u64,
    snapshot_file: &'a str,
}

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

    let transition_id = decode_hex_16(
        manifest["identifiers"][spec.transition_id_field]
            .as_str()
            .ok_or_else(|| fail(format!("missing {}", spec.transition_id_field)))?,
        spec.transition_id_field,
    )?;

    // Independently derive expected AAD from authoritative fields
    let expected_aad = derive_expected_commit_aad(
        conversation_id,
        0,
        transition_id,
        spec.prior_state_version,
        group_id,
        prior.epoch,
        prior.group_context_hash,
        prior.confirmation_tag,
    )?;
    ensure(
        validated.aad() == expected_aad.as_slice(),
        format!("commit AAD mismatch for {label}"),
    )?;

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

    let processed = process_public_commit(
        &prior.state,
        validated,
        PublicCommitValidationPolicy {
            expected_aad: &expected_aad,
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

    let server_manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mls_ds_root = server_manifest_dir
        .parent()
        .ok_or_else(|| fail("server has no parent"))?;
    let (fork_source, fork_version) = verify_server_fork_lock(&mls_ds_root.join("Cargo.lock"))?;
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

    // Add commit: 2 -> 3 (epoch 0 -> 1)
    let add_spec = CommitLinkSpec {
        label: "Add commit",
        commit_file: "commit-public.mls",
        transition_id_field: "transitionIdHex",
        group_context_hash_field: "committedGroupContextHashHex",
        confirmation_tag_field: "committedConfirmationTagHex",
        prior_state_version: 2,
        next_state_version: 3,
        next_epoch: 1,
        snapshot_file: "committed-public-state.bin",
    };
    link = seal_commit_link(
        &target_dir,
        &manifest,
        conversation_id,
        group_id,
        evaluation_unix_seconds,
        &link,
        &add_spec,
    )?;

    // Generic commit: 3 -> 4 (epoch 1 -> 2)
    let generic_spec = CommitLinkSpec {
        label: "generic commit",
        commit_file: "commit-generic-public.mls",
        transition_id_field: "genericTransitionIdHex",
        group_context_hash_field: "genericCommittedGroupContextHashHex",
        confirmation_tag_field: "genericCommittedConfirmationTagHex",
        prior_state_version: 3,
        next_state_version: 4,
        next_epoch: 2,
        snapshot_file: "committed-generic-public-state.bin",
    };
    link = seal_commit_link(
        &target_dir,
        &manifest,
        conversation_id,
        group_id,
        evaluation_unix_seconds,
        &link,
        &generic_spec,
    )?;

    // Prove server rejection expectation for metadata AppData commit
    let appdata_commit_bytes = fs::read(target_dir.join("commit-metadata-appdata-public.mls"))?;
    let appdata_validation_res =
        validate_public_commit(&appdata_commit_bytes, MAX_PUBLIC_MESSAGE_WIRE_BYTES);
    ensure(
        appdata_validation_res.is_err(),
        "server must reject metadata AppData commit under Add/Remove-only constraint",
    )?;

    // Remove commit: 4 -> 5 (epoch 2 -> 3)
    let remove_spec = CommitLinkSpec {
        label: "remove commit",
        commit_file: "commit-remove-public.mls",
        transition_id_field: "leaveFulfillmentTransitionIdHex",
        group_context_hash_field: "removeCommittedGroupContextHashHex",
        confirmation_tag_field: "removeCommittedConfirmationTagHex",
        prior_state_version: 4,
        next_state_version: 5,
        next_epoch: 3,
        snapshot_file: "committed-remove-public-state.bin",
    };
    link = seal_commit_link(
        &target_dir,
        &manifest,
        conversation_id,
        group_id,
        evaluation_unix_seconds,
        &link,
        &remove_spec,
    )?;

    // Rejoin commit: prior state version 7 -> next state version 8 (epoch 3 -> 4)
    // Bind prior at stateVersion 7 (preserving epoch 3 public state)
    let rejoin_spec = CommitLinkSpec {
        label: "rejoin commit",
        commit_file: "commit-rejoin-public.mls",
        transition_id_field: "rejoinTransitionIdHex",
        group_context_hash_field: "rejoinGroupContextHashHex",
        confirmation_tag_field: "rejoinConfirmationTagHex",
        prior_state_version: 7,
        next_state_version: 8,
        next_epoch: 4,
        snapshot_file: "committed-rejoin-public-state.bin",
    };
    let _rejoin_link = seal_commit_link(
        &target_dir,
        &manifest,
        conversation_id,
        group_id,
        evaluation_unix_seconds,
        &link,
        &rejoin_spec,
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

    let payload_files: [(&str, &'static str, Option<u16>, Option<u64>); 23] = [
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
            "commit-metadata-appdata-public.mls",
            "mlsMessagePublicCommit",
            Some(1),
            Some(2),
        ),
        (
            "own-pending-commit.mls",
            "mlsMessagePublicCommit",
            Some(1),
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
        if filename == "commit-metadata-appdata-public.mls" {
            record.insert("serverRejectionExpected".into(), json!(true));
            record.insert("serverRejectionReason".into(), json!("ProposalNotAllowed"));
        }
        if let Some(wf) = wire_format {
            record.insert("wireFormat".into(), json!(wf));
        }
        if let Some(ep) = epoch {
            record.insert("epoch".into(), json!(ep));
        }
        file_manifest.insert(filename.to_owned(), Value::Object(record));
    }

    // Sealer and server provenance
    let sealer_source = server_manifest_dir.join("examples/seal_mls_chat_crypto_wire_v09.rs");
    let sealer_source_sha256 = sha256_hex(&fs::read(&sealer_source)?);
    let server_cargo_manifest_sha256 =
        sha256_hex(&fs::read(server_manifest_dir.join("Cargo.toml"))?);
    let server_cargo_lock_sha256 = sha256_hex(&fs::read(mls_ds_root.join("Cargo.lock"))?);
    let mut server_snapshot_wire_hasher = Sha256::new();
    for rel_path in ["src/chat_protocol/snapshot.rs", "src/chat_protocol/wire.rs"] {
        let path = server_manifest_dir.join(rel_path);
        let bytes = fs::read(&path)?;
        server_snapshot_wire_hasher.update(rel_path.as_bytes());
        server_snapshot_wire_hasher.update([0u8]);
        server_snapshot_wire_hasher.update((bytes.len() as u64).to_be_bytes());
        server_snapshot_wire_hasher.update(&bytes);
    }
    let server_snapshot_wire_source_sha256 = hex::encode(server_snapshot_wire_hasher.finalize());

    manifest["sealer"] = json!({
        "source": "mls-ds/server/examples/seal_mls_chat_crypto_wire_v09.rs",
        "sourceSha256Hex": sealer_source_sha256,
        "serverCargoManifestSha256Hex": server_cargo_manifest_sha256,
        "serverCargoLockSha256Hex": server_cargo_lock_sha256,
        "serverSnapshotWireSourceSha256Hex": server_snapshot_wire_source_sha256,
        "openmlsForkSource": fork_source,
        "openmlsForkVersion": fork_version,
        "openmlsForkRevision": EXPECTED_FORK_REVISION,
    });

    manifest["publicSnapshots"] = public_snapshots_profile;
    manifest["files"] = Value::Object(file_manifest);

    // Fail-closed remove candidate manifest
    fs::remove_file(&candidate_manifest_path)?;
    ensure(
        !candidate_manifest_path.exists(),
        "candidate-manifest.json must not remain after sealing",
    )?;

    let mut final_manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    final_manifest_bytes.push(b'\n');
    write_atomic(&target_dir.join("manifest.json"), &final_manifest_bytes)?;

    println!("Sealed 23 payload files + manifest.json successfully!");
    Ok(())
}
