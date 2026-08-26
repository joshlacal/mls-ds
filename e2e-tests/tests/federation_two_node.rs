//! Real two-DS federation scenario integration test.
//!
//! Run with: `cargo test --test federation_two_node -- --ignored --nocapture`

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use catbird_mls::chat_v2::transcript::signed::SignedWrapper;
use catbird_mls::chat_v2::transcript::strict_json::decode_strict_json;
use catbird_mls::chat_v2::transcript::value::CanonicalValue;
use catbird_mls::chat_v2::transcript::{
    application_entry_fingerprint, control_entry_fingerprint, project_signed_body,
    ControlEntryKind, ControlServerFields, EntryRow, SignedMutationKind, SigningTranscript,
};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use mls_e2e_tests::federation::boot_two_node_cluster;
use mls_e2e_tests::mls_engine::MlsEngine;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::pkcs8::DecodePrivateKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"CATBIRD-CLEAN-FEDERATION-ENVELOPE-V1\0";
const RECEIPT_SIGNING_DOMAIN: &[u8] = b"CATBIRD-CLEAN-FEDERATION-RECEIPT-V1\0";

const DELIVER_MESSAGE_NSID: &str = "blue.catbird.mlsDS.deliverMessage";
const DELIVER_WELCOME_NSID: &str = "blue.catbird.mlsDS.deliverWelcome";
const SUBMIT_COMMIT_NSID: &str = "blue.catbird.mlsDS.submitCommit";

// Corpus crypto-wire fixtures for canonical commit verification
const MANIFEST_BYTES: &[u8] =
    include_bytes!("../../server/tests/fixtures/crypto-wire/manifest.json");
const GENESIS_PUBLIC_STATE: &[u8] =
    include_bytes!("../../server/tests/fixtures/crypto-wire/genesis-public-state.bin");
const COMMITTED_PUBLIC_STATE: &[u8] =
    include_bytes!("../../server/tests/fixtures/crypto-wire/committed-public-state.bin");
const COMMIT_GENERIC_PUBLIC_MLS: &[u8] =
    include_bytes!("../../server/tests/fixtures/crypto-wire/commit-generic-public.mls");
const GROUP_INFO_MLS: &[u8] =
    include_bytes!("../../server/tests/fixtures/crypto-wire/group-info.mls");
const COMMIT_PUBLIC_MLS: &[u8] =
    include_bytes!("../../server/tests/fixtures/crypto-wire/commit-public.mls");

const ALICE_SIGNING_SEED: [u8; 32] = [
    0x38, 0x8f, 0x37, 0x73, 0x57, 0x9e, 0x8a, 0x2b, 0x5d, 0x57, 0x2d, 0x3b, 0x19, 0x85, 0x55, 0xa6,
    0x93, 0x6f, 0xb7, 0xf0, 0x13, 0xb8, 0x58, 0xe2, 0x69, 0xf6, 0x4f, 0x6e, 0x8c, 0x6b, 0x12, 0x8d,
];

const BOB_SIGNING_SEED: [u8; 32] = [
    0xd4, 0xa1, 0xc4, 0x8e, 0x33, 0x92, 0x40, 0x8e, 0x24, 0x40, 0x90, 0x3f, 0xc5, 0x67, 0x8d, 0xa5,
    0x69, 0x98, 0xeb, 0x66, 0xeb, 0xb8, 0xa9, 0x64, 0xa7, 0xe4, 0xe4, 0xc2, 0xad, 0x82, 0xe9, 0xb5,
];

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("valid hex string")
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N}-byte array"))
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> &'a [u8] {
    let slice = &bytes[*offset..*offset + len];
    *offset += len;
    slice
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> u16 {
    u16::from_be_bytes(take(bytes, offset, 2).try_into().expect("two bytes"))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> u32 {
    u32::from_be_bytes(take(bytes, offset, 4).try_into().expect("four bytes"))
}

fn snapshot_records(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut offset = 0;
    let _magic: [u8; 8] = take(bytes, &mut offset, 8).try_into().expect("magic");
    let _schema = take_u16(bytes, &mut offset);
    let openmls_len = usize::from(take_u16(bytes, &mut offset));
    let _openmls = take(bytes, &mut offset, openmls_len).to_vec();
    let storage_len = usize::from(take_u16(bytes, &mut offset));
    let _storage = take(bytes, &mut offset, storage_len).to_vec();
    let count = usize::try_from(take_u32(bytes, &mut offset)).expect("record count");
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let key_len = usize::try_from(take_u32(bytes, &mut offset)).expect("key length");
        let key = take(bytes, &mut offset, key_len).to_vec();
        let value_len = usize::try_from(take_u32(bytes, &mut offset)).expect("value length");
        let value = take(bytes, &mut offset, value_len).to_vec();
        records.push((key, value));
    }
    assert_eq!(offset, bytes.len(), "frozen snapshot is exact");
    records
}

fn json_bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .expect("byte array")
        .iter()
        .map(|byte| u8::try_from(byte.as_u64().expect("byte")).expect("u8"))
        .collect()
}

fn extract_tree_summary_from_snapshot(encoded: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let records = snapshot_records(encoded);
    let group_context: Value = records
        .iter()
        .find(|(key, _)| key.starts_with(b"GroupContext"))
        .map(|(_, value)| serde_json::from_slice(value).expect("GroupContext json"))
        .expect("GroupContext record");
    let tree_hash: [u8; 32] = json_bytes(&group_context["tree_hash"]["vec"])
        .try_into()
        .expect("32-byte tree hash");
    let tree: Value = records
        .iter()
        .find(|(key, _)| key.starts_with(b"Tree"))
        .map(|(_, value)| serde_json::from_slice(value).expect("Tree json"))
        .expect("Tree record");
    let mut leaves: Vec<(u32, Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for (leaf_index, stored) in tree["tree"]["leaf_nodes"]
        .as_array()
        .expect("leaf array")
        .iter()
        .enumerate()
    {
        if let Some(node) = stored.get("node") {
            if !node.is_null() {
                let payload = &node["payload"];
                let cred =
                    json_bytes(&payload["credential"]["serialized_credential_content"]["vec"]);
                let sig_key = json_bytes(&payload["signature_key"]["value"]["vec"]);
                let enc_key = json_bytes(&payload["encryption_key"]["key"]["vec"]);
                leaves.push((
                    u32::try_from(leaf_index).expect("leaf index"),
                    cred,
                    sig_key,
                    enc_key,
                ));
            }
        }
    }
    let leaf_slices: Vec<(u32, &[u8], &[u8], &[u8])> = leaves
        .iter()
        .map(|(idx, c, s, e)| (*idx, c.as_slice(), s.as_slice(), e.as_slice()))
        .collect();
    make_tree_summary_bytes(&tree_hash, &leaf_slices)
}

fn lp_bytes(bytes: &[u8], buf: &mut Vec<u8>) {
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn compute_message_envelope_digest(
    delivery_id: Uuid,
    conversation_id: Uuid,
    sender_ds_did: &str,
    receiver_ds_did: &str,
    sequencer_did: &str,
    sequencer_term: u64,
    recipient_did: &str,
    entry_id: Uuid,
    seq: u64,
    accepted_payload_sha256: &[u8; 32],
    outer_entry_fingerprint: &[u8; 32],
    entry_bytes: &[u8],
    signed_request_bytes: &[u8],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(ENVELOPE_DIGEST_DOMAIN);
    lp_bytes(DELIVER_MESSAGE_NSID.as_bytes(), &mut buf);
    buf.extend_from_slice(delivery_id.as_bytes());
    buf.extend_from_slice(conversation_id.as_bytes());
    lp_bytes(sender_ds_did.as_bytes(), &mut buf);
    lp_bytes(receiver_ds_did.as_bytes(), &mut buf);
    lp_bytes(sequencer_did.as_bytes(), &mut buf);
    buf.extend_from_slice(&sequencer_term.to_be_bytes());

    lp_bytes(recipient_did.as_bytes(), &mut buf);
    buf.extend_from_slice(entry_id.as_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(accepted_payload_sha256);
    buf.extend_from_slice(outer_entry_fingerprint);

    let entry_sha256: [u8; 32] = Sha256::digest(entry_bytes).into();
    buf.extend_from_slice(&entry_sha256);
    let signed_req_sha256: [u8; 32] = Sha256::digest(signed_request_bytes).into();
    buf.extend_from_slice(&signed_req_sha256);

    Sha256::digest(&buf).into()
}

#[allow(clippy::too_many_arguments)]
fn compute_welcome_envelope_digest(
    delivery_id: Uuid,
    conversation_id: Uuid,
    sender_ds_did: &str,
    receiver_ds_did: &str,
    sequencer_did: &str,
    sequencer_term: u64,
    recipient_did: &str,
    recipient_device_id: Uuid,
    welcome_id: Uuid,
    recovery_request_id: Uuid,
    key_package_ref: &[u8; 32],
    _welcome_bytes: &[u8],
    welcome_sha256: &[u8; 32],
    entry_bytes: &[u8],
    signed_request_bytes: &[u8],
    entry_id: Uuid,
    seq: u64,
    accepted_payload_sha256: &[u8; 32],
    outer_entry_fingerprint: &[u8; 32],
    generation: u64,
    state_version: u64,
    group_id: &[u8; 32],
    epoch: u64,
    group_context_hash: &[u8; 32],
    confirmation_tag: &[u8; 32],
    public_snapshot_sha256: &[u8; 32],
    tree_summary_sha256: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1024);
    buf.extend_from_slice(ENVELOPE_DIGEST_DOMAIN);
    lp_bytes(DELIVER_WELCOME_NSID.as_bytes(), &mut buf);
    buf.extend_from_slice(delivery_id.as_bytes());
    buf.extend_from_slice(conversation_id.as_bytes());
    lp_bytes(sender_ds_did.as_bytes(), &mut buf);
    lp_bytes(receiver_ds_did.as_bytes(), &mut buf);
    lp_bytes(sequencer_did.as_bytes(), &mut buf);
    buf.extend_from_slice(&sequencer_term.to_be_bytes());

    lp_bytes(recipient_did.as_bytes(), &mut buf);
    buf.extend_from_slice(recipient_device_id.as_bytes());
    buf.extend_from_slice(welcome_id.as_bytes());
    buf.extend_from_slice(recovery_request_id.as_bytes());
    buf.extend_from_slice(key_package_ref);
    buf.extend_from_slice(welcome_sha256);
    let entry_sha256: [u8; 32] = Sha256::digest(entry_bytes).into();
    buf.extend_from_slice(&entry_sha256);
    let signed_req_sha256: [u8; 32] = Sha256::digest(signed_request_bytes).into();
    buf.extend_from_slice(&signed_req_sha256);
    buf.extend_from_slice(entry_id.as_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(accepted_payload_sha256);
    buf.extend_from_slice(outer_entry_fingerprint);

    buf.extend_from_slice(&generation.to_be_bytes());
    buf.extend_from_slice(&state_version.to_be_bytes());
    buf.extend_from_slice(group_id);
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(group_context_hash);
    buf.extend_from_slice(confirmation_tag);
    buf.extend_from_slice(public_snapshot_sha256);
    buf.extend_from_slice(tree_summary_sha256);

    Sha256::digest(&buf).into()
}

fn compute_commit_envelope_digest(
    delivery_id: Uuid,
    conversation_id: Uuid,
    sender_ds_did: &str,
    receiver_ds_did: &str,
    sequencer_did: &str,
    sequencer_term: u64,
    received_at: &str,
    signed_request_bytes: &[u8],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(ENVELOPE_DIGEST_DOMAIN);
    lp_bytes(SUBMIT_COMMIT_NSID.as_bytes(), &mut buf);
    buf.extend_from_slice(delivery_id.as_bytes());
    buf.extend_from_slice(conversation_id.as_bytes());
    lp_bytes(sender_ds_did.as_bytes(), &mut buf);
    lp_bytes(receiver_ds_did.as_bytes(), &mut buf);
    lp_bytes(sequencer_did.as_bytes(), &mut buf);
    buf.extend_from_slice(&sequencer_term.to_be_bytes());
    lp_bytes(received_at.as_bytes(), &mut buf);

    let signed_req_sha256: [u8; 32] = Sha256::digest(signed_request_bytes).into();
    buf.extend_from_slice(&signed_req_sha256);

    Sha256::digest(&buf).into()
}

fn canonical_receipt_bytes(
    endpoint: &str,
    delivery_id: Uuid,
    conversation_id: Uuid,
    sender_ds_did: &str,
    receiver_ds_did: &str,
    sequencer_did: &str,
    sequencer_term: u64,
    envelope_sha256: &[u8; 32],
    result_sha256: &[u8; 32],
    source_locator: Option<(Uuid, u64, &[u8; 32], &[u8; 32])>,
    completed_at_rfc3339: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(RECEIPT_SIGNING_DOMAIN);
    lp_bytes(b"1", &mut buf);
    lp_bytes(endpoint.as_bytes(), &mut buf);
    buf.extend_from_slice(delivery_id.as_bytes());
    buf.extend_from_slice(conversation_id.as_bytes());
    lp_bytes(sender_ds_did.as_bytes(), &mut buf);
    lp_bytes(receiver_ds_did.as_bytes(), &mut buf);
    lp_bytes(sequencer_did.as_bytes(), &mut buf);
    buf.extend_from_slice(&sequencer_term.to_be_bytes());
    buf.extend_from_slice(envelope_sha256);
    buf.extend_from_slice(result_sha256);

    if let Some((entry_id, seq, payload_sha, fp)) = source_locator {
        buf.push(1u8);
        buf.extend_from_slice(entry_id.as_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(payload_sha);
        buf.extend_from_slice(fp);
    } else {
        buf.push(0u8);
    }
    lp_bytes(completed_at_rfc3339.as_bytes(), &mut buf);
    buf
}

fn make_tree_summary_bytes(
    tree_hash: &[u8; 32],
    leaves: &[(u32, &[u8], &[u8], &[u8])],
) -> (Vec<u8>, [u8; 32]) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"CBTSUM01");
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(tree_hash);
    bytes.extend_from_slice(&(leaves.len() as u16).to_be_bytes());
    for (leaf_index, cred, sig_key, enc_key) in leaves {
        bytes.extend_from_slice(&leaf_index.to_be_bytes());
        bytes.extend_from_slice(&(cred.len() as u16).to_be_bytes());
        bytes.extend_from_slice(cred);
        bytes.extend_from_slice(sig_key);
        bytes.extend_from_slice(enc_key);
    }
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    (bytes, sha256)
}

struct TestIdentity {
    did: String,
    device_id: Uuid,
    key_id: String,
    signing_key: Ed25519SigningKey,
    public_key: [u8; 32],
    engine: MlsEngine,
}

impl TestIdentity {
    fn new(label: &str) -> Self {
        let bytes: [u8; 15] = Uuid::new_v4().as_bytes()[..15].try_into().unwrap();
        let suffix: String = (0..24)
            .map(|i| {
                let value = (bytes[i % 15] as usize + i * 7) % 32;
                char::from(b"abcdefghijklmnopqrstuvwxyz234567"[value])
            })
            .collect();
        let did = format!("did:plc:{suffix}");
        let device_id = Uuid::new_v4();
        let mut seed = [0u8; 32];
        seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        let signing_key = Ed25519SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&public_key));
        let engine = MlsEngine::new(label).expect("create MlsEngine");
        Self {
            did,
            device_id,
            key_id,
            signing_key,
            public_key,
            engine,
        }
    }
}

fn make_creation_body_with_invitee(
    convo_id: Uuid,
    entry_id: Uuid,
    creator: &TestIdentity,
    invitee: Option<&TestIdentity>,
    group_id: &[u8; 32],
    genesis_group_context_hash: &[u8; 32],
    genesis_confirmation_tag: &[u8; 32],
    genesis_group_info: &[u8],
    metadata_ciphertext: &[u8],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let mut participants = vec![json!({
        "userDid": creator.did,
        "status": "active",
        "role": "admin"
    })];
    if let Some(inv) = invitee {
        participants.push(json!({
            "userDid": inv.did,
            "status": "pending",
            "role": "member",
            "invitationProvenance": {
                "invitationTransitionId": entry_id.to_string(),
                "invitedByDid": creator.did,
                "invitedByDeviceId": creator.device_id.to_string()
            }
        }));
    }
    participants.sort_by(|a, b| {
        a["userDid"]
            .as_str()
            .unwrap()
            .cmp(b["userDid"].as_str().unwrap())
    });
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#creationBody",
        "signatureDomain": "CATBIRD-CHAT-CREATE\u{0000}",
        "conversationId": convo_id.to_string(),
        "conversationKind": "group",
        "transitionId": entry_id.to_string(),
        "idempotencyKey": entry_id.to_string(),
        "actorDid": creator.did,
        "actorDeviceId": creator.device_id.to_string(),
        "keyId": creator.key_id,
        "authGeneration": 1,
        "absence": true,
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 0,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(genesis_group_context_hash),
            "confirmationTag": STANDARD.encode(genesis_confirmation_tag),
            "lifecycle": "active"
        },
        "manifest": {
            "actorLeaf": {
                "userDid": creator.did,
                "deviceId": creator.device_id.to_string(),
                "leafOrigin": "genesis"
            },
            "participants": participants
        },
        "genesisGroupInfo": {
            "framing": "mlsMessage",
            "contentType": "groupInfo",
            "bytes": STANDARD.encode(genesis_group_info),
            "sha256": STANDARD.encode(Sha256::digest(genesis_group_info))
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 0,
                "groupContextHash": STANDARD.encode(genesis_group_context_hash),
                "confirmationTag": STANDARD.encode(genesis_confirmation_tag),
            },
            "originTransitionId": entry_id.to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0x73_u8; 12]),
            "ciphertext": STANDARD.encode(metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": creator.did,
                "authorDeviceId": creator.device_id.to_string(),
                "authorKeyId": creator.key_id,
                "signaturePublicKey": STANDARD.encode(&creator.public_key),
                "authGenerationAtOrigin": 1,
                "originTransitionId": entry_id.to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        },
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    });

    let unsigned_bytes = serde_json::to_vec(&unsigned).unwrap();
    let strict = decode_strict_json(&unsigned_bytes).unwrap();
    let projected = project_signed_body(SignedMutationKind::Creation, &strict).unwrap();
    let mutation = SigningTranscript::build_for(SignedMutationKind::Creation, &projected).unwrap();
    let sig = creator.signing_key.sign(mutation.bytes());
    let wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode(sig.to_bytes()),
    });
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

fn make_acceptance_body(
    convo_id: Uuid,
    transition_id: Uuid,
    recovery_request_id: Uuid,
    invitation_transition_id: Uuid,
    actor: &TestIdentity,
    inviter: &TestIdentity,
    group_id: &[u8; 32],
    prior_group_context_hash: &[u8; 32],
    prior_confirmation_tag: &[u8; 32],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#participantAcceptanceBody",
        "signatureDomain": "CATBIRD-CHAT-ACCEPT\u{0000}",
        "transitionId": transition_id.to_string(),
        "recoveryRequestId": recovery_request_id.to_string(),
        "idempotencyKey": transition_id.to_string(),
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 1,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(prior_group_context_hash),
            "confirmationTag": STANDARD.encode(prior_confirmation_tag),
            "lifecycle": "active"
        },
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 2,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(prior_group_context_hash),
            "confirmationTag": STANDARD.encode(prior_confirmation_tag),
            "lifecycle": "active"
        },
        "invitationProvenance": {
            "invitationTransitionId": invitation_transition_id.to_string(),
            "invitedByDid": inviter.did,
            "invitedByDeviceId": inviter.device_id.to_string()
        }
    });

    let unsigned_bytes = serde_json::to_vec(&unsigned).unwrap();
    let strict = decode_strict_json(&unsigned_bytes).unwrap();
    let projected =
        project_signed_body(SignedMutationKind::ParticipantAcceptance, &strict).unwrap();
    let mutation =
        SigningTranscript::build_for(SignedMutationKind::ParticipantAcceptance, &projected)
            .unwrap();
    let sig = actor.signing_key.sign(mutation.bytes());
    let wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode(sig.to_bytes()),
    });
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

fn make_leaf_recovery_fulfillment_body(
    convo_id: Uuid,
    transition_id: Uuid,
    recovery_request_id: Uuid,
    origin_transition_id: Uuid,
    actor: &TestIdentity,
    target: &TestIdentity,
    group_id: &[u8; 32],
    prior_gch: &[u8; 32],
    prior_ctag: &[u8; 32],
    sv2_gch: &[u8; 32],
    sv2_ctag: &[u8; 32],
    welcome_id: Uuid,
    welcome_bytes: &[u8],
    commit_bytes: &[u8],
    metadata_ciphertext: &[u8],
    key_package_ref: &[u8; 32],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
        "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\u{0000}",
        "transitionId": transition_id.to_string(),
        "recoveryRequestId": recovery_request_id.to_string(),
        "idempotencyKey": transition_id.to_string(),
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 2,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(prior_gch),
            "confirmationTag": STANDARD.encode(prior_ctag),
            "lifecycle": "active"
        },
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 3,
            "groupId": STANDARD.encode(group_id),
            "epoch": 1,
            "groupContextHash": STANDARD.encode(sv2_gch),
            "confirmationTag": STANDARD.encode(sv2_ctag),
            "lifecycle": "active"
        },
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(convo_id.as_bytes()),
            "generation": 0,
            "transitionId": STANDARD.encode(transition_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "stateVersion": 2,
                "groupId": STANDARD.encode(group_id),
                "epoch": 0,
                "groupContextHash": STANDARD.encode(prior_gch),
                "confirmationTag": STANDARD.encode(prior_ctag),
                "lifecycle": "active"
            }
        },
        "manifest": {
            "participantChanges": [],
            "leafChanges": [
                {
                    "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                    "userDid": target.did,
                    "deviceId": target.device_id.to_string(),
                    "recoveryRequestId": recovery_request_id.to_string(),
                    "keyPackageRef": STANDARD.encode(key_package_ref)
                }
            ],
            "leafRecoveryRequestId": recovery_request_id.to_string(),
            "welcomeBundle": {
                "welcomeId": welcome_id.to_string(),
                "framing": "mlsMessage",
                "contentType": "welcome",
                "opaqueWelcome": STANDARD.encode(welcome_bytes),
                "sha256": STANDARD.encode(Sha256::digest(welcome_bytes)),
                "deliveries": [{
                    "recipientDid": target.did,
                    "recipientDeviceId": target.device_id.to_string(),
                    "provenance": {
                        "recoveryRequestId": recovery_request_id.to_string(),
                        "keyPackageRef": STANDARD.encode(key_package_ref)
                    }
                }]
            }
        },
        "commit": {
            "framing": "mlsMessage",
            "contentType": "publicMessageCommit",
            "bytes": STANDARD.encode(commit_bytes),
            "sha256": STANDARD.encode(Sha256::digest(commit_bytes))
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 1,
                "groupContextHash": STANDARD.encode(sv2_gch),
                "confirmationTag": STANDARD.encode(sv2_ctag),
            },
            "originTransitionId": origin_transition_id.to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0x6Bu8; 12]),
            "ciphertext": STANDARD.encode(metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": actor.did,
                "authorDeviceId": actor.device_id.to_string(),
                "authorKeyId": actor.key_id,
                "signaturePublicKey": STANDARD.encode(&actor.public_key),
                "authGenerationAtOrigin": 1,
                "originTransitionId": origin_transition_id.to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active"
            }
        }
    });

    let unsigned_bytes = serde_json::to_vec(&unsigned).unwrap();
    let strict = decode_strict_json(&unsigned_bytes).unwrap();
    let projected =
        project_signed_body(SignedMutationKind::LeafRecoveryFulfillment, &strict).unwrap();
    let mutation =
        SigningTranscript::build_for(SignedMutationKind::LeafRecoveryFulfillment, &projected)
            .unwrap();
    let sig = actor.signing_key.sign(mutation.bytes());
    let wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode(sig.to_bytes()),
    });
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

#[allow(clippy::too_many_arguments)]
fn make_corpus_commit_body(
    convo_id: Uuid,
    transition_id: Uuid,
    creation_transition_id: Uuid,
    actor_did: &str,
    actor_device_id: Uuid,
    actor_key_id: &str,
    actor_public_key: &[u8],
    actor_signing_key: &Ed25519SigningKey,
    group_id: &[u8],
    prior_group_context_hash: &[u8],
    prior_confirmation_tag: &[u8],
    next_group_context_hash: &[u8],
    next_confirmation_tag: &[u8],
    commit_bytes: &[u8],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let ciphertext = vec![0x88u8; 48];
    let nonce = vec![0x78u8; 12];
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#commitTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-COMMIT\u{0000}",
        "transitionId": transition_id.to_string(),
        "idempotencyKey": transition_id.to_string(),
        "actorDid": actor_did,
        "actorDeviceId": actor_device_id.to_string(),
        "keyId": actor_key_id,
        "authGeneration": 1,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 3,
            "groupId": STANDARD.encode(group_id),
            "epoch": 1,
            "groupContextHash": STANDARD.encode(prior_group_context_hash),
            "confirmationTag": STANDARD.encode(prior_confirmation_tag),
            "lifecycle": "active"
        },
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 4,
            "groupId": STANDARD.encode(group_id),
            "epoch": 2,
            "groupContextHash": STANDARD.encode(next_group_context_hash),
            "confirmationTag": STANDARD.encode(next_confirmation_tag),
            "lifecycle": "active"
        },
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(convo_id.as_bytes()),
            "generation": 0,
            "transitionId": STANDARD.encode(transition_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "stateVersion": 3,
                "groupId": STANDARD.encode(group_id),
                "epoch": 1,
                "groupContextHash": STANDARD.encode(prior_group_context_hash),
                "confirmationTag": STANDARD.encode(prior_confirmation_tag),
                "lifecycle": "active"
            }
        },
        "manifest": {
            "participantChanges": [],
            "leafChanges": []
        },
        "commit": {
            "framing": "mlsMessage",
            "contentType": "publicMessageCommit",
            "bytes": STANDARD.encode(commit_bytes),
            "sha256": STANDARD.encode(Sha256::digest(commit_bytes))
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 2,
                "groupContextHash": STANDARD.encode(next_group_context_hash),
                "confirmationTag": STANDARD.encode(next_confirmation_tag),
            },
            "originTransitionId": creation_transition_id.to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode(&nonce),
            "ciphertext": STANDARD.encode(&ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
            "ciphertextSize": ciphertext.len(),
            "authorProof": {
                "authorDid": actor_did,
                "authorDeviceId": actor_device_id.to_string(),
                "authorKeyId": actor_key_id,
                "signaturePublicKey": STANDARD.encode(actor_public_key),
                "authGenerationAtOrigin": 1,
                "originTransitionId": creation_transition_id.to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active"
            }
        }
    });

    let unsigned_bytes = serde_json::to_vec(&unsigned).unwrap();
    let strict = decode_strict_json(&unsigned_bytes).unwrap();
    let projected = project_signed_body(SignedMutationKind::CommitTransition, &strict).unwrap();
    let mutation =
        SigningTranscript::build_for(SignedMutationKind::CommitTransition, &projected).unwrap();
    let sig = actor_signing_key.sign(mutation.bytes());
    let wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode(sig.to_bytes()),
    });
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

fn make_message_body(
    convo_id: Uuid,
    message_id: Uuid,
    actor: &TestIdentity,
    group_id: &[u8; 32],
    state_version: u64,
    epoch: u64,
    group_context_hash: &[u8; 32],
    confirmation_tag: &[u8; 32],
    ciphertext: &[u8],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#applicationSendBody",
        "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0}",
        "messageId": message_id.to_string(),
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": state_version,
            "groupId": STANDARD.encode(group_id),
            "epoch": epoch,
            "groupContextHash": STANDARD.encode(group_context_hash),
            "confirmationTag": STANDARD.encode(confirmation_tag),
            "lifecycle": "active"
        },
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(convo_id.as_bytes()),
            "generation": 0,
            "messageId": STANDARD.encode(message_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "stateVersion": state_version,
                "groupId": STANDARD.encode(group_id),
                "epoch": epoch,
                "groupContextHash": STANDARD.encode(group_context_hash),
                "confirmationTag": STANDARD.encode(confirmation_tag),
                "lifecycle": "active"
            }
        },
        "applicationMessage": {
            "framing": "mlsMessage",
            "contentType": "privateMessageApplication",
            "bytes": STANDARD.encode(ciphertext),
            "sha256": STANDARD.encode(Sha256::digest(ciphertext))
        },
        "blobBindings": []
    });

    let unsigned_bytes = serde_json::to_vec(&unsigned).unwrap();
    let strict = decode_strict_json(&unsigned_bytes).unwrap();
    let projected = project_signed_body(SignedMutationKind::ApplicationSend, &strict).unwrap();
    let mutation =
        SigningTranscript::build_for(SignedMutationKind::ApplicationSend, &projected).unwrap();
    let sig = actor.signing_key.sign(mutation.bytes());
    let wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode(sig.to_bytes()),
    });
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct DbSnapshot {
    ds1_entries: i64,
    ds1_conversations: i64,
    ds1_participants: i64,
    ds1_generation_states: i64,
    ds1_receipts: i64,
    ds1_outbound_queue: i64,
    ds1_outbox: i64,
    ds2_entries: i64,
    ds2_conversations: i64,
    ds2_participants: i64,
    ds2_generation_states: i64,
    ds2_receipts: i64,
    ds2_outbound_queue: i64,
    ds2_outbox: i64,
}

async fn count_table(pg: &tokio_postgres::Client, sql: &str) -> Result<i64> {
    let row = pg.query_one(sql, &[]).await?;
    Ok(row.get(0))
}

async fn take_db_snapshot(
    ds1_pg: &tokio_postgres::Client,
    ds2_pg: &tokio_postgres::Client,
) -> Result<DbSnapshot> {
    Ok(DbSnapshot {
        ds1_entries: count_table(ds1_pg, "SELECT count(*) FROM chat.entries").await?,
        ds1_conversations: count_table(ds1_pg, "SELECT count(*) FROM chat.conversations").await?,
        ds1_participants: count_table(ds1_pg, "SELECT count(*) FROM chat.participants").await?,
        ds1_generation_states: count_table(ds1_pg, "SELECT count(*) FROM chat.generation_states")
            .await?,
        ds1_receipts: count_table(
            ds1_pg,
            "SELECT count(*) FROM chat.federation_delivery_receipts",
        )
        .await?,
        ds1_outbound_queue: count_table(ds1_pg, "SELECT count(*) FROM outbound_queue").await?,
        ds1_outbox: count_table(ds1_pg, "SELECT count(*) FROM federation_outbox").await?,
        ds2_entries: count_table(ds2_pg, "SELECT count(*) FROM chat.entries").await?,
        ds2_conversations: count_table(ds2_pg, "SELECT count(*) FROM chat.conversations").await?,
        ds2_participants: count_table(ds2_pg, "SELECT count(*) FROM chat.participants").await?,
        ds2_generation_states: count_table(ds2_pg, "SELECT count(*) FROM chat.generation_states")
            .await?,
        ds2_receipts: count_table(
            ds2_pg,
            "SELECT count(*) FROM chat.federation_delivery_receipts",
        )
        .await?,
        ds2_outbound_queue: count_table(ds2_pg, "SELECT count(*) FROM outbound_queue").await?,
        ds2_outbox: count_table(ds2_pg, "SELECT count(*) FROM federation_outbox").await?,
    })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_federation_two_node_complete_lifecycle_and_hostile_matrix() {
    if let Err(e) = run_test_scenario().await {
        panic!("Federation two-node scenario failed with error: {e:?}");
    }
}

async fn run_test_scenario() -> Result<()> {
    mls_e2e_tests::init_tracing();

    println!("=== STEP 0: Booting Two-Node Federated Cluster ===");
    let cluster = boot_two_node_cluster().await?;
    println!(
        "✓ Booted DS1 at {} and DS2 at {}",
        cluster.ds1_url, cluster.ds2_url
    );

    // ──────────────────────────────────────────────────────────────────────────
    // STEP 1: Peer Registration via Authenticated Admin API
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n=== STEP 1: Register Peers via Authenticated Admin API ===");

    // DS1 registers DS2 as allowlisted peer
    let ds1_admin_jwt = cluster.mint_ds1_jwt(
        &cluster.ds1_service_did,
        "blue.catbird.mlsDS.upsertFederationPeer",
    );
    let resp1 = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.upsertFederationPeer",
            cluster.ds1_url
        ))
        .header("authorization", format!("Bearer {ds1_admin_jwt}"))
        .json(&json!({
            "dsDid": cluster.ds2_service_did,
            "status": "allow",
            "maxRequestsPerMinute": 1000,
            "note": "Federation test DS2"
        }))
        .send()
        .await?;
    assert_eq!(
        resp1.status(),
        reqwest::StatusCode::OK,
        "DS1 upsertFederationPeer DS2 failed"
    );
    println!("✓ DS1 registered DS2 as allowlisted peer");

    // DS2 registers DS1 as allowlisted peer
    let ds2_admin_jwt = cluster.mint_ds2_jwt(
        &cluster.ds2_service_did,
        "blue.catbird.mlsDS.upsertFederationPeer",
    );
    let resp2 = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.upsertFederationPeer",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {ds2_admin_jwt}"))
        .json(&json!({
            "dsDid": cluster.ds1_service_did,
            "status": "allow",
            "maxRequestsPerMinute": 1000,
            "note": "Federation test DS1"
        }))
        .send()
        .await?;
    assert_eq!(
        resp2.status(),
        reqwest::StatusCode::OK,
        "DS2 upsertFederationPeer DS1 failed"
    );
    println!("✓ DS2 registered DS1 as allowlisted peer");

    // Verify peer listing on DS1
    let list_jwt1 = cluster.mint_ds1_jwt(
        &cluster.ds1_service_did,
        "blue.catbird.mlsDS.getFederationPeers",
    );
    let list_resp1: Value = cluster
        .http_client
        .get(format!(
            "{}/xrpc/blue.catbird.mlsDS.getFederationPeers",
            cluster.ds1_url
        ))
        .header("authorization", format!("Bearer {list_jwt1}"))
        .send()
        .await?
        .json()
        .await?;
    let peers1 = list_resp1["peers"].as_array().expect("peers array");
    assert!(
        peers1
            .iter()
            .any(|p| p["dsDid"] == cluster.ds2_service_did && p["status"] == "allow"),
        "DS1 peer list must include DS2 as allow: {list_resp1:?}"
    );

    // Verify peer listing on DS2
    let list_jwt2 = cluster.mint_ds2_jwt(
        &cluster.ds2_service_did,
        "blue.catbird.mlsDS.getFederationPeers",
    );
    let list_resp2: Value = cluster
        .http_client
        .get(format!(
            "{}/xrpc/blue.catbird.mlsDS.getFederationPeers",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {list_jwt2}"))
        .send()
        .await?
        .json()
        .await?;
    let peers2 = list_resp2["peers"].as_array().expect("peers array");
    assert!(
        peers2
            .iter()
            .any(|p| p["dsDid"] == cluster.ds1_service_did && p["status"] == "allow"),
        "DS2 peer list must include DS1 as allow: {list_resp2:?}"
    );
    println!("✓ Verified getFederationPeers on both nodes");

    // ──────────────────────────────────────────────────────────────────────────
    // STEP 2: Real MLS Crypto & Choice C Preprovisioning
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n=== STEP 2: Generate Real MLS Artifacts and Preprovision Mailboxes ===");

    let alice = TestIdentity::new("alice");
    let bob = TestIdentity::new("bob");

    // Alice creates real MLS group
    let alice_identity = format!("{}#{}", alice.did, alice.device_id);
    let group_id_bytes = alice.engine.create_group(&alice_identity)?;
    assert_eq!(group_id_bytes.len(), 32);
    let mut group_id = [0u8; 32];
    group_id.copy_from_slice(&group_id_bytes);

    // Bob creates real MLS key package
    let bob_identity = format!("{}#{}", bob.did, bob.device_id);
    let (bob_kp_bytes, bob_kp_ref_bytes) = bob.engine.create_key_package(&bob_identity)?;
    assert_eq!(bob_kp_ref_bytes.len(), 32);
    let mut key_package_ref = [0u8; 32];
    key_package_ref.copy_from_slice(&bob_kp_ref_bytes);

    // Alice adds Bob -> produces real commit and Welcome
    let (_commit_data, welcome_bytes) = alice
        .engine
        .add_members(&group_id, vec![bob_kp_bytes.clone()])?;
    let welcome_sha256: [u8; 32] = Sha256::digest(&welcome_bytes).into();
    let alice_new_epoch = alice.engine.merge_pending_commit(&group_id)?;
    assert_eq!(alice_new_epoch, 1);

    let convo_id = Uuid::new_v4();
    let now = Utc::now();
    let creation_transition_id = Uuid::new_v4();
    let creation_entry_id = creation_transition_id;
    let fulfillment_transition_id = Uuid::new_v4();
    let fulfillment_entry_id = fulfillment_transition_id;
    let welcome_id = Uuid::new_v4();
    let recovery_request_id = Uuid::new_v4();

    let genesis_gch = [0x22u8; 32];
    let genesis_ctag = [0x33u8; 32];
    let sv2_gch = [0x55u8; 32];
    let sv2_ctag = [0x77u8; 32];
    let sv2_gch_vec = sv2_gch.to_vec();
    let sv2_ctag_vec = sv2_ctag.to_vec();
    let public_snapshot_bytes = vec![0x99u8; 32];
    let public_snapshot_sha256: [u8; 32] = Sha256::digest(&public_snapshot_bytes).into();
    let alice_credential = alice_identity.into_bytes();
    let bob_credential = bob_identity.as_bytes().to_vec();
    let enc_key = vec![0x55u8; 32];
    let (tree_summary_0_bytes, tree_summary_0_sha) = make_tree_summary_bytes(
        &[0x44u8; 32],
        &[(0, &alice_credential, &alice.public_key, &enc_key)],
    );
    let (tree_summary_1_bytes, tree_summary_1_sha) = make_tree_summary_bytes(
        &[0x63u8; 32],
        &[
            (0, &alice_credential, &alice.public_key, &enc_key),
            (1, &bob_credential, &bob.public_key, &enc_key),
        ],
    );
    // Connect to DS1 and DS2 Postgres
    let mut ds1_pg = cluster.connect_ds1_db().await?;
    let mut ds2_pg = cluster.connect_ds2_db().await?;
    for pg in [&ds1_pg, &ds2_pg] {
        let key_material = vec![0x51_u8; 32];
        let row = pg
            .query_one("SELECT chat.ed25519_key_id($1)", &[&key_material])
            .await?;
        let cursor_key_id: String = row.get(0);
        let protocol_instance_id = Uuid::new_v4();
        pg.execute(
            "INSERT INTO chat.protocol_instances(singleton, protocol_version, protocol_instance_id, cursor_key_id) \
             VALUES (TRUE, '1', $1, $2) ON CONFLICT DO NOTHING",
            &[&protocol_instance_id, &cursor_key_id],
        )
        .await?;
        pg.execute(
            "INSERT INTO chat.event_retention(protocol_instance_id, retained_floor, updated_at) \
             VALUES ($1, 0, clock_timestamp()) ON CONFLICT DO NOTHING",
            &[&protocol_instance_id],
        )
        .await?;
    }

    // Pre-seed ds_endpoints so the reconciliation worker's resolver hits its cache
    // instead of attempting live DNS for the peer did:web (which the offline DID
    // fixtures do NOT feed — those only populate the auth JWT cache).
    // DS1 DB: register DS2 endpoint.
    ds1_pg
        .execute(
            "INSERT INTO ds_endpoints (did, endpoint, supported_cipher_suites, resolved_at, expires_at) \
             VALUES ($1, $2, NULL, clock_timestamp(), clock_timestamp() + interval '2 hours') \
             ON CONFLICT (did) DO UPDATE SET endpoint = EXCLUDED.endpoint, \
               supported_cipher_suites = EXCLUDED.supported_cipher_suites, \
               resolved_at = clock_timestamp(), \
               expires_at = clock_timestamp() + interval '2 hours'",
            &[&cluster.ds2_service_did, &"http://ds2:3001"],
        )
        .await?;
    // DS2 DB: register DS1 endpoint (the sequencer DS2 must reconcile against).
    ds2_pg
        .execute(
            "INSERT INTO ds_endpoints (did, endpoint, supported_cipher_suites, resolved_at, expires_at) \
             VALUES ($1, $2, NULL, clock_timestamp(), clock_timestamp() + interval '2 hours') \
             ON CONFLICT (did) DO UPDATE SET endpoint = EXCLUDED.endpoint, \
               supported_cipher_suites = EXCLUDED.supported_cipher_suites, \
               resolved_at = clock_timestamp(), \
               expires_at = clock_timestamp() + interval '2 hours'",
            &[&cluster.ds1_service_did, &"http://ds1:3001"],
        )
        .await?;

    // Seed Principals and Devices on DS1 & DS2
    for pg in [&ds1_pg, &ds2_pg] {
        pg.execute(
            "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2), ($3, $2) ON CONFLICT DO NOTHING",
            &[&alice.did, &now, &bob.did],
        )
        .await?;

        pg.execute(
            "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
             VALUES ($1, $2, 'Alice Device', 'active', NULL, 1, chat.protocol_capabilities(), $3, $3) ON CONFLICT DO NOTHING",
            &[&alice.did, &alice.device_id, &now],
        )
        .await?;

        pg.execute(
            "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
             VALUES ($1, $2, 'Bob Device', 'active', NULL, 1, chat.protocol_capabilities(), $3, $3) ON CONFLICT DO NOTHING",
            &[&bob.did, &bob.device_id, &now],
        )
        .await?;

        let alice_pk_vec = alice.public_key.to_vec();
        let bob_pk_vec = bob.public_key.to_vec();

        pg.execute(
            "INSERT INTO chat.device_keys (user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at) \
             VALUES ($1, $2, $3, $4, 1, $5) ON CONFLICT DO NOTHING",
            &[&alice.did, &alice.device_id, &alice.key_id, &alice_pk_vec, &now],
        )
        .await?;

        pg.execute(
            "INSERT INTO chat.device_keys (user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at) \
             VALUES ($1, $2, $3, $4, 1, $5) ON CONFLICT DO NOTHING",
            &[&bob.did, &bob.device_id, &bob.key_id, &bob_pk_vec, &now],
        )
        .await?;
    }

    // Seed DS1 Sequencer Conversation Structure
    let alice_participant_period_id_ds1 = Uuid::new_v4();
    let bob_participant_period_id_ds1 = Uuid::new_v4();
    let alice_leaf_period_id_ds1 = Uuid::new_v4();
    let ds1_creation_metadata_id = Uuid::new_v4();
    let group_info_bytes = vec![0x99u8; 16];
    let group_info_sha = Sha256::digest(&group_info_bytes).to_vec();
    let snapshot_sha = Sha256::digest(&public_snapshot_bytes).to_vec();
    let alice_pk_vec = alice.public_key.to_vec();
    let bob_pk_vec = bob.public_key.to_vec();
    let kp_ref_vec = key_package_ref.to_vec();

    // 1. Creation body & entry (Seq 1)
    let (_, creation_signed_req) = make_creation_body_with_invitee(
        convo_id,
        creation_entry_id,
        &alice,
        Some(&bob),
        &group_id,
        &genesis_gch,
        &genesis_ctag,
        &group_info_bytes,
        &public_snapshot_bytes,
        now,
    );
    let creation_wrapper = SignedWrapper::decode(&creation_signed_req).unwrap();
    let creation_projected =
        project_signed_body(SignedMutationKind::Creation, &creation_wrapper.body).unwrap();
    let creation_mutation =
        SigningTranscript::build_for(SignedMutationKind::Creation, &creation_projected).unwrap();
    let creation_unsigned_proj = creation_mutation.canonical_projection().to_vec();
    let creation_transcript = creation_mutation.bytes().to_vec();
    let creation_request_digest = creation_mutation.request_digest().to_vec();
    let creation_sig = alice
        .signing_key
        .sign(&creation_transcript)
        .to_bytes()
        .to_vec();
    let mut creation_sig_arr = [0u8; 64];
    creation_sig_arr.copy_from_slice(&creation_sig);
    let creation_row = EntryRow {
        entry_id: *creation_entry_id.as_bytes(),
        conversation_id: *convo_id.as_bytes(),
        seq: 1,
        request_digest: *creation_mutation.request_digest(),
        signature: creation_sig_arr,
        received_at: now.to_rfc3339_opts(SecondsFormat::Millis, true),
    };
    let creation_server_fields = ControlServerFields::empty(ControlEntryKind::Creation).unwrap();
    let creation_fp_obj = control_entry_fingerprint(
        ControlEntryKind::Creation,
        &creation_row,
        &creation_server_fields,
    )
    .unwrap();
    let creation_outer_fp = *creation_fp_obj.fingerprint().as_bytes();
    let creation_outer_fp_vec = creation_outer_fp.to_vec();
    let creation_wrapper_json: Value = serde_json::from_slice(&creation_signed_req).unwrap();
    let creation_entry_bytes = serde_json::to_vec(&json!({
        "$type": "blue.catbird.chat.defs#creationEntry",
        "entryId": creation_entry_id.to_string(),
        "conversationId": convo_id.to_string(),
        "seq": 1,
        "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "signedRequest": creation_wrapper_json,
    }))?;
    let creation_payload_sha: [u8; 32] = Sha256::digest(&creation_entry_bytes).into();

    // 2. Acceptance body & entry (Seq 2)
    let acc_transition_id = Uuid::new_v4();
    let acc_entry_id = acc_transition_id;
    let (_, acc_signed_req) = make_acceptance_body(
        convo_id,
        acc_transition_id,
        recovery_request_id,
        creation_transition_id,
        &bob,
        &alice,
        &group_id,
        &genesis_gch,
        &genesis_ctag,
        now,
    );
    let acc_wrapper = SignedWrapper::decode(&acc_signed_req).unwrap();
    let acc_projected =
        project_signed_body(SignedMutationKind::ParticipantAcceptance, &acc_wrapper.body).unwrap();
    let acc_mutation =
        SigningTranscript::build_for(SignedMutationKind::ParticipantAcceptance, &acc_projected)
            .unwrap();
    let acc_unsigned_proj = acc_mutation.canonical_projection().to_vec();
    let acc_transcript = acc_mutation.bytes().to_vec();
    let acc_digest = acc_mutation.request_digest().to_vec();
    let acc_sig = bob.signing_key.sign(&acc_transcript).to_bytes().to_vec();
    let mut acc_sig_arr = [0u8; 64];
    acc_sig_arr.copy_from_slice(&acc_sig);
    let acc_row = EntryRow {
        entry_id: *acc_entry_id.as_bytes(),
        conversation_id: *convo_id.as_bytes(),
        seq: 2,
        request_digest: *acc_mutation.request_digest(),
        signature: acc_sig_arr,
        received_at: now.to_rfc3339_opts(SecondsFormat::Millis, true),
    };
    let recovery_value = CanonicalValue::Map(BTreeMap::from([
        (
            "keyPackageRef".to_owned(),
            CanonicalValue::Bytes(key_package_ref.to_vec()),
        ),
        (
            "recoveryRequestId".to_owned(),
            CanonicalValue::Uuid(*recovery_request_id.as_bytes()),
        ),
    ]));
    let acc_server_fields = ControlServerFields::single(
        ControlEntryKind::ParticipantAcceptance,
        "recovery",
        recovery_value,
    )
    .unwrap();
    let acc_fp_obj = control_entry_fingerprint(
        ControlEntryKind::ParticipantAcceptance,
        &acc_row,
        &acc_server_fields,
    )
    .unwrap();
    let acc_outer_fp = *acc_fp_obj.fingerprint().as_bytes();
    let acc_outer_fp_vec = acc_outer_fp.to_vec();
    let acc_wrapper_json: Value = serde_json::from_slice(&acc_signed_req).unwrap();
    let acc_entry_bytes = serde_json::to_vec(&json!({
        "$type": "blue.catbird.chat.defs#participantAcceptanceEntry",
        "entryId": acc_entry_id.to_string(),
        "conversationId": convo_id.to_string(),
        "seq": 2,
        "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "signedRequest": acc_wrapper_json,
        "recovery": {
            "recoveryRequestId": recovery_request_id.to_string(),
            "keyPackageRef": { "$bytes": STANDARD.encode(&key_package_ref) }
        }
    }))?;
    let mock_commit_bytes = vec![0x5au8; 8];
    let mock_ct_bytes = vec![0x5au8; 16];
    let acc_payload_sha: [u8; 32] = Sha256::digest(&acc_entry_bytes).into();

    // 3. Leaf Recovery Fulfillment body & entry (Seq 3)
    let (_, signed_req_bytes) = make_leaf_recovery_fulfillment_body(
        convo_id,
        fulfillment_transition_id,
        recovery_request_id,
        creation_transition_id,
        &alice,
        &bob,
        &group_id,
        &genesis_gch,
        &genesis_ctag,
        &sv2_gch,
        &sv2_ctag,
        welcome_id,
        &welcome_bytes,
        &mock_commit_bytes,
        &mock_ct_bytes,
        &key_package_ref,
        now,
    );
    let fulfill_wrapper = SignedWrapper::decode(&signed_req_bytes).unwrap();
    let fulfill_projected = project_signed_body(
        SignedMutationKind::LeafRecoveryFulfillment,
        &fulfill_wrapper.body,
    )
    .unwrap();
    let fulfill_mutation = SigningTranscript::build_for(
        SignedMutationKind::LeafRecoveryFulfillment,
        &fulfill_projected,
    )
    .unwrap();
    let fulfill_transcript = fulfill_mutation.bytes().to_vec();
    let fulfill_request_digest = fulfill_mutation.request_digest().to_vec();
    let fulfill_sig = alice
        .signing_key
        .sign(&fulfill_transcript)
        .to_bytes()
        .to_vec();
    let mut fulfill_sig_arr = [0u8; 64];
    fulfill_sig_arr.copy_from_slice(&fulfill_sig);
    let fulfill_row = EntryRow {
        entry_id: *fulfillment_entry_id.as_bytes(),
        conversation_id: *convo_id.as_bytes(),
        seq: 3,
        request_digest: *fulfill_mutation.request_digest(),
        signature: fulfill_sig_arr,
        received_at: now.to_rfc3339_opts(SecondsFormat::Millis, true),
    };
    let fulfill_server_fields =
        ControlServerFields::empty(ControlEntryKind::LeafRecoveryFulfillment).unwrap();
    let fulfill_fp_obj = control_entry_fingerprint(
        ControlEntryKind::LeafRecoveryFulfillment,
        &fulfill_row,
        &fulfill_server_fields,
    )
    .unwrap();
    let outer_fp = *fulfill_fp_obj.fingerprint().as_bytes();
    let outer_fp_vec = outer_fp.to_vec();
    let fulfill_wrapper_json: Value = serde_json::from_slice(&signed_req_bytes).unwrap();
    let entry_bytes = serde_json::to_vec(&json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
        "entryId": fulfillment_entry_id.to_string(),
        "conversationId": convo_id.to_string(),
        "seq": 3,
        "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "signedRequest": fulfill_wrapper_json,
    }))?;
    let accepted_payload_sha256: [u8; 32] = Sha256::digest(&entry_bytes).into();
    let not_before = now - chrono::Duration::minutes(5);
    let not_after = now + chrono::Duration::hours(1);
    let expires_at = now + chrono::Duration::minutes(5);
    let welcome_expires_at = now + chrono::Duration::hours(1);

    let mut tx1 = ds1_pg.transaction().await?;
    tx1.execute("SET CONSTRAINTS ALL DEFERRED", &[]).await?;
    tx1.execute(
        "INSERT INTO chat.conversations (conversation_id, kind, lifecycle, current_generation, current_state_version, next_entry_seq, created_at, is_remote, sequencer_ds, sequencer_term) \
         VALUES ($1, 'group', 'active', 0, 2, 4, $2, false, NULL, 0)",
        &[&convo_id, &now],
    )
    .await?;

    tx1.execute(
        "INSERT INTO chat.generations (conversation_id, generation, group_id, lifecycle, genesis_group_info_bytes, genesis_group_info_sha256, current_state_version, activated_seq, activated_at) \
         VALUES ($1, 0, $2, 'active', $3, $4, 2, 1, $5)",
        &[&convo_id, &group_id_bytes, &group_info_bytes, &group_info_sha, &now],
    )
    .await?;

    // Transition 1: creation
    tx1.execute(
        "INSERT INTO chat.transitions (transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at) \
         VALUES ($1, $2, 'creation', $3, $4, $5, 1, 'admin', 'active', $6, $7, $8, $9, $10, 0, 0, $11, 1, $12)",
        &[
            &creation_transition_id, &convo_id, &alice.did, &alice.device_id, &alice.key_id,
            &creation_signed_req, &creation_unsigned_proj, &creation_transcript, &creation_request_digest, &creation_sig,
            &ds1_creation_metadata_id, &now,
        ],
    )
    .await?;

    let genesis_gch_vec = genesis_gch.to_vec();
    let genesis_ctag_vec = genesis_ctag.to_vec();
    let tree_summary_0_sha_vec = tree_summary_0_sha.to_vec();
    let tree_summary_1_sha_vec = tree_summary_1_sha.to_vec();

    // State version 0 (creation)
    tx1.execute(
        "INSERT INTO chat.generation_states (conversation_id, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, lifecycle, state_kind, producing_transition_id, public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count, created_at) \
         VALUES ($1, 0, 0, $2, 0, $3, $4, 'active', 'creation', $5, $6, $7, $8, $9, 1, $10)",
        &[
            &convo_id, &group_id_bytes, &genesis_gch_vec, &genesis_ctag_vec,
            &creation_transition_id, &public_snapshot_bytes, &snapshot_sha,
            &tree_summary_0_bytes, &tree_summary_0_sha_vec, &now,
        ],
    )
    .await?;

    // State version 1 (accept)
    tx1.execute(
        "INSERT INTO chat.generation_states (conversation_id, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, lifecycle, state_kind, producing_transition_id, public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count, created_at) \
         VALUES ($1, 0, 1, $2, 0, $3, $4, 'active', 'acceptConversation', $5, $6, $7, $8, $9, 1, $10)",
        &[
            &convo_id, &group_id_bytes, &genesis_gch_vec, &genesis_ctag_vec,
            &acc_transition_id, &public_snapshot_bytes, &snapshot_sha,
            &tree_summary_0_bytes, &tree_summary_0_sha_vec, &now,
        ],
    )
    .await?;

    // State version 2 (fulfillment)
    tx1.execute(
        "INSERT INTO chat.generation_states (conversation_id, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, lifecycle, state_kind, producing_transition_id, public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count, created_at) \
         VALUES ($1, 0, 2, $2, 1, $3, $4, 'active', 'commit', $5, $6, $7, $8, $9, 2, $10)",
        &[
            &convo_id, &group_id_bytes, &sv2_gch_vec, &sv2_ctag_vec,
            &fulfillment_transition_id, &public_snapshot_bytes, &snapshot_sha,
            &tree_summary_1_bytes, &tree_summary_1_sha_vec, &now,
        ],
    )
    .await?;

    // Transition 2: accept
    tx1.execute(
        "INSERT INTO chat.transitions (transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, prior_generation, prior_state_version, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at) \
         VALUES ($1, $2, 'acceptConversation', $3, $4, $5, 1, 'member', 'active', $6, $7, $8, $9, $10, 0, 0, 0, 1, NULL, 2, $11)",
        &[
            &acc_transition_id, &convo_id, &bob.did, &bob.device_id, &bob.key_id,
            &acc_signed_req, &acc_unsigned_proj, &acc_transcript, &acc_digest, &acc_sig,
            &now,
        ],
    )
    .await?;

    // Transition 3: leaf recovery fulfillment
    let ds1_fulfillment_metadata_id = Uuid::new_v4();
    tx1.execute(
        "INSERT INTO chat.transitions (transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, prior_generation, prior_state_version, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at) \
         VALUES ($1, $2, 'leafRecovery', $3, $4, $5, 1, 'admin', 'active', $6, $6, $7, $8, $9, 0, 1, 0, 2, $10, 3, $11)",
        &[
            &fulfillment_transition_id, &convo_id, &alice.did, &alice.device_id, &alice.key_id,
            &signed_req_bytes, &fulfill_transcript, &fulfill_request_digest, &fulfill_sig,
            &ds1_fulfillment_metadata_id, &now,
        ],
    )
    .await?;

    // Participants: Alice on DS1 (local), Bob on DS2
    tx1.execute(
        "INSERT INTO chat.participants (participant_period_id, conversation_id, user_did, status, role, role_transition_id, role_changed_at, created_by_did, created_by_device_id, invitation_transition_id, invitation_entry_id, invited_at, acceptance_transition_id, acceptance_entry_id, accepted_at, current_membership, created_at, ds_did) \
         VALUES ($1, $2, $3, 'active', 'admin', $4, $5, $3, $6, NULL, NULL, NULL, NULL, NULL, NULL, TRUE, $5, NULL), \
                ($7, $2, $8, 'active', 'member', $4, $5, $3, $6, $4, $9, $5, $10, $10, $5, TRUE, $5, $11)",
        &[
            &alice_participant_period_id_ds1, &convo_id, &alice.did, &creation_transition_id, &now, &alice.device_id,
            &bob_participant_period_id_ds1, &bob.did, &creation_entry_id,
            &acc_transition_id,
            &cluster.ds2_service_did,
        ],
    )
    .await?;

    // Key package & recovery state on DS1
    tx1.execute(
        "INSERT INTO chat.key_packages (key_package_ref, wrapper_bytes, wrapper_sha256, init_key, owner_did, owner_device_id, owner_key_id, owner_auth_generation, not_before, not_after, status, terminal_transition_id, terminal_at, created_at) \
         VALUES ($1, repeat('w', 32)::bytea, digest(repeat('w', 32)::bytea, 'sha256'), repeat('k', 32)::bytea, $2, $3, $4, 1, $5, $6, 'consumed', $7, $8, $8) ON CONFLICT DO NOTHING",
        &[&kp_ref_vec, &bob.did, &bob.device_id, &bob.key_id, &not_before, &not_after, &fulfillment_transition_id, &now],
    )
    .await?;

    tx1.execute(
        "INSERT INTO chat.leaf_recovery_requests (recovery_request_id, conversation_id, generation, requester_did, requester_device_id, requester_key_id, requester_auth_generation, recovery_kind, source, bound_state_version, bound_group_id, bound_epoch, bound_group_context_hash, bound_confirmation_tag, reservation_request_id, status, fulfilling_transition_id, terminal_at, signed_request_bytes, signing_transcript_bytes, request_digest, signature, requested_at, expires_at) \
         VALUES ($1, $2, 0, $3, $4, $5, 1, 'add', 'acceptConversation', 1, $6, 0, $7, $8, $1, 'fulfilled', $9, $10, repeat('r', 32)::bytea, repeat('t', 32)::bytea, digest(repeat('t', 32)::bytea, 'sha256'), repeat('s', 64)::bytea, $10, $11) ON CONFLICT DO NOTHING",
        &[&recovery_request_id, &convo_id, &bob.did, &bob.device_id, &bob.key_id, &group_id_bytes, &genesis_gch_vec, &genesis_ctag_vec, &fulfillment_transition_id, &now, &expires_at],
    )
    .await?;

    tx1.execute(
        "INSERT INTO chat.key_package_reservations (recovery_request_id, key_package_ref, conversation_id, generation, requester_did, requester_device_id, requester_key_id, requester_auth_generation, recipient_did, recipient_device_id, bound_state_version, bound_group_id, bound_epoch, bound_group_context_hash, bound_confirmation_tag, purpose, expires_at, status, consumed_transition_id, terminal_at, created_at) \
         VALUES ($1, $2, $3, 0, $4, $5, $6, 1, $4, $5, 1, $7, 0, $8, $9, 'leafRecovery', $10, 'consumed', $11, $12, $12) ON CONFLICT DO NOTHING",
        &[&recovery_request_id, &kp_ref_vec, &convo_id, &bob.did, &bob.device_id, &bob.key_id, &group_id_bytes, &genesis_gch_vec, &genesis_ctag_vec, &expires_at, &fulfillment_transition_id, &now],
    )
    .await?;

    // Member devices for Alice and Bob on DS1
    let recipient_leaf_id_ds1 = Uuid::new_v4();
    tx1.execute(
        "INSERT INTO chat.member_devices (leaf_period_id, participant_period_id, conversation_id, generation, user_did, device_id, leaf_index, basic_credential, leaf_signature_key, leaf_key_id, leaf_auth_generation, origin, join_key_package_ref, joined_state_version, joined_transition_id, joined_seq, active, created_at) \
         VALUES ($1, $2, $3, 0, $4, $5, 0, $6, $7, $8, 1, 'genesis', NULL, 0, $9, 1, TRUE, $10), \
                ($11, $12, $3, 0, $13, $14, 1, $15, $16, $17, 1, 'keyPackage', $18, 2, $19, 3, TRUE, $10)",
        &[
            &alice_leaf_period_id_ds1, &alice_participant_period_id_ds1, &convo_id,
            &alice.did, &alice.device_id, &alice_credential, &alice_pk_vec, &alice.key_id,
            &creation_transition_id, &now,
            &recipient_leaf_id_ds1, &bob_participant_period_id_ds1,
            &bob.did, &bob.device_id, &bob_credential, &bob_pk_vec, &bob.key_id,
            &kp_ref_vec, &fulfillment_transition_id,
        ],
    )
    .await?;

    // Metadata snapshots
    tx1.execute(
        "INSERT INTO chat.metadata_snapshots (metadata_snapshot_id, conversation_id, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, producing_transition_id, origin_transition_id, metadata_version, nonce, ciphertext, ciphertext_sha256, ciphertext_size, author_did, author_device_id, author_key_id, author_public_key, author_auth_generation, author_origin_seq, author_role, author_device_status, created_at) \
         VALUES ($1, $2, 0, 0, $3, 0, $4, $5, $6, $6, 1, repeat('n', 12)::bytea, repeat('c', 16)::bytea, digest(repeat('c', 16)::bytea, 'sha256'), 16, $7, $8, $9, $10, 1, 1, 'admin', 'active', $11), \
                ($12, $2, 0, 2, $3, 1, $14, $15, $13, $6, 1, repeat('k', 12)::bytea, repeat('c', 16)::bytea, digest(repeat('c', 16)::bytea, 'sha256'), 16, $7, $8, $9, $10, 1, 1, 'admin', 'active', $11)",
        &[
            &ds1_creation_metadata_id, &convo_id, &group_id_bytes, &genesis_gch_vec, &genesis_ctag_vec,
            &creation_transition_id, &alice.did, &alice.device_id, &alice.key_id, &alice_pk_vec, &now,
            &ds1_fulfillment_metadata_id, &fulfillment_transition_id,
            &sv2_gch_vec, &sv2_ctag_vec,
        ],
    )
    .await?;

    // Entries: seq 1, 2, 3
    tx1.execute(
        "INSERT INTO chat.entries (conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at) \
         VALUES ($1, 1, $2, 'blue.catbird.chat.defs#creationEntry', $3, $4, $5, $6, $7, repeat('0', 1)::bytea, $8, $9, $10, $11, 1, 0, 0, $12, $13)",
        &[
            &convo_id, &creation_entry_id, &creation_entry_bytes, &creation_payload_sha.to_vec(),
            &creation_signed_req, &creation_request_digest, &creation_sig,
            &creation_outer_fp_vec, &alice.did, &alice.device_id, &alice.key_id, &creation_transition_id, &now,
        ],
    )
    .await?;

    tx1.execute(
        "INSERT INTO chat.entries (conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at) \
         VALUES ($1, 2, $2, 'blue.catbird.chat.defs#participantAcceptanceEntry', $3, $4, $5, $6, $7, repeat('0', 1)::bytea, $8, $9, $10, $11, 1, 0, 1, $12, $13)",
        &[
            &convo_id, &acc_entry_id, &acc_entry_bytes, &acc_payload_sha.to_vec(),
            &acc_signed_req, &acc_digest, &acc_sig,
            &acc_outer_fp_vec, &bob.did, &bob.device_id, &bob.key_id, &acc_transition_id, &now,
        ],
    )
    .await?;

    tx1.execute(
        "INSERT INTO chat.entries (conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at) \
         VALUES ($1, 3, $2, 'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry', $3, $4, $5, $6, $7, repeat('0', 1)::bytea, $8, $9, $10, $11, 1, 0, 2, $12, $13)",
        &[
            &convo_id, &fulfillment_entry_id, &entry_bytes, &accepted_payload_sha256.to_vec(),
            &signed_req_bytes, &fulfill_request_digest, &fulfill_sig,
            &outer_fp_vec, &alice.did, &alice.device_id, &alice.key_id,
            &fulfillment_transition_id, &now,
        ],
    )
    .await?;

    // Application intervals for Alice and Bob
    tx1.execute(
        "INSERT INTO chat.application_intervals (membership_interval_id, conversation_id, generation, recipient_did, recipient_device_id, start_seq, opening_kind, opening_transition_id, opening_outer_entry_fingerprint, opening_state_version, opening_group_id, opening_epoch, opening_group_context_hash, opening_confirmation_tag, opening_leaf_period_id, created_at) \
         VALUES ($1, $2, 0, $3, $4, 1, 'creation', $1, $5, 0, $6, 0, $7, $8, $9, $10), \
                ($11, $2, 0, $12, $13, 3, 'add', $11, $14, 2, $6, 1, $15, $16, $17, $10)",
        &[
            &creation_transition_id, &convo_id, &alice.did, &alice.device_id,
            &creation_outer_fp_vec, &group_id_bytes, &genesis_gch_vec, &genesis_ctag_vec,
            &alice_leaf_period_id_ds1, &now,
            &fulfillment_transition_id, &bob.did, &bob.device_id,
            &outer_fp_vec, &sv2_gch_vec, &sv2_ctag_vec, &recipient_leaf_id_ds1,
        ],
    )
    .await?;

    tx1.execute(
        "INSERT INTO chat.welcome_bundles (welcome_id, conversation_id, transition_id, entry_seq, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, wrapper_bytes, wrapper_sha256, created_at) \
         VALUES ($1, $2, $3, 3, 0, 2, $4, 1, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
        &[
            &welcome_id, &convo_id, &fulfillment_transition_id, &group_id_bytes,
            &sv2_gch_vec, &sv2_ctag_vec, &welcome_bytes, &welcome_sha256.to_vec(), &now,
        ],
    )
    .await?;

    tx1.execute(
        "INSERT INTO chat.welcome_deliveries (welcome_id, recipient_did, recipient_device_id, recovery_request_id, key_package_ref, expires_at, status) \
         VALUES ($1, $2, $3, $4, $5, $6, 'pending') ON CONFLICT DO NOTHING",
        &[
            &welcome_id, &bob.did, &bob.device_id, &recovery_request_id,
            &kp_ref_vec, &welcome_expires_at,
        ],
    )
    .await?;

    tx1.commit().await?;

    let alice_participant_period_id_ds2 = Uuid::new_v4();
    let bob_participant_period_id_ds2 = Uuid::new_v4();
    let alice_leaf_period_id_ds2 = Uuid::new_v4();
    let ds2_creation_metadata_id = Uuid::new_v4();

    let mut tx2 = ds2_pg.transaction().await?;
    tx2.execute("SET CONSTRAINTS ALL DEFERRED", &[]).await?;
    tx2.execute(
        "INSERT INTO chat.conversations (conversation_id, kind, lifecycle, current_generation, current_state_version, next_entry_seq, created_at, is_remote, sequencer_ds, sequencer_term) \
         VALUES ($1, 'group', 'active', 0, 2, 4, $2, true, $3, 0) ON CONFLICT DO NOTHING",
        &[&convo_id, &now, &cluster.ds1_service_did],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.generations (conversation_id, generation, group_id, lifecycle, genesis_group_info_bytes, genesis_group_info_sha256, current_state_version, activated_seq, activated_at) \
         VALUES ($1, 0, $2, 'active', $3, $4, 2, 1, $5) ON CONFLICT DO NOTHING",
        &[&convo_id, &group_id_bytes, &group_info_bytes, &group_info_sha, &now],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.transitions (transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at) \
         VALUES ($1, $2, 'creation', $3, $4, $5, 1, 'admin', 'active', $6, $7, $8, $9, $10, 0, 0, $11, 1, $12) ON CONFLICT DO NOTHING",
        &[
            &creation_transition_id, &convo_id, &alice.did, &alice.device_id, &alice.key_id,
            &creation_signed_req, &creation_unsigned_proj, &creation_transcript, &creation_request_digest, &creation_sig,
            &ds2_creation_metadata_id, &now,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.generation_states (conversation_id, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, lifecycle, state_kind, producing_transition_id, public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count, created_at) \
         VALUES ($1, 0, 0, $2, 0, $3, $4, 'active', 'creation', $5, $6, $7, $8, $9, 1, $10)",
        &[
            &convo_id, &group_id_bytes, &genesis_gch_vec, &genesis_ctag_vec,
            &creation_transition_id, &public_snapshot_bytes, &snapshot_sha,
            &tree_summary_0_bytes, &tree_summary_0_sha_vec, &now,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.generation_states (conversation_id, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, lifecycle, state_kind, producing_transition_id, public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count, created_at) \
         VALUES ($1, 0, 1, $2, 0, $3, $4, 'active', 'acceptConversation', $5, $6, $7, $8, $9, 1, $10)",
        &[
            &convo_id, &group_id_bytes, &genesis_gch_vec, &genesis_ctag_vec,
            &acc_transition_id, &public_snapshot_bytes, &snapshot_sha,
            &tree_summary_0_bytes, &tree_summary_0_sha_vec, &now,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.generation_states (conversation_id, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, lifecycle, state_kind, producing_transition_id, public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count, created_at) \
         VALUES ($1, 0, 2, $2, 1, $3, $4, 'active', 'commit', $5, $6, $7, $8, $9, 2, $10) ON CONFLICT DO NOTHING",
        &[
            &convo_id, &group_id_bytes, &sv2_gch_vec, &sv2_ctag_vec,
            &fulfillment_transition_id, &public_snapshot_bytes, &snapshot_sha,
            &tree_summary_1_bytes, &tree_summary_1_sha_vec, &now,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.transitions (transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, prior_generation, prior_state_version, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at) \
         VALUES ($1, $2, 'acceptConversation', $3, $4, $5, 1, 'member', 'active', $6, $7, $8, $9, $10, 0, 0, 0, 1, NULL, 2, $11) ON CONFLICT DO NOTHING",
        &[
            &acc_transition_id, &convo_id, &bob.did, &bob.device_id, &bob.key_id,
            &acc_signed_req, &acc_unsigned_proj, &acc_transcript, &acc_digest, &acc_sig,
            &now,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.participants (participant_period_id, conversation_id, user_did, status, role, role_transition_id, role_changed_at, created_by_did, created_by_device_id, invitation_transition_id, invitation_entry_id, invited_at, acceptance_transition_id, acceptance_entry_id, accepted_at, current_membership, created_at, ds_did) \
         VALUES ($1, $2, $3, 'active', 'admin', $4, $5, $3, $6, NULL, NULL, NULL, NULL, NULL, NULL, TRUE, $5, $7), \
                ($8, $2, $9, 'active', 'member', $4, $5, $3, $6, $4, $10, $5, $11, $11, $5, TRUE, $5, NULL)",
        &[
            &alice_participant_period_id_ds2, &convo_id, &alice.did, &creation_transition_id, &now, &alice.device_id,
            &cluster.ds1_service_did,
            &bob_participant_period_id_ds2, &bob.did, &creation_entry_id,
            &acc_transition_id,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.member_devices (leaf_period_id, participant_period_id, conversation_id, generation, user_did, device_id, leaf_index, basic_credential, leaf_signature_key, leaf_key_id, leaf_auth_generation, origin, joined_state_version, joined_transition_id, joined_seq, active, created_at) \
         VALUES ($1, $2, $3, 0, $4, $5, 0, $6, $7, $8, 1, 'genesis', 0, $9, 1, TRUE, $10)",
        &[
            &alice_leaf_period_id_ds2, &alice_participant_period_id_ds2, &convo_id,
            &alice.did, &alice.device_id, &alice_credential, &alice_pk_vec, &alice.key_id,
            &creation_transition_id, &now,
        ],
    )
    .await?;

    let ds2_fulfillment_metadata_id = Uuid::new_v4();

    tx2.execute(
        "INSERT INTO chat.metadata_snapshots (metadata_snapshot_id, conversation_id, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, producing_transition_id, origin_transition_id, metadata_version, nonce, ciphertext, ciphertext_sha256, ciphertext_size, author_did, author_device_id, author_key_id, author_public_key, author_auth_generation, author_origin_seq, author_role, author_device_status, created_at) \
         VALUES ($1, $2, 0, 0, $3, 0, $4, $5, $6, $6, 1, repeat('n', 12)::bytea, repeat('c', 16)::bytea, digest(repeat('c', 16)::bytea, 'sha256'), 16, $7, $8, $9, $10, 1, 1, 'admin', 'active', $11), \
                ($12, $2, 0, 2, $3, 1, $14, $15, $13, $6, 1, repeat('k', 12)::bytea, repeat('c', 16)::bytea, digest(repeat('c', 16)::bytea, 'sha256'), 16, $7, $8, $9, $10, 1, 1, 'admin', 'active', $11)",
        &[
            &ds2_creation_metadata_id, &convo_id, &group_id_bytes, &genesis_gch_vec, &genesis_ctag_vec,
            &creation_transition_id, &alice.did, &alice.device_id, &alice.key_id, &alice_pk_vec, &now,
            &ds2_fulfillment_metadata_id, &fulfillment_transition_id,
            &sv2_gch_vec, &sv2_ctag_vec,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.entries (conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at) \
         VALUES ($1, 1, $2, 'blue.catbird.chat.defs#creationEntry', $3, $4, $5, $6, $7, repeat('0', 1)::bytea, $8, $9, $10, $11, 1, 0, 0, $12, $13)",
        &[
            &convo_id, &creation_entry_id, &creation_entry_bytes, &creation_payload_sha.to_vec(),
            &creation_signed_req, &creation_request_digest, &creation_sig,
            &creation_outer_fp_vec, &alice.did, &alice.device_id, &alice.key_id, &creation_transition_id, &now,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.entries (conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at) \
         VALUES ($1, 2, $2, 'blue.catbird.chat.defs#participantAcceptanceEntry', $3, $4, $5, $6, $7, repeat('0', 1)::bytea, $8, $9, $10, $11, 1, 0, 1, $12, $13)",
        &[
            &convo_id, &acc_entry_id, &acc_entry_bytes, &acc_payload_sha.to_vec(),
            &acc_signed_req, &acc_digest, &acc_sig,
            &acc_outer_fp_vec, &bob.did, &bob.device_id, &bob.key_id, &acc_transition_id, &now,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.transitions (transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, prior_generation, prior_state_version, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at) \
         VALUES ($1, $2, 'leafRecovery', $3, $4, $5, 1, 'admin', 'active', $6, $6, $7, $8, $9, 0, 1, 0, 2, $10, 3, $11) ON CONFLICT DO NOTHING",
        &[
            &fulfillment_transition_id, &convo_id, &alice.did, &alice.device_id, &alice.key_id,
            &signed_req_bytes, &fulfill_transcript, &fulfill_request_digest, &fulfill_sig,
            &ds2_fulfillment_metadata_id, &now,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.entries (conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at) \
         VALUES ($1, 3, $2, 'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry', $3, $4, $5, $6, $7, repeat('0', 1)::bytea, $8, $9, $10, $11, 1, 0, 2, $12, $13) ON CONFLICT DO NOTHING",
        &[
            &convo_id, &fulfillment_entry_id, &entry_bytes, &accepted_payload_sha256.to_vec(),
            &signed_req_bytes, &fulfill_request_digest, &fulfill_sig,
            &outer_fp_vec, &alice.did, &alice.device_id, &alice.key_id,
            &fulfillment_transition_id, &now,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.application_intervals (membership_interval_id, conversation_id, generation, recipient_did, recipient_device_id, start_seq, opening_kind, opening_transition_id, opening_outer_entry_fingerprint, opening_state_version, opening_group_id, opening_epoch, opening_group_context_hash, opening_confirmation_tag, opening_leaf_period_id, created_at) \
         VALUES ($1, $2, 0, $3, $4, 1, 'creation', $1, $5, 0, $6, 0, $7, $8, $9, $10)",
        &[
            &creation_transition_id, &convo_id, &alice.did, &alice.device_id,
            &creation_outer_fp_vec, &group_id_bytes, &genesis_gch_vec, &genesis_ctag_vec,
            &alice_leaf_period_id_ds2, &now,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.key_packages (key_package_ref, wrapper_bytes, wrapper_sha256, init_key, owner_did, owner_device_id, owner_key_id, owner_auth_generation, not_before, not_after, status, terminal_transition_id, terminal_at, created_at) \
         VALUES ($1, repeat('w', 32)::bytea, digest(repeat('w', 32)::bytea, 'sha256'), repeat('k', 32)::bytea, $2, $3, $4, 1, $5, $6, 'consumed', $7, $8, $8) ON CONFLICT DO NOTHING",
        &[&kp_ref_vec, &bob.did, &bob.device_id, &bob.key_id, &not_before, &not_after, &fulfillment_transition_id, &now],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.leaf_recovery_requests (recovery_request_id, conversation_id, generation, requester_did, requester_device_id, requester_key_id, requester_auth_generation, recovery_kind, source, bound_state_version, bound_group_id, bound_epoch, bound_group_context_hash, bound_confirmation_tag, reservation_request_id, status, fulfilling_transition_id, terminal_at, signed_request_bytes, signing_transcript_bytes, request_digest, signature, requested_at, expires_at) \
         VALUES ($1, $2, 0, $3, $4, $5, 1, 'add', 'acceptConversation', 1, $6, 0, $7, $8, $1, 'fulfilled', $9, $10, repeat('r', 32)::bytea, repeat('t', 32)::bytea, digest(repeat('t', 32)::bytea, 'sha256'), repeat('s', 64)::bytea, $10, $11) ON CONFLICT DO NOTHING",
        &[&recovery_request_id, &convo_id, &bob.did, &bob.device_id, &bob.key_id, &group_id_bytes, &genesis_gch_vec, &genesis_ctag_vec, &fulfillment_transition_id, &now, &expires_at],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.key_package_reservations (recovery_request_id, key_package_ref, conversation_id, generation, requester_did, requester_device_id, requester_key_id, requester_auth_generation, recipient_did, recipient_device_id, bound_state_version, bound_group_id, bound_epoch, bound_group_context_hash, bound_confirmation_tag, purpose, expires_at, status, consumed_transition_id, terminal_at, created_at) \
         VALUES ($1, $2, $3, 0, $4, $5, $6, 1, $4, $5, 1, $7, 0, $8, $9, 'leafRecovery', $10, 'consumed', $11, $12, $12) ON CONFLICT DO NOTHING",
        &[&recovery_request_id, &kp_ref_vec, &convo_id, &bob.did, &bob.device_id, &bob.key_id, &group_id_bytes, &genesis_gch_vec, &genesis_ctag_vec, &expires_at, &fulfillment_transition_id, &now],
    )
    .await?;

    let recipient_leaf_id = Uuid::new_v4();
    tx2.execute(
        "INSERT INTO chat.member_devices (leaf_period_id, participant_period_id, conversation_id, generation, user_did, device_id, leaf_index, basic_credential, leaf_signature_key, leaf_key_id, leaf_auth_generation, origin, join_key_package_ref, joined_state_version, joined_transition_id, joined_seq, active, created_at) \
         VALUES ($1, $2, $3, 0, $4, $5, 1, $6, $7, $8, 1, 'keyPackage', $9, 2, $10, 3, TRUE, $11) ON CONFLICT DO NOTHING",
        &[
            &recipient_leaf_id, &bob_participant_period_id_ds2, &convo_id,
            &bob.did, &bob.device_id, &bob_credential, &bob_pk_vec, &bob.key_id,
            &kp_ref_vec, &fulfillment_transition_id, &now,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.application_intervals (membership_interval_id, conversation_id, generation, recipient_did, recipient_device_id, start_seq, opening_kind, opening_transition_id, opening_outer_entry_fingerprint, opening_state_version, opening_group_id, opening_epoch, opening_group_context_hash, opening_confirmation_tag, opening_leaf_period_id, created_at) \
         VALUES ($1, $2, 0, $3, $4, 3, 'add', $5, $6, 2, $7, 1, $8, $9, $10, $11) ON CONFLICT DO NOTHING",
        &[
            &fulfillment_transition_id, &convo_id, &bob.did, &bob.device_id,
            &fulfillment_transition_id, &outer_fp_vec, &group_id_bytes, &sv2_gch_vec, &sv2_ctag_vec,
            &recipient_leaf_id, &now,
        ],
    )
    .await?;

    tx2.execute(
        "INSERT INTO chat.welcome_bundles (welcome_id, conversation_id, transition_id, entry_seq, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, wrapper_bytes, wrapper_sha256, created_at) \
         VALUES ($1, $2, $3, 3, 0, 2, $4, 1, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
        &[
            &welcome_id, &convo_id, &fulfillment_transition_id, &group_id_bytes,
            &sv2_gch_vec, &sv2_ctag_vec, &welcome_bytes, &welcome_sha256.to_vec(), &now,
        ],
    )
    .await?;

    let welcome_expires_at = now + chrono::Duration::hours(1);
    tx2.execute(
        "INSERT INTO chat.welcome_deliveries (welcome_id, recipient_did, recipient_device_id, recovery_request_id, key_package_ref, expires_at, status) \
         VALUES ($1, $2, $3, $4, $5, $6, 'pending') ON CONFLICT DO NOTHING",
        &[
            &welcome_id, &bob.did, &bob.device_id, &recovery_request_id,
            &kp_ref_vec, &welcome_expires_at,
        ],
    )
    .await?;
    tx2.commit().await?;
    println!("✓ Choice C preprovisioning complete on DS1 and DS2");

    // ──────────────────────────────────────────────────────────────────────────
    // STEP 3: Deliver Welcome DS1 -> DS2
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n=== STEP 3: Deliver Welcome DS1 -> DS2 ===");

    let welcome_delivery_id = Uuid::new_v4();
    let welcome_payload_sha = compute_welcome_envelope_digest(
        welcome_delivery_id,
        convo_id,
        &cluster.ds1_service_did,
        &cluster.ds2_service_did,
        &cluster.ds1_service_did,
        0,
        &bob.did,
        bob.device_id,
        welcome_id,
        recovery_request_id,
        &key_package_ref,
        &welcome_bytes,
        &welcome_sha256,
        &entry_bytes,
        &signed_req_bytes,
        fulfillment_entry_id,
        3,
        &accepted_payload_sha256,
        &outer_fp,
        0,
        2,
        &group_id,
        1,
        &sv2_gch,
        &sv2_ctag,
        &public_snapshot_sha256,
        &tree_summary_1_sha,
    );

    let welcome_header_json = json!({
        "protocolVersion": "1",
        "deliveryId": welcome_delivery_id.to_string(),
        "conversationId": convo_id.to_string(),
        "senderDsDid": cluster.ds1_service_did,
        "receiverDsDid": cluster.ds2_service_did,
        "sequencerDid": cluster.ds1_service_did,
        "sequencerTerm": 0,
        "payloadSha256": { "$bytes": STANDARD.encode(&welcome_payload_sha) }
    });

    let welcome_locator_json = json!({
        "entryId": fulfillment_entry_id.to_string(),
        "seq": 3,
        "acceptedPayloadSha256": { "$bytes": STANDARD.encode(&accepted_payload_sha256) },
        "outerEntryFingerprint": { "$bytes": STANDARD.encode(&outer_fp) }
    });

    let coordinates_json = json!({
        "conversationId": convo_id.to_string(),
        "generation": 0,
        "stateVersion": 2,
        "groupId": { "$bytes": STANDARD.encode(&group_id) },
        "epoch": 1,
        "groupContextHash": { "$bytes": STANDARD.encode(&sv2_gch) },
        "confirmationTag": { "$bytes": STANDARD.encode(&sv2_ctag) },
        "lifecycle": "active"
    });
    let deliver_welcome_body = json!({
        "header": welcome_header_json,
        "entryLocator": welcome_locator_json,
        "coordinates": coordinates_json,
        "recipientDid": bob.did,
        "recipientDeviceId": bob.device_id.to_string(),
        "welcomeId": welcome_id.to_string(),
        "recoveryRequestId": recovery_request_id.to_string(),
        "keyPackageRef": { "$bytes": STANDARD.encode(&key_package_ref) },
        "welcomeBytes": { "$bytes": STANDARD.encode(&welcome_bytes) },
        "welcomeSha256": { "$bytes": STANDARD.encode(&welcome_sha256) },
        "publicSnapshotSha256": { "$bytes": STANDARD.encode(&public_snapshot_sha256) },
        "treeSummarySha256": { "$bytes": STANDARD.encode(&tree_summary_1_sha) },
        "entryBytes": { "$bytes": STANDARD.encode(&entry_bytes) },
        "signedRequestBytes": { "$bytes": STANDARD.encode(&signed_req_bytes) }
    });

    let ds1_welcome_jwt = cluster.mint_ds1_jwt(&cluster.ds2_service_did, DELIVER_WELCOME_NSID);

    let welcome_resp = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.deliverWelcome",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {ds1_welcome_jwt}"))
        .json(&deliver_welcome_body)
        .send()
        .await?;
    let welcome_status = welcome_resp.status();
    let welcome_text = welcome_resp.text().await?;
    if welcome_status != reqwest::StatusCode::OK {
        panic!("deliverWelcome to DS2 failed (status {welcome_status}): {welcome_text}");
    }
    let welcome_res_json: Value = serde_json::from_str(&welcome_text)?;
    let receipt1 = &welcome_res_json["receipt"];
    assert_eq!(receipt1["endpoint"], DELIVER_WELCOME_NSID);
    assert_eq!(receipt1["deliveryId"], welcome_delivery_id.to_string());
    assert_eq!(receipt1["receiverDsDid"], cluster.ds2_service_did);

    let sig_bytes1 = STANDARD.decode(receipt1["signature"]["$bytes"].as_str().unwrap())?;
    let res_sha1: [u8; 32] = hex_or_bytes(&receipt1["resultSha256"])?;
    let canonical_rec1 = canonical_receipt_bytes(
        DELIVER_WELCOME_NSID,
        welcome_delivery_id,
        convo_id,
        &cluster.ds1_service_did,
        &cluster.ds2_service_did,
        &cluster.ds1_service_did,
        0,
        &welcome_payload_sha,
        &res_sha1,
        Some((fulfillment_entry_id, 3, &accepted_payload_sha256, &outer_fp)),
        receipt1["completedAt"].as_str().unwrap(),
    );
    cluster.verify_ds2_signature(&canonical_rec1, &sig_bytes1)?;
    println!("✓ DS2 returned valid signed receipt for deliverWelcome");

    // Idempotent Replay of deliverWelcome
    let ds1_welcome_jwt_replay =
        cluster.mint_ds1_jwt(&cluster.ds2_service_did, DELIVER_WELCOME_NSID);
    let welcome_replay_resp = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.deliverWelcome",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {ds1_welcome_jwt_replay}"))
        .json(&deliver_welcome_body)
        .send()
        .await?;
    assert_eq!(
        welcome_replay_resp.status(),
        reqwest::StatusCode::OK,
        "deliverWelcome replay failed"
    );
    let replay_json: Value = welcome_replay_resp.json().await?;
    assert_eq!(
        replay_json["receipt"]["signature"]["$bytes"], receipt1["signature"]["$bytes"],
        "replay must return identical signed receipt"
    );
    println!("✓ Idempotent replay of deliverWelcome returned identical receipt");

    // Bob processes the Welcome
    let bob_group_id = bob.engine.process_welcome(&welcome_bytes, &bob_identity)?;
    assert_eq!(
        bob_group_id, group_id,
        "Bob's processed welcome group ID must match Alice's group ID"
    );
    println!("✓ Bob successfully joined MLS group using the delivered Welcome");

    // ──────────────────────────────────────────────────────────────────────────
    // STEP 4: Message Delivery DS1 -> DS2
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n=== STEP 4: Deliver Message DS1 -> DS2 ===");

    let plaintext_msg = b"Hello federated Bob from Alice!";
    let (ciphertext, _padded_size) = alice.engine.encrypt(&group_id, plaintext_msg)?;

    let msg_delivery_id = Uuid::new_v4();
    let msg_entry_id = Uuid::new_v4();
    let msg_seq = 4u64;

    let (_, msg_signed_req_bytes) = make_message_body(
        convo_id,
        msg_entry_id,
        &alice,
        &group_id,
        2,
        1,
        &sv2_gch,
        &sv2_ctag,
        &ciphertext,
        now,
    );
    let msg_wrapper = SignedWrapper::decode(&msg_signed_req_bytes).unwrap();
    let msg_projected =
        project_signed_body(SignedMutationKind::ApplicationSend, &msg_wrapper.body).unwrap();
    let msg_mutation =
        SigningTranscript::build_for(SignedMutationKind::ApplicationSend, &msg_projected).unwrap();
    let msg_transcript = msg_mutation.bytes().to_vec();
    let msg_digest = msg_mutation.request_digest().to_vec();
    let msg_sig = alice.signing_key.sign(&msg_transcript).to_bytes().to_vec();
    let mut msg_sig_arr = [0u8; 64];
    msg_sig_arr.copy_from_slice(&msg_sig);
    let msg_row = EntryRow {
        entry_id: *msg_entry_id.as_bytes(),
        conversation_id: *convo_id.as_bytes(),
        seq: msg_seq,
        request_digest: *msg_mutation.request_digest(),
        signature: msg_sig_arr,
        received_at: now.to_rfc3339_opts(SecondsFormat::Millis, true),
    };
    let msg_fp_obj = application_entry_fingerprint(&msg_row).unwrap();
    let msg_outer_fp = *msg_fp_obj.fingerprint().as_bytes();

    let app_entry_dag = BTreeMap::from([
        (
            "conversationId".to_owned(),
            CanonicalValue::Uuid(*convo_id.as_bytes()),
        ),
        (
            "entryId".to_owned(),
            CanonicalValue::Uuid(*msg_entry_id.as_bytes()),
        ),
        (
            "receivedAt".to_owned(),
            CanonicalValue::Timestamp(now.to_rfc3339_opts(SecondsFormat::Millis, true)),
        ),
        ("seq".to_owned(), CanonicalValue::Integer(msg_seq)),
        (
            "signedRequest".to_owned(),
            CanonicalValue::Map(BTreeMap::from([
                ("body".to_owned(), CanonicalValue::Map(msg_projected)),
                (
                    "signature".to_owned(),
                    CanonicalValue::Bytes(msg_sig.to_vec()),
                ),
            ])),
        ),
    ]);
    let app_entry_bytes = serde_ipld_dagcbor::to_vec(&app_entry_dag).unwrap();
    let app_payload_sha: [u8; 32] = Sha256::digest(&app_entry_bytes).into();
    let msg_payload_sha = compute_message_envelope_digest(
        msg_delivery_id,
        convo_id,
        &cluster.ds1_service_did,
        &cluster.ds2_service_did,
        &cluster.ds1_service_did,
        0,
        &bob.did,
        msg_entry_id,
        msg_seq,
        &app_payload_sha,
        &msg_outer_fp,
        &app_entry_bytes,
        &msg_signed_req_bytes,
    );

    let msg_header_json = json!({
        "protocolVersion": "1",
        "deliveryId": msg_delivery_id.to_string(),
        "conversationId": convo_id.to_string(),
        "senderDsDid": cluster.ds1_service_did,
        "receiverDsDid": cluster.ds2_service_did,
        "sequencerDid": cluster.ds1_service_did,
        "sequencerTerm": 0,
        "payloadSha256": { "$bytes": STANDARD.encode(&msg_payload_sha) }
    });

    let msg_locator_json = json!({
        "entryId": msg_entry_id.to_string(),
        "seq": msg_seq,
        "acceptedPayloadSha256": { "$bytes": STANDARD.encode(&app_payload_sha) },
        "outerEntryFingerprint": { "$bytes": STANDARD.encode(&msg_outer_fp) }
    });

    let deliver_message_body = json!({
        "header": msg_header_json,
        "entryLocator": msg_locator_json,
        "recipientDid": bob.did,
        "entryBytes": { "$bytes": STANDARD.encode(&app_entry_bytes) },
        "signedRequestBytes": { "$bytes": STANDARD.encode(&msg_signed_req_bytes) }
    });

    let ds1_msg_jwt = cluster.mint_ds1_jwt(&cluster.ds2_service_did, DELIVER_MESSAGE_NSID);

    let msg_resp = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.deliverMessage",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {ds1_msg_jwt}"))
        .json(&deliver_message_body)
        .send()
        .await?;
    let msg_status = msg_resp.status();
    let msg_text = msg_resp.text().await?;
    if msg_status != reqwest::StatusCode::OK {
        panic!("deliverMessage to DS2 failed (status {msg_status}): {msg_text}");
    }
    let msg_res_json: Value = serde_json::from_str(&msg_text)?;
    let receipt2 = &msg_res_json["receipt"];
    assert_eq!(receipt2["endpoint"], DELIVER_MESSAGE_NSID);
    assert_eq!(receipt2["deliveryId"], msg_delivery_id.to_string());

    let sig_bytes2 = STANDARD.decode(receipt2["signature"]["$bytes"].as_str().unwrap())?;
    let res_sha2: [u8; 32] = hex_or_bytes(&receipt2["resultSha256"])?;
    let canonical_rec2 = canonical_receipt_bytes(
        DELIVER_MESSAGE_NSID,
        msg_delivery_id,
        convo_id,
        &cluster.ds1_service_did,
        &cluster.ds2_service_did,
        &cluster.ds1_service_did,
        0,
        &msg_payload_sha,
        &res_sha2,
        Some((msg_entry_id, msg_seq, &app_payload_sha, &msg_outer_fp)),
        receipt2["completedAt"].as_str().unwrap(),
    );
    cluster.verify_ds2_signature(&canonical_rec2, &sig_bytes2)?;
    println!("✓ DS2 returned valid signed receipt for deliverMessage");

    // Also record message entry in DS1 database so DS1 sequence stays accurate
    let none_tr_id: Option<Uuid> = None;
    let outcome_bytes = serde_json::to_vec(&json!({
        "entry": {
            "entryId": msg_entry_id.to_string(),
            "conversationId": convo_id.to_string(),
            "seq": 4,
            "signedRequest": serde_json::from_slice::<Value>(&msg_signed_req_bytes).unwrap(),
            "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
        }
    }))?;
    let outcome_sha = Sha256::digest(&outcome_bytes).to_vec();

    let mut tx_msg = ds1_pg.transaction().await?;
    tx_msg.execute(
        "INSERT INTO chat.message_sends (conversation_id, message_id, signed_request_bytes, signing_transcript_bytes, request_digest, signature, status, accepted_entry_seq, outcome_bytes, outcome_sha256, received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'accepted', $7, $8, $9, $10) ON CONFLICT DO NOTHING",
        &[
            &convo_id, &msg_entry_id, &msg_signed_req_bytes, &msg_transcript, &msg_digest, &msg_sig,
            &4i64, &outcome_bytes, &outcome_sha, &now,
        ],
    )
    .await?;

    tx_msg.execute(
        "INSERT INTO chat.entries (conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, message_id, received_at) \
         VALUES ($1, 4, $2, 'blue.catbird.chat.defs#applicationEntry', $3, $4, $5, $6, $7, repeat('0', 1)::bytea, $8, $9, $10, $11, 1, 0, 2, $12, $13, $14) ON CONFLICT DO NOTHING",
        &[
            &convo_id, &msg_entry_id, &app_entry_bytes, &app_payload_sha.to_vec(),
            &msg_signed_req_bytes, &msg_digest, &msg_sig,
            &msg_outer_fp.to_vec(), &alice.did, &alice.device_id, &alice.key_id,
            &none_tr_id, &msg_entry_id, &now,
        ],
    )
    .await?;
    tx_msg
        .execute(
            "UPDATE chat.conversations SET next_entry_seq = 5 WHERE conversation_id = $1",
            &[&convo_id],
        )
        .await?;
    tx_msg.commit().await?;

    // Bob decrypts the message
    let decrypted = bob.engine.decrypt(&group_id, &ciphertext)?;
    assert_eq!(
        decrypted, plaintext_msg,
        "Bob decrypted plaintext must match Alice's message"
    );
    println!(
        "✓ Bob successfully decrypted Alice's message: '{}'",
        String::from_utf8_lossy(&decrypted)
    );

    // ──────────────────────────────────────────────────────────────────────────
    // STEP 5: Canonical Submit Commit DS2 -> DS1 (Sequencer)
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n=== STEP 5: Canonical Submit Commit DS2 -> DS1 ===");

    // Parse corpus manifest and seed corpus conversation on DS1
    let manifest: Value = serde_json::from_slice(MANIFEST_BYTES).expect("parse manifest.json");
    let chain = &manifest["chain"];
    let corpus_convo_id =
        Uuid::parse_str(manifest["identifiers"]["conversationId"].as_str().unwrap()).unwrap();
    let corpus_group_id: [u8; 32] = hex_array(chain["groupIdHex"].as_str().unwrap());
    let genesis_gch: [u8; 32] = hex_array(chain["genesisGroupContextHashHex"].as_str().unwrap());
    let genesis_ctag: [u8; 32] = hex_array(chain["genesisConfirmationTagHex"].as_str().unwrap());
    let committed_gch: [u8; 32] =
        hex_array(chain["committedGroupContextHashHex"].as_str().unwrap());
    let committed_ctag: [u8; 32] =
        hex_array(chain["committedConfirmationTagHex"].as_str().unwrap());
    let generic_gch: [u8; 32] = hex_array(
        chain["genericCommittedGroupContextHashHex"]
            .as_str()
            .unwrap(),
    );
    let generic_ctag: [u8; 32] = hex_array(
        chain["genericCommittedConfirmationTagHex"]
            .as_str()
            .unwrap(),
    );
    let corpus_creation_tr_id =
        Uuid::parse_str(manifest["creation"]["transitionId"].as_str().unwrap()).unwrap();
    let corpus_generic_tr_id = Uuid::parse_str(
        manifest["identifiers"]["genericTransitionId"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let (genesis_tree_summary, genesis_tree_summary_sha) =
        extract_tree_summary_from_snapshot(GENESIS_PUBLIC_STATE);
    let (committed_tree_summary, committed_tree_summary_sha) =
        extract_tree_summary_from_snapshot(COMMITTED_PUBLIC_STATE);

    let corpus_alice_manifest = &manifest["identity"]["alice"];
    let corpus_alice_did = corpus_alice_manifest["actorDid"]
        .as_str()
        .unwrap()
        .to_string();
    let corpus_alice_device_id =
        Uuid::parse_str(corpus_alice_manifest["deviceId"].as_str().unwrap()).unwrap();
    let corpus_alice_key_id = corpus_alice_manifest["keyId"].as_str().unwrap().to_string();
    let corpus_alice_signing_key = Ed25519SigningKey::from_bytes(&ALICE_SIGNING_SEED);
    let corpus_alice_public_key = corpus_alice_signing_key.verifying_key().to_bytes();

    let corpus_bob_manifest = &manifest["identity"]["bob"];
    let corpus_bob_did = corpus_bob_manifest["actorDid"]
        .as_str()
        .unwrap()
        .to_string();
    let corpus_bob_device_id =
        Uuid::parse_str(corpus_bob_manifest["deviceId"].as_str().unwrap()).unwrap();
    let corpus_bob_key_id = corpus_bob_manifest["keyId"].as_str().unwrap().to_string();
    let corpus_bob_signing_key = Ed25519SigningKey::from_bytes(&BOB_SIGNING_SEED);
    let corpus_bob_public_key = corpus_bob_signing_key.verifying_key().to_bytes();

    // Seed principals and keys for corpus actors on DS1
    let corpus_seed_time = now - chrono::Duration::minutes(5);
    ds1_pg.execute(
        "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2), ($3, $2) ON CONFLICT DO NOTHING",
        &[&corpus_alice_did, &corpus_seed_time, &corpus_bob_did],
    )
    .await?;

    ds1_pg.execute(
        "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
         VALUES ($1, $2, 'Corpus Alice Device', 'active', NULL, 1, chat.protocol_capabilities(), $3, $3) ON CONFLICT DO NOTHING",
        &[&corpus_alice_did, &corpus_alice_device_id, &corpus_seed_time],
    )
    .await?;

    ds1_pg.execute(
        "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
         VALUES ($1, $2, 'Corpus Bob Device', 'active', NULL, 1, chat.protocol_capabilities(), $3, $3) ON CONFLICT DO NOTHING",
        &[&corpus_bob_did, &corpus_bob_device_id, &corpus_seed_time],
    )
    .await?;

    ds1_pg.execute(
        "INSERT INTO chat.device_keys (user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at) \
         VALUES ($1, $2, $3, $4, 1, $5) ON CONFLICT DO NOTHING",
        &[&corpus_alice_did, &corpus_alice_device_id, &corpus_alice_key_id, &corpus_alice_public_key.to_vec(), &corpus_seed_time],
    )
    .await?;

    ds1_pg.execute(
        "INSERT INTO chat.device_keys (user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at) \
         VALUES ($1, $2, $3, $4, 1, $5) ON CONFLICT DO NOTHING",
        &[&corpus_bob_did, &corpus_bob_device_id, &corpus_bob_key_id, &corpus_bob_public_key.to_vec(), &corpus_seed_time],
    )
    .await?;

    let corpus_creation_entry_id = corpus_creation_tr_id;
    let corpus_inv_tr_id = Uuid::new_v4();
    let corpus_inv_entry_id = Uuid::new_v4();
    let corpus_acc_tr_id = Uuid::new_v4();
    let corpus_acc_entry_id = Uuid::new_v4();
    let corpus_add_tr_id = Uuid::new_v4();
    let corpus_add_entry_id = corpus_add_tr_id;
    let corpus_recovery_req_id = Uuid::new_v4();
    let corpus_welcome_id = Uuid::new_v4();
    let corpus_kp_ref: [u8; 32] = hex_array(chain["innerKeyPackageRefHex"].as_str().unwrap());
    let corpus_kp_wrapper = vec![0x77u8; 32];
    let corpus_metadata_ct = vec![0x88u8; 48];

    // Build creation entry (seq 1)
    let corpus_alice_identity = TestIdentity {
        did: corpus_alice_did.clone(),
        device_id: corpus_alice_device_id,
        key_id: corpus_alice_key_id.clone(),
        signing_key: Ed25519SigningKey::from_bytes(&ALICE_SIGNING_SEED),
        public_key: corpus_alice_public_key,
        engine: MlsEngine::new("alice-corpus").unwrap(),
    };
    let corpus_bob_identity = TestIdentity {
        did: corpus_bob_did.clone(),
        device_id: corpus_bob_device_id,
        key_id: corpus_bob_key_id.clone(),
        signing_key: Ed25519SigningKey::from_bytes(&BOB_SIGNING_SEED),
        public_key: corpus_bob_public_key,
        engine: MlsEngine::new("bob-corpus").unwrap(),
    };

    let (_, c_creation_signed_req) = make_creation_body_with_invitee(
        corpus_convo_id,
        corpus_creation_entry_id,
        &corpus_alice_identity,
        Some(&corpus_bob_identity),
        &corpus_group_id,
        &genesis_gch,
        &genesis_ctag,
        GROUP_INFO_MLS,
        &corpus_metadata_ct,
        corpus_seed_time,
    );
    let c_creation_wrapper = SignedWrapper::decode(&c_creation_signed_req).unwrap();
    let c_creation_projected =
        project_signed_body(SignedMutationKind::Creation, &c_creation_wrapper.body).unwrap();
    let c_creation_mutation =
        SigningTranscript::build_for(SignedMutationKind::Creation, &c_creation_projected).unwrap();
    let c_creation_unsigned_proj = c_creation_mutation.canonical_projection().to_vec();
    let c_creation_transcript = c_creation_mutation.bytes().to_vec();
    let c_creation_digest = c_creation_mutation.request_digest().to_vec();
    let c_creation_sig = corpus_alice_identity
        .signing_key
        .sign(&c_creation_transcript)
        .to_bytes()
        .to_vec();
    let mut c_creation_sig_arr = [0u8; 64];
    c_creation_sig_arr.copy_from_slice(&c_creation_sig);
    let c_creation_row = EntryRow {
        entry_id: *corpus_creation_entry_id.as_bytes(),
        conversation_id: *corpus_convo_id.as_bytes(),
        seq: 1,
        request_digest: *c_creation_mutation.request_digest(),
        signature: c_creation_sig_arr,
        received_at: corpus_seed_time.to_rfc3339_opts(SecondsFormat::Millis, true),
    };
    let c_creation_server_fields = ControlServerFields::empty(ControlEntryKind::Creation).unwrap();
    let c_creation_fp_obj = control_entry_fingerprint(
        ControlEntryKind::Creation,
        &c_creation_row,
        &c_creation_server_fields,
    )
    .unwrap();
    let c_creation_outer_fp = *c_creation_fp_obj.fingerprint().as_bytes();
    let c_creation_wrapper_json: Value = serde_json::from_slice(&c_creation_signed_req).unwrap();
    let c_creation_entry_bytes = serde_json::to_vec(&json!({
        "$type": "blue.catbird.chat.defs#creationEntry",
        "entryId": corpus_creation_entry_id.to_string(),
        "conversationId": corpus_convo_id.to_string(),
        "seq": 1,
        "receivedAt": corpus_seed_time.to_rfc3339_opts(SecondsFormat::Millis, true),
        "signedRequest": c_creation_wrapper_json,
    }))?;
    let c_creation_payload_sha: [u8; 32] = Sha256::digest(&c_creation_entry_bytes).into();

    // Build acceptance entry (seq 3)
    let (_, c_acc_signed_req) = make_acceptance_body(
        corpus_convo_id,
        corpus_acc_tr_id,
        corpus_recovery_req_id,
        corpus_creation_tr_id,
        &corpus_bob_identity,
        &corpus_alice_identity,
        &corpus_group_id,
        &genesis_gch,
        &genesis_ctag,
        corpus_seed_time,
    );
    let c_acc_wrapper = SignedWrapper::decode(&c_acc_signed_req).unwrap();
    let c_acc_projected = project_signed_body(
        SignedMutationKind::ParticipantAcceptance,
        &c_acc_wrapper.body,
    )
    .unwrap();
    let c_acc_mutation =
        SigningTranscript::build_for(SignedMutationKind::ParticipantAcceptance, &c_acc_projected)
            .unwrap();
    let c_acc_unsigned_proj = c_acc_mutation.canonical_projection().to_vec();
    let c_acc_transcript = c_acc_mutation.bytes().to_vec();
    let c_acc_digest = c_acc_mutation.request_digest().to_vec();
    let c_acc_sig = corpus_bob_identity
        .signing_key
        .sign(&c_acc_transcript)
        .to_bytes()
        .to_vec();
    let mut c_acc_sig_arr = [0u8; 64];
    c_acc_sig_arr.copy_from_slice(&c_acc_sig);
    let c_acc_row = EntryRow {
        entry_id: *corpus_acc_entry_id.as_bytes(),
        conversation_id: *corpus_convo_id.as_bytes(),
        seq: 3,
        request_digest: *c_acc_mutation.request_digest(),
        signature: c_acc_sig_arr,
        received_at: corpus_seed_time.to_rfc3339_opts(SecondsFormat::Millis, true),
    };
    let c_recovery_val = CanonicalValue::Map(BTreeMap::from([
        (
            "keyPackageRef".to_owned(),
            CanonicalValue::Bytes(corpus_kp_ref.to_vec()),
        ),
        (
            "recoveryRequestId".to_owned(),
            CanonicalValue::Uuid(*corpus_recovery_req_id.as_bytes()),
        ),
    ]));
    let c_acc_server_fields = ControlServerFields::single(
        ControlEntryKind::ParticipantAcceptance,
        "recovery",
        c_recovery_val.clone(),
    )
    .unwrap();
    let c_acc_fp_obj = control_entry_fingerprint(
        ControlEntryKind::ParticipantAcceptance,
        &c_acc_row,
        &c_acc_server_fields,
    )
    .unwrap();
    let c_acc_outer_fp = *c_acc_fp_obj.fingerprint().as_bytes();
    let c_acc_wrapper_json: Value = serde_json::from_slice(&c_acc_signed_req).unwrap();
    let c_acc_entry_bytes = serde_json::to_vec(&json!({
        "$type": "blue.catbird.chat.defs#participantAcceptanceEntry",
        "entryId": corpus_acc_entry_id.to_string(),
        "conversationId": corpus_convo_id.to_string(),
        "seq": 3,
        "receivedAt": corpus_seed_time.to_rfc3339_opts(SecondsFormat::Millis, true),
        "signedRequest": c_acc_wrapper_json,
        "recovery": {
            "recoveryRequestId": corpus_recovery_req_id.to_string(),
            "conversationId": corpus_convo_id.to_string(),
            "requesterDid": corpus_bob_did,
            "requesterDeviceId": corpus_bob_device_id.to_string(),
            "recoveryKind": "add",
            "boundCoordinate": {
                "conversationId": corpus_convo_id.to_string(),
                "generation": 0,
                "stateVersion": 2,
                "groupId": { "$bytes": STANDARD.encode(&corpus_group_id) },
                "epoch": 0,
                "groupContextHash": { "$bytes": STANDARD.encode(&genesis_gch) },
                "confirmationTag": { "$bytes": STANDARD.encode(&genesis_ctag) },
                "lifecycle": "active"
            },
            "reservation": {
                "recoveryRequestId": corpus_recovery_req_id.to_string(),
                "conversationId": corpus_convo_id.to_string(),
                "boundCoordinate": {
                    "conversationId": corpus_convo_id.to_string(),
                    "generation": 0,
                    "stateVersion": 2,
                    "groupId": { "$bytes": STANDARD.encode(&corpus_group_id) },
                    "epoch": 0,
                    "groupContextHash": { "$bytes": STANDARD.encode(&genesis_gch) },
                    "confirmationTag": { "$bytes": STANDARD.encode(&genesis_ctag) },
                    "lifecycle": "active"
                },
                "requesterDid": corpus_bob_did,
                "requesterDeviceId": corpus_bob_device_id.to_string(),
                "requesterKeyId": corpus_bob_key_id,
                "requesterAuthGeneration": 1,
                "keyPackageRef": { "$bytes": STANDARD.encode(&corpus_kp_ref) },
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "purpose": "leafRecovery",
                "status": "active",
                "expiresAt": (corpus_seed_time + chrono::Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "keyPackage": {
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": { "$bytes": STANDARD.encode(&corpus_kp_wrapper) },
                    "sha256": { "$bytes": STANDARD.encode(Sha256::digest(&corpus_kp_wrapper)) },
                    "keyPackageRef": { "$bytes": STANDARD.encode(&corpus_kp_ref) }
                }
            },
            "status": "open",
            "requestedAt": corpus_seed_time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expiresAt": (corpus_seed_time + chrono::Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        }
    }))?;

    // Build leaf recovery fulfillment entry (seq 4)
    let c_welcome_raw = vec![0x33u8; 64];
    let (_, c_add_signed_req) = make_leaf_recovery_fulfillment_body(
        corpus_convo_id,
        corpus_add_tr_id,
        corpus_recovery_req_id,
        corpus_creation_tr_id,
        &corpus_alice_identity,
        &corpus_bob_identity,
        &corpus_group_id,
        &genesis_gch,
        &genesis_ctag,
        &committed_gch,
        &committed_ctag,
        corpus_welcome_id,
        &c_welcome_raw,
        COMMIT_PUBLIC_MLS,
        &corpus_metadata_ct,
        &corpus_kp_ref,
        corpus_seed_time,
    );
    let c_add_wrapper = SignedWrapper::decode(&c_add_signed_req).unwrap();
    let c_add_projected = project_signed_body(
        SignedMutationKind::LeafRecoveryFulfillment,
        &c_add_wrapper.body,
    )
    .unwrap();
    let c_add_mutation = SigningTranscript::build_for(
        SignedMutationKind::LeafRecoveryFulfillment,
        &c_add_projected,
    )
    .unwrap();
    let c_add_transcript = c_add_mutation.bytes().to_vec();
    let c_add_digest = c_add_mutation.request_digest().to_vec();
    let c_add_sig = corpus_alice_identity
        .signing_key
        .sign(&c_add_transcript)
        .to_bytes()
        .to_vec();
    let mut c_add_sig_arr = [0u8; 64];
    c_add_sig_arr.copy_from_slice(&c_add_sig);
    let c_add_row = EntryRow {
        entry_id: *corpus_add_entry_id.as_bytes(),
        conversation_id: *corpus_convo_id.as_bytes(),
        seq: 4,
        request_digest: *c_add_mutation.request_digest(),
        signature: c_add_sig_arr,
        received_at: corpus_seed_time.to_rfc3339_opts(SecondsFormat::Millis, true),
    };
    let c_add_server_fields =
        ControlServerFields::empty(ControlEntryKind::LeafRecoveryFulfillment).unwrap();
    let c_add_fp_obj = control_entry_fingerprint(
        ControlEntryKind::LeafRecoveryFulfillment,
        &c_add_row,
        &c_add_server_fields,
    )
    .unwrap();
    let c_add_outer_fp = *c_add_fp_obj.fingerprint().as_bytes();
    let c_add_wrapper_json: Value = serde_json::from_slice(&c_add_signed_req).unwrap();
    let c_add_entry_bytes = serde_json::to_vec(&json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
        "entryId": corpus_add_entry_id.to_string(),
        "conversationId": corpus_convo_id.to_string(),
        "seq": 4,
        "receivedAt": corpus_seed_time.to_rfc3339_opts(SecondsFormat::Millis, true),
        "signedRequest": c_add_wrapper_json,
    }))?;

    let mut tx_c = ds1_pg.transaction().await?;
    tx_c.execute("SET CONSTRAINTS ALL DEFERRED", &[]).await?;
    tx_c.execute(
        "INSERT INTO chat.conversations (conversation_id, kind, lifecycle, current_generation, current_state_version, next_entry_seq, created_at, is_remote, sequencer_ds, sequencer_term) \
         VALUES ($1, 'group', 'active', 0, 3, 5, $2, false, NULL, 0) ON CONFLICT DO NOTHING",
        &[&corpus_convo_id, &corpus_seed_time],
    )
    .await?;

    tx_c.execute(
        "INSERT INTO chat.generations (conversation_id, generation, group_id, lifecycle, genesis_group_info_bytes, genesis_group_info_sha256, current_state_version, activated_seq, activated_at) \
         VALUES ($1, 0, $2, 'active', $3, $4, 3, 1, $5) ON CONFLICT DO NOTHING",
        &[
            &corpus_convo_id, &corpus_group_id.to_vec(), &GROUP_INFO_MLS.to_vec(),
            &Sha256::digest(GROUP_INFO_MLS).to_vec(), &corpus_seed_time,
        ],
    )
    .await?;

    let corpus_metadata_id_0 = Uuid::new_v4();
    let corpus_metadata_id_3 = Uuid::new_v4();

    // Transitions 1..=4
    tx_c.execute(
        "INSERT INTO chat.transitions (transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at) \
         VALUES ($1, $2, 'creation', $3, $4, $5, 1, 'admin', 'active', $6, $7, $8, $9, $10, 0, 0, $11, 1, $12)",
        &[
            &corpus_creation_tr_id, &corpus_convo_id, &corpus_alice_did, &corpus_alice_device_id, &corpus_alice_key_id,
            &c_creation_signed_req, &c_creation_unsigned_proj, &c_creation_transcript, &c_creation_digest, &c_creation_sig,
            &corpus_metadata_id_0, &corpus_seed_time,
        ],
    )
    .await?;

    tx_c.execute(
        "INSERT INTO chat.transitions (transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, prior_generation, prior_state_version, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at) \
         VALUES ($1, $2, 'policy', $3, $4, $5, 1, 'admin', 'active', $6, $7, $8, $9, $10, 0, 0, 0, 1, NULL, 2, $11)",
        &[
            &corpus_inv_tr_id, &corpus_convo_id, &corpus_alice_did, &corpus_alice_device_id, &corpus_alice_key_id,
            &c_creation_signed_req, &c_creation_unsigned_proj, &c_creation_transcript, &c_creation_digest, &c_creation_sig,
            &corpus_seed_time,
        ],
    )
    .await?;

    tx_c.execute(
        "INSERT INTO chat.transitions (transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, prior_generation, prior_state_version, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at) \
         VALUES ($1, $2, 'acceptConversation', $3, $4, $5, 1, 'member', 'active', $6, $7, $8, $9, $10, 0, 1, 0, 2, NULL, 3, $11)",
        &[
            &corpus_acc_tr_id, &corpus_convo_id, &corpus_bob_did, &corpus_bob_device_id, &corpus_bob_key_id,
            &c_acc_signed_req, &c_acc_unsigned_proj, &c_acc_transcript, &c_acc_digest, &c_acc_sig,
            &corpus_seed_time,
        ],
    )
    .await?;

    tx_c.execute(
        "INSERT INTO chat.transitions (transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, prior_generation, prior_state_version, next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at) \
         VALUES ($1, $2, 'leafRecovery', $3, $4, $5, 1, 'admin', 'active', $6, $6, $7, $8, $9, 0, 2, 0, 3, $10, 4, $11)",
        &[
            &corpus_add_tr_id, &corpus_convo_id, &corpus_alice_did, &corpus_alice_device_id, &corpus_alice_key_id,
            &c_add_signed_req, &c_add_transcript, &c_add_digest, &c_add_sig,
            &corpus_metadata_id_3, &corpus_seed_time,
        ],
    )
    .await?;

    // State versions 0..=3
    tx_c.execute(
        "INSERT INTO chat.generation_states (conversation_id, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, lifecycle, state_kind, producing_transition_id, public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count, created_at) \
         VALUES ($1, 0, 0, $2, 0, $3, $4, 'active', 'creation', $5, $6, $7, $8, $9, 1, $10), \
                ($1, 0, 1, $2, 0, $3, $4, 'active', 'policy', $11, $6, $7, $8, $9, 1, $10), \
                ($1, 0, 2, $2, 0, $3, $4, 'active', 'acceptConversation', $12, $6, $7, $8, $9, 1, $10), \
                ($1, 0, 3, $2, 1, $13, $14, 'active', 'commit', $15, $16, $17, $18, $19, 2, $10) ON CONFLICT DO NOTHING",
        &[
            &corpus_convo_id, &corpus_group_id.to_vec(), &genesis_gch.to_vec(), &genesis_ctag.to_vec(),
            &corpus_creation_tr_id, &GENESIS_PUBLIC_STATE.to_vec(), &Sha256::digest(GENESIS_PUBLIC_STATE).to_vec(),
            &genesis_tree_summary, &genesis_tree_summary_sha.to_vec(), &corpus_seed_time,
            &corpus_inv_tr_id, &corpus_acc_tr_id,
            &committed_gch.to_vec(), &committed_ctag.to_vec(),
            &corpus_add_tr_id, &COMMITTED_PUBLIC_STATE.to_vec(), &Sha256::digest(COMMITTED_PUBLIC_STATE).to_vec(),
            &committed_tree_summary, &committed_tree_summary_sha.to_vec(),
        ],
    )
    .await?;

    let corpus_alice_period = Uuid::new_v4();
    let corpus_bob_period = Uuid::new_v4();
    let corpus_alice_leaf = Uuid::new_v4();
    let corpus_bob_leaf = Uuid::new_v4();

    // Participants: Alice on DS2 (sender_ds_did), Bob on DS1 (local)
    tx_c.execute(
        "INSERT INTO chat.participants (participant_period_id, conversation_id, user_did, status, role, role_transition_id, role_changed_at, created_by_did, created_by_device_id, invitation_transition_id, invitation_entry_id, invited_at, acceptance_transition_id, acceptance_entry_id, accepted_at, current_membership, created_at, ds_did) \
         VALUES ($1, $2, $3, 'active', 'admin', $4, $5, $3, $6, NULL, NULL, NULL, NULL, NULL, NULL, TRUE, $5, $7), \
                ($8, $2, $9, 'active', 'member', $4, $5, $3, $6, $4, $10, $5, $11, $12, $5, TRUE, $5, NULL) ON CONFLICT DO NOTHING",
        &[
            &corpus_alice_period, &corpus_convo_id, &corpus_alice_did, &corpus_creation_tr_id, &corpus_seed_time, &corpus_alice_device_id,
            &cluster.ds2_service_did,
            &corpus_bob_period, &corpus_bob_did,
            &corpus_creation_entry_id, &corpus_acc_tr_id, &corpus_acc_entry_id,
        ],
    )
    .await?;

    let c_not_before = corpus_seed_time - chrono::Duration::minutes(5);
    let c_not_after = corpus_seed_time + chrono::Duration::hours(24);
    let c_expires_at = corpus_seed_time + chrono::Duration::minutes(5);
    let c_welcome_expires_at = corpus_seed_time + chrono::Duration::hours(24);

    // Key package & recovery state on DS1
    tx_c.execute(
        "INSERT INTO chat.key_packages (key_package_ref, wrapper_bytes, wrapper_sha256, init_key, owner_did, owner_device_id, owner_key_id, owner_auth_generation, not_before, not_after, status, terminal_transition_id, terminal_at, created_at) \
         VALUES ($1, repeat('w', 32)::bytea, digest(repeat('w', 32)::bytea, 'sha256'), repeat('c', 32)::bytea, $2, $3, $4, 1, $5, $6, 'consumed', $7, $8, $8)",
        &[&corpus_kp_ref.to_vec(), &corpus_bob_did, &corpus_bob_device_id, &corpus_bob_key_id, &c_not_before, &c_not_after, &corpus_add_tr_id, &corpus_seed_time],
    )
    .await?;

    tx_c.execute(
        "INSERT INTO chat.leaf_recovery_requests (recovery_request_id, conversation_id, generation, requester_did, requester_device_id, requester_key_id, requester_auth_generation, recovery_kind, source, bound_state_version, bound_group_id, bound_epoch, bound_group_context_hash, bound_confirmation_tag, reservation_request_id, status, fulfilling_transition_id, terminal_at, signed_request_bytes, signing_transcript_bytes, request_digest, signature, requested_at, expires_at) \
         VALUES ($1, $2, 0, $3, $4, $5, 1, 'add', 'acceptConversation', 2, $6, 0, $7, $8, $1, 'fulfilled', $9, $10, $11, $12, $13, $14, $10, $15)",
        &[
            &corpus_recovery_req_id, &corpus_convo_id, &corpus_bob_did, &corpus_bob_device_id, &corpus_bob_key_id,
            &corpus_group_id.to_vec(), &genesis_gch.to_vec(), &genesis_ctag.to_vec(), &corpus_add_tr_id, &corpus_seed_time,
            &c_acc_signed_req, &c_acc_transcript, &c_acc_digest, &c_acc_sig, &c_expires_at,
        ],
    )
    .await?;
    tx_c.execute(
        "INSERT INTO chat.key_package_reservations (recovery_request_id, key_package_ref, conversation_id, generation, requester_did, requester_device_id, requester_key_id, requester_auth_generation, recipient_did, recipient_device_id, bound_state_version, bound_group_id, bound_epoch, bound_group_context_hash, bound_confirmation_tag, purpose, expires_at, status, consumed_transition_id, terminal_at, created_at) \
         VALUES ($1, $2, $3, 0, $4, $5, $6, 1, $4, $5, 2, $7, 0, $8, $9, 'leafRecovery', $10, 'consumed', $11, $12, $12)",
        &[&corpus_recovery_req_id, &corpus_kp_ref.to_vec(), &corpus_convo_id, &corpus_bob_did, &corpus_bob_device_id, &corpus_bob_key_id, &corpus_group_id.to_vec(), &genesis_gch.to_vec(), &genesis_ctag.to_vec(), &c_expires_at, &corpus_add_tr_id, &corpus_seed_time],
    )
    .await?;

    let c_welcome_bytes = vec![0x33u8; 64];
    let c_welcome_sha: [u8; 32] = Sha256::digest(&c_welcome_bytes).into();
    tx_c.execute(
        "INSERT INTO chat.welcome_bundles (welcome_id, conversation_id, transition_id, entry_seq, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, wrapper_bytes, wrapper_sha256, created_at) \
         VALUES ($1, $2, $3, 4, 0, 3, $4, 1, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
        &[
            &corpus_welcome_id, &corpus_convo_id, &corpus_add_tr_id, &corpus_group_id.to_vec(),
            &committed_gch.to_vec(), &committed_ctag.to_vec(), &c_welcome_bytes, &c_welcome_sha.to_vec(), &corpus_seed_time,
        ],
    )
    .await?;

    tx_c.execute(
        "INSERT INTO chat.welcome_deliveries (welcome_id, recipient_did, recipient_device_id, recovery_request_id, key_package_ref, expires_at, status) \
         VALUES ($1, $2, $3, $4, $5, $6, 'pending') ON CONFLICT DO NOTHING",
        &[
            &corpus_welcome_id, &corpus_bob_did, &corpus_bob_device_id, &corpus_recovery_req_id,
            &corpus_kp_ref.to_vec(), &c_welcome_expires_at,
        ],
    )
    .await?;

    let alice_cred = format!("{}#{}", corpus_alice_did, corpus_alice_device_id).into_bytes();
    let bob_cred = format!("{}#{}", corpus_bob_did, corpus_bob_device_id).into_bytes();

    tx_c.execute(
        "INSERT INTO chat.member_devices (leaf_period_id, participant_period_id, conversation_id, generation, user_did, device_id, leaf_index, basic_credential, leaf_signature_key, leaf_key_id, leaf_auth_generation, origin, join_key_package_ref, joined_state_version, joined_transition_id, joined_seq, active, created_at) \
         VALUES ($1, $2, $3, 0, $4, $5, 0, $6, $7, $8, 1, 'genesis', NULL, 0, $9, 1, TRUE, $10), \
                ($11, $12, $3, 0, $13, $14, 1, $15, $16, $17, 1, 'keyPackage', $18, 3, $19, 4, TRUE, $10) ON CONFLICT DO NOTHING",
        &[
            &corpus_alice_leaf, &corpus_alice_period, &corpus_convo_id,
            &corpus_alice_did, &corpus_alice_device_id, &alice_cred, &corpus_alice_public_key.to_vec(), &corpus_alice_key_id,
            &corpus_creation_tr_id, &corpus_seed_time,
            &corpus_bob_leaf, &corpus_bob_period,
            &corpus_bob_did, &corpus_bob_device_id, &bob_cred, &corpus_bob_public_key.to_vec(), &corpus_bob_key_id,
            &corpus_kp_ref.to_vec(), &corpus_add_tr_id,
        ],
    )
    .await?;

    tx_c.execute(
        "INSERT INTO chat.metadata_snapshots (metadata_snapshot_id, conversation_id, generation, state_version, group_id, epoch, group_context_hash, confirmation_tag, producing_transition_id, origin_transition_id, metadata_version, nonce, ciphertext, ciphertext_sha256, ciphertext_size, author_did, author_device_id, author_key_id, author_public_key, author_auth_generation, author_origin_seq, author_role, author_device_status, created_at) \
         VALUES ($1, $2, 0, 0, $3, 0, $4, $5, $6, $6, 1, repeat('n', 12)::bytea, $16::bytea, digest($16::bytea, 'sha256'), 48, $7, $8, $9, $10, 1, 1, 'admin', 'active', $11), \
                ($12, $2, 0, 3, $3, 1, $13, $14, $15, $6, 1, repeat('k', 12)::bytea, $16::bytea, digest($16::bytea, 'sha256'), 48, $7, $8, $9, $10, 1, 1, 'admin', 'active', $11) ON CONFLICT DO NOTHING",
        &[
            &corpus_metadata_id_0, &corpus_convo_id, &corpus_group_id.to_vec(), &genesis_gch.to_vec(), &genesis_ctag.to_vec(),
            &corpus_creation_tr_id, &corpus_alice_did, &corpus_alice_device_id, &corpus_alice_key_id, &corpus_alice_public_key.to_vec(), &corpus_seed_time,
            &corpus_metadata_id_3, &committed_gch.to_vec(), &committed_ctag.to_vec(), &corpus_add_tr_id, &corpus_metadata_ct,
        ],
    )
    .await?;

    // Entries 1..=4
    let empty_map: BTreeMap<String, String> = BTreeMap::new();
    let c_creation_sf_bytes = serde_ipld_dagcbor::to_vec(&empty_map).unwrap();
    let c_acc_sf_map = BTreeMap::from([("recovery".to_string(), c_recovery_val)]);
    let c_acc_sf_bytes = serde_ipld_dagcbor::to_vec(&c_acc_sf_map).unwrap();
    let c_add_sf_bytes = c_creation_sf_bytes.clone();
    tx_c.execute(
        "INSERT INTO chat.entries (conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at) \
         VALUES ($1, 1, $2, 'blue.catbird.chat.defs#creationEntry', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 1, 0, 0, $13, $14)",
        &[
            &corpus_convo_id, &corpus_creation_entry_id, &c_creation_entry_bytes, &c_creation_payload_sha.to_vec(),
            &c_creation_signed_req, &c_creation_digest, &c_creation_sig,
            &c_creation_sf_bytes, &c_creation_outer_fp.to_vec(),
            &corpus_alice_did, &corpus_alice_device_id, &corpus_alice_key_id,
            &corpus_creation_tr_id, &corpus_seed_time,
        ],
    )
    .await?;

    tx_c.execute(
        "INSERT INTO chat.entries (conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at) \
         VALUES ($1, 2, $2, 'blue.catbird.chat.defs#policyEntry', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 1, 0, 1, $13, $14)",
        &[
            &corpus_convo_id, &corpus_inv_entry_id, &c_creation_entry_bytes, &c_creation_payload_sha.to_vec(),
            &c_creation_signed_req, &c_creation_digest, &c_creation_sig,
            &c_creation_sf_bytes, &c_creation_outer_fp.to_vec(),
            &corpus_alice_did, &corpus_alice_device_id, &corpus_alice_key_id,
            &corpus_inv_tr_id, &corpus_seed_time,
        ],
    )
    .await?;

    tx_c.execute(
        "INSERT INTO chat.entries (conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at) \
         VALUES ($1, 3, $2, 'blue.catbird.chat.defs#participantAcceptanceEntry', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 1, 0, 2, $13, $14)",
        &[
            &corpus_convo_id, &corpus_acc_entry_id, &c_acc_entry_bytes, &Sha256::digest(&c_acc_entry_bytes).to_vec(),
            &c_acc_signed_req, &c_acc_digest, &c_acc_sig,
            &c_acc_sf_bytes, &c_acc_outer_fp.to_vec(),
            &corpus_bob_did, &corpus_bob_device_id, &corpus_bob_key_id,
            &corpus_acc_tr_id, &corpus_seed_time,
        ],
    )
    .await?;

    tx_c.execute(
        "INSERT INTO chat.entries (conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at) \
         VALUES ($1, 4, $2, 'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 1, 0, 3, $13, $14)",
        &[
            &corpus_convo_id, &corpus_add_entry_id, &c_add_entry_bytes, &Sha256::digest(&c_add_entry_bytes).to_vec(),
            &c_add_signed_req, &c_add_digest, &c_add_sig,
            &c_add_sf_bytes, &c_add_outer_fp.to_vec(),
            &corpus_alice_did, &corpus_alice_device_id, &corpus_alice_key_id,
            &corpus_add_tr_id, &corpus_seed_time,
        ],
    )
    .await?;

    // Application intervals for Alice and Bob
    tx_c.execute(
        "INSERT INTO chat.application_intervals (membership_interval_id, conversation_id, generation, recipient_did, recipient_device_id, start_seq, opening_kind, opening_transition_id, opening_outer_entry_fingerprint, opening_state_version, opening_group_id, opening_epoch, opening_group_context_hash, opening_confirmation_tag, opening_leaf_period_id, created_at) \
         VALUES ($1, $2, 0, $3, $4, 1, 'creation', $1, $5, 0, $6, 0, $7, $8, $9, $10), \
                ($11, $2, 0, $12, $13, 4, 'add', $11, $14, 3, $6, 1, $15, $16, $17, $10)",
        &[
            &corpus_creation_tr_id, &corpus_convo_id, &corpus_alice_did, &corpus_alice_device_id,
            &c_creation_outer_fp.to_vec(), &corpus_group_id.to_vec(), &genesis_gch.to_vec(), &genesis_ctag.to_vec(),
            &corpus_alice_leaf, &corpus_seed_time,
            &corpus_add_tr_id, &corpus_bob_did, &corpus_bob_device_id,
            &c_add_outer_fp.to_vec(), &committed_gch.to_vec(), &committed_ctag.to_vec(), &corpus_bob_leaf,
        ],
    )
    .await?;

    tx_c.commit().await?;

    // Generate canonical valid signed commit
    let (_, corpus_signed_req_bytes) = make_corpus_commit_body(
        corpus_convo_id,
        corpus_generic_tr_id,
        corpus_creation_tr_id,
        &corpus_alice_did,
        corpus_alice_device_id,
        &corpus_alice_key_id,
        &corpus_alice_public_key,
        &corpus_alice_signing_key,
        &corpus_group_id,
        &committed_gch,
        &committed_ctag,
        &generic_gch,
        &generic_ctag,
        COMMIT_GENERIC_PUBLIC_MLS,
        now,
    );

    let canonical_commit_delivery_id = Uuid::new_v4();
    let canonical_commit_received_at = now.to_rfc3339_opts(SecondsFormat::Millis, true);
    let canonical_commit_payload_sha = compute_commit_envelope_digest(
        canonical_commit_delivery_id,
        corpus_convo_id,
        &cluster.ds2_service_did,
        &cluster.ds1_service_did,
        &cluster.ds1_service_did,
        0,
        &canonical_commit_received_at,
        &corpus_signed_req_bytes,
    );

    let canonical_commit_header_json = json!({
        "protocolVersion": "1",
        "deliveryId": canonical_commit_delivery_id.to_string(),
        "conversationId": corpus_convo_id.to_string(),
        "senderDsDid": cluster.ds2_service_did,
        "receiverDsDid": cluster.ds1_service_did,
        "sequencerDid": cluster.ds1_service_did,
        "sequencerTerm": 0,
        "receivedAt": canonical_commit_received_at,
        "payloadSha256": { "$bytes": STANDARD.encode(&canonical_commit_payload_sha) }
    });

    let canonical_submit_commit_body = json!({
        "header": canonical_commit_header_json,
        "signedRequestBytes": { "$bytes": STANDARD.encode(&corpus_signed_req_bytes) }
    });

    let ds2_canonical_commit_jwt =
        cluster.mint_ds2_jwt(&cluster.ds1_service_did, SUBMIT_COMMIT_NSID);

    // 1. Positive authenticated submitCommit
    let canonical_commit_resp = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.submitCommit",
            cluster.ds1_url
        ))
        .header(
            "authorization",
            format!("Bearer {ds2_canonical_commit_jwt}"),
        )
        .json(&canonical_submit_commit_body)
        .send()
        .await?;
    let commit_status = canonical_commit_resp.status();
    let commit_text = canonical_commit_resp.text().await?;
    if commit_status != reqwest::StatusCode::OK {
        panic!("submitCommit to DS1 failed (status {commit_status}): {commit_text}");
    }
    let commit_res_json: Value = serde_json::from_str(&commit_text)?;
    let commit_receipt = &commit_res_json["receipt"];
    assert_eq!(commit_receipt["endpoint"], SUBMIT_COMMIT_NSID);
    assert_eq!(
        commit_receipt["deliveryId"],
        canonical_commit_delivery_id.to_string()
    );
    assert_eq!(commit_receipt["senderDsDid"], cluster.ds2_service_did);
    assert_eq!(commit_receipt["receiverDsDid"], cluster.ds1_service_did);
    assert_eq!(commit_receipt["sequencerDid"], cluster.ds1_service_did);
    assert_eq!(
        commit_receipt["sequencerTerm"], 0,
        "sequencer term is preserved (0), not incremented"
    );

    let coordinates = &commit_res_json["coordinates"];
    assert_eq!(
        coordinates["stateVersion"], 4,
        "state version advanced to 4"
    );
    assert_eq!(coordinates["epoch"], 2, "epoch advanced to 2");
    assert_eq!(coordinates["lifecycle"], "active");

    let sig_bytes_commit =
        STANDARD.decode(commit_receipt["signature"]["$bytes"].as_str().unwrap())?;
    let res_sha_commit: [u8; 32] = hex_or_bytes(&commit_receipt["resultSha256"])?;
    let source_loc_seq = commit_receipt["sourceLocator"]["seq"].as_u64().unwrap();
    let source_loc_entry_id =
        Uuid::parse_str(commit_receipt["sourceLocator"]["entryId"].as_str().unwrap())?;
    let source_loc_payload_sha: [u8; 32] =
        hex_or_bytes(&commit_receipt["sourceLocator"]["acceptedPayloadSha256"])?;
    let source_loc_fp: [u8; 32] =
        hex_or_bytes(&commit_receipt["sourceLocator"]["outerEntryFingerprint"])?;

    let canonical_rec_commit = canonical_receipt_bytes(
        SUBMIT_COMMIT_NSID,
        canonical_commit_delivery_id,
        corpus_convo_id,
        &cluster.ds2_service_did,
        &cluster.ds1_service_did,
        &cluster.ds1_service_did,
        0,
        &canonical_commit_payload_sha,
        &res_sha_commit,
        Some((
            source_loc_entry_id,
            source_loc_seq,
            &source_loc_payload_sha,
            &source_loc_fp,
        )),
        commit_receipt["completedAt"].as_str().unwrap(),
    );
    cluster.verify_ds1_signature(&canonical_rec_commit, &sig_bytes_commit)?;
    println!("✓ DS1 returned valid signed receipt for submitCommit (stateVersion=4, epoch=2, term=0 preserved)");

    // Verify DS1 database state: conversations, entries, generation_states, delivery_receipts
    let (ds1_seq_term, ds1_sv, ds1_next_seq): (i64, i64, i64) = {
        let row = ds1_pg.query_one(
            "SELECT sequencer_term, current_state_version, next_entry_seq FROM chat.conversations WHERE conversation_id = $1",
            &[&corpus_convo_id],
        ).await?;
        (row.get(0), row.get(1), row.get(2))
    };
    assert_eq!(
        ds1_seq_term, 0,
        "sequencer_term in chat.conversations must remain 0"
    );
    assert_eq!(ds1_sv, 4, "current_state_version must advance to 4");
    assert_eq!(ds1_next_seq, 6, "next_entry_seq must advance to 6");

    let ds1_commit_entry_count: i64 = ds1_pg.query_one(
        "SELECT count(*) FROM chat.entries WHERE conversation_id = $1 AND seq = 5 AND entry_kind = 'blue.catbird.chat.defs#commitEntry'",
        &[&corpus_convo_id],
    ).await?.get(0);
    assert_eq!(
        ds1_commit_entry_count, 1,
        "commitEntry must be persisted in chat.entries on DS1"
    );

    let ds1_gen_state_count: i64 = ds1_pg.query_one(
        "SELECT count(*) FROM chat.generation_states WHERE conversation_id = $1 AND state_version = 4 AND epoch = 2",
        &[&corpus_convo_id],
    ).await?.get(0);
    assert_eq!(
        ds1_gen_state_count, 1,
        "generation_states for state_version 4, epoch 2 must exist on DS1"
    );

    // Idempotent replay of submitCommit
    let ds2_canonical_commit_jwt_replay =
        cluster.mint_ds2_jwt(&cluster.ds1_service_did, SUBMIT_COMMIT_NSID);
    let commit_replay_resp = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.submitCommit",
            cluster.ds1_url
        ))
        .header(
            "authorization",
            format!("Bearer {ds2_canonical_commit_jwt_replay}"),
        )
        .json(&canonical_submit_commit_body)
        .send()
        .await?;
    assert_eq!(
        commit_replay_resp.status(),
        reqwest::StatusCode::OK,
        "submitCommit replay must succeed"
    );
    let commit_replay_json: Value = commit_replay_resp.json().await?;
    assert_eq!(
        commit_replay_json["receipt"]["signature"]["$bytes"], commit_receipt["signature"]["$bytes"],
        "submitCommit replay must return identical signed receipt"
    );
    println!("✓ Idempotent replay of submitCommit returned identical receipt");

    // Negative: Corrupted / mock commit bytes rejected by canonical executor
    let mock_delivery_id = Uuid::new_v4();
    let mock_bytes = vec![0x5au8; 8];
    let mock_received_at = now.to_rfc3339_opts(SecondsFormat::Millis, true);
    let mock_payload_sha = compute_commit_envelope_digest(
        mock_delivery_id,
        corpus_convo_id,
        &cluster.ds2_service_did,
        &cluster.ds1_service_did,
        &cluster.ds1_service_did,
        0,
        &mock_received_at,
        &mock_bytes,
    );
    let mock_body = json!({
        "header": {
            "protocolVersion": "1",
            "deliveryId": mock_delivery_id.to_string(),
            "conversationId": corpus_convo_id.to_string(),
            "senderDsDid": cluster.ds2_service_did,
            "receiverDsDid": cluster.ds1_service_did,
            "sequencerDid": cluster.ds1_service_did,
            "sequencerTerm": 0,
            "receivedAt": mock_received_at,
            "payloadSha256": { "$bytes": STANDARD.encode(&mock_payload_sha) }
        },
        "signedRequestBytes": { "$bytes": STANDARD.encode(&mock_bytes) }
    });
    let mock_jwt = cluster.mint_ds2_jwt(&cluster.ds1_service_did, SUBMIT_COMMIT_NSID);
    let mock_resp = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.submitCommit",
            cluster.ds1_url
        ))
        .header("authorization", format!("Bearer {mock_jwt}"))
        .json(&mock_body)
        .send()
        .await?;
    assert!(
        mock_resp.status().is_client_error(),
        "mock commit bytes must be rejected by canonical planner: {:?}",
        mock_resp.status()
    );
    println!("✓ DS1 rejected mock commit bytes via canonical executor verification");

    // ──────────────────────────────────────────────────────────────────────────
    // STEP 6: Deliberate Drift + Real Reconciliation Worker Await
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n=== STEP 6: Deliberate Drift + Real Reconciliation Worker Await ===");

    // Add message 2 on DS1 at seq 5 to create deliberate drift on convo_id
    let plaintext_msg_2 = b"Second message creating drift on DS1";
    let (ciphertext_2, _) = alice.engine.encrypt(&group_id, plaintext_msg_2)?;
    let msg2_entry_id = Uuid::new_v4();
    let msg2_seq = 5u64;

    let (_, msg2_signed_req_bytes) = make_message_body(
        convo_id,
        msg2_entry_id,
        &alice,
        &group_id,
        2,
        1,
        &sv2_gch,
        &sv2_ctag,
        &ciphertext_2,
        now,
    );
    let msg2_wrapper = SignedWrapper::decode(&msg2_signed_req_bytes).unwrap();
    let msg2_projected =
        project_signed_body(SignedMutationKind::ApplicationSend, &msg2_wrapper.body).unwrap();
    let msg2_mutation =
        SigningTranscript::build_for(SignedMutationKind::ApplicationSend, &msg2_projected).unwrap();
    let msg2_transcript = msg2_mutation.bytes().to_vec();
    let msg2_digest = msg2_mutation.request_digest().to_vec();
    let msg2_sig = alice.signing_key.sign(&msg2_transcript).to_bytes().to_vec();
    let mut msg2_sig_arr = [0u8; 64];
    msg2_sig_arr.copy_from_slice(&msg2_sig);
    let msg2_row = EntryRow {
        entry_id: *msg2_entry_id.as_bytes(),
        conversation_id: *convo_id.as_bytes(),
        seq: msg2_seq,
        request_digest: *msg2_mutation.request_digest(),
        signature: msg2_sig_arr,
        received_at: now.to_rfc3339_opts(SecondsFormat::Millis, true),
    };
    let msg2_fp_obj = application_entry_fingerprint(&msg2_row).unwrap();
    let msg2_outer_fp = *msg2_fp_obj.fingerprint().as_bytes();

    let app2_entry_dag = BTreeMap::from([
        (
            "conversationId".to_owned(),
            CanonicalValue::Uuid(*convo_id.as_bytes()),
        ),
        (
            "entryId".to_owned(),
            CanonicalValue::Uuid(*msg2_entry_id.as_bytes()),
        ),
        (
            "receivedAt".to_owned(),
            CanonicalValue::Timestamp(now.to_rfc3339_opts(SecondsFormat::Millis, true)),
        ),
        ("seq".to_owned(), CanonicalValue::Integer(msg2_seq)),
        (
            "signedRequest".to_owned(),
            CanonicalValue::Map(BTreeMap::from([
                ("body".to_owned(), CanonicalValue::Map(msg2_projected)),
                (
                    "signature".to_owned(),
                    CanonicalValue::Bytes(msg2_sig.to_vec()),
                ),
            ])),
        ),
    ]);
    let app2_entry_bytes = serde_ipld_dagcbor::to_vec(&app2_entry_dag).unwrap();
    let app2_payload_sha: [u8; 32] = Sha256::digest(&app2_entry_bytes).into();

    // Insert seq 5 entry ONLY on DS1
    let none_tr_id_2: Option<Uuid> = None;
    let outcome2_bytes = serde_json::to_vec(&json!({
        "entry": {
            "entryId": msg2_entry_id.to_string(),
            "conversationId": convo_id.to_string(),
            "seq": 5,
            "signedRequest": serde_json::from_slice::<Value>(&msg2_signed_req_bytes).unwrap(),
            "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
        }
    }))?;
    let outcome2_sha = Sha256::digest(&outcome2_bytes).to_vec();

    let mut tx_msg2 = ds1_pg.transaction().await?;
    tx_msg2.execute(
        "INSERT INTO chat.message_sends (conversation_id, message_id, signed_request_bytes, signing_transcript_bytes, request_digest, signature, status, accepted_entry_seq, outcome_bytes, outcome_sha256, received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'accepted', $7, $8, $9, $10) ON CONFLICT DO NOTHING",
        &[
            &convo_id, &msg2_entry_id, &msg2_signed_req_bytes, &msg2_transcript, &msg2_digest, &msg2_sig,
            &5i64, &outcome2_bytes, &outcome2_sha, &now,
        ],
    )
    .await?;

    tx_msg2.execute(
        "INSERT INTO chat.entries (conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes, request_digest, signature, server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, actor_key_id, actor_auth_generation, generation, state_version, transition_id, message_id, received_at) \
         VALUES ($1, 5, $2, 'blue.catbird.chat.defs#applicationEntry', $3, $4, $5, $6, $7, repeat('0', 1)::bytea, $8, $9, $10, $11, 1, 0, 2, $12, $13, $14) ON CONFLICT DO NOTHING",
        &[
            &convo_id, &msg2_entry_id, &app2_entry_bytes, &app2_payload_sha.to_vec(),
            &msg2_signed_req_bytes, &msg2_digest, &msg2_sig,
            &msg2_outer_fp.to_vec(), &alice.did, &alice.device_id, &alice.key_id,
            &none_tr_id_2, &msg2_entry_id, &now,
        ],
    )
    .await?;
    tx_msg2
        .execute(
            "UPDATE chat.conversations SET next_entry_seq = 6 WHERE conversation_id = $1",
            &[&convo_id],
        )
        .await?;
    tx_msg2.commit().await?;

    // Query DS1 digest
    let digest_jwt = cluster.mint_ds2_jwt(
        &cluster.ds1_service_did,
        "blue.catbird.mlsDS.getConvoDigest",
    );
    let digest_resp = cluster
        .http_client
        .get(format!(
            "{}/xrpc/blue.catbird.mlsDS.getConvoDigest?convoId={convo_id}",
            cluster.ds1_url
        ))
        .header("authorization", format!("Bearer {digest_jwt}"))
        .send()
        .await?;
    assert_eq!(digest_resp.status(), reqwest::StatusCode::OK);
    let ds1_digest_json: Value = digest_resp.json().await?;
    let ds1_last_seq = ds1_digest_json["lastSeq"].as_i64().unwrap();
    let ds1_digest_sha = ds1_digest_json["digestSha256"].as_str().unwrap();
    assert_eq!(ds1_last_seq, 5, "DS1 lastSeq must be 5");
    println!("✓ DS1 current digest at seq 5: {}", ds1_digest_sha);

    // Verify DS2 is initially drifted (only has 4 entries)
    let ds2_entries_before: i64 = ds2_pg
        .query_one(
            "SELECT count(*) FROM chat.entries WHERE conversation_id = $1",
            &[&convo_id],
        )
        .await?
        .get(0);
    assert_eq!(
        ds2_entries_before, 4,
        "DS2 must initially have only 4 entries"
    );

    // Await background reconciliation worker on DS2 (configured to tick every 2s)
    println!("Waiting for DS2 reconciliation worker to detect drift and catch up...");
    let mut reconciled = false;
    for _ in 0..100 {
        let sync_row = ds2_pg.query_opt(
            "SELECT last_seq, last_digest, drift_count FROM federation_sync_state WHERE convo_id = $1",
            &[&convo_id.to_string()],
        ).await?;
        if let Some(row) = sync_row {
            let last_seq: i64 = row.get("last_seq");
            let last_digest: String = row.get("last_digest");
            let drift_count: i64 = row.get("drift_count");
            if last_seq >= 5 && drift_count >= 1 && last_digest == ds1_digest_sha {
                reconciled = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        reconciled,
        "DS2 reconciliation worker must catch up missing event seq 5"
    );

    // Verify DS2 entries and conversations updated
    let ds2_entries_after: i64 = ds2_pg
        .query_one(
            "SELECT count(*) FROM chat.entries WHERE conversation_id = $1 AND seq = 5",
            &[&convo_id],
        )
        .await?
        .get(0);
    assert_eq!(
        ds2_entries_after, 1,
        "missing event seq 5 must be applied in DS2 chat.entries"
    );

    let ds2_next_seq_after: i64 = ds2_pg
        .query_one(
            "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id = $1",
            &[&convo_id],
        )
        .await?
        .get(0);
    assert_eq!(
        ds2_next_seq_after, 6,
        "DS2 next_entry_seq must advance to 6"
    );

    // Query DS2 digest to verify convergence
    let ds2_digest_jwt = cluster.mint_ds1_jwt(
        &cluster.ds2_service_did,
        "blue.catbird.mlsDS.getConvoDigest",
    );
    let ds2_digest_resp = cluster
        .http_client
        .get(format!(
            "{}/xrpc/blue.catbird.mlsDS.getConvoDigest?convoId={convo_id}",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {ds2_digest_jwt}"))
        .send()
        .await?;
    assert_eq!(ds2_digest_resp.status(), reqwest::StatusCode::OK);
    let ds2_digest_json: Value = ds2_digest_resp.json().await?;
    assert_eq!(
        ds2_digest_json["digestSha256"].as_str().unwrap(),
        ds1_digest_sha,
        "DS2 digest must converge with DS1 after reconciliation"
    );
    println!(
        "✓ DS1 and DS2 state & digests successfully converged (seq=5, digest={ds1_digest_sha})"
    );

    // ──────────────────────────────────────────────────────────────────────────
    // STEP 7: Assert Delivery Receipts and Queue Terminal States
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n=== STEP 7: Assert Delivery Receipts and Outbox/Queue Rows ===");

    let ds2_receipt_rows = ds2_pg
        .query(
            "SELECT endpoint_nsid, delivery_id, sender_ds_did, receiver_ds_did \
             FROM chat.federation_delivery_receipts WHERE conversation_id = $1 ORDER BY completed_at ASC",
            &[&convo_id],
        )
        .await?;
    assert!(
        ds2_receipt_rows.len() >= 2,
        "Expected at least 2 receipts on DS2, got {}",
        ds2_receipt_rows.len()
    );
    println!(
        "✓ Verified {} delivery receipts stored in DS2 database",
        ds2_receipt_rows.len()
    );

    let ds1_receipt_rows = ds1_pg
        .query(
            "SELECT endpoint_nsid, delivery_id, sender_ds_did, receiver_ds_did \
             FROM chat.federation_delivery_receipts WHERE conversation_id = $1 ORDER BY completed_at ASC",
            &[&corpus_convo_id],
        )
        .await?;
    assert_eq!(
        ds1_receipt_rows.len(),
        1,
        "Expected 1 submitCommit delivery receipt on DS1"
    );
    let ds1_receipt_endpoint: String = ds1_receipt_rows[0].get("endpoint_nsid");
    assert_eq!(ds1_receipt_endpoint, SUBMIT_COMMIT_NSID);
    println!("✓ Verified submitCommit delivery receipt stored in DS1 database");

    // Assert outbound_queue and federation_outbox terminal / clean states
    for (name, pg) in [("DS1", &ds1_pg), ("DS2", &ds2_pg)] {
        let in_flight_queue: i64 = pg.query_one(
            "SELECT count(*) FROM outbound_queue WHERE status = 'in_flight' AND claim_expires_at < NOW()",
            &[],
        ).await?.get(0);
        assert_eq!(
            in_flight_queue, 0,
            "{name} outbound_queue must have no expired in_flight claims"
        );

        let in_flight_outbox: i64 = pg.query_one(
            "SELECT count(*) FROM federation_outbox WHERE status = 'in_flight' AND claim_expires_at < NOW()",
            &[],
        ).await?.get(0);
        assert_eq!(
            in_flight_outbox, 0,
            "{name} federation_outbox must have no expired in_flight claims"
        );
    }
    println!("✓ Verified outbound_queue and federation_outbox invariants on both nodes");

    // ──────────────────────────────────────────────────────────────────────────
    // STEP 8: Hostile Negative Matrix with Snapshot Verification
    // ──────────────────────────────────────────────────────────────────────────
    println!("\n=== STEP 8: Hostile Negatives Matrix with Snapshot Verification ===");

    // 1. Unallowlisted peer
    let snap_before = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    let untrusted_did = "did:web:untrusted.evil.com";
    let untrusted_key =
        P256SigningKey::from_pkcs8_pem(include_str!("../fixtures/ds1-key.pem")).unwrap();
    let untrusted_jwt = cluster.mint_jwt(
        untrusted_did,
        &untrusted_key,
        &cluster.ds2_service_did,
        DELIVER_MESSAGE_NSID,
        None,
    );
    let resp_untrusted = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.deliverMessage",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {untrusted_jwt}"))
        .json(&deliver_message_body)
        .send()
        .await?;
    assert!(
        resp_untrusted.status().is_client_error(),
        "Unallowlisted peer must be rejected with 400/401/403: {:?}",
        resp_untrusted.status()
    );
    let snap_after = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    assert_eq!(
        snap_before, snap_after,
        "Negative 1 mutated database state!"
    );
    println!(
        "✓ Negative 1: Unallowlisted peer rejected ({}) with DB state unchanged",
        resp_untrusted.status()
    );

    // 2. Issuer / body mismatch
    let snap_before = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    let mut mismatch_body = deliver_message_body.clone();
    mismatch_body["header"]["senderDsDid"] = json!("did:web:attacker.local");
    let resp_mismatch = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.deliverMessage",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {ds1_msg_jwt}"))
        .json(&mismatch_body)
        .send()
        .await?;
    assert!(
        resp_mismatch.status().is_client_error(),
        "Issuer / body mismatch must be rejected: {:?}",
        resp_mismatch.status()
    );
    let snap_after = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    assert_eq!(
        snap_before, snap_after,
        "Negative 2 mutated database state!"
    );
    println!(
        "✓ Negative 2: Issuer / body mismatch rejected ({}) with DB state unchanged",
        resp_mismatch.status()
    );

    // 3. Wrong audience or LXM
    let snap_before = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    let wrong_aud_jwt = cluster.mint_jwt(
        &cluster.ds1_service_did,
        &cluster.ds1_signing_key,
        "did:web:wrong.audience.local",
        DELIVER_MESSAGE_NSID,
        None,
    );
    let resp_wrong_aud = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.deliverMessage",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {wrong_aud_jwt}"))
        .json(&deliver_message_body)
        .send()
        .await?;
    assert_eq!(
        resp_wrong_aud.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Wrong audience must be rejected with 401"
    );
    let snap_after = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    assert_eq!(
        snap_before, snap_after,
        "Negative 3 mutated database state!"
    );
    println!("✓ Negative 3: Wrong audience rejected (401) with DB state unchanged");

    // 4. JTI replay
    let snap_before = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    let fixed_jti = format!("test-jti-replay-{}", Uuid::new_v4());
    let jti_jwt_1 = cluster.mint_jwt(
        &cluster.ds1_service_did,
        &cluster.ds1_signing_key,
        &cluster.ds2_service_did,
        "blue.catbird.mlsDS.getFederationPeers",
        Some(&fixed_jti),
    );
    let resp_jti_1 = cluster
        .http_client
        .get(format!(
            "{}/xrpc/blue.catbird.mlsDS.getFederationPeers",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {jti_jwt_1}"))
        .send()
        .await?;
    assert_eq!(resp_jti_1.status(), reqwest::StatusCode::OK);

    let resp_jti_2 = cluster
        .http_client
        .get(format!(
            "{}/xrpc/blue.catbird.mlsDS.getFederationPeers",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {jti_jwt_1}"))
        .send()
        .await?;
    assert_eq!(
        resp_jti_2.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Replaying JTI token must return 401 Unauthorized"
    );
    let snap_after = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    assert_eq!(
        snap_before, snap_after,
        "Negative 4 mutated database state!"
    );
    println!("✓ Negative 4: JTI replay rejected (401 Unauthorized) with DB state unchanged");

    // 5. Non-sequencer delivery
    let snap_before = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    let mut non_seq_body = deliver_message_body.clone();
    non_seq_body["header"]["senderDsDid"] = json!(cluster.ds2_service_did);
    non_seq_body["header"]["sequencerDid"] = json!(cluster.ds2_service_did);
    let resp_non_seq = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.deliverMessage",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {ds2_admin_jwt}"))
        .json(&non_seq_body)
        .send()
        .await?;
    assert!(
        resp_non_seq.status().is_client_error(),
        "Non-sequencer delivery must be rejected"
    );
    let snap_after = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    assert_eq!(
        snap_before, snap_after,
        "Negative 5 mutated database state!"
    );
    println!(
        "✓ Negative 5: Non-sequencer delivery rejected ({}) with DB state unchanged",
        resp_non_seq.status()
    );

    // 6. Stale sequencer term
    let snap_before = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    let mut stale_term_body = deliver_message_body.clone();
    stale_term_body["header"]["sequencerTerm"] = json!(-1);
    let resp_stale_term = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.deliverMessage",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {ds1_msg_jwt}"))
        .json(&stale_term_body)
        .send()
        .await?;
    assert!(
        resp_stale_term.status().is_client_error(),
        "Negative / stale term must be rejected"
    );
    let snap_after = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    assert_eq!(
        snap_before, snap_after,
        "Negative 6 mutated database state!"
    );
    println!(
        "✓ Negative 6: Stale / negative sequencer term rejected ({}) with DB state unchanged",
        resp_stale_term.status()
    );

    // 7. Non-participant commit
    let snap_before = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    let non_part_jwt = cluster.mint_jwt(
        "did:plc:intruder123",
        &cluster.ds1_signing_key,
        &cluster.ds1_service_did,
        SUBMIT_COMMIT_NSID,
        None,
    );
    let resp_non_part = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.submitCommit",
            cluster.ds1_url
        ))
        .header("authorization", format!("Bearer {non_part_jwt}"))
        .json(&canonical_submit_commit_body)
        .send()
        .await?;
    assert!(
        resp_non_part.status().is_client_error(),
        "Non-participant submitCommit must be rejected"
    );
    let snap_after = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    assert_eq!(
        snap_before, snap_after,
        "Negative 7 mutated database state!"
    );
    println!(
        "✓ Negative 7: Non-participant commit rejected ({}) with DB state unchanged",
        resp_non_part.status()
    );

    // 8. Blocked / suspended peer
    let snap_before = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    let block_jwt = cluster.mint_ds1_jwt(
        &cluster.ds1_service_did,
        "blue.catbird.mlsDS.upsertFederationPeer",
    );
    let block_resp = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.upsertFederationPeer",
            cluster.ds1_url
        ))
        .header("authorization", format!("Bearer {block_jwt}"))
        .json(&json!({
            "dsDid": cluster.ds2_service_did,
            "status": "block"
        }))
        .send()
        .await?;
    assert_eq!(block_resp.status(), reqwest::StatusCode::OK);

    // Call from DS2 to DS1 should now fail (blocked)
    let call_from_blocked_jwt = cluster.mint_ds2_jwt(
        &cluster.ds1_service_did,
        "blue.catbird.mlsDS.getConvoDigest",
    );
    let blocked_call_resp = cluster
        .http_client
        .get(format!(
            "{}/xrpc/blue.catbird.mlsDS.getConvoDigest?convoId={convo_id}",
            cluster.ds1_url
        ))
        .header("authorization", format!("Bearer {call_from_blocked_jwt}"))
        .send()
        .await?;
    assert!(
        blocked_call_resp.status().is_client_error(),
        "Call from blocked peer must be rejected: {:?}",
        blocked_call_resp.status()
    );

    // Restore DS2 peer policy to allow
    let restore_jwt = cluster.mint_ds1_jwt(
        &cluster.ds1_service_did,
        "blue.catbird.mlsDS.upsertFederationPeer",
    );
    let _ = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.upsertFederationPeer",
            cluster.ds1_url
        ))
        .header("authorization", format!("Bearer {restore_jwt}"))
        .json(&json!({
            "dsDid": cluster.ds2_service_did,
            "status": "allow"
        }))
        .send()
        .await?;

    let snap_after = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    assert_eq!(
        snap_before, snap_after,
        "Negative 8 mutated database state!"
    );
    println!(
        "✓ Negative 8: Blocked peer policy enforced ({}) with DB state unchanged",
        blocked_call_resp.status()
    );

    // 9. SSRF destination rejection
    let snap_before = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    let malformed_ssrf_jwt = cluster.mint_jwt(
        &cluster.ds1_service_did,
        &cluster.ds1_signing_key,
        "http://127.0.0.1:9999",
        DELIVER_MESSAGE_NSID,
        None,
    );
    let resp_ssrf = cluster
        .http_client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.deliverMessage",
            cluster.ds2_url
        ))
        .header("authorization", format!("Bearer {malformed_ssrf_jwt}"))
        .json(&deliver_message_body)
        .send()
        .await?;
    assert!(
        resp_ssrf.status().is_client_error(),
        "SSRF target must fail closed: {:?}",
        resp_ssrf.status()
    );
    let snap_after = take_db_snapshot(&ds1_pg, &ds2_pg).await?;
    assert_eq!(
        snap_before, snap_after,
        "Negative 9 mutated database state!"
    );
    println!(
        "✓ Negative 9: SSRF destination rejected ({}) with DB state unchanged",
        resp_ssrf.status()
    );

    println!("\n=== ALL FEDERATION TWO-NODE SCENARIOS AND NEGATIVES PASSED ===");

    cluster.shutdown().await;
    Ok(())
}

fn hex_or_bytes(val: &Value) -> Result<[u8; 32]> {
    if let Some(s) = val.as_str() {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32 bytes"))?;
        Ok(arr)
    } else if let Some(b) = val.get("$bytes").and_then(|v| v.as_str()) {
        let bytes = STANDARD.decode(b)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32 bytes"))?;
        Ok(arr)
    } else {
        anyhow::bail!("invalid bytes field: {val:?}")
    }
}
