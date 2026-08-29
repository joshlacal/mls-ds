//! Real two-DS federation scenario integration test using clean-chat public HTTP endpoints
//! and selector-only fixture execution.
//!
//! Run with: `cargo test --test federation_two_node -- --ignored --nocapture`

use std::time::Duration;

use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use catbird_mls::chat_v2::transcript::strict_json::decode_strict_json;
use catbird_mls::chat_v2::transcript::{
    project_signed_body, SignedMutationKind, SigningTranscript,
};
use catbird_mls::orchestrator::{
    canonical_application_aad_bytes, canonical_commit_aad_bytes,
};
use chrono::{DateTime, SecondsFormat, Utc};
use mls_e2e_tests::federation::{boot_two_node_cluster, TwoNodeCluster, DIGEST_ALLOWED_TABLES};
use mls_e2e_tests::mls_engine::MlsEngine;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::pkcs8::DecodePrivateKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const ALICE_DID: &str = "did:web:alice.catbird.blue";
const BOB_DID: &str = "did:web:bob.catbird.blue";
const RECEIPT_SIGNING_DOMAIN: &[u8] = b"CATBIRD-CLEAN-FEDERATION-RECEIPT-V1\0";
const DELIVER_MESSAGE_NSID: &str = "blue.catbird.mlsDS.deliverMessage";
const DELIVER_WELCOME_NSID: &str = "blue.catbird.mlsDS.deliverWelcome";
const SUBMIT_COMMIT_NSID: &str = "blue.catbird.mlsDS.submitCommit";


struct TestIdentity {
    did: String,
    device_id: Uuid,
    p256_signing_key: P256SigningKey,
    engine: MlsEngine,
}

impl TestIdentity {
    fn with_fixed_identity(
        label: &str,
        did: &str,
        device_id: Uuid,
        p256_signing_key: P256SigningKey,
    ) -> Self {
        Self {
            did: did.to_string(),
            device_id,
            p256_signing_key,
            engine: MlsEngine::new(label).expect("create MlsEngine"),
        }
    }

    fn credential_identity(&self) -> String {
        format!("{}#{}", self.did, self.device_id)
    }

    fn public_key(&self) -> Vec<u8> {
        self.engine
            .identity_public_key(&self.credential_identity())
            .expect("MLS identity public key")
    }

    fn key_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.public_key()))
    }

    fn sign(&self, payload: &[u8]) -> ed25519_dalek::Signature {
        let bytes: [u8; 64] = self
            .engine
            .sign_with_identity_key(&self.credential_identity(), payload)
            .expect("sign with MLS identity key")
            .try_into()
            .expect("Ed25519 signature length");
        ed25519_dalek::Signature::from_bytes(&bytes)
    }

    fn mint_chat_jwt(&self, cluster: &TwoNodeCluster, endpoint_nsid: &str) -> String {
        cluster.mint_chat_jwt(&self.did, &self.p256_signing_key, endpoint_nsid)
    }
}

fn capability() -> Value {
    json!({
        "protocolVersion": "1",
        "mlsVersion": "1.0",
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "credentialType": "basic",
        "addByValue": "supported",
        "updatePath": "supported",
        "removeByValue": "supported",
        "ratchetTreeGroupInfo": "supported",
        "externalPubGroupInfo": "presentButExternalCommitsForbidden",
        "applicationFrameProfile": "dagCborApplication1",
        "controlProfile": "publicGroup1",
        "attachmentProfile": "aes256GcmBlob1",
        "metadataProfile": "exporterAes256Gcm1",
        "typingProfile": "signedClearEphemeral1"
    })
}

fn make_key_package_entry(kp_bytes: &[u8], key_package_ref: &[u8]) -> Value {
    let sha256 = Sha256::digest(kp_bytes);
    json!({
        "framing": "mlsMessage",
        "contentType": "keyPackage",
        "bytes": STANDARD.encode(kp_bytes),
        "sha256": STANDARD.encode(sha256),
        "keyPackageRef": STANDARD.encode(key_package_ref),
    })
}

fn make_device_enrollment_body(
    actor: &TestIdentity,
    key_packages: Vec<Value>,
    idempotency_key: Uuid,
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\u{0}",
        "actorDid": actor.did,
        "deviceId": actor.device_id.to_string(),
        "deviceName": format!("{} test device", actor.did),
        "keyId": actor.key_id(),
        "signaturePublicKey": STANDARD.encode(actor.public_key()),
        "expectedAuthGeneration": 0,
        "capability": capability(),
        "keyPackages": key_packages,
        "idempotencyKey": idempotency_key.to_string(),
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    });

    let unsigned_bytes = serde_json::to_vec(&unsigned).unwrap();
    let strict = decode_strict_json(&unsigned_bytes).unwrap();
    let projected = project_signed_body(SignedMutationKind::DeviceEnrollment, &strict).unwrap();
    let mutation =
        SigningTranscript::build_for(SignedMutationKind::DeviceEnrollment, &projected).unwrap();
    let sig = actor.sign(mutation.bytes());
    let wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode(sig.to_bytes()),
    });
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

#[allow(dead_code)]
fn make_key_package_replenishment_body(
    actor: &TestIdentity,
    auth_generation: u64,
    key_packages: Vec<Value>,
    idempotency_key: Uuid,
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#keyPackageReplenishmentBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REPLENISH\u{0}",
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id(),
        "authGeneration": auth_generation,
        "signaturePublicKey": STANDARD.encode(actor.public_key()),
        "keyPackages": key_packages,
        "idempotencyKey": idempotency_key.to_string(),
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    });

    let unsigned_bytes = serde_json::to_vec(&unsigned).unwrap();
    let strict = decode_strict_json(&unsigned_bytes).unwrap();
    let projected =
        project_signed_body(SignedMutationKind::KeyPackageReplenishment, &strict).unwrap();
    let mutation =
        SigningTranscript::build_for(SignedMutationKind::KeyPackageReplenishment, &projected)
            .unwrap();
    let sig = actor.sign(mutation.bytes());
    let wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode(sig.to_bytes()),
    });
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}
fn mls_aad_prior(
    convo_id: Uuid,
    group_id: &[u8; 32],
    state_version: u64,
    epoch: u64,
    group_context_hash: &[u8; 32],
    confirmation_tag: &[u8; 32],
) -> Value {
    json!({
        "conversationId": STANDARD.encode(convo_id.as_bytes()),
        "generation": 0,
        "stateVersion": state_version,
        "groupId": STANDARD.encode(group_id),
        "epoch": epoch,
        "groupContextHash": STANDARD.encode(group_context_hash),
        "confirmationTag": STANDARD.encode(confirmation_tag),
        "lifecycle": "active"
    })
}

fn commit_aad(
    convo_id: Uuid,
    transition_id: Uuid,
    group_id: &[u8; 32],
    state_version: u64,
    epoch: u64,
    group_context_hash: &[u8; 32],
    confirmation_tag: &[u8; 32],
) -> Value {
    json!({
        "protocolVersion": "1",
        "conversationId": STANDARD.encode(convo_id.as_bytes()),
        "generation": 0,
        "transitionId": STANDARD.encode(transition_id.as_bytes()),
        "prior": mls_aad_prior(
            convo_id,
            group_id,
            state_version,
            epoch,
            group_context_hash,
            confirmation_tag,
        )
    })
}

fn application_aad(
    convo_id: Uuid,
    message_id: Uuid,
    group_id: &[u8; 32],
    state_version: u64,
    epoch: u64,
    group_context_hash: &[u8; 32],
    confirmation_tag: &[u8; 32],
) -> Value {
    json!({
        "protocolVersion": "1",
        "conversationId": STANDARD.encode(convo_id.as_bytes()),
        "generation": 0,
        "messageId": STANDARD.encode(message_id.as_bytes()),
        "prior": mls_aad_prior(
            convo_id,
            group_id,
            state_version,
            epoch,
            group_context_hash,
            confirmation_tag,
        )
    })
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
        "keyId": creator.key_id(),
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
            "participants": participants,
            "actorLeaf": {
                "userDid": creator.did,
                "deviceId": creator.device_id.to_string(),
                "leafOrigin": "genesis"
            }
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
            "nonce": STANDARD.encode([0x4Au8; 12]),
            "ciphertext": STANDARD.encode(metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": creator.did,
                "authorDeviceId": creator.device_id.to_string(),
                "authorKeyId": creator.key_id(),
                "signaturePublicKey": STANDARD.encode(creator.public_key()),
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
    let sig = creator.sign(mutation.bytes());
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
        "keyId": actor.key_id(),
        "authGeneration": 1,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 0,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(prior_group_context_hash),
            "confirmationTag": STANDARD.encode(prior_confirmation_tag),
            "lifecycle": "active"
        },
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 1,
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
    let sig = actor.sign(mutation.bytes());
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
        "keyId": actor.key_id(),
        "authGeneration": 1,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 1,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(prior_gch),
            "confirmationTag": STANDARD.encode(prior_ctag),
            "lifecycle": "active"
        },
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 2,
            "groupId": STANDARD.encode(group_id),
            "epoch": 1,
            "groupContextHash": STANDARD.encode(sv2_gch),
            "confirmationTag": STANDARD.encode(sv2_ctag),
            "lifecycle": "active"
        },
        "aad": commit_aad(
            convo_id,
            transition_id,
            group_id,
            1,
            0,
            prior_gch,
            prior_ctag,
        ),
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
                "authorKeyId": actor.key_id(),
                "signaturePublicKey": STANDARD.encode(actor.public_key()),
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
    let sig = actor.sign(mutation.bytes());
    let wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode(sig.to_bytes()),
    });
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

#[allow(clippy::too_many_arguments)]
fn make_commit_body(
    convo_id: Uuid,
    transition_id: Uuid,
    origin_transition_id: Uuid,
    actor: &TestIdentity,
    metadata_author: &TestIdentity,
    group_id: &[u8; 32],
    prior_state_version: u64,
    prior_epoch: u64,
    prior_gch: &[u8; 32],
    prior_ctag: &[u8; 32],
    next_gch: &[u8; 32],
    next_ctag: &[u8; 32],
    commit_bytes: &[u8],
    metadata_ciphertext: &[u8],
    now: DateTime<Utc>,
) -> (Value, Vec<u8>) {
    let next_state_version = prior_state_version + 1;
    let next_epoch = prior_epoch + 1;
    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#commitTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-COMMIT\u{0}",
        "transitionId": transition_id.to_string(),
        "idempotencyKey": transition_id.to_string(),
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id(),
        "authGeneration": 1,
        "signedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": prior_state_version,
            "groupId": STANDARD.encode(group_id),
            "epoch": prior_epoch,
            "groupContextHash": STANDARD.encode(prior_gch),
            "confirmationTag": STANDARD.encode(prior_ctag),
            "lifecycle": "active"
        },
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": next_state_version,
            "groupId": STANDARD.encode(group_id),
            "epoch": next_epoch,
            "groupContextHash": STANDARD.encode(next_gch),
            "confirmationTag": STANDARD.encode(next_ctag),
            "lifecycle": "active"
        },
        "aad": commit_aad(
            convo_id,
            transition_id,
            group_id,
            prior_state_version,
            prior_epoch,
            prior_gch,
            prior_ctag,
        ),
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
                "epoch": next_epoch,
                "groupContextHash": STANDARD.encode(next_gch),
                "confirmationTag": STANDARD.encode(next_ctag)
            },
            "originTransitionId": origin_transition_id.to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0x7Cu8; 12]),
            "ciphertext": STANDARD.encode(metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": metadata_author.did,
                "authorDeviceId": metadata_author.device_id.to_string(),
                "authorKeyId": metadata_author.key_id(),
                "signaturePublicKey": STANDARD.encode(metadata_author.public_key()),
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
    let projected = project_signed_body(SignedMutationKind::CommitTransition, &strict).unwrap();
    let mutation =
        SigningTranscript::build_for(SignedMutationKind::CommitTransition, &projected).unwrap();
    let sig = actor.sign(mutation.bytes());
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
        "keyId": actor.key_id(),
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
        "aad": application_aad(
            convo_id,
            message_id,
            group_id,
            state_version,
            epoch,
            group_context_hash,
            confirmation_tag,
        ),
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
    let sig = actor.sign(mutation.bytes());
    let wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode(sig.to_bytes()),
    });
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();
    (wrapper, signed_bytes)
}

async fn post_signed_chat_op(
    http_client: &reqwest::Client,
    base_url: &str,
    endpoint_nsid: &str,
    jwt: &str,
    signed_wrapper: &Value,
) -> Result<Value> {
    let url = format!("{base_url}/xrpc/{endpoint_nsid}");
    let body = json!({
        "signedRequest": signed_wrapper
    });
    let resp = http_client
        .post(&url)
        .header("Authorization", format!("Bearer {jwt}"))
        .json(&body)
        .send()
        .await
        .with_context(|| format!("HTTP POST {url}"))?;
    let status = resp.status();
    let text = resp.text().await.context("read response text")?;
    if !status.is_success() {
        anyhow::bail!("HTTP POST {url} returned {status}: {text}");
    }
    let res_json: Value = serde_json::from_str(&text).unwrap_or(json!({ "raw": text }));
    Ok(res_json)
}

fn lp_bytes(bytes: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn digest32(bytes: Vec<u8>, label: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("expected 32-byte {label}, got {}", bytes.len()))
}

#[allow(clippy::too_many_arguments)]
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
    source_entry_id: Uuid,
    source_entry_seq: u64,
    accepted_payload_sha256: &[u8; 32],
    outer_entry_fingerprint: &[u8; 32],
    completed_at: &str,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(512);
    output.extend_from_slice(RECEIPT_SIGNING_DOMAIN);
    lp_bytes(b"1", &mut output);
    lp_bytes(endpoint.as_bytes(), &mut output);
    output.extend_from_slice(delivery_id.as_bytes());
    output.extend_from_slice(conversation_id.as_bytes());
    lp_bytes(sender_ds_did.as_bytes(), &mut output);
    lp_bytes(receiver_ds_did.as_bytes(), &mut output);
    lp_bytes(sequencer_did.as_bytes(), &mut output);
    output.extend_from_slice(&sequencer_term.to_be_bytes());
    output.extend_from_slice(envelope_sha256);
    output.extend_from_slice(result_sha256);
    output.push(1);
    output.extend_from_slice(source_entry_id.as_bytes());
    output.extend_from_slice(&source_entry_seq.to_be_bytes());
    output.extend_from_slice(accepted_payload_sha256);
    output.extend_from_slice(outer_entry_fingerprint);
    lp_bytes(completed_at.as_bytes(), &mut output);
    output
}

async fn wait_for_signed_receipt(
    cluster: &TwoNodeCluster,
    pg: &tokio_postgres::Client,
    endpoint: &str,
    conversation_id: Uuid,
    receiver_ds_did: &str,
) -> Result<DateTime<Utc>> {
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(20) {
        let row = pg
            .query_opt(
                r#"
                SELECT r.delivery_id, r.sender_ds_did, r.receiver_ds_did,
                       r.sequencer_did, r.sequencer_term, r.envelope_sha256,
                       r.result_sha256, r.source_entry_id, r.source_entry_seq,
                       r.source_entry_fingerprint, r.receipt_signature,
                       r.completed_at, e.accepted_payload_sha256,
                       r.response_bytes, r.response_sha256
                  FROM chat.federation_delivery_receipts AS r
                  JOIN chat.entries AS e
                    ON e.conversation_id = r.conversation_id
                   AND e.seq = r.source_entry_seq
                   AND e.entry_id = r.source_entry_id
                 WHERE r.conversation_id = $1
                   AND r.endpoint_nsid = $2
                   AND r.receiver_ds_did = $3
                 ORDER BY r.completed_at DESC
                 LIMIT 1
                "#,
                &[&conversation_id, &endpoint, &receiver_ds_did],
            )
            .await?;
        if let Some(row) = row {
            let response_bytes: Vec<u8> = row.get("response_bytes");
            let response_sha256: Vec<u8> = row.get("response_sha256");
            anyhow::ensure!(
                Sha256::digest(&response_bytes).as_slice() == response_sha256,
                "stored receipt response digest mismatch"
            );
            let response: Value = serde_json::from_slice(&response_bytes)?;
            let receipt = response
                .get("receipt")
                .context("federation response omitted receipt")?;
            let completed_at_text = receipt
                .get("completedAt")
                .and_then(Value::as_str)
                .context("federation receipt omitted completedAt")?;
            let envelope_sha256 = digest32(row.get("envelope_sha256"), "envelope digest")?;
            let result_sha256 = digest32(row.get("result_sha256"), "result digest")?;
            let accepted_payload_sha256 =
                digest32(row.get("accepted_payload_sha256"), "payload digest")?;
            let outer_entry_fingerprint =
                digest32(row.get("source_entry_fingerprint"), "entry fingerprint")?;
            let canonical = canonical_receipt_bytes(
                endpoint,
                row.get("delivery_id"),
                conversation_id,
                row.get::<_, String>("sender_ds_did").as_str(),
                row.get::<_, String>("receiver_ds_did").as_str(),
                row.get::<_, String>("sequencer_did").as_str(),
                row.get::<_, i64>("sequencer_term").try_into()?,
                &envelope_sha256,
                &result_sha256,
                row.get("source_entry_id"),
                row.get::<_, i64>("source_entry_seq").try_into()?,
                &accepted_payload_sha256,
                &outer_entry_fingerprint,
                completed_at_text,
            );
            let signature: Vec<u8> = row.get("receipt_signature");
            if receiver_ds_did == cluster.ds1_service_did {
                cluster.verify_ds1_signature(&canonical, &signature)?;
            } else if receiver_ds_did == cluster.ds2_service_did {
                cluster.verify_ds2_signature(&canonical, &signature)?;
            } else {
                anyhow::bail!("unexpected receipt signer {receiver_ds_did}");
            }
            return Ok(row.get("completed_at"));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    anyhow::bail!("timed out waiting for signed {endpoint} receipt")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_federation_two_node_complete_lifecycle() {
    run_test_scenario()
        .await
        .expect("federation two node complete lifecycle");
}

async fn run_test_scenario() -> Result<()> {
    tracing::info!("=== STARTING TWO-NODE FEDERATION TEST ===");
    let cluster = boot_two_node_cluster().await?;
    if let Err(error) = run_live_scenario(&cluster).await {
        cluster.capture_diagnostics();
        return Err(error);
    }
    tracing::info!("Step 14: Shutting down cluster and verifying clean teardown...");
    cluster.shutdown().await?;
    tracing::info!("=== TWO-NODE FEDERATION TEST COMPLETED SUCCESSFULLY ===");
    Ok(())
}

async fn run_live_scenario(cluster: &TwoNodeCluster) -> Result<()> {
    let ds1_pg = cluster.connect_ds1_db().await?;
    let ds2_pg = cluster.connect_ds2_db().await?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    // Step 0: Peer allowlisting (DS1 <-> DS2)
    tracing::info!("Step 0: Upserting federation peers...");
    let ds1_peer_jwt = cluster.mint_ds1_jwt(
        &cluster.ds2_service_did,
        "blue.catbird.mlsDS.upsertFederationPeer",
    );
    let resp = http
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.upsertFederationPeer",
            cluster.ds2_url
        ))
        .header("Authorization", format!("Bearer {ds1_peer_jwt}"))
        .json(&json!({
            "dsDid": cluster.ds1_service_did,
            "status": "allow"
        }))
        .send()
        .await?;
    assert!(
        resp.status().is_success(),
        "upsertFederationPeer on DS2 for DS1 failed: {:?}",
        resp.text().await
    );

    let ds2_peer_jwt = cluster.mint_ds2_jwt(
        &cluster.ds1_service_did,
        "blue.catbird.mlsDS.upsertFederationPeer",
    );
    let resp = http
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.upsertFederationPeer",
            cluster.ds1_url
        ))
        .header("Authorization", format!("Bearer {ds2_peer_jwt}"))
        .json(&json!({
            "dsDid": cluster.ds2_service_did,
            "status": "allow"
        }))
        .send()
        .await?;
    assert!(
        resp.status().is_success(),
        "upsertFederationPeer on DS1 for DS2 failed: {:?}",
        resp.text().await
    );

    // Step 1: Initialize fixed did:web identities and load fixture auth keys
    tracing::info!("Step 1: Initializing Alice and Bob identities...");
    let fixtures_dir = cluster.compose_file.parent().unwrap().join("fixtures");
    let alice_pem = std::fs::read_to_string(fixtures_dir.join("alice-key.pem"))
        .context("read alice-key.pem")?;
    let bob_pem =
        std::fs::read_to_string(fixtures_dir.join("bob-key.pem")).context("read bob-key.pem")?;

    let alice_p256 = P256SigningKey::from_pkcs8_pem(&alice_pem)
        .map_err(|e| anyhow::anyhow!("parse alice-key.pem: {e}"))?;
    let bob_p256 = P256SigningKey::from_pkcs8_pem(&bob_pem)
        .map_err(|e| anyhow::anyhow!("parse bob-key.pem: {e}"))?;

    let alice_device_id = Uuid::parse_str("70707070-7070-4070-b070-707070707070")?;
    let bob_device_id = Uuid::parse_str("80808080-8080-4080-b080-808080808080")?;

    let alice = TestIdentity::with_fixed_identity(
        "alice",
        ALICE_DID,
        alice_device_id,
        alice_p256,
    );
    let bob = TestIdentity::with_fixed_identity(
        "bob",
        BOB_DID,
        bob_device_id,
        bob_p256,
    );
    let alice_credential = alice.credential_identity();
    let bob_credential = bob.credential_identity();


    // Step 2: Generate real OpenMLS key packages
    tracing::info!("Step 2: Generating OpenMLS key packages...");
    let (alice_kp_bytes, alice_kp_ref_vec) =
        alice.engine.create_key_package(&alice_credential)?;
    let (bob_kp_bytes, bob_kp_ref_vec) = bob.engine.create_key_package(&bob_credential)?;
    let mut bob_kp_ref = [0u8; 32];
    bob_kp_ref.copy_from_slice(&bob_kp_ref_vec);

    let alice_kp_val = make_key_package_entry(&alice_kp_bytes, &alice_kp_ref_vec);
    let bob_kp_val = make_key_package_entry(&bob_kp_bytes, &bob_kp_ref_vec);

    let now = Utc::now();

    // Step 3: Enroll Alice on DS1
    tracing::info!("Step 3: Enrolling Alice on DS1 via enrollDevice...");
    let (alice_enroll_wrapper, _) = make_device_enrollment_body(
        &alice,
        vec![alice_kp_val.clone()],
        Uuid::new_v4(),
        now,
    );
    let alice_enroll_jwt = alice.mint_chat_jwt(&cluster, "blue.catbird.chat.enrollDevice");
    let alice_enroll_res = post_signed_chat_op(
        &http,
        &cluster.ds1_url,
        "blue.catbird.chat.enrollDevice",
        &alice_enroll_jwt,
        &alice_enroll_wrapper,
    )
    .await?;
    tracing::info!(?alice_enroll_res, "Alice enrolled on DS1");

    // Step 4: Enroll Bob on DS1 (for authorization on sequencer)
    tracing::info!("Step 4: Enrolling Bob on DS1 via enrollDevice...");
    let (bob_enroll_wrapper_ds1, _) =
        make_device_enrollment_body(&bob, vec![bob_kp_val.clone()], Uuid::new_v4(), now);
    let bob_enroll_jwt_ds1 = bob.mint_chat_jwt(&cluster, "blue.catbird.chat.enrollDevice");
    let bob_enroll_res_ds1 = post_signed_chat_op(
        &http,
        &cluster.ds1_url,
        "blue.catbird.chat.enrollDevice",
        &bob_enroll_jwt_ds1,
        &bob_enroll_wrapper_ds1,
    )
    .await?;
    tracing::info!(?bob_enroll_res_ds1, "Bob enrolled on DS1");

    // Step 5: Enroll Bob on DS2 (exact identical device & key package material)
    tracing::info!("Step 5: Enrolling Bob on DS2 via enrollDevice...");
    let (bob_enroll_wrapper_ds2, _) =
        make_device_enrollment_body(&bob, vec![bob_kp_val], Uuid::new_v4(), now);
    let bob_enroll_jwt_ds2 = bob.mint_chat_jwt(&cluster, "blue.catbird.chat.enrollDevice");
    let bob_enroll_res_ds2 = post_signed_chat_op(
        &http,
        &cluster.ds2_url,
        "blue.catbird.chat.enrollDevice",
        &bob_enroll_jwt_ds2,
        &bob_enroll_wrapper_ds2,
    )
    .await?;
    tracing::info!(?bob_enroll_res_ds2, "Bob enrolled on DS2");

    // DS2 needs the immutable author key to re-verify Alice's historical entries.
    tracing::info!("Step 5a: Enrolling Alice authority material on DS2...");
    let (alice_enroll_wrapper_ds2, _) =
        make_device_enrollment_body(&alice, vec![alice_kp_val], Uuid::new_v4(), now);
    let alice_enroll_jwt_ds2 = alice.mint_chat_jwt(&cluster, "blue.catbird.chat.enrollDevice");
    let alice_enroll_res_ds2 = post_signed_chat_op(
        &http,
        &cluster.ds2_url,
        "blue.catbird.chat.enrollDevice",
        &alice_enroll_jwt_ds2,
        &alice_enroll_wrapper_ds2,
    )
    .await?;
    tracing::info!(?alice_enroll_res_ds2, "Alice authority material enrolled on DS2");

    // Step 6: Create conversation on DS1
    tracing::info!("Step 6: Creating conversation on DS1 as Alice...");
    let convo_id = Uuid::new_v4();
    let creation_entry_id = Uuid::new_v4();
    let recovery_request_id = Uuid::new_v4();

    let group_id_vec = alice.engine.create_group(&alice_credential)?;
    let group_id: [u8; 32] = group_id_vec.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("expected 32-byte group ID, got {}", bytes.len())
    })?;
    let genesis_gch: [u8; 32] = alice
        .engine
        .group_context_hash(&group_id)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("expected 32-byte GroupContext hash, got {}", bytes.len())
        })?;
    let genesis_ctag: [u8; 32] = alice
        .engine
        .confirmation_tag(&group_id)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("expected 32-byte confirmation tag, got {}", bytes.len())
        })?;
    let genesis_group_info = alice
        .engine
        .export_group_info(&group_id, &alice_credential)?;
    let metadata_ciphertext = vec![0x33u8; 32];

    let (creation_wrapper, _) = make_creation_body_with_invitee(
        convo_id,
        creation_entry_id,
        &alice,
        Some(&bob),
        &group_id,
        &genesis_gch,
        &genesis_ctag,
        &genesis_group_info,
        &metadata_ciphertext,
        now,
    );
    let create_jwt = alice.mint_chat_jwt(&cluster, "blue.catbird.chat.createConversation");
    let create_res = post_signed_chat_op(
        &http,
        &cluster.ds1_url,
        "blue.catbird.chat.createConversation",
        &create_jwt,
        &creation_wrapper,
    )
    .await?;
    tracing::info!(?create_res, "Conversation created on DS1");

    // Step 7: Accept conversation on DS1 as Bob
    tracing::info!("Step 7: Accepting conversation on DS1 as Bob...");
    let acc_transition_id = Uuid::new_v4();
    let (acc_wrapper, _) = make_acceptance_body(
        convo_id,
        acc_transition_id,
        recovery_request_id,
        creation_entry_id,
        &bob,
        &alice,
        &group_id,
        &genesis_gch,
        &genesis_ctag,
        now,
    );
    let acc_jwt = bob.mint_chat_jwt(&cluster, "blue.catbird.chat.acceptConversation");
    let acc_res = post_signed_chat_op(
        &http,
        &cluster.ds1_url,
        "blue.catbird.chat.acceptConversation",
        &acc_jwt,
        &acc_wrapper,
    )
    .await?;
    tracing::info!(?acc_res, "Conversation accepted on DS1");

    // Step 8: Alice adds Bob via OpenMLS and submits leaf recovery fulfillment on DS1.
    tracing::info!("Step 8: Submitting leaf recovery fulfillment on DS1...");
    let fulfill_transition_id = Uuid::new_v4();
    let fulfill_aad = commit_aad(
        convo_id,
        fulfill_transition_id,
        &group_id,
        1,
        0,
        &genesis_gch,
        &genesis_ctag,
    );
    let fulfill_aad = canonical_commit_aad_bytes(&fulfill_aad)
        .map_err(|error| anyhow::anyhow!("canonical recovery Commit AAD: {error}"))?;
    let (commit_data, welcome_data, sv2_gch, sv2_ctag) = alice.engine.add_members_with_aad(
        &group_id,
        vec![bob_kp_bytes.clone()],
        &fulfill_aad,
    )?;
    let sv2_gch: [u8; 32] = sv2_gch.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("expected 32-byte GroupContext hash, got {}", bytes.len())
    })?;
    let sv2_ctag: [u8; 32] = sv2_ctag.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("expected 32-byte confirmation tag, got {}", bytes.len())
    })?;
    let welcome_id = Uuid::new_v4();

    let (fulfill_wrapper, _) = make_leaf_recovery_fulfillment_body(
        convo_id,
        fulfill_transition_id,
        recovery_request_id,
        creation_entry_id,
        &alice,
        &bob,
        &group_id,
        &genesis_gch,
        &genesis_ctag,
        &sv2_gch,
        &sv2_ctag,
        welcome_id,
        &welcome_data,
        &commit_data,
        &metadata_ciphertext,
        &bob_kp_ref,
        now,
    );
    let fulfill_jwt = alice.mint_chat_jwt(&cluster, "blue.catbird.chat.submitTransition");
    let fulfill_res = post_signed_chat_op(
        &http,
        &cluster.ds1_url,
        "blue.catbird.chat.submitTransition",
        &fulfill_jwt,
        &fulfill_wrapper,
    )
    .await?;
    let _new_epoch = alice.engine.merge_pending_commit(&group_id)?;
    tracing::info!(?fulfill_res, "Leaf recovery fulfillment submitted on DS1");

    // Step 9: Bootstrap DS2 via selector-only fixture (First Invocation -> Applied)
    tracing::info!("Step 9: Bootstrapping DS2 via selector fixture (first invocation)...");
    let outcome1 = cluster
        .bootstrap_ds2_from_selector(convo_id, &cluster.ds1_service_did, 0)
        .await?;
    tracing::info!(?outcome1, "DS2 first selector invocation result");
    assert_eq!(outcome1.outcome, "applied");
    assert_eq!(outcome1.conversation_id, convo_id.to_string());
    assert_eq!(outcome1.head_seq, 3);
    assert_eq!(outcome1.sequencer_term, 0);

    // Capture DS2 table digests right after Applied
    let ds2_digests_first = cluster
        .table_digests(&ds2_pg, DIGEST_ALLOWED_TABLES)
        .await?;

    // Step 10: Replay selector on DS2 (Second Invocation -> ExactReplay with zero semantic writes)
    tracing::info!("Step 10: Replaying selector fixture on DS2 (second invocation)...");
    let outcome2 = cluster
        .bootstrap_ds2_from_selector(convo_id, &cluster.ds1_service_did, 0)
        .await?;
    tracing::info!(?outcome2, "DS2 second selector invocation result");
    assert_eq!(outcome2.outcome, "exactReplay");
    assert_eq!(outcome2.conversation_id, convo_id.to_string());
    assert_eq!(outcome2.head_seq, outcome1.head_seq);
    assert_eq!(outcome2.digest_sha256, outcome1.digest_sha256);
    assert_eq!(outcome2.sequencer_term, outcome1.sequencer_term);

    let ds2_digests_replay = cluster
        .table_digests(&ds2_pg, DIGEST_ALLOWED_TABLES)
        .await?;
    assert_eq!(
        ds2_digests_first, ds2_digests_replay,
        "DS2 semantic table content must be unchanged on exact replay"
    );
    let _welcome_receipt_at = wait_for_signed_receipt(
        &cluster,
        &ds1_pg,
        DELIVER_WELCOME_NSID,
        convo_id,
        &cluster.ds2_service_did,
    )
    .await?;

    // Step 11: Post-bootstrap message on DS1 & Welcome processing on DS2
    tracing::info!("Step 11: Sending post-bootstrap message from Alice on DS1...");
    let bob_group_id = bob.engine.process_welcome(&welcome_data, &bob_credential)?;

    let msg1_id = Uuid::new_v4();
    let msg1_text = b"Hello Bob from Alice after remote-prefix bootstrap!";
    let msg1_aad = application_aad(
        convo_id,
        msg1_id,
        &group_id,
        2,
        1,
        &sv2_gch,
        &sv2_ctag,
    );
    let msg1_aad = canonical_application_aad_bytes(&msg1_aad)
        .map_err(|error| anyhow::anyhow!("canonical message AAD: {error}"))?;
    let (msg1_ciphertext, _) =
        alice
            .engine
            .encrypt_with_aad(&group_id, msg1_text, &msg1_aad)?;

    let (msg1_wrapper, _) = make_message_body(
        convo_id,
        msg1_id,
        &alice,
        &group_id,
        2,
        1,
        &sv2_gch,
        &sv2_ctag,
        &msg1_ciphertext,
        now,
    );
    let msg1_jwt = alice.mint_chat_jwt(&cluster, "blue.catbird.chat.sendMessage");
    let msg1_res = post_signed_chat_op(
        &http,
        &cluster.ds1_url,
        "blue.catbird.chat.sendMessage",
        &msg1_jwt,
        &msg1_wrapper,
    )
    .await?;
    tracing::info!(?msg1_res, "Message 1 sent on DS1");

    // Poll DS2 until seq 4 arrives (via background federation delivery / reconciliation)
    tracing::info!("Polling DS2 for message 1 arrival (seq 4)...");
    let poll_start = std::time::Instant::now();
    let mut seq4_arrived = false;
    while poll_start.elapsed() < Duration::from_secs(20) {
        let row = ds2_pg
            .query_opt(
                "SELECT seq FROM chat.entries WHERE conversation_id = $1 AND seq = 4",
                &[&convo_id],
            )
            .await?;
        if row.is_some() {
            seq4_arrived = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        seq4_arrived,
        "Message 1 (seq 4) did not arrive on DS2 within timeout"
    );

    let decrypted1 = bob.engine.decrypt(&bob_group_id, &msg1_ciphertext)?;
    assert_eq!(
        decrypted1, msg1_text,
        "Bob successfully decrypted message 1 on DS2"
    );

    let _message_receipt_at = wait_for_signed_receipt(
        &cluster,
        &ds1_pg,
        DELIVER_MESSAGE_NSID,
        convo_id,
        &cluster.ds2_service_did,
    )
    .await?;

    // Step 12: Bob submits a real self-update through DS2 to the DS1 sequencer.
    tracing::info!("Step 12: Submitting remote commit through DS2...");
    anyhow::ensure!(
        bob_group_id == group_id,
        "Welcome joined an unexpected MLS group"
    );
    let prior_gch: [u8; 32] = bob
        .engine
        .group_context_hash(&bob_group_id)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("expected 32-byte GroupContext hash, got {}", bytes.len())
        })?;
    let prior_ctag: [u8; 32] = bob
        .engine
        .confirmation_tag(&bob_group_id)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("expected 32-byte confirmation tag, got {}", bytes.len())
        })?;
    let commit_transition_id = Uuid::new_v4();
    let remote_commit_aad = commit_aad(
        convo_id,
        commit_transition_id,
        &group_id,
        2,
        1,
        &prior_gch,
        &prior_ctag,
    );
    let remote_commit_aad = canonical_commit_aad_bytes(&remote_commit_aad)
        .map_err(|error| anyhow::anyhow!("canonical remote Commit AAD: {error}"))?;
    let remote_commit = bob
        .engine
        .self_update_with_aad(&bob_group_id, &remote_commit_aad)?;
    let _bob_epoch = bob.engine.merge_pending_commit(&bob_group_id)?;
    let commit_gch: [u8; 32] = bob
        .engine
        .group_context_hash(&bob_group_id)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("expected 32-byte GroupContext hash, got {}", bytes.len())
        })?;
    let commit_ctag: [u8; 32] = bob
        .engine
        .confirmation_tag(&bob_group_id)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("expected 32-byte confirmation tag, got {}", bytes.len())
        })?;
    let (commit_wrapper, _) = make_commit_body(
        convo_id,
        commit_transition_id,
        creation_entry_id,
        &bob,
        &alice,
        &group_id,
        2,
        1,
        &prior_gch,
        &prior_ctag,
        &commit_gch,
        &commit_ctag,
        &remote_commit,
        &metadata_ciphertext,
        Utc::now(),
    );
    let commit_jwt = bob.mint_chat_jwt(&cluster, "blue.catbird.chat.submitTransition");
    let commit_res = post_signed_chat_op(
        &http,
        &cluster.ds2_url,
        "blue.catbird.chat.submitTransition",
        &commit_jwt,
        &commit_wrapper,
    )
    .await?;
    tracing::info!(?commit_res, "Remote commit accepted through DS2");
    let commit_receipt_at = wait_for_signed_receipt(
        &cluster,
        &ds2_pg,
        SUBMIT_COMMIT_NSID,
        convo_id,
        &cluster.ds1_service_did,
    )
    .await?;
    let ds1_commit_seq: i64 = ds1_pg
        .query_one(
            "SELECT seq FROM chat.entries WHERE conversation_id = $1 AND transition_id = $2",
            &[&convo_id, &commit_transition_id],
        )
        .await?
        .get(0);
    anyhow::ensure!(
        ds1_commit_seq == 5,
        "sequencer stored remote commit at wrong seq"
    );

    let convo_id_text = convo_id.to_string();
    let sync_started = std::time::Instant::now();
    let ds2_apply_at = loop {
        if sync_started.elapsed() >= Duration::from_secs(20) {
            anyhow::bail!("DS2 did not apply remote commit after sequencer acceptance");
        }
        if let Some(row) = ds2_pg
            .query_opt(
                "SELECT last_seq, updated_at FROM federation_sync_state WHERE convo_id = $1 AND sequencer_ds_did = $2",
                &[&convo_id_text, &cluster.ds1_service_did],
            )
            .await?
        {
            let last_seq: i64 = row.get(0);
            if last_seq >= 5 {
                break row.get::<_, DateTime<Utc>>(1);
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    anyhow::ensure!(
        commit_receipt_at <= ds2_apply_at,
        "DS2 applied remote commit before DS1 signed sequencer acceptance"
    );

    let target_epoch = match alice.engine.process_message(&group_id, &remote_commit)? {
        catbird_mls::ProcessedContent::StagedCommit { new_epoch, .. } => new_epoch,
        _ => anyhow::bail!("Alice did not stage Bob's commit"),
    };
    alice
        .engine
        .merge_incoming_commit(&group_id, target_epoch)?;

    // Step 13: Force delivery backoff, then prove reconciliation wins the retry race.
    tracing::info!("Step 13: Pausing DS2 and sending message 2 on DS1...");
    cluster.pause_service("ds2")?;

    let msg2_id = Uuid::new_v4();
    let msg2_text = b"Message 2 sent while DS2 was paused!";
    let msg2_aad = application_aad(
        convo_id,
        msg2_id,
        &group_id,
        3,
        2,
        &commit_gch,
        &commit_ctag,
    );
    let msg2_aad = canonical_application_aad_bytes(&msg2_aad)
        .map_err(|error| anyhow::anyhow!("canonical message AAD: {error}"))?;
    let (msg2_ciphertext, _) =
        alice
            .engine
            .encrypt_with_aad(&group_id, msg2_text, &msg2_aad)?;
    let (msg2_wrapper, _) = make_message_body(
        convo_id,
        msg2_id,
        &alice,
        &group_id,
        3,
        2,
        &commit_gch,
        &commit_ctag,
        &msg2_ciphertext,
        Utc::now(),
    );
    let msg2_jwt = alice.mint_chat_jwt(&cluster, "blue.catbird.chat.sendMessage");
    let msg2_res = post_signed_chat_op(
        &http,
        &cluster.ds1_url,
        "blue.catbird.chat.sendMessage",
        &msg2_jwt,
        &msg2_wrapper,
    )
    .await?;
    tracing::info!(?msg2_res, "Message 2 sent on DS1 while DS2 paused");

    let backoff_started = std::time::Instant::now();
    let delayed_delivery_id = loop {
        if backoff_started.elapsed() >= Duration::from_secs(15) {
            anyhow::bail!("delivery did not enter pending backoff while DS2 was paused");
        }
        if let Some(row) = ds1_pg
            .query_opt(
                "SELECT id, retry_count, next_retry_at, status FROM outbound_queue \
                 WHERE convo_id = $1 AND method = $2 \
                 ORDER BY created_at DESC LIMIT 1",
                &[&convo_id_text, &DELIVER_MESSAGE_NSID],
            )
            .await?
        {
            let retry_count: i32 = row.get("retry_count");
            let next_retry_at: DateTime<Utc> = row.get("next_retry_at");
            let status: String = row.get("status");
            if retry_count >= 1 && status == "pending" {
                anyhow::ensure!(
                    next_retry_at > Utc::now(),
                    "failed delivery did not schedule future backoff"
                );
                break row.get::<_, String>("id");
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let next_delivery_retry: DateTime<Utc> = ds1_pg
        .query_one(
            "UPDATE outbound_queue \
             SET next_retry_at = NOW() + INTERVAL '5 minutes' \
             WHERE id = $1 \
             RETURNING next_retry_at",
            &[&delayed_delivery_id],
        )
        .await?
        .get("next_retry_at");

    tracing::info!("Unpausing DS2 and waiting for reconciliation...");
    cluster.unpause_service("ds2")?;
    let reconciliation_started = std::time::Instant::now();
    loop {
        if reconciliation_started.elapsed() >= Duration::from_secs(20) {
            anyhow::bail!("reconciliation did not import seq 6 after DS2 resumed");
        }
        if ds2_pg
            .query_opt(
                "SELECT 1 FROM chat.entries WHERE conversation_id = $1 AND seq = 6",
                &[&convo_id],
            )
            .await?
            .is_some()
        {
            anyhow::ensure!(
                Utc::now() < next_delivery_retry,
                "delayed delivery retry ran before reconciliation imported the suffix"
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let decrypted2 = bob.engine.decrypt(&bob_group_id, &msg2_ciphertext)?;
    assert_eq!(
        decrypted2, msg2_text,
        "Bob successfully decrypted message 2 on DS2"
    );

    Ok(())
}
