//! Actual generated-Rust producers for submitTransition compatibility tests.
//!
//! Every request, signed wrapper, body, reference object, and union below is
//! constructed explicitly with `extra_data: None`. Deserializing a tagged body
//! into the generated type would retain its tag in `extra_data` and conceal the
//! missing-body-tag presentation this regression must exercise.
//!
//! The five frozen cases are transcript/fingerprint fixtures, not valid MLS
//! artifacts or encrypted metadata. The supplemental recovery case adds real
//! schema-shaped union/reference coverage and a valid test signature; it makes
//! the same limited claim about its opaque MLS/metadata byte payloads.

use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use catbird_atproto::{blue_catbird::chat as dto, jacquard_common::deps::bytes::Bytes};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const TYPE_PREFIX: &str = "blue.catbird.chat.defs#";
const FROZEN_SOURCE: &str = include_str!("../fixtures/mls_chat_control_fingerprint_source.json");
const FROZEN_PRODUCTS: &str = include_str!("../fixtures/mls_chat_contract_vectors.json");
const CONTRACT: &str =
    include_str!("../../../lexicon/blue/catbird/chat/blue.catbird.chat.defs.json");

pub struct GeneratedTransitionCase {
    pub name: &'static str,
    /// Original canonical presentation: `{body: <tagged body>, signature: <base64>}`.
    pub legacy_wrapper: Vec<u8>,
    /// Unmodified `serde_json::to_vec(&SubmitTransition<String>)` output.
    pub generated_request: Vec<u8>,
    pub public_key: Vec<u8>,
    /// Frozen vector row for the original five; explicitly labeled derived
    /// signing products for the maintained supplemental recovery input.
    pub expected: Value,
}

fn text(value: &Value) -> String {
    value.as_str().expect("fixture string").to_owned()
}

fn integer(value: &Value) -> i64 {
    value.as_i64().expect("fixture integer")
}

fn bytes(value: &Value) -> Bytes {
    STANDARD
        .decode(value.as_str().expect("fixture canonical base64"))
        .expect("fixture base64 decodes")
        .into()
}

fn did(value: &Value) -> dto::BareDid<String> {
    dto::BareDid::new(text(value)).expect("fixture DID")
}

fn datetime(value: &Value) -> dto::CanonicalDatetime {
    value
        .as_str()
        .expect("fixture datetime")
        .parse()
        .expect("fixture datetime parses")
}

fn coordinates(value: &Value) -> dto::ConversationCoordinates<String> {
    dto::ConversationCoordinates {
        confirmation_tag: bytes(&value["confirmationTag"]),
        conversation_id: text(&value["conversationId"]),
        epoch: integer(&value["epoch"]),
        generation: integer(&value["generation"]),
        group_context_hash: bytes(&value["groupContextHash"]),
        group_id: bytes(&value["groupId"]),
        lifecycle: text(&value["lifecycle"]),
        state_version: integer(&value["stateVersion"]),
        extra_data: None,
    }
}

fn aad(value: &Value) -> dto::CommitAad<String> {
    let prior = &value["prior"];
    dto::CommitAad {
        conversation_id: bytes(&value["conversationId"]),
        generation: integer(&value["generation"]),
        prior: dto::MlsAadPriorContext {
            confirmation_tag: bytes(&prior["confirmationTag"]),
            conversation_id: bytes(&prior["conversationId"]),
            epoch: integer(&prior["epoch"]),
            generation: integer(&prior["generation"]),
            group_context_hash: bytes(&prior["groupContextHash"]),
            group_id: bytes(&prior["groupId"]),
            lifecycle: text(&prior["lifecycle"]),
            state_version: integer(&prior["stateVersion"]),
            extra_data: None,
        },
        protocol_version: text(&value["protocolVersion"]),
        transition_id: bytes(&value["transitionId"]),
        extra_data: None,
    }
}

fn commit(value: &Value) -> dto::PublicCommit<String> {
    dto::PublicCommit {
        bytes: bytes(&value["bytes"]),
        content_type: text(&value["contentType"]),
        framing: text(&value["framing"]),
        sha256: bytes(&value["sha256"]),
        extra_data: None,
    }
}

fn metadata(value: &Value) -> dto::MetadataSnapshot<String> {
    let coordinate = &value["coordinate"];
    let author = &value["authorProof"];
    dto::MetadataSnapshot {
        author_proof: dto::MetadataAuthorProof {
            auth_generation_at_origin: integer(&author["authGenerationAtOrigin"]),
            author_device_id: text(&author["authorDeviceId"]),
            author_did: did(&author["authorDid"]),
            author_key_id: text(&author["authorKeyId"]),
            device_status_at_origin: text(&author["deviceStatusAtOrigin"]),
            origin_seq: integer(&author["originSeq"]),
            origin_transition_id: text(&author["originTransitionId"]),
            role_at_origin: text(&author["roleAtOrigin"]),
            signature_public_key: bytes(&author["signaturePublicKey"]),
            extra_data: None,
        },
        avatar_binding: value
            .get("avatarBinding")
            .map(|avatar| dto::MetadataAvatarBinding {
                blob_id: text(&avatar["blobId"]),
                ciphertext_sha256: bytes(&avatar["ciphertextSha256"]),
                ciphertext_size: integer(&avatar["ciphertextSize"]),
                purpose: text(&avatar["purpose"]),
                extra_data: None,
            }),
        ciphertext: bytes(&value["ciphertext"]),
        ciphertext_sha256: bytes(&value["ciphertextSha256"]),
        ciphertext_size: integer(&value["ciphertextSize"]),
        coordinate: dto::MetadataCryptoContext {
            confirmation_tag: bytes(&coordinate["confirmationTag"]),
            conversation_id: bytes(&coordinate["conversationId"]),
            epoch: integer(&coordinate["epoch"]),
            generation: integer(&coordinate["generation"]),
            group_context_hash: bytes(&coordinate["groupContextHash"]),
            group_id: bytes(&coordinate["groupId"]),
            extra_data: None,
        },
        metadata_version: integer(&value["metadataVersion"]),
        nonce: bytes(&value["nonce"]),
        origin_transition_id: text(&value["originTransitionId"]),
        extra_data: None,
    }
}

fn participant_change(value: &Value) -> dto::ParticipantChange<String> {
    match value["$type"].as_str().expect("participant union tag") {
        "blue.catbird.chat.defs#addParticipant" => {
            let provenance = &value["invitationProvenance"];
            dto::ParticipantChange::AddParticipant(Box::new(dto::AddParticipant {
                invitation_provenance: dto::InvitationProvenance {
                    invitation_transition_id: text(&provenance["invitationTransitionId"]),
                    invited_by_device_id: text(&provenance["invitedByDeviceId"]),
                    invited_by_did: did(&provenance["invitedByDid"]),
                    extra_data: None,
                },
                role: text(&value["role"]),
                status: text(&value["status"]),
                user_did: did(&value["userDid"]),
                extra_data: None,
            }))
        }
        "blue.catbird.chat.defs#removeParticipant" => {
            dto::ParticipantChange::RemoveParticipant(Box::new(dto::RemoveParticipant {
                user_did: did(&value["userDid"]),
                extra_data: None,
            }))
        }
        "blue.catbird.chat.defs#changeParticipantRole" => {
            dto::ParticipantChange::ChangeParticipantRole(Box::new(dto::ChangeParticipantRole {
                role: text(&value["role"]),
                user_did: did(&value["userDid"]),
                extra_data: None,
            }))
        }
        other => panic!("unsupported participant fixture variant {other}"),
    }
}

fn leaf_change(value: &Value) -> dto::LeafChange<String> {
    match value["$type"].as_str().expect("leaf union tag") {
        "blue.catbird.chat.defs#addLeafByRecovery" => {
            dto::LeafChange::AddLeafByRecovery(Box::new(dto::AddLeafByRecovery {
                device_id: text(&value["deviceId"]),
                key_package_ref: bytes(&value["keyPackageRef"]),
                recovery_request_id: text(&value["recoveryRequestId"]),
                user_did: did(&value["userDid"]),
                extra_data: None,
            }))
        }
        "blue.catbird.chat.defs#removeLeaf" => {
            dto::LeafChange::RemoveLeaf(Box::new(dto::RemoveLeaf {
                device_id: text(&value["deviceId"]),
                user_did: did(&value["userDid"]),
                extra_data: None,
            }))
        }
        other => panic!("unsupported leaf fixture variant {other}"),
    }
}

fn welcome(value: &Value) -> dto::WelcomeBundle<String> {
    dto::WelcomeBundle {
        content_type: text(&value["contentType"]),
        deliveries: value["deliveries"]
            .as_array()
            .expect("Welcome deliveries")
            .iter()
            .map(|delivery| {
                let provenance = &delivery["provenance"];
                dto::WelcomeDelivery {
                    provenance: dto::RecoveryWelcomeProvenance {
                        key_package_ref: bytes(&provenance["keyPackageRef"]),
                        recovery_request_id: text(&provenance["recoveryRequestId"]),
                        extra_data: None,
                    },
                    recipient_device_id: text(&delivery["recipientDeviceId"]),
                    recipient_did: did(&delivery["recipientDid"]),
                    extra_data: None,
                }
            })
            .collect(),
        framing: text(&value["framing"]),
        opaque_welcome: bytes(&value["opaqueWelcome"]),
        sha256: bytes(&value["sha256"]),
        welcome_id: text(&value["welcomeId"]),
        extra_data: None,
    }
}

fn manifest(value: &Value) -> dto::TransitionManifest<String> {
    dto::TransitionManifest {
        leaf_changes: value["leafChanges"]
            .as_array()
            .expect("leaf changes")
            .iter()
            .map(leaf_change)
            .collect(),
        leaf_recovery_request_id: value.get("leafRecoveryRequestId").map(text),
        participant_changes: value["participantChanges"]
            .as_array()
            .expect("participant changes")
            .iter()
            .map(participant_change)
            .collect(),
        welcome_bundle: value.get("welcomeBundle").map(welcome),
        extra_data: None,
    }
}

/// Fresh generated construction; neither bodies nor reference objects pass
/// through a generated `Deserialize` implementation anywhere in this module.
pub fn generated_request(body: &Value, signature: &[u8]) -> Vec<u8> {
    let signed_request = match body["$type"].as_str().expect("source body tag") {
        "blue.catbird.chat.defs#commitTransitionBody" => {
            dto::SignedTransition::SignedCommitTransition(Box::new(dto::SignedCommitTransition {
                body: dto::CommitTransitionBody {
                    aad: aad(&body["aad"]),
                    actor_device_id: text(&body["actorDeviceId"]),
                    actor_did: did(&body["actorDid"]),
                    auth_generation: integer(&body["authGeneration"]),
                    commit: commit(&body["commit"]),
                    idempotency_key: text(&body["idempotencyKey"]),
                    key_id: text(&body["keyId"]),
                    manifest: manifest(&body["manifest"]),
                    metadata_snapshot: metadata(&body["metadataSnapshot"]),
                    next: coordinates(&body["next"]),
                    prior: coordinates(&body["prior"]),
                    signature_domain: text(&body["signatureDomain"]),
                    signed_at: datetime(&body["signedAt"]),
                    transition_id: text(&body["transitionId"]),
                    extra_data: None,
                },
                signature: signature.to_vec().into(),
                extra_data: None,
            }))
        }
        "blue.catbird.chat.defs#policyTransitionBody" => {
            dto::SignedTransition::SignedPolicyTransition(Box::new(dto::SignedPolicyTransition {
                body: dto::PolicyTransitionBody {
                    actor_device_id: text(&body["actorDeviceId"]),
                    actor_did: did(&body["actorDid"]),
                    auth_generation: integer(&body["authGeneration"]),
                    idempotency_key: text(&body["idempotencyKey"]),
                    key_id: text(&body["keyId"]),
                    next: coordinates(&body["next"]),
                    participant_changes: body["participantChanges"]
                        .as_array()
                        .expect("policy changes")
                        .iter()
                        .map(participant_change)
                        .collect(),
                    prior: coordinates(&body["prior"]),
                    signature_domain: text(&body["signatureDomain"]),
                    signed_at: datetime(&body["signedAt"]),
                    transition_id: text(&body["transitionId"]),
                    extra_data: None,
                },
                signature: signature.to_vec().into(),
                extra_data: None,
            }))
        }
        "blue.catbird.chat.defs#metadataTransitionBody" => {
            dto::SignedTransition::SignedMetadataTransition(Box::new(
                dto::SignedMetadataTransition {
                    body: dto::MetadataTransitionBody {
                        actor_device_id: text(&body["actorDeviceId"]),
                        actor_did: did(&body["actorDid"]),
                        auth_generation: integer(&body["authGeneration"]),
                        idempotency_key: text(&body["idempotencyKey"]),
                        key_id: text(&body["keyId"]),
                        metadata_snapshot: metadata(&body["metadataSnapshot"]),
                        next: coordinates(&body["next"]),
                        prior: coordinates(&body["prior"]),
                        signature_domain: text(&body["signatureDomain"]),
                        signed_at: datetime(&body["signedAt"]),
                        transition_id: text(&body["transitionId"]),
                        extra_data: None,
                    },
                    signature: signature.to_vec().into(),
                    extra_data: None,
                },
            ))
        }
        "blue.catbird.chat.defs#leafRecoveryFulfillmentBody" => {
            dto::SignedTransition::SignedLeafRecoveryFulfillment(Box::new(
                dto::SignedLeafRecoveryFulfillment {
                    body: dto::LeafRecoveryFulfillmentBody {
                        aad: aad(&body["aad"]),
                        actor_device_id: text(&body["actorDeviceId"]),
                        actor_did: did(&body["actorDid"]),
                        auth_generation: integer(&body["authGeneration"]),
                        commit: commit(&body["commit"]),
                        idempotency_key: text(&body["idempotencyKey"]),
                        key_id: text(&body["keyId"]),
                        manifest: manifest(&body["manifest"]),
                        metadata_snapshot: metadata(&body["metadataSnapshot"]),
                        next: coordinates(&body["next"]),
                        prior: coordinates(&body["prior"]),
                        recovery_request_id: text(&body["recoveryRequestId"]),
                        signature_domain: text(&body["signatureDomain"]),
                        signed_at: datetime(&body["signedAt"]),
                        transition_id: text(&body["transitionId"]),
                        extra_data: None,
                    },
                    signature: signature.to_vec().into(),
                    extra_data: None,
                },
            ))
        }
        "blue.catbird.chat.defs#leaveCommitFulfillmentBody" => {
            dto::SignedTransition::SignedLeaveCommitFulfillment(Box::new(
                dto::SignedLeaveCommitFulfillment {
                    body: dto::LeaveCommitFulfillmentBody {
                        aad: aad(&body["aad"]),
                        actor_device_id: text(&body["actorDeviceId"]),
                        actor_did: did(&body["actorDid"]),
                        auth_generation: integer(&body["authGeneration"]),
                        commit: commit(&body["commit"]),
                        idempotency_key: text(&body["idempotencyKey"]),
                        key_id: text(&body["keyId"]),
                        leave_request_id: text(&body["leaveRequestId"]),
                        manifest: manifest(&body["manifest"]),
                        metadata_snapshot: metadata(&body["metadataSnapshot"]),
                        next: coordinates(&body["next"]),
                        prior: coordinates(&body["prior"]),
                        signature_domain: text(&body["signatureDomain"]),
                        signed_at: datetime(&body["signedAt"]),
                        transition_id: text(&body["transitionId"]),
                        extra_data: None,
                    },
                    signature: signature.to_vec().into(),
                    extra_data: None,
                },
            ))
        }
        other => panic!("unsupported generated transition fixture {other}"),
    };
    let input = dto::submit_transition::SubmitTransition::<String> {
        signed_request,
        extra_data: None,
    };
    serde_json::to_vec(&input).expect("actual generated request serialization")
}

// Source markers describe canonical values. In bytes-schema positions a UUID
// marker is sixteen raw bytes; operationId/deviceId references remain transport
// UUID text. This conversion does not serialize or deserialize generated DTOs.
fn source_wire(value: &Value, schema: &Value, defs: &Value) -> Value {
    match schema["type"].as_str().expect("fixture schema type") {
        "ref" => {
            let name = schema["ref"].as_str().unwrap().strip_prefix('#').unwrap();
            source_wire(value, &defs[name], defs)
        }
        "union" => {
            let name = value["$type"]
                .as_str()
                .unwrap()
                .strip_prefix(TYPE_PREFIX)
                .unwrap();
            assert!(schema["refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| reference.as_str() == Some(&format!("#{name}"))));
            source_wire(value, &defs[name], defs)
        }
        "object" => Value::Object(
            value
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, value)| {
                    let converted = if name == "$type" {
                        value.clone()
                    } else {
                        source_wire(value, &schema["properties"][name], defs)
                    };
                    (name.clone(), converted)
                })
                .collect(),
        ),
        "array" => Value::Array(
            value
                .as_array()
                .unwrap()
                .iter()
                .map(|item| source_wire(item, &schema["items"], defs))
                .collect(),
        ),
        "bytes" => {
            let object = value.as_object().expect("semantic source bytes marker");
            assert_eq!(object.len(), 1, "exact semantic source bytes marker");
            let raw = if let Some(encoded) = object.get("$bytesHex") {
                hex::decode(encoded.as_str().unwrap()).unwrap()
            } else {
                uuid::Uuid::parse_str(object["$uuid"].as_str().unwrap())
                    .unwrap()
                    .as_bytes()
                    .to_vec()
            };
            json!(STANDARD.encode(raw))
        }
        "string" if value.is_object() => {
            assert_eq!(value.as_object().unwrap().len(), 1, "exact UUID marker");
            let raw = value["$uuid"]
                .as_str()
                .expect("semantic source UUID marker");
            uuid::Uuid::parse_str(raw).expect("source UUID");
            json!(raw)
        }
        "string" | "integer" | "boolean" => value.clone(),
        other => panic!("unsupported source schema {other}"),
    }
}

fn canonical_source_body(source_case: &Value) -> Value {
    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    let body = &source_case["body"];
    let name = body["$type"]
        .as_str()
        .unwrap()
        .strip_prefix(TYPE_PREFIX)
        .unwrap();
    source_wire(body, &contract["defs"][name], &contract["defs"])
}

pub fn frozen_cases() -> Vec<GeneratedTransitionCase> {
    let source: Value = serde_json::from_str(FROZEN_SOURCE).unwrap();
    let products: Value = serde_json::from_str(FROZEN_PRODUCTS).unwrap();
    [
        ("commit", "commitEntry"),
        ("policy", "policyEntry"),
        ("metadata", "metadataEntry"),
        ("recovery", "leafRecoveryFulfillmentEntry"),
        ("leave", "leaveCommitFulfillmentEntry"),
    ]
    .into_iter()
    .map(|(name, entry_name)| {
        let entry_type = format!("{TYPE_PREFIX}{entry_name}");
        let source_case = source["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["entryKind"] == entry_type)
            .unwrap();
        let expected = products["controlEntryFingerprints"]["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["entryKind"] == entry_type)
            .unwrap()
            .clone();
        let key_ref = expected["historicalPublicKeyRef"].as_str().unwrap();
        let public_key = hex::decode(
            products["controlEntryFingerprints"]["historicalPublicKeys"][key_ref]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let body = canonical_source_body(source_case);
        let signature = STANDARD
            .decode(expected["signature"].as_str().unwrap())
            .unwrap();
        GeneratedTransitionCase {
            name,
            legacy_wrapper: serde_json::to_vec(
                &json!({"body":body,"signature":STANDARD.encode(&signature)}),
            )
            .unwrap(),
            generated_request: generated_request(&body, &signature),
            public_key,
            expected,
        }
    })
    .collect()
}

pub fn recovery_nonempty_case() -> GeneratedTransitionCase {
    let source: Value = serde_json::from_str(FROZEN_SOURCE).unwrap();
    let source_case = source["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["entryKind"] == "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry")
        .unwrap();
    let mut body = canonical_source_body(source_case);
    // A deliberately public, fixed TEST-ONLY key; never used for an account.
    let signing_key = SigningKey::from_bytes(&[0xa5; 32]);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    body["keyId"] =
        json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&public_key)));
    let recovery_id = body["recoveryRequestId"].clone();
    let key_package_ref = STANDARD.encode([0x61; 32]);
    let welcome_bytes = [0x62; 24];
    body["manifest"] = json!({
        "participantChanges": [],
        "leafChanges": [{
            "$type": "blue.catbird.chat.defs#addLeafByRecovery",
            "userDid": "did:plc:bobfixtureaaaaaaaaaaaaaa",
            "deviceId": "73737373-7373-4373-b373-737373737373",
            "recoveryRequestId": recovery_id,
            "keyPackageRef": key_package_ref
        }],
        "leafRecoveryRequestId": recovery_id,
        "welcomeBundle": {
            "welcomeId": "74747474-7474-4474-b474-747474747474",
            "framing": "mlsMessage",
            "contentType": "welcome",
            "opaqueWelcome": STANDARD.encode(welcome_bytes),
            "sha256": STANDARD.encode(Sha256::digest(welcome_bytes)),
            "deliveries": [{
                "recipientDid": "did:plc:bobfixtureaaaaaaaaaaaaaa",
                "recipientDeviceId": "73737373-7373-4373-b373-737373737373",
                "provenance": {"recoveryRequestId": recovery_id,"keyPackageRef": key_package_ref}
            }]
        }
    });
    let unsigned =
        serde_json::to_vec(&json!({"body":body,"signature":STANDARD.encode([0;64])})).unwrap();
    let canonical = crate::transcript::decode_canonical_signed_mutation(&unsigned)
        .expect("production decoder accepts supplemental recovery shape");
    let signature = signing_key.sign(canonical.transcript_bytes()).to_bytes();
    let expected = json!({
        "publicKeyHex": hex::encode(&public_key),
        "unsignedSigningProjectionCanonicalDagCborHex": hex::encode(canonical.canonical_projection()),
        "signingTranscriptHex": hex::encode(canonical.transcript_bytes()),
        "requestDigest": STANDARD.encode(canonical.request_digest()),
        "signature": STANDARD.encode(signature),
        "source": "server/tests/common/generated_transition_requests.rs::recovery_nonempty_case",
        "baseSource": "server/tests/fixtures/mls_chat_control_fingerprint_source.json#leafRecoveryFulfillmentEntry",
        "testOnlySigningSeedHex": hex::encode([0xa5;32]),
        "productsOrigin": "production canonical decoder; supplemental signing vector, not an independent frozen fingerprint oracle",
        "qualification": "schema, actual generated serialization, canonical transcript and signature only; opaque Commit, Welcome and metadata bytes are not MLS or encryption qualification"
    });
    GeneratedTransitionCase {
        name: "recovery-nonempty",
        legacy_wrapper: serde_json::to_vec(
            &json!({"body":body,"signature":STANDARD.encode(signature)}),
        )
        .unwrap(),
        generated_request: generated_request(&body, &signature),
        public_key,
        expected,
    }
}

/// Explicit fixture publication step for the Swift serializer producer. Normal
/// regression runs never write files, and frozen inputs/products are untouched.
pub fn write_recovery_nonempty_inputs(directory: &Path) {
    assert_eq!(
        std::env::var("CATBIRD_WRITE_GENERATED_TRANSITION_INPUTS").as_deref(),
        Ok("1"),
        "supplemental input generation requires explicit opt-in"
    );
    let case = recovery_nonempty_case();
    std::fs::create_dir_all(directory).expect("supplemental fixture directory");
    let wrapper: Value = serde_json::from_slice(&case.legacy_wrapper).unwrap();
    for (name, value) in [
        ("recovery-nonempty.canonical.json", wrapper),
        ("recovery-nonempty.expected.json", case.expected),
    ] {
        let mut encoded = serde_json::to_vec_pretty(&value).unwrap();
        encoded.push(b'\n');
        std::fs::write(directory.join(name), encoded).expect("write supplemental fixture input");
    }
}
