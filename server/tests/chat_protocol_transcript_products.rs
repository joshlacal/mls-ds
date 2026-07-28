#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use transcript::{
    build_verified_application_entry, build_verified_control_entry,
    decode_and_verify_application_entry, decode_and_verify_control_entry,
    decode_and_verify_signed_mutation, decode_canonical_signed_mutation,
    decode_control_fingerprint, rebind_persisted_application_entry, rebind_persisted_control_entry,
    CanonicalControlEntryProducts, CanonicalControlServerFields, ControlEntryKind,
};
use validation::{
    ed25519_key_id, CanonicalTimestamp, CanonicalUuidV4, TrustedRequestInstant, ValidatedChatNsid,
};

fn control_endpoint(kind: ControlEntryKind) -> &'static str {
    match kind {
        ControlEntryKind::Creation => "blue.catbird.chat.createConversation",
        ControlEntryKind::ParticipantAcceptance => "blue.catbird.chat.acceptConversation",
        ControlEntryKind::ConversationClose => "blue.catbird.chat.closeConversation",
        ControlEntryKind::ResetRequest => "blue.catbird.chat.requestReset",
        ControlEntryKind::ResetActivation => "blue.catbird.chat.activateReset",
        ControlEntryKind::LeaveRequest => "blue.catbird.chat.requestLeave",
        ControlEntryKind::LeaveCancellation => "blue.catbird.chat.cancelLeave",
        ControlEntryKind::Commit
        | ControlEntryKind::Policy
        | ControlEntryKind::Metadata
        | ControlEntryKind::LeafRecoveryFulfillment
        | ControlEntryKind::ZeroLeafLeave
        | ControlEntryKind::LeaveCommitFulfillment => "blue.catbird.chat.submitTransition",
    }
}

#[test]
fn all_thirteen_verified_control_variants_mint_one_strict_durable_and_response_projection() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/mls_chat_contract_vectors.json")).unwrap();
    let contract: Value = serde_json::from_str(include_str!(
        "../../lexicon/blue/catbird/chat/blue.catbird.chat.defs.json"
    ))
    .unwrap();
    let definitions = contract["defs"].as_object().unwrap();
    let cases = fixture["controlEntryFingerprints"]["cases"]
        .as_array()
        .unwrap();
    assert_eq!(cases.len(), 13);
    let actual_kinds = ControlEntryKind::ALL
        .into_iter()
        .map(ControlEntryKind::type_id)
        .collect::<BTreeSet<_>>();
    let expected_kinds = BTreeSet::from([
        "blue.catbird.chat.defs#commitEntry",
        "blue.catbird.chat.defs#policyEntry",
        "blue.catbird.chat.defs#metadataEntry",
        "blue.catbird.chat.defs#creationEntry",
        "blue.catbird.chat.defs#participantAcceptanceEntry",
        "blue.catbird.chat.defs#conversationCloseEntry",
        "blue.catbird.chat.defs#resetRequestEntry",
        "blue.catbird.chat.defs#resetActivationEntry",
        "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
        "blue.catbird.chat.defs#leaveRequestEntry",
        "blue.catbird.chat.defs#zeroLeafLeaveEntry",
        "blue.catbird.chat.defs#leaveCancellationEntry",
        "blue.catbird.chat.defs#leaveCommitFulfillmentEntry",
    ]);
    assert_eq!(actual_kinds, expected_kinds);

    for case in cases {
        let fingerprint_projection = json!({
            "entryKind": case["entryKind"],
            "entryId": case["entryId"],
            "conversationId": case["conversationId"],
            "seq": case["seq"],
            "requestDigest": case["requestDigest"],
            "signature": case["signature"],
            "serverFields": case["serverFields"],
            "receivedAt": case["receivedAt"]
        });
        let frozen_fingerprint =
            decode_control_fingerprint(&serde_json::to_vec(&fingerprint_projection).unwrap())
                .unwrap();
        assert_eq!(
            hex::encode(frozen_fingerprint.canonical_projection()),
            case["canonicalDagCborHex"]
        );
        assert_eq!(
            hex::encode(frozen_fingerprint.fingerprint()),
            case["fingerprintSha256Hex"]
        );

        let body_cbor = hex::decode(
            case["unsignedSigningProjectionCanonicalDagCborHex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let body: FixtureDagValue = serde_ipld_dagcbor::from_slice(&body_cbor).unwrap();
        let signed_name = case["signedRequestRef"]
            .as_str()
            .unwrap()
            .strip_prefix("blue.catbird.chat.defs#")
            .unwrap();
        let body_name = definitions[signed_name]["properties"]["body"]["refs"][0]
            .as_str()
            .unwrap()
            .strip_prefix('#')
            .unwrap();
        let signing_body = body.into_json_for_schema(&definitions[body_name], definitions);
        let public_key_ref = case["historicalPublicKeyRef"].as_str().unwrap();
        let public_key = hex::decode(
            fixture["controlEntryFingerprints"]["historicalPublicKeys"][public_key_ref]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let signed_request = json!({
            "body": signing_body,
            "signature": case["signature"],
        });
        let signed_request_bytes = serde_json::to_vec(&signed_request).unwrap();
        let verified_request =
            decode_and_verify_signed_mutation(&signed_request_bytes, &public_key).unwrap();
        let entry_kind = case["entryKind"].as_str().unwrap();
        let control_kind = ControlEntryKind::ALL
            .into_iter()
            .find(|kind| kind.type_id() == entry_kind)
            .unwrap();
        let server_fields = CanonicalControlServerFields::decode(
            control_kind,
            &serde_json::to_vec(&case["serverFields"]).unwrap(),
        )
        .unwrap();
        let received_at = TrustedRequestInstant::from_canonical_for_test(
            CanonicalTimestamp::parse(case["receivedAt"].as_str().unwrap()).unwrap(),
        );
        let built = build_verified_control_entry(
            verified_request,
            &ValidatedChatNsid::parse(control_endpoint(control_kind)).unwrap(),
            CanonicalUuidV4::parse(case["entryId"].as_str().unwrap()).unwrap(),
            CanonicalUuidV4::parse(case["conversationId"].as_str().unwrap()).unwrap(),
            case["seq"].as_u64().unwrap(),
            &received_at,
            server_fields,
        )
        .unwrap();
        assert_eq!(
            hex::encode(built.outer_control_projection()),
            case["canonicalDagCborHex"]
        );
        assert_eq!(
            hex::encode(built.outer_control_fingerprint()),
            case["fingerprintSha256Hex"]
        );

        let products = CanonicalControlEntryProducts::mint(&built).expect("mint products");
        let durable: Value = serde_json::from_slice(products.durable_json()).expect("durable JSON");
        assert_eq!(durable["$type"], case["entryKind"]);
        assert_eq!(durable["entryId"], case["entryId"]);
        assert_eq!(durable["conversationId"], case["conversationId"]);
        assert_eq!(durable["seq"], case["seq"]);
        assert_eq!(durable["receivedAt"], case["receivedAt"]);
        assert_eq!(
            durable["signedRequest"]["signature"], case["signature"],
            "durable nested signature must be bare STANDARD base64"
        );
        assert_eq!(
            STANDARD
                .decode(
                    durable["signedRequest"]["signature"]
                        .as_str()
                        .expect("bare signature")
                )
                .expect("STANDARD base64"),
            built.mutation().signature()
        );
        let reverified = decode_and_verify_control_entry(products.durable_json(), &public_key)
            .expect("durable product must strictly decode and reverify");
        assert_eq!(reverified.kind(), built.kind());
        assert_eq!(reverified.entry_id(), built.entry_id());
        assert_eq!(reverified.conversation_id(), built.conversation_id());
        assert_eq!(reverified.seq(), built.seq());
        assert_eq!(reverified.received_at(), built.received_at());
        assert_eq!(
            reverified.outer_control_fingerprint(),
            built.outer_control_fingerprint()
        );

        let response: Value =
            serde_json::from_slice(products.canonical_response_json()).expect("response JSON");
        assert_eq!(response["$type"], case["entryKind"]);
        assert_eq!(
            response["signedRequest"]["signature"]["$bytes"], case["signature"],
            "response nested signature must use the DAG-JSON bytes representation"
        );
        assert_eq!(
            products.canonical_response_json(),
            serde_json::to_vec(products.response_entry())
                .expect("serialize sole response authority")
                .as_slice(),
            "exposed response bytes must be the exact generated DTO serialization"
        );
        let generated_round_trip = serde_json::to_vec(products.response_entry())
            .expect("serialize generated closed union");
        let round_tripped: catbird_atproto::generated::blue_catbird::chat::ConversationEntry =
            serde_json::from_slice(&generated_round_trip)
                .expect("deserialize generated closed union");
        assert_eq!(
            serde_json::to_value(round_tripped).expect("round-trip value"),
            serde_json::to_value(products.response_entry()).expect("original response value")
        );

        let mut changed_signature = durable.clone();
        let mut signature = STANDARD
            .decode(
                changed_signature["signedRequest"]["signature"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        signature[0] ^= 1;
        changed_signature["signedRequest"]["signature"] = json!(STANDARD.encode(signature));
        assert!(decode_and_verify_control_entry(
            &serde_json::to_vec(&changed_signature).unwrap(),
            &public_key
        )
        .is_err());

        let wrong_key = SigningKey::from_bytes(&[0x7d_u8; 32]);
        assert!(decode_and_verify_control_entry(
            products.durable_json(),
            wrong_key.verifying_key().as_bytes()
        )
        .is_err());
        let mut changed_key_id = durable.clone();
        changed_key_id["signedRequest"]["body"]["keyId"] =
            json!(ed25519_key_id(wrong_key.verifying_key().as_bytes())
                .unwrap()
                .as_str());
        assert!(decode_and_verify_control_entry(
            &serde_json::to_vec(&changed_key_id).unwrap(),
            &public_key
        )
        .is_err());

        let mut changed_body_conversation = durable.clone();
        if changed_body_conversation["signedRequest"]["body"]
            .get("conversationId")
            .is_some()
        {
            changed_body_conversation["signedRequest"]["body"]["conversationId"] =
                json!("22222222-2222-4222-8222-222222222222");
        } else {
            changed_body_conversation["signedRequest"]["body"]["prior"]["conversationId"] =
                json!("22222222-2222-4222-8222-222222222222");
        }
        assert!(decode_and_verify_control_entry(
            &serde_json::to_vec(&changed_body_conversation).unwrap(),
            &public_key
        )
        .is_err());
        let mut changed_outer_conversation = durable.clone();
        changed_outer_conversation["conversationId"] =
            json!("22222222-2222-4222-8222-222222222222");
        assert!(decode_and_verify_control_entry(
            &serde_json::to_vec(&changed_outer_conversation).unwrap(),
            &public_key
        )
        .is_err());

        let mut changed_type = durable.clone();
        changed_type["$type"] = json!(ControlEntryKind::ALL
            .into_iter()
            .find(|kind| kind.type_id() != entry_kind)
            .unwrap()
            .type_id());
        assert!(decode_and_verify_control_entry(
            &serde_json::to_vec(&changed_type).unwrap(),
            &public_key
        )
        .is_err());
        let mut changed_server_fields = durable.clone();
        match control_kind {
            ControlEntryKind::ParticipantAcceptance => {
                changed_server_fields
                    .as_object_mut()
                    .unwrap()
                    .remove("recovery");
            }
            ControlEntryKind::ConversationClose => {
                changed_server_fields
                    .as_object_mut()
                    .unwrap()
                    .remove("tombstone");
            }
            _ => {
                changed_server_fields["unexpectedServerField"] = json!(true);
            }
        }
        assert!(decode_and_verify_control_entry(
            &serde_json::to_vec(&changed_server_fields).unwrap(),
            &public_key
        )
        .is_err());

        let rebound = rebind_persisted_control_entry(
            decode_and_verify_control_entry(products.durable_json(), &public_key).unwrap(),
            &signed_request_bytes,
            &public_key,
        )
        .expect("exact persisted control wrapper/key rebind");
        assert_eq!(
            rebound.mutation().accepted_wrapper_bytes(),
            Some(signed_request_bytes.as_slice())
        );
        assert!(rebind_persisted_control_entry(
            decode_and_verify_control_entry(products.durable_json(), &public_key).unwrap(),
            &signed_request_bytes,
            wrong_key.verifying_key().as_bytes(),
        )
        .is_err());
        let mut changed_wrapper = signed_request.clone();
        changed_wrapper["signature"] = json!(STANDARD.encode([0_u8; 64]));
        assert!(rebind_persisted_control_entry(
            decode_and_verify_control_entry(products.durable_json(), &public_key).unwrap(),
            &serde_json::to_vec(&changed_wrapper).unwrap(),
            &public_key,
        )
        .is_err());
    }
}

const APPLICATION_CONVERSATION_ID: &str = "11111111-1111-4111-9111-111111111111";
const APPLICATION_ENTRY_ID: &str = "8eee908a-1f55-4b55-8271-7690f6de14fc";
const APPLICATION_MESSAGE_ID: &str = "51515151-5151-4151-9151-515151515151";
const APPLICATION_ACTOR_DEVICE_ID: &str = "70707070-7070-4070-b070-707070707070";
const APPLICATION_ACTOR_DID: &str = "did:plc:alicefixtureaaaaaaaaaaaa";

fn application_coordinates(conversation_id: &str) -> Value {
    json!({
        "conversationId": conversation_id,
        "generation": 1,
        "stateVersion": 2,
        "groupId": STANDARD.encode([0x22_u8; 32]),
        "epoch": 1,
        "groupContextHash": STANDARD.encode([0x23_u8; 32]),
        "confirmationTag": STANDARD.encode([0x24_u8; 32]),
        "lifecycle": "active"
    })
}

fn application_aad_prior(conversation_id: &str) -> Value {
    let mut prior = application_coordinates(conversation_id);
    prior["conversationId"] =
        json!(STANDARD.encode(uuid::Uuid::parse_str(conversation_id).unwrap().as_bytes()));
    prior
}

fn sign_application_wrapper(
    signing_key: &SigningKey,
    conversation_id: &str,
    message_id: &str,
) -> Vec<u8> {
    let key_id = ed25519_key_id(signing_key.verifying_key().as_bytes()).unwrap();
    let message_bytes = [0x31_u8; 8];
    let conversation_bytes = uuid::Uuid::parse_str(conversation_id).unwrap();
    let message_id_bytes = uuid::Uuid::parse_str(message_id).unwrap();
    let mut wrapper = json!({
        "body": {
            "$type": "blue.catbird.chat.defs#applicationSendBody",
            "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0}",
            "messageId": message_id,
            "actorDid": APPLICATION_ACTOR_DID,
            "actorDeviceId": APPLICATION_ACTOR_DEVICE_ID,
            "keyId": key_id.as_str(),
            "authGeneration": 1,
            "prior": application_coordinates(conversation_id),
            "aad": {
                "protocolVersion": "1",
                "conversationId": STANDARD.encode(conversation_bytes.as_bytes()),
                "generation": 1,
                "messageId": STANDARD.encode(message_id_bytes.as_bytes()),
                "prior": application_aad_prior(conversation_id)
            },
            "applicationMessage": {
                "framing": "mlsMessage",
                "contentType": "privateMessageApplication",
                "bytes": STANDARD.encode(message_bytes),
                "sha256": STANDARD.encode(Sha256::digest(message_bytes))
            },
            "blobBindings": [],
            "signedAt": "2026-07-22T12:34:55.000Z"
        },
        "signature": STANDARD.encode([0_u8; 64])
    });
    let canonical = decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper).unwrap())
        .expect("synthetic application body satisfies the live contract");
    wrapper["signature"] =
        json!(STANDARD.encode(signing_key.sign(canonical.transcript_bytes()).to_bytes()));
    serde_json::to_vec(&wrapper).unwrap()
}

struct SyntheticApplication {
    canonical_entry: Vec<u8>,
    raw_wrapper: Vec<u8>,
    public_key: [u8; 32],
    payload_sha256: [u8; 32],
    request_digest: [u8; 32],
    signature: [u8; 64],
    fingerprint: [u8; 32],
}

fn synthetic_application(message_id: &str) -> SyntheticApplication {
    let signing_key = SigningKey::from_bytes(&[0x61_u8; 32]);
    let raw_wrapper =
        sign_application_wrapper(&signing_key, APPLICATION_CONVERSATION_ID, message_id);
    let mutation =
        decode_and_verify_signed_mutation(&raw_wrapper, signing_key.verifying_key().as_bytes())
            .unwrap();
    let received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2026-07-22T12:34:56.000Z").unwrap(),
    );
    let built = build_verified_application_entry(
        mutation,
        CanonicalUuidV4::parse(APPLICATION_ENTRY_ID).unwrap(),
        CanonicalUuidV4::parse(APPLICATION_CONVERSATION_ID).unwrap(),
        929_873_984_000_188,
        &received_at,
    )
    .unwrap();
    SyntheticApplication {
        canonical_entry: built.canonical_entry_bytes().to_vec(),
        raw_wrapper,
        public_key: *signing_key.verifying_key().as_bytes(),
        payload_sha256: *built.accepted_payload_sha256(),
        request_digest: *built.mutation().request_digest(),
        signature: *built.mutation().signature(),
        fingerprint: *built.outer_application_fingerprint(),
    }
}

#[test]
fn persisted_application_rebind_rejects_wrapper_key_and_fingerprint_splices() {
    let fixture = synthetic_application(APPLICATION_MESSAGE_ID);
    let decoded =
        decode_and_verify_application_entry(&fixture.canonical_entry, &fixture.public_key).unwrap();
    let rebound = rebind_persisted_application_entry(
        decoded,
        &fixture.canonical_entry,
        &fixture.payload_sha256,
        &fixture.raw_wrapper,
        &fixture.request_digest,
        &fixture.signature,
        &fixture.fingerprint,
        &fixture.public_key,
    )
    .expect("exact persisted application rebind");
    assert_eq!(
        rebound.mutation().accepted_wrapper_bytes(),
        Some(fixture.raw_wrapper.as_slice())
    );

    let other = synthetic_application("52525252-5252-4252-9252-525252525252");
    let decoded =
        decode_and_verify_application_entry(&fixture.canonical_entry, &fixture.public_key).unwrap();
    assert!(rebind_persisted_application_entry(
        decoded,
        &fixture.canonical_entry,
        &fixture.payload_sha256,
        &other.raw_wrapper,
        &fixture.request_digest,
        &fixture.signature,
        &fixture.fingerprint,
        &fixture.public_key,
    )
    .is_err());

    let wrong_key = SigningKey::from_bytes(&[0x64_u8; 32]);
    let decoded =
        decode_and_verify_application_entry(&fixture.canonical_entry, &fixture.public_key).unwrap();
    assert!(rebind_persisted_application_entry(
        decoded,
        &fixture.canonical_entry,
        &fixture.payload_sha256,
        &fixture.raw_wrapper,
        &fixture.request_digest,
        &fixture.signature,
        &fixture.fingerprint,
        wrong_key.verifying_key().as_bytes(),
    )
    .is_err());

    let mut wrong_fingerprint = fixture.fingerprint;
    wrong_fingerprint[0] ^= 1;
    let decoded =
        decode_and_verify_application_entry(&fixture.canonical_entry, &fixture.public_key).unwrap();
    assert!(rebind_persisted_application_entry(
        decoded,
        &fixture.canonical_entry,
        &fixture.payload_sha256,
        &fixture.raw_wrapper,
        &fixture.request_digest,
        &fixture.signature,
        &wrong_fingerprint,
        &fixture.public_key,
    )
    .is_err());
}

enum FixtureDagValue {
    String(String),
    Integer(u64),
    Bool(bool),
    Bytes(Vec<u8>),
    Array(Vec<Self>),
    Map(BTreeMap<String, Self>),
}

impl<'de> Deserialize<'de> for FixtureDagValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(FixtureDagVisitor)
    }
}

struct FixtureDagVisitor;

impl<'de> Visitor<'de> for FixtureDagVisitor {
    type Value = FixtureDagValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the frozen clean-chat DAG-CBOR value profile")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(FixtureDagValue::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(FixtureDagValue::Integer(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        u64::try_from(value)
            .map(FixtureDagValue::Integer)
            .map_err(|_| E::custom("negative fixture integer"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(FixtureDagValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(FixtureDagValue::String(value))
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(FixtureDagValue::Bytes(value.to_vec()))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(FixtureDagValue::Bytes(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(FixtureDagValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some((key, value)) = map.next_entry()? {
            values.insert(key, value);
        }
        Ok(FixtureDagValue::Map(values))
    }
}

impl FixtureDagValue {
    fn into_json_for_schema(
        self,
        schema: &Value,
        definitions: &serde_json::Map<String, Value>,
    ) -> Value {
        match schema["type"].as_str().unwrap() {
            "ref" => {
                let definition_name = schema["ref"].as_str().unwrap().strip_prefix('#').unwrap();
                if matches!(definition_name, "operationId" | "deviceId") {
                    let Self::Bytes(value) = self else {
                        panic!("frozen UUID projection was not DAG-CBOR bytes");
                    };
                    Value::String(
                        uuid::Uuid::from_slice(&value)
                            .unwrap()
                            .hyphenated()
                            .to_string(),
                    )
                } else {
                    self.into_json_for_schema(&definitions[definition_name], definitions)
                }
            }
            "union" => {
                let definition_name = {
                    let Self::Map(values) = &self else {
                        panic!("frozen union projection was not a DAG-CBOR map");
                    };
                    let Some(Self::String(type_id)) = values.get("$type") else {
                        panic!("frozen union projection omitted its type tag");
                    };
                    type_id
                        .strip_prefix("blue.catbird.chat.defs#")
                        .unwrap()
                        .to_owned()
                };
                assert!(
                    schema["refs"].as_array().unwrap().iter().any(
                        |reference| reference.as_str() == Some(&format!("#{definition_name}"))
                    ),
                    "frozen union selected a disallowed type"
                );
                self.into_json_for_schema(&definitions[definition_name.as_str()], definitions)
            }
            "object" => {
                let Self::Map(values) = self else {
                    panic!("frozen object projection was not a DAG-CBOR map");
                };
                let properties = schema["properties"].as_object().unwrap();
                Value::Object(
                    values
                        .into_iter()
                        .map(|(name, value)| {
                            let value = if name == "$type" {
                                let Self::String(type_id) = value else {
                                    panic!("frozen object type tag was not text");
                                };
                                Value::String(type_id)
                            } else {
                                value.into_json_for_schema(&properties[&name], definitions)
                            };
                            (name, value)
                        })
                        .collect(),
                )
            }
            "string" => {
                let Self::String(value) = self else {
                    panic!("frozen string projection was not DAG-CBOR text");
                };
                Value::String(value)
            }
            "bytes" => {
                let Self::Bytes(value) = self else {
                    panic!("frozen byte projection was not DAG-CBOR bytes");
                };
                Value::String(STANDARD.encode(value))
            }
            "integer" => {
                let Self::Integer(value) = self else {
                    panic!("frozen integer projection was not a DAG-CBOR integer");
                };
                json!(value)
            }
            "boolean" => {
                let Self::Bool(value) = self else {
                    panic!("frozen boolean projection was not a DAG-CBOR boolean");
                };
                json!(value)
            }
            "array" => {
                let Self::Array(values) = self else {
                    panic!("frozen array projection was not a DAG-CBOR array");
                };
                Value::Array(
                    values
                        .into_iter()
                        .map(|value| value.into_json_for_schema(&schema["items"], definitions))
                        .collect(),
                )
            }
            other => panic!("unsupported frozen fixture schema type {other}"),
        }
    }
}
