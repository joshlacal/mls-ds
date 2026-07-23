#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

use std::{collections::BTreeMap, fmt};

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use transcript::{
    build_verified_application_entry, decode_and_verify_application_entry,
    decode_and_verify_signed_mutation, decode_canonical_signed_mutation,
    rebind_persisted_application_entry, VerifiedApplicationEntry,
};
use validation::{ed25519_key_id, CanonicalTimestamp, CanonicalUuidV4, TrustedRequestInstant};

const CONVERSATION_ID: &str = "11111111-1111-4111-9111-111111111111";
const ENTRY_ID: &str = "8eee908a-1f55-4b55-8271-7690f6de14fc";
const MESSAGE_ID: &str = "51515151-5151-4151-9151-515151515151";
const ACTOR_DEVICE_ID: &str = "70707070-7070-4070-b070-707070707070";
const ACTOR_DID: &str = "did:plc:alicefixtureaaaaaaaaaaaa";

#[derive(Clone, Debug, Eq, PartialEq)]
enum TestCbor {
    Text(String),
    Bytes(Vec<u8>),
    Integer(u64),
    Bool(bool),
    Array(Vec<TestCbor>),
    Map(BTreeMap<String, TestCbor>),
}

impl<'de> Deserialize<'de> for TestCbor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(TestCborVisitor)
    }
}

struct TestCborVisitor;

impl<'de> Visitor<'de> for TestCborVisitor {
    type Value = TestCbor;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("closed DAG-CBOR")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(TestCbor::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(TestCbor::Integer(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        u64::try_from(value)
            .map(TestCbor::Integer)
            .map_err(|_| E::custom("negative integer"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(TestCbor::Text(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(TestCbor::Text(value))
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(TestCbor::Bytes(value.to_vec()))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(TestCbor::Bytes(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(TestCbor::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value()?;
            if values.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate key"));
            }
        }
        Ok(TestCbor::Map(values))
    }
}

impl Serialize for TestCbor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Text(value) => serializer.serialize_str(value),
            Self::Bytes(value) => serializer.serialize_bytes(value),
            Self::Integer(value) => serializer.serialize_u64(*value),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Self::Map(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

fn test_map(value: &TestCbor) -> &BTreeMap<String, TestCbor> {
    match value {
        TestCbor::Map(value) => value,
        _ => panic!("expected CBOR map"),
    }
}

fn test_map_mut(value: &mut TestCbor) -> &mut BTreeMap<String, TestCbor> {
    match value {
        TestCbor::Map(value) => value,
        _ => panic!("expected CBOR map"),
    }
}

fn decode_test_cbor(bytes: &[u8]) -> TestCbor {
    serde_ipld_dagcbor::from_slice(bytes).unwrap()
}

fn encode_test_cbor(value: &TestCbor) -> Vec<u8> {
    serde_ipld_dagcbor::to_vec(value).unwrap()
}

struct Golden {
    entry: Vec<u8>,
    public_key: [u8; 32],
    payload_sha256: [u8; 32],
    request_digest: [u8; 32],
    fingerprint_projection: Vec<u8>,
    fingerprint: [u8; 32],
}

fn hex_array<const N: usize>(value: &Value) -> [u8; N] {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn golden() -> Golden {
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../docs/generated-artifacts/chat-application-v1/manifest.json"
    ))
    .unwrap();
    let vector = &manifest["vectors"][0];
    let signed = &vector["signedOuterEntry"];
    Golden {
        entry: hex::decode(signed["applicationEntryCborHex"].as_str().unwrap()).unwrap(),
        public_key: hex_array(&vector["transportEvidence"]["senderLeafSignaturePublicKeyHex"]),
        payload_sha256: hex_array(&signed["applicationEntryCborSha256Hex"]),
        request_digest: hex_array(&signed["requestDigestHex"]),
        fingerprint_projection: hex::decode(
            signed["fingerprintProjectionCborHex"].as_str().unwrap(),
        )
        .unwrap(),
        fingerprint: hex_array(&signed["fingerprintHex"]),
    }
}

fn coordinates(conversation_id: &str) -> Value {
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

fn aad_prior(conversation_id: &str) -> Value {
    let mut prior = coordinates(conversation_id);
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
            "actorDid": ACTOR_DID,
            "actorDeviceId": ACTOR_DEVICE_ID,
            "keyId": key_id.as_str(),
            "authGeneration": 1,
            "prior": coordinates(conversation_id),
            "aad": {
                "protocolVersion": "1",
                "conversationId": STANDARD.encode(conversation_bytes.as_bytes()),
                "generation": 1,
                "messageId": STANDARD.encode(message_id_bytes.as_bytes()),
                "prior": aad_prior(conversation_id)
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
        .expect("synthetic application body must satisfy the live lexicon");
    wrapper["signature"] =
        json!(STANDARD.encode(signing_key.sign(canonical.transcript_bytes()).to_bytes()));
    serde_json::to_vec(&wrapper).unwrap()
}

struct Synthetic {
    canonical_entry: Vec<u8>,
    raw_wrapper: Vec<u8>,
    public_key: [u8; 32],
    payload_sha256: [u8; 32],
    request_digest: [u8; 32],
    signature: [u8; 64],
    fingerprint: [u8; 32],
}

fn synthetic(message_id: &str) -> Synthetic {
    let signing_key = SigningKey::from_bytes(&[0x61_u8; 32]);
    let raw_wrapper = sign_application_wrapper(&signing_key, CONVERSATION_ID, message_id);
    let mutation =
        decode_and_verify_signed_mutation(&raw_wrapper, signing_key.verifying_key().as_bytes())
            .unwrap();
    let received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2026-07-22T12:34:56.000Z").unwrap(),
    );
    let built = build_verified_application_entry(
        mutation,
        CanonicalUuidV4::parse(ENTRY_ID).unwrap(),
        CanonicalUuidV4::parse(CONVERSATION_ID).unwrap(),
        929_873_984_000_188,
        &received_at,
    )
    .unwrap();
    Synthetic {
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
fn frozen_application_entry_golden_is_exact_and_historically_verified() {
    let golden = golden();
    let entry = decode_and_verify_application_entry(&golden.entry, &golden.public_key).unwrap();

    assert_eq!(entry.entry_id().as_str(), ENTRY_ID);
    assert_eq!(entry.conversation_id().as_str(), CONVERSATION_ID);
    assert_eq!(entry.seq(), 930_197_622_689_980);
    assert_eq!(entry.received_at().as_str(), "2026-07-22T12:34:56.000Z");
    assert_eq!(entry.canonical_entry_bytes(), golden.entry);
    assert_eq!(entry.accepted_payload_sha256(), &golden.payload_sha256);
    assert_eq!(entry.mutation().request_digest(), &golden.request_digest);
    assert_eq!(
        entry.outer_application_projection(),
        golden.fingerprint_projection
    );
    assert_eq!(entry.outer_application_fingerprint(), &golden.fingerprint);
    assert_eq!(entry.mutation().accepted_wrapper_bytes(), None);
}

#[test]
fn repository_builder_consumes_only_a_verified_application_send() {
    let fixture = synthetic(MESSAGE_ID);
    let decoded =
        decode_and_verify_application_entry(&fixture.canonical_entry, &fixture.public_key).unwrap();
    assert_eq!(decoded.canonical_entry_bytes(), fixture.canonical_entry);
    assert_eq!(decoded.accepted_payload_sha256(), &fixture.payload_sha256);
    assert_eq!(
        decoded.outer_application_fingerprint(),
        &fixture.fingerprint
    );

    let signing_key = SigningKey::from_bytes(&[0x62_u8; 32]);
    let key_id = ed25519_key_id(signing_key.verifying_key().as_bytes()).unwrap();
    let mut wrapper = json!({
        "body": {
            "$type": "blue.catbird.chat.defs#leaveCancellationBody",
            "signatureDomain": "CATBIRD-CHAT-LEAVE-CANCEL\u{0}",
            "conversationId": CONVERSATION_ID,
            "leaveRequestId": "33333333-3333-4333-8333-333333333333",
            "actorDid": ACTOR_DID,
            "actorDeviceId": ACTOR_DEVICE_ID,
            "keyId": key_id.as_str(),
            "authGeneration": 1,
            "idempotencyKey": "44444444-4444-4444-8444-444444444444",
            "signedAt": "2026-07-22T12:34:55.000Z"
        },
        "signature": STANDARD.encode([0_u8; 64])
    });
    let canonical =
        decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper).unwrap()).unwrap();
    wrapper["signature"] =
        json!(STANDARD.encode(signing_key.sign(canonical.transcript_bytes()).to_bytes()));
    let control = decode_and_verify_signed_mutation(
        &serde_json::to_vec(&wrapper).unwrap(),
        signing_key.verifying_key().as_bytes(),
    )
    .unwrap();
    assert!(build_verified_application_entry(
        control,
        CanonicalUuidV4::parse(ENTRY_ID).unwrap(),
        CanonicalUuidV4::parse(CONVERSATION_ID).unwrap(),
        1,
        &TrustedRequestInstant::from_canonical_for_test(
            CanonicalTimestamp::parse("2026-07-22T12:34:56.000Z").unwrap()
        ),
    )
    .is_err());
}

#[test]
fn repository_builder_rejects_body_conversation_and_safe_sequence_mismatches() {
    let signing_key = SigningKey::from_bytes(&[0x63_u8; 32]);
    let raw_wrapper = sign_application_wrapper(&signing_key, CONVERSATION_ID, MESSAGE_ID);
    let mutation = || {
        decode_and_verify_signed_mutation(&raw_wrapper, signing_key.verifying_key().as_bytes())
            .unwrap()
    };
    let received_at = TrustedRequestInstant::from_canonical_for_test(
        CanonicalTimestamp::parse("2026-07-22T12:34:56.000Z").unwrap(),
    );
    let entry_id = || CanonicalUuidV4::parse(ENTRY_ID).unwrap();

    assert!(build_verified_application_entry(
        mutation(),
        entry_id(),
        CanonicalUuidV4::parse("12121212-1212-4212-9212-121212121212").unwrap(),
        1,
        &received_at,
    )
    .is_err());
    assert!(build_verified_application_entry(
        mutation(),
        entry_id(),
        CanonicalUuidV4::parse(CONVERSATION_ID).unwrap(),
        0,
        &received_at,
    )
    .is_err());
    assert!(build_verified_application_entry(
        mutation(),
        entry_id(),
        CanonicalUuidV4::parse(CONVERSATION_ID).unwrap(),
        9_007_199_254_740_992,
        &received_at,
    )
    .is_err());
}

#[test]
fn restart_rebind_requires_every_exact_persisted_crypto_column() {
    let fixture = synthetic(MESSAGE_ID);
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
    .unwrap();
    assert_eq!(
        rebound.mutation().accepted_wrapper_bytes(),
        Some(fixture.raw_wrapper.as_slice())
    );

    let mut wrong_hash = fixture.payload_sha256;
    wrong_hash[0] ^= 1;
    let decoded =
        decode_and_verify_application_entry(&fixture.canonical_entry, &fixture.public_key).unwrap();
    assert!(rebind_persisted_application_entry(
        decoded,
        &fixture.canonical_entry,
        &wrong_hash,
        &fixture.raw_wrapper,
        &fixture.request_digest,
        &fixture.signature,
        &fixture.fingerprint,
        &fixture.public_key,
    )
    .is_err());

    let mut wrong_digest = fixture.request_digest;
    wrong_digest[0] ^= 1;
    let decoded =
        decode_and_verify_application_entry(&fixture.canonical_entry, &fixture.public_key).unwrap();
    assert!(rebind_persisted_application_entry(
        decoded,
        &fixture.canonical_entry,
        &fixture.payload_sha256,
        &fixture.raw_wrapper,
        &wrong_digest,
        &fixture.signature,
        &fixture.fingerprint,
        &fixture.public_key,
    )
    .is_err());

    let mut wrong_signature = fixture.signature;
    wrong_signature[0] ^= 1;
    let decoded =
        decode_and_verify_application_entry(&fixture.canonical_entry, &fixture.public_key).unwrap();
    assert!(rebind_persisted_application_entry(
        decoded,
        &fixture.canonical_entry,
        &fixture.payload_sha256,
        &fixture.raw_wrapper,
        &fixture.request_digest,
        &wrong_signature,
        &fixture.fingerprint,
        &fixture.public_key,
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

    let mut wrong_bytes = fixture.canonical_entry.clone();
    wrong_bytes.push(0);
    let decoded =
        decode_and_verify_application_entry(&fixture.canonical_entry, &fixture.public_key).unwrap();
    assert!(rebind_persisted_application_entry(
        decoded,
        &wrong_bytes,
        &fixture.payload_sha256,
        &fixture.raw_wrapper,
        &fixture.request_digest,
        &fixture.signature,
        &fixture.fingerprint,
        &fixture.public_key,
    )
    .is_err());
}

#[test]
fn outer_scalar_mutations_are_bound_or_rejected_before_authority() {
    let golden = golden();
    let original = decode_test_cbor(&golden.entry);

    for field in ["entryId", "seq", "receivedAt"] {
        let mut changed = original.clone();
        match test_map_mut(&mut changed).get_mut(field).unwrap() {
            TestCbor::Bytes(bytes) => bytes[15] ^= 1,
            TestCbor::Integer(value) => *value += 1,
            TestCbor::Text(value) => *value = "2026-07-22T12:34:56.001Z".to_owned(),
            _ => panic!("unexpected scalar type"),
        }
        let changed = encode_test_cbor(&changed);
        let verified = decode_and_verify_application_entry(&changed, &golden.public_key).unwrap();
        assert_ne!(verified.canonical_entry_bytes(), golden.entry);
        assert_ne!(verified.accepted_payload_sha256(), &golden.payload_sha256);
        assert_ne!(
            verified.outer_application_fingerprint(),
            &golden.fingerprint
        );
    }

    let mut conversation_mismatch = original.clone();
    match test_map_mut(&mut conversation_mismatch)
        .get_mut("conversationId")
        .unwrap()
    {
        TestCbor::Bytes(bytes) => bytes[15] ^= 1,
        _ => panic!("conversationId must be bytes"),
    }
    assert!(decode_and_verify_application_entry(
        &encode_test_cbor(&conversation_mismatch),
        &golden.public_key,
    )
    .is_err());

    let mut signature = original.clone();
    let signed = test_map_mut(
        test_map_mut(&mut signature)
            .get_mut("signedRequest")
            .unwrap(),
    );
    match signed.get_mut("signature").unwrap() {
        TestCbor::Bytes(bytes) => bytes[0] ^= 1,
        _ => panic!("signature must be bytes"),
    }
    assert!(
        decode_and_verify_application_entry(&encode_test_cbor(&signature), &golden.public_key,)
            .is_err()
    );

    let mut body_digest = original;
    let signed = test_map_mut(
        test_map_mut(&mut body_digest)
            .get_mut("signedRequest")
            .unwrap(),
    );
    let body = test_map_mut(signed.get_mut("body").unwrap());
    match body.get_mut("messageId").unwrap() {
        TestCbor::Bytes(bytes) => bytes[15] ^= 1,
        _ => panic!("messageId must be bytes"),
    }
    assert!(decode_and_verify_application_entry(
        &encode_test_cbor(&body_digest),
        &golden.public_key,
    )
    .is_err());
}

#[test]
fn closed_application_entry_rejects_extra_missing_wrong_wrapper_and_noncanonical_bytes() {
    let golden = golden();
    let original = decode_test_cbor(&golden.entry);

    let mut extra = original.clone();
    test_map_mut(&mut extra).insert("unknown".into(), TestCbor::Bool(true));
    assert!(
        decode_and_verify_application_entry(&encode_test_cbor(&extra), &golden.public_key).is_err()
    );

    let mut missing = original.clone();
    test_map_mut(&mut missing).remove("entryId");
    assert!(
        decode_and_verify_application_entry(&encode_test_cbor(&missing), &golden.public_key)
            .is_err()
    );

    let mut wrong_wrapper = original.clone();
    let body = test_map(&test_map(&wrong_wrapper)["signedRequest"])["body"].clone();
    test_map_mut(&mut wrong_wrapper).insert("signedRequest".into(), body);
    assert!(decode_and_verify_application_entry(
        &encode_test_cbor(&wrong_wrapper),
        &golden.public_key,
    )
    .is_err());

    let mut trailing = golden.entry.clone();
    trailing.push(0);
    assert!(decode_and_verify_application_entry(&trailing, &golden.public_key).is_err());

    assert_eq!(golden.entry[0], 0xa5);
    let mut nonminimal_map = vec![0xb8, 0x05];
    nonminimal_map.extend_from_slice(&golden.entry[1..]);
    assert!(decode_and_verify_application_entry(&nonminimal_map, &golden.public_key).is_err());

    assert!(decode_and_verify_application_entry(br#"{}"#, &golden.public_key).is_err());
}

#[test]
fn restart_rebind_rejects_another_valid_signed_wrapper_and_fingerprint_substitution() {
    let fixture = synthetic(MESSAGE_ID);
    let other = synthetic("52525252-5252-4252-9252-525252525252");
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

    let decoded =
        decode_and_verify_application_entry(&fixture.canonical_entry, &fixture.public_key).unwrap();
    assert!(rebind_persisted_application_entry(
        decoded,
        &fixture.canonical_entry,
        &fixture.payload_sha256,
        &fixture.raw_wrapper,
        &fixture.request_digest,
        &fixture.signature,
        &other.fingerprint,
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
}

#[test]
fn application_authority_has_no_public_raw_constructor_and_is_non_clone() {
    trait AmbiguousIfClone<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: ?Sized + Clone> AmbiguousIfClone<u8> for T {}
    let _ = <VerifiedApplicationEntry as AmbiguousIfClone<_>>::marker;

    let source = include_str!("../src/chat_protocol/transcript.rs");
    assert!(source.contains("pub(crate) struct VerifiedApplicationEntry"));
    assert!(!source.contains("pub struct VerifiedApplicationEntry"));
    assert!(!source.contains("pub fn build_verified_application_entry"));
    assert!(!source.contains("pub fn decode_and_verify_application_entry"));
    assert!(!source.contains("pub fn rebind_persisted_application_entry"));
}
